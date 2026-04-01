import json
import tempfile
import time
import unittest
from pathlib import Path

from ctf_agent.core.agent_loop import (
    AgentLoop,
    ToolRegistry,
    _load_session,
    _restore_state,
    _save_session,
    _serialize_session,
)
from ctf_agent.core.board import build_board_summary, load_workspace_board
from ctf_agent.core.llm import LLMResponse, ToolCall
from ctf_agent.core.models import Challenge, ChallengeState
from ctf_agent.core.workspace import WorkspaceManager
from ctf_agent.mcp_server import CTFMCPServer


def _tool_registry(tool_map):
    registry = ToolRegistry()
    for name, func in dict(tool_map or {}).items():
        registry.register(
            name,
            func,
            "test tool {0}".format(name),
            {
                "type": "object",
                "properties": {},
                "additionalProperties": True,
            },
        )
    return registry


class _RepeatingToolLLM(object):
    def __init__(self, tool_name, tool_args=None, start_tokens=0, token_increment=0, response_text=""):
        self.tool_name = str(tool_name)
        self.tool_args = dict(tool_args or {})
        self.token_increment = int(token_increment or 0)
        self.response_text = str(response_text or "")
        self.stats = {"total_tokens": int(start_tokens or 0)}
        self._call_count = 0

    def chat(self, messages, tools=None, temperature=None, max_tokens=None, json_mode=False):
        self._call_count += 1
        self.stats["total_tokens"] = int(self.stats.get("total_tokens", 0) or 0) + self.token_increment
        return LLMResponse(
            text=self.response_text,
            tool_calls=[ToolCall("call-{0}".format(self._call_count), self.tool_name, dict(self.tool_args))],
            finish_reason="tool_calls",
        )

    def structured_output(self, messages, schema_hint="", temperature=None):
        return []

    def quick(self, prompt, system_prompt=None, temperature=None):
        return "continue"


class SubAgentBudgetRuntimeV2Tests(unittest.TestCase):
    def _challenge(self, run_id):
        return Challenge(
            contest_id="demo",
            challenge_id=run_id,
            title=run_id,
            category="misc",
            description="subagent budget runtime test",
            metadata={"run_id": run_id},
        )

    def _run_subagent(self, workspace, llm, tool_map, task):
        tools = _tool_registry(tool_map)
        loop = AgentLoop(
            llm=llm,
            tools=tools,
            workspace_manager=WorkspaceManager(workspace.parent),
        )
        challenge = self._challenge(task.get("purpose", "subagent-budget-test").replace(" ", "-"))
        state = ChallengeState(phase="agent-loop")
        loop._configure_runtime(challenge, workspace, background=False)
        loop._active_tools = loop._select_active_tools(challenge, "standard", {})
        results = loop._spawn_subagents(challenge, state, workspace, [dict(task)])
        loop._write_board(challenge, workspace, state, speed_mode="standard")
        self.assertEqual(1, len(results))
        self.assertEqual(1, len(state.subagents))
        record = state.subagents[0]
        subagent_root = workspace / "subagents" / record.id
        with (subagent_root / "summary.json").open("r", encoding="utf-8-sig") as handle:
            summary_payload = json.load(handle)
        return loop, challenge, state, results[0], record, summary_payload, subagent_root

    def test_subagent_max_steps_is_budget_exhausted_and_summary_only(self):
        with tempfile.TemporaryDirectory() as workspace_dir:
            workspace = Path(workspace_dir)
            _, challenge, state, result_entry, record, summary_payload, subagent_root = self._run_subagent(
                workspace,
                _RepeatingToolLLM("echo_tool"),
                {"echo_tool": lambda args: "echo-tool-output"},
                {
                    "mode": "subagent",
                    "purpose": "max steps branch",
                    "prompt": "Loop on echo_tool",
                    "allowed_tools": ["echo_tool"],
                    "max_steps": 1,
                    "max_tool_calls": 5,
                    "max_tokens": 2000000,
                    "timeout_sec": 90,
                },
            )

            self.assertEqual("budget_exhausted", record.status)
            self.assertEqual("max_steps", record.stop_reason)
            self.assertEqual(1, int(record.usage.get("steps", 0) or 0))
            self.assertEqual("budget_exhausted", summary_payload.get("status"))
            self.assertEqual("max_steps", summary_payload.get("stop_reason"))
            self.assertEqual(1, int((summary_payload.get("usage") or {}).get("steps", 0) or 0))
            self.assertTrue((subagent_root / "transcript.jsonl").exists())
            self.assertNotIn("Subagent Mission", result_entry["result"])
            self.assertNotIn("\"role\": \"assistant\"", result_entry["result"])

            board = load_workspace_board(workspace)
            self.assertEqual("max_steps", board["subagents"][0]["stop_reason"])
            self.assertEqual(1, int((board["subagents"][0]["usage"] or {}).get("steps", 0) or 0))

            board_summary = build_board_summary(workspace)
            self.assertEqual("max_steps", board_summary["subagents"][0]["stop_reason"])
            self.assertIn("subagents:", board_summary["text"])

            continue_payload = CTFMCPServer()._continue_ctf_session({"workspace": str(workspace)})
            self.assertEqual("max_steps", continue_payload["subagents"][0]["stop_reason"])
            self.assertEqual(1, int((continue_payload["subagents"][0]["usage"] or {}).get("steps", 0) or 0))

            session = _serialize_session(challenge, state, [], 0, workspace)
            _save_session(workspace, session)
            restored = _restore_state(_load_session(workspace))
            self.assertEqual("max_steps", restored.subagents[0].stop_reason)
            self.assertEqual(1, int((restored.subagents[0].usage or {}).get("steps", 0) or 0))

    def test_subagent_max_tool_calls_stops_before_extra_tool_execution(self):
        with tempfile.TemporaryDirectory() as workspace_dir:
            workspace = Path(workspace_dir)
            _, _, _, _, record, summary_payload, _ = self._run_subagent(
                workspace,
                _RepeatingToolLLM("echo_tool"),
                {"echo_tool": lambda args: "echo-tool-output"},
                {
                    "mode": "subagent",
                    "purpose": "max tool calls branch",
                    "prompt": "Loop on echo_tool",
                    "allowed_tools": ["echo_tool"],
                    "max_steps": 5,
                    "max_tool_calls": 1,
                    "max_tokens": 2000000,
                    "timeout_sec": 90,
                },
            )

            self.assertEqual("budget_exhausted", record.status)
            self.assertEqual("max_tool_calls", record.stop_reason)
            self.assertEqual(1, int(record.usage.get("tool_calls", 0) or 0))
            self.assertEqual(1, int((summary_payload.get("usage") or {}).get("tool_calls", 0) or 0))

    def test_subagent_max_tokens_uses_shared_llm_delta_baseline(self):
        with tempfile.TemporaryDirectory() as workspace_dir:
            workspace = Path(workspace_dir)
            _, _, _, _, record, summary_payload, _ = self._run_subagent(
                workspace,
                _RepeatingToolLLM("echo_tool", start_tokens=5000, token_increment=7),
                {"echo_tool": lambda args: "echo-tool-output"},
                {
                    "mode": "subagent",
                    "purpose": "max tokens branch",
                    "prompt": "Spend tokens",
                    "allowed_tools": ["echo_tool"],
                    "max_steps": 5,
                    "max_tool_calls": 5,
                    "max_tokens": 6,
                    "timeout_sec": 90,
                },
            )

            self.assertEqual("budget_exhausted", record.status)
            self.assertEqual("max_tokens", record.stop_reason)
            self.assertEqual(7, int(record.usage.get("tokens_used", 0) or 0))
            self.assertEqual(7, int((summary_payload.get("usage") or {}).get("tokens_used", 0) or 0))

    def test_subagent_timeout_is_cooperative_and_sets_timed_out(self):
        with tempfile.TemporaryDirectory() as workspace_dir:
            workspace = Path(workspace_dir)
            _, _, _, _, record, summary_payload, _ = self._run_subagent(
                workspace,
                _RepeatingToolLLM("sleep_tool"),
                {"sleep_tool": lambda args: (time.sleep(1.05) or "slept")},
                {
                    "mode": "subagent",
                    "purpose": "timeout branch",
                    "prompt": "Sleep once",
                    "allowed_tools": ["sleep_tool"],
                    "max_steps": 5,
                    "max_tool_calls": 5,
                    "max_tokens": 2000000,
                    "timeout_sec": 1,
                },
            )

            self.assertEqual("timed_out", record.status)
            self.assertEqual("timeout", record.stop_reason)
            self.assertGreaterEqual(int(record.usage.get("elapsed_ms", 0) or 0), 1000)
            self.assertEqual("timeout", summary_payload.get("stop_reason"))


if __name__ == "__main__":
    unittest.main()
