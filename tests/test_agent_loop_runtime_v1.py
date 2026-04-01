import json
import tempfile
import unittest
from pathlib import Path

from ctf_agent.core.agent_loop import AgentLoop, ToolRegistry, build_default_tools
from ctf_agent.core.board import load_workspace_board
from ctf_agent.core.llm import LLMResponse, ToolCall
from ctf_agent.core.models import Challenge, ChallengeState
from ctf_agent.core.verifier import FlagVerifier
from ctf_agent.core.workspace import WorkspaceManager
from ctf_agent.tools.file_tool import FileTool


class _StaticLLM(object):
    def __init__(self, read_path):
        self.read_path = str(read_path)
        self.stats = {"total_tokens": 0}

    def chat(self, messages, tools=None, temperature=None, max_tokens=None, json_mode=False):
        tool_names = [item["function"]["name"] for item in list(tools or [])]
        if "read_file" in tool_names and not any(item.get("role") == "tool" for item in messages):
            return LLMResponse(
                text="",
                tool_calls=[ToolCall("call-read", "read_file", {"path": self.read_path})],
                finish_reason="tool_calls",
            )
        return LLMResponse(text="Subagent completed.", finish_reason="stop")

    def structured_output(self, messages, schema_hint="", temperature=None):
        return []

    def quick(self, prompt, system_prompt=None, temperature=None):
        return "continue with the current path"


class AgentLoopRuntimeV1Tests(unittest.TestCase):
    def test_subagents_persist_summary_and_board(self):
        with tempfile.TemporaryDirectory() as workspace_dir:
            workspace = Path(workspace_dir)
            sample_path = workspace / "sample.txt"
            sample_path.write_text("flag{subagent-runtime}\n", encoding="utf-8")

            llm = _StaticLLM(sample_path)
            file_tool = FileTool()
            tools = build_default_tools(
                verifier=FlagVerifier(),
                file_tool=file_tool,
                workspace=str(workspace),
            )
            loop = AgentLoop(
                llm=llm,
                tools=tools,
                verifier=FlagVerifier(),
                file_tool=file_tool,
                workspace_manager=WorkspaceManager(workspace.parent),
            )
            challenge = Challenge(
                contest_id="demo",
                challenge_id="runtime-v1",
                title="runtime-v1",
                category="misc",
                description="subagent runtime test",
                attachments=[sample_path],
                metadata={"run_id": "run-subagent-v1"},
            )
            state = ChallengeState(phase="agent-loop")
            loop._configure_runtime(challenge, workspace, background=False)
            loop._active_tools = loop._select_active_tools(challenge, "standard", {})

            results = loop._spawn_subagents(
                challenge,
                state,
                workspace,
                [
                    {"mode": "subagent", "purpose": "read sample", "prompt": "Read the sample file", "allowed_tools": ["read_file"]},
                    {"mode": "subagent", "purpose": "read sample again", "prompt": "Read the sample file again", "allowed_tools": ["read_file"]},
                ],
            )
            loop._write_board(challenge, workspace, state, speed_mode="standard")

            self.assertEqual(2, len(results))
            self.assertEqual(2, len(state.subagents))
            for item in state.subagents:
                sub_root = workspace / "subagents" / item.id
                self.assertTrue((sub_root / "summary.json").exists())
                self.assertTrue((sub_root / "transcript.jsonl").exists())
            board = load_workspace_board(workspace)
            self.assertEqual(2, len(board.get("subagents", [])))


if __name__ == "__main__":
    unittest.main()
