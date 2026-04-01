import tempfile
import unittest
from pathlib import Path

from ctf_agent.core.agent_loop import AgentLoop, ToolRegistry
from ctf_agent.core.execution_policy import ExecutionPolicy
from ctf_agent.core.models import Challenge
from ctf_agent.core.workspace import WorkspaceManager
from ctf_agent.knowledge.skillpacks import get_skillpack
from ctf_agent.tools.file_tool import FileTool
from ctf_agent.tools.mcp_runtime import MCPRuntimeRegistry
from ctf_agent.tools.remote_tool import RemoteTool


class _DummyLLM(object):
    def __init__(self):
        self.stats = {"total_tokens": 0}

    def quick(self, prompt, system_prompt=None, temperature=None):
        return ""


class _FakeKnowledge(object):
    def __init__(self):
        self.calls = 0

    def is_loaded(self):
        return True

    def query(self, query, top_k=4, category_hint=None, source_filter=None):
        self.calls += 1
        return [{"source_type": "skills", "heading": "demo", "text": "demo"}]


class ExecutionPolicyRuntimeV1Tests(unittest.TestCase):
    def test_policy_blocks_workspace_external_write(self):
        with tempfile.TemporaryDirectory() as workspace_dir:
            workspace = Path(workspace_dir)
            file_tool = FileTool()
            policy = ExecutionPolicy.build_default(workspace=workspace)
            file_tool.configure_policy(policy, workspace=str(workspace))
            outside = workspace.parent / "outside-write.txt"
            with self.assertRaises(PermissionError):
                file_tool.write_text(outside, "blocked")

    def test_policy_blocks_unlisted_remote_host(self):
        with tempfile.TemporaryDirectory() as workspace_dir:
            policy = ExecutionPolicy.build_default(
                workspace=workspace_dir,
                category="pwn",
                remote_hosts=["allowed-host"],
            )
            remote_tool = RemoteTool(
                hosts={
                    "allowed-host": {"host": "127.0.0.1"},
                    "blocked-host": {"host": "127.0.0.1"},
                }
            )
            remote_tool.configure_policy(policy, category="pwn", target="", background=False)
            result = remote_tool.run_command("blocked-host", "echo hello")
            self.assertEqual("blocked", result.get("status"))
            self.assertIn("allowlist", result.get("message", ""))

    def test_mcp_large_output_is_persisted(self):
        with tempfile.TemporaryDirectory() as workspace_dir:
            workspace = Path(workspace_dir)
            registry = MCPRuntimeRegistry(
                server_configs=[{"name": "mock-server", "enabled": True, "command": "python", "args": ["-c", "print('ok')"]}],
                workspace_manager=WorkspaceManager(workspace.parent),
                workspace=str(workspace),
            )
            registry.call_tool = lambda server_name, tool_name, arguments=None, timeout=None: {
                "content": [{"type": "text", "text": "A" * 6000}]
            }
            payload = registry.call_tool_safe("mock-server", "dump_blob", arguments={"size": 6000})
            self.assertTrue(payload.get("ok"))
            self.assertTrue(payload.get("truncated"))
            self.assertTrue(payload.get("saved_to"))
            self.assertTrue(Path(payload["saved_to"]).exists())
            self.assertTrue((workspace / "logs" / "mcp_call_log.jsonl").exists())

    def test_fastest_skillpack_narrows_tools_and_skips_knowledge(self):
        with tempfile.TemporaryDirectory() as workspace_dir:
            knowledge = _FakeKnowledge()
            reg = ToolRegistry()
            reg.register("search_knowledge", lambda args: "knowledge", "knowledge", {"type": "object", "properties": {}})
            reg.register("http_request", lambda args: "ok", "http", {"type": "object", "properties": {}})
            reg.register("plan_parallel", lambda args: "parallel", "parallel", {"type": "object", "properties": {}})
            loop = AgentLoop(llm=_DummyLLM(), tools=reg, knowledge_retriever=knowledge)
            challenge = Challenge(
                contest_id="demo",
                challenge_id="fastest",
                title="fastest",
                category="web",
                description="fastest mode",
                metadata={"speed_mode": "fastest"},
            )
            speed_mode, profile = loop._resolve_speed_profile(challenge)
            selected = loop._select_active_tools(challenge, speed_mode, profile)
            skipped = loop._retrieve_initial_knowledge(challenge, speed_mode=speed_mode, speed_profile=profile)

            self.assertEqual("fastest", speed_mode)
            self.assertNotIn("search_knowledge", selected.names)
            self.assertNotIn("plan_parallel", selected.names)
            self.assertIn("fastest mode skipped knowledge retrieval", skipped)
            self.assertEqual(0, knowledge.calls)


if __name__ == "__main__":
    unittest.main()
