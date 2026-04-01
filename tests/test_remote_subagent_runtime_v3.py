import json
import re
import shutil
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ctf_agent.core.agent_loop import AgentLoop, ToolRegistry
from ctf_agent.core.board import build_board_summary
from ctf_agent.core.llm import LLMResponse, ToolCall
from ctf_agent.core.models import Challenge, ChallengeState
from ctf_agent.core.workspace import WorkspaceManager, load_workspace_approval_status
from ctf_agent.core.approval import ApprovalManager
from ctf_agent.core.execution_policy import ExecutionPolicy
from ctf_agent.mcp_server import CTFMCPServer


class _RemoteSubagentLLM(object):
    def __init__(self):
        self.stats = {"total_tokens": 0}
        self._call_count = 0

    def chat(self, messages, tools=None, temperature=None, max_tokens=None, json_mode=False):
        self._call_count += 1
        self.stats["total_tokens"] = int(self.stats.get("total_tokens", 0) or 0) + 9
        if self._call_count == 1:
            return LLMResponse(
                text="",
                tool_calls=[ToolCall("call-1", "run_remote_command", {"command": "echo remote", "host": "stub-remote"})],
                finish_reason="tool_calls",
            )
        return LLMResponse(text="remote branch wrapped", tool_calls=[], finish_reason="stop")

    def structured_output(self, messages, schema_hint="", temperature=None):
        return []

    def quick(self, prompt, system_prompt=None, temperature=None):
        return "continue"


class _FakeRemoteTool(object):
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.hosts = {"stub-remote": {"python_bin": "python3"}}
        self.execution_policy = None
        self.execution_context = {}
        self.jobs = {}

    def configure_policy(self, policy, category="", target="", background=False):
        self.execution_policy = policy
        self.execution_context = {
            "category": category,
            "target": target,
            "background": background,
        }
        return self

    def list_hosts(self):
        return sorted(self.hosts.keys())

    def recommend_host(self, category="", target=""):
        return {"selected_host": "stub-remote", "reason": "test"}

    def ensure_workspace(self, host, run_id="", timeout=30):
        root = self.root / run_id
        (root / "input").mkdir(parents=True, exist_ok=True)
        (root / "output" / "artifacts").mkdir(parents=True, exist_ok=True)
        remote_root = str(root).replace("\\", "/")
        return {
            "status": "ok",
            "workspace_root": remote_root,
            "input_dir": remote_root + "/input",
        }

    def _path(self, remote_path):
        return Path(str(remote_path or "").replace("\\", "/"))

    def _write_json(self, path, payload):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8-sig")

    def _read_json(self, path):
        path = Path(path)
        if not path.exists():
            return {}
        return json.loads(path.read_text(encoding="utf-8-sig"))

    def upload(self, host, local_path, remote_path="", timeout=30):
        source = Path(local_path)
        target = self._path(remote_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        return {"status": "ok", "remote_path": str(target)}

    def upload_text(self, host, content, remote_path="", timeout=30):
        target = self._path(remote_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(str(content or ""), encoding="utf-8-sig")
        return {"status": "ok", "remote_path": str(target)}

    def download(self, host, remote_path, local_path, timeout=30):
        source = self._path(remote_path)
        if not source.exists():
            return {"status": "error", "message": "missing remote artifact", "remote_path": str(source)}
        target = Path(local_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        return {"status": "ok", "remote_path": str(source), "local_path": str(target)}

    def run_command(self, host, command, timeout=30):
        quoted_paths = re.findall(r'"([^"]+)"', str(command or ""))
        if str(command or "").startswith("mkdir -p"):
            for item in quoted_paths:
                self._path(item).mkdir(parents=True, exist_ok=True)
            return {
                "status": "ok",
                "host": host,
                "command": str(command or ""),
                "stdout": "ok",
                "stderr": "",
                "returncode": 0,
                "message": "executed",
            }
        if len(quoted_paths) >= 3:
            workspace = self._path(quoted_paths[2])
            output_dir = workspace / "output"
            output_dir.mkdir(parents=True, exist_ok=True)
            phase = str(command or "").strip().split()[-1]
            job_id = "job-{0}".format(workspace.name)
            if phase == "init":
                payload = {"status": "ok", "workspace": str(workspace).replace("\\", "/")}
                self._write_json(output_dir / "heartbeat.json", {"status": "queued", "job_id": "", "workspace": str(workspace)})
                self._write_json(output_dir / "state.json", {"status": "queued", "workspace": str(workspace)})
                return {
                    "status": "ok",
                    "host": host,
                    "command": str(command or ""),
                    "stdout": json.dumps(payload),
                    "stderr": "",
                    "returncode": 0,
                    "message": "initialized",
                }
            if phase == "start":
                artifacts_dir = output_dir / "artifacts"
                artifacts_dir.mkdir(parents=True, exist_ok=True)
                artifact_file = artifacts_dir / "remote.txt"
                artifact_file.write_text("remote artifact", encoding="utf-8-sig")
                tar_path = output_dir / "artifacts.tar.gz"
                with tarfile.open(tar_path, "w:gz") as handle:
                    handle.add(str(artifact_file), arcname="remote.txt")
                summary = {
                    "id": workspace.name,
                    "status": "completed",
                    "stop_reason": "completed",
                    "usage": {"steps": 1, "tool_calls": 1, "tokens_used": 9, "elapsed_ms": 12},
                    "summary": {
                        "what_was_tried": "remote lane",
                        "what_was_found": "remote runner protocol simulated",
                        "what_to_do_next": "promote result to parent",
                        "summary_text": "remote runner protocol simulated",
                    },
                    "artifact_paths": [str(artifact_file).replace("\\", "/")],
                }
                (output_dir / "transcript.jsonl").write_text(
                    json.dumps({"role": "assistant", "content": "remote transcript"}) + "\n",
                    encoding="utf-8-sig",
                )
                self._write_json(output_dir / "summary.json", summary)
                self._write_json(output_dir / "job.json", {"status": "ok", "job_id": job_id, "workspace": str(workspace)})
                self._write_json(
                    output_dir / "heartbeat.json",
                    {"status": "completed", "job_id": job_id, "workspace": str(workspace), "stop_reason": "completed"},
                )
                self._write_json(
                    output_dir / "state.json",
                    {
                        "status": "completed",
                        "job_id": job_id,
                        "workspace": str(workspace),
                        "stop_reason": "completed",
                        "usage": summary["usage"],
                    },
                )
                self.jobs[str(workspace)] = {"state": "completed", "job_id": job_id}
                payload = {"status": "ok", "job_id": job_id, "workspace": str(workspace), "log_path": str(output_dir / "runner.log")}
                return {
                    "status": "ok",
                    "host": host,
                    "command": str(command or ""),
                    "stdout": json.dumps(payload),
                    "stderr": "",
                    "returncode": 0,
                    "message": "started",
                }
            if phase == "status":
                summary = self._read_json(output_dir / "summary.json")
                payload = {
                    "status": "ok",
                    "state": str(summary.get("status", "completed") or "completed"),
                    "job_id": job_id,
                    "workspace": str(workspace),
                    "summary_ready": bool(summary),
                }
                return {
                    "status": "ok",
                    "host": host,
                    "command": str(command or ""),
                    "stdout": json.dumps(payload),
                    "stderr": "",
                    "returncode": 0,
                    "message": "status",
                }
            if phase == "cancel":
                self._write_json(
                    output_dir / "heartbeat.json",
                    {"status": "cancelled", "job_id": job_id, "workspace": str(workspace), "stop_reason": "cancelled"},
                )
                self._write_json(
                    output_dir / "state.json",
                    {"status": "cancelled", "job_id": job_id, "workspace": str(workspace), "stop_reason": "cancelled"},
                )
                payload = {"status": "ok", "state": "cancelled", "job_id": job_id, "workspace": str(workspace)}
                return {
                    "status": "ok",
                    "host": host,
                    "command": str(command or ""),
                    "stdout": json.dumps(payload),
                    "stderr": "",
                    "returncode": 0,
                    "message": "cancelled",
                }
        return {
            "status": "ok",
            "host": host,
            "command": str(command or ""),
            "stdout": "ok",
            "stderr": "",
            "returncode": 0,
            "message": "executed",
        }


class RemoteSubagentRuntimeV3Tests(unittest.TestCase):
    def _challenge(self, name, metadata=None):
        return Challenge(
            contest_id="demo",
            challenge_id=name,
            title=name,
            category="pwn",
            description="remote subagent runtime",
            metadata=dict(metadata or {}),
        )

    def test_remote_subagent_mirrors_summary_and_artifacts_without_transcript_reinjection(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir) / "workspace"
            workspace.mkdir(parents=True, exist_ok=True)
            loop = AgentLoop(
                llm=_RemoteSubagentLLM(),
                tools=ToolRegistry(),
                remote_tool=_FakeRemoteTool(Path(temp_dir) / "remote"),
                workspace_manager=WorkspaceManager(workspace.parent),
            )
            challenge = self._challenge("remote-subagent-ok", metadata={"run_id": "run-remote-v3"})
            state = ChallengeState(phase="agent-loop")
            loop._configure_runtime(challenge, workspace, background=False)

            with mock.patch.object(AgentLoop, "_run_loop", side_effect=AssertionError("parent should not run local child loop")):
                results = loop._spawn_subagents(
                    challenge,
                    state,
                    workspace,
                    [
                        {
                            "mode": "subagent",
                            "execution_mode": "remote",
                            "purpose": "remote lane",
                            "prompt": "Use remote command once",
                            "allowed_tools": ["run_remote_command"],
                            "max_steps": 2,
                            "max_tool_calls": 2,
                            "max_tokens": 2000000,
                            "timeout_sec": 30,
                            "poll_interval_sec": 1,
                            "mirror_artifacts": True,
                        }
                    ],
                )

            self.assertEqual(1, len(results))
            self.assertEqual(1, len(state.subagents))
            record = state.subagents[0]
            self.assertEqual("remote", record.spec.execution_mode)
            self.assertEqual("stub-remote", record.spec.remote_host)
            self.assertTrue(record.remote_status)
            self.assertTrue(record.sync_manifest.get("uploads"))
            self.assertTrue(record.sync_manifest.get("downloads"))
            self.assertNotIn("\"role\": \"assistant\"", results[0]["result"])

            sub_root = workspace / "subagents" / record.id
            self.assertTrue((sub_root / "summary.json").exists())
            self.assertTrue((sub_root / "remote_status.json").exists())
            self.assertTrue((sub_root / "sync_manifest.json").exists())
            self.assertTrue((sub_root / "remote_summary.json").exists())
            self.assertTrue((sub_root / "remote_transcript.jsonl").exists())
            self.assertTrue((sub_root / "transcript.jsonl").exists())
            self.assertTrue(any(path.endswith("remote_artifacts.tar.gz") for path in record.artifact_paths))

            loop._write_board(challenge, workspace, state, speed_mode="standard")
            board_summary = build_board_summary(workspace)
            self.assertEqual(1, len(board_summary["remote_subagents"]))
            self.assertIn("remote_subagents:", board_summary["text"])

            continue_payload = CTFMCPServer()._continue_ctf_session({"workspace": str(workspace)})
            self.assertEqual(1, len(continue_payload["remote_subagents"]))
            self.assertEqual(record.id, continue_payload["remote_subagents"][0]["id"])

    def test_remote_subagent_approval_gates_spawn_and_persists_request(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir) / "workspace"
            workspace.mkdir(parents=True, exist_ok=True)
            approval_manager = ApprovalManager(
                workspace_manager=WorkspaceManager(workspace.parent),
                workspace=str(workspace),
                run_id="run-remote-approval-v3",
                approval_policy={
                    "enabled": True,
                    "default_scope": "workspace_session",
                    "session_ttl_sec": 1800,
                    "auto_resume": True,
                    "ask_categories": ["remote_subagent"],
                },
            )
            policy = ExecutionPolicy.build_default(
                workspace=workspace,
                category="pwn",
                target="127.0.0.1:31337",
                remote_hosts=["stub-remote"],
                approval_policy=approval_manager.approval_policy,
                approval_manager=approval_manager,
                run_id="run-remote-approval-v3",
            )
            loop = AgentLoop(
                llm=_RemoteSubagentLLM(),
                tools=ToolRegistry(),
                remote_tool=_FakeRemoteTool(Path(temp_dir) / "remote"),
                workspace_manager=WorkspaceManager(workspace.parent),
                execution_policy=policy,
                approval_manager=approval_manager,
            )
            challenge = self._challenge("remote-subagent-approval", metadata={"run_id": "run-remote-approval-v3"})
            state = ChallengeState(phase="agent-loop")
            loop._configure_runtime(challenge, workspace, background=False)

            results = loop._spawn_subagents(
                challenge,
                state,
                workspace,
                [
                    {
                        "mode": "subagent",
                        "execution_mode": "remote",
                        "purpose": "approval lane",
                        "prompt": "pause for approval",
                        "allowed_tools": ["run_remote_command"],
                        "max_steps": 2,
                        "max_tool_calls": 1,
                        "max_tokens": 2000000,
                        "timeout_sec": 30,
                    }
                ],
            )

            self.assertEqual(1, len(results))
            self.assertEqual("needs_approval", results[0]["status"])
            self.assertEqual([], state.subagents)

            approval_status = load_workspace_approval_status(workspace)
            self.assertEqual(1, len(approval_status["pending_requests"]))

            remote_status_path = workspace / "subagents" / "subagent-1-approval-lane" / "remote_status.json"
            self.assertTrue(remote_status_path.exists())
            remote_status = json.loads(remote_status_path.read_text(encoding="utf-8-sig"))
            self.assertEqual("queued", remote_status["status"])
            self.assertTrue(remote_status["request_id"])


if __name__ == "__main__":
    unittest.main()
