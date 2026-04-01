import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from ctf_agent.core.approval import ApprovalManager
from ctf_agent.core.execution_policy import ExecutionPolicy
from ctf_agent.core.run_manager import RunRecord, utc_now
from ctf_agent.core.runtime import RUN_MANAGER
from ctf_agent.core.workspace import WorkspaceManager
from ctf_agent.mcp_server import CTFMCPServer


def _write_config(path, workspace_root):
    toolkit_root = Path(workspace_root) / "toolkit"
    toolkit_root.mkdir(parents=True, exist_ok=True)
    payload = {
        "workspace_root": str(workspace_root),
        "toolkit_root": str(toolkit_root),
        "approval_policy": {
            "enabled": True,
            "default_scope": "workspace_session",
            "session_ttl_sec": 1800,
            "auto_resume": True,
            "ask_categories": ["shell_mutation", "remote_subagent"],
        },
    }
    Path(path).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


class ApprovalRuntimeV3Tests(unittest.TestCase):
    def test_execution_policy_approval_grants_support_once_and_workspace_session(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir) / "workspace"
            workspace.mkdir(parents=True, exist_ok=True)
            manager = ApprovalManager(
                workspace_manager=WorkspaceManager(workspace.parent),
                workspace=str(workspace),
                run_id="run-approval-v3",
                approval_policy={
                    "enabled": True,
                    "default_scope": "workspace_session",
                    "session_ttl_sec": 1800,
                    "auto_resume": True,
                    "ask_categories": ["shell_mutation", "remote_subagent"],
                },
            )
            policy = ExecutionPolicy.build_default(
                workspace=workspace,
                category="pwn",
                target="127.0.0.1:31337",
                remote_hosts=["stub-remote"],
                approval_policy=manager.approval_policy,
                approval_manager=manager,
                run_id="run-approval-v3",
            )

            write_decision = policy.evaluate_shell(
                'echo hello > "note.txt"',
                cwd=workspace,
                pending_action={"kind": "shell_mutation"},
            )
            self.assertEqual("ask", write_decision.decision)
            self.assertTrue(write_decision.request_id)
            status_payload = manager.get_status(workspace=workspace)
            self.assertEqual(1, len(status_payload["pending_requests"]))

            approve_once = manager.respond(
                write_decision.request_id,
                decision="approve",
                scope="once",
                workspace=str(workspace),
            )
            self.assertEqual("approved", approve_once["status"])

            allow_once = policy.evaluate_shell('echo hello > "note.txt"', cwd=workspace)
            self.assertEqual("allow", allow_once.decision)
            self.assertTrue(allow_once.grant_id)

            ask_again = policy.evaluate_shell('echo hello > "note.txt"', cwd=workspace)
            self.assertEqual("ask", ask_again.decision)
            self.assertNotEqual(write_decision.request_id, ask_again.request_id)

            remote_ask = policy.evaluate_remote_subagent(
                "stub-remote",
                category="pwn",
                target="127.0.0.1:31337",
                pending_action={"kind": "remote_subagent"},
            )
            self.assertEqual("ask", remote_ask.decision)

            approve_session = manager.respond(
                remote_ask.request_id,
                decision="approve",
                scope="workspace_session",
                ttl_sec=1,
                workspace=str(workspace),
            )
            self.assertEqual("approved", approve_session["status"])

            allow_session = policy.evaluate_remote_subagent(
                "stub-remote",
                category="pwn",
                target="127.0.0.1:31337",
            )
            self.assertEqual("allow", allow_session.decision)

            time.sleep(1.1)
            expired = policy.evaluate_remote_subagent(
                "stub-remote",
                category="pwn",
                target="127.0.0.1:31337",
            )
            self.assertEqual("ask", expired.decision)

            final_status = manager.get_status(workspace=workspace)
            self.assertTrue((workspace / "approval_status.json").exists())
            self.assertGreaterEqual(final_status["counts"].get("approved", 0), 2)

    def test_mcp_server_approval_tools_list_status_and_respond(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            workspace = temp_root / "workspace"
            workspace.mkdir(parents=True, exist_ok=True)
            config_path = temp_root / "config.json"
            _write_config(config_path, temp_root)

            approval_manager = ApprovalManager(
                workspace_manager=WorkspaceManager(temp_root),
                workspace=str(workspace),
                run_id="run-approval-mcp-v3",
                approval_policy={
                    "enabled": True,
                    "default_scope": "workspace_session",
                    "session_ttl_sec": 1800,
                    "auto_resume": True,
                    "ask_categories": ["remote_subagent"],
                },
            )
            request = approval_manager.create_request(
                operation="remote",
                category="remote_subagent",
                fingerprint="stub-remote:subagent-1",
                subject="remote subagent",
                reason="approval required",
                pending_action={"kind": "remote_subagent", "subagent_id": "subagent-1"},
                workspace=str(workspace),
                run_id="run-approval-mcp-v3",
            )

            (workspace / "triage_board.json").write_text(
                json.dumps(
                    {
                        "run": {"meta": {"status": "needs_approval", "solver": "agent-loop", "category": "pwn", "title": "approval-demo"}},
                        "input_summary": {"title": "approval-demo"},
                        "target_summary": {"target": "127.0.0.1:31337"},
                        "knowledge": {},
                        "binary": {},
                        "findings": [],
                        "candidate_flags": [],
                        "exploit_plans": [],
                        "action_timeline": [],
                        "subagents": [],
                        "next_actions": ["respond to approval"],
                        "blockers": ["approval pending"],
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )

            record = RunRecord(
                run_id="run-approval-mcp-v3",
                created_at=utc_now(),
                updated_at=utc_now(),
                status="needs_approval",
                category="pwn",
                workspace=str(workspace),
                challenge_title="approval-demo",
                request={"config_path": str(config_path), "output_root": str(temp_root)},
                result={"workspace": str(workspace), "status": "needs_approval"},
            )

            with RUN_MANAGER._lock:
                saved_runs = dict(RUN_MANAGER._runs)
                saved_threads = dict(RUN_MANAGER._threads)
                saved_events = dict(RUN_MANAGER._cancel_events)
                saved_root = RUN_MANAGER._storage_root
                RUN_MANAGER._runs = {record.run_id: record}
                RUN_MANAGER._threads = {}
                RUN_MANAGER._cancel_events = {}
                RUN_MANAGER.set_storage_root(temp_root)

            try:
                server = CTFMCPServer()
                listed = server._list_ctf_approval_requests(
                    {"workspace": str(workspace), "config_path": str(config_path)}
                )
                self.assertEqual(1, len(listed["requests"]))
                self.assertEqual(request.id, listed["requests"][0]["id"])

                status_payload = server._get_ctf_approval_status(
                    {"workspace": str(workspace), "config_path": str(config_path)}
                )
                self.assertTrue(status_payload["enabled"])
                self.assertEqual(1, len(status_payload["pending_requests"]))

                with patch.object(RUN_MANAGER, "resume", return_value={"status": "running", "run_id": record.run_id}) as resume_mock:
                    response = server._respond_ctf_approval_request(
                        {
                            "request_id": request.id,
                            "decision": "approve",
                            "scope": "run",
                            "auto_resume": True,
                            "config_path": str(config_path),
                            "workspace_root": str(temp_root),
                        }
                    )

                self.assertEqual("approved", response["response"]["status"])
                resume_mock.assert_called_once()
                self.assertEqual([], list((response["session"].get("approval_status") or {}).get("pending_requests", [])))
                self.assertEqual(request.id, response["request_id"])
            finally:
                with RUN_MANAGER._lock:
                    RUN_MANAGER._runs = saved_runs
                    RUN_MANAGER._threads = saved_threads
                    RUN_MANAGER._cancel_events = saved_events
                    RUN_MANAGER._storage_root = saved_root


if __name__ == "__main__":
    unittest.main()
