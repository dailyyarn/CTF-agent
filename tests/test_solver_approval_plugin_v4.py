import tempfile
import unittest
from pathlib import Path

from ctf_agent.core.models import Challenge
from ctf_agent.core.workspace import WorkspaceManager
from ctf_agent.solvers.binary import BinarySolver
from ctf_agent.solvers.web import WebSolver


class _FakeVerifier(object):
    def choose_best(self, state, challenge):
        return None

    def discover_from_text(self, text):
        return []


class _FakeMCPRegistry(object):
    def __init__(self):
        self.calls = 0

    def has_servers(self):
        return True

    def call_browser_flow_safe(self, url, action="recon", task=None, timeout=None, **extra_arguments):
        self.calls += 1
        if self.calls == 1:
            return {
                "status": "needs_approval",
                "message": "approval required",
                "request_id": "req-browser-1",
                "approval": {"request_id": "req-browser-1"},
            }
        return {
            "status": "ok",
            "server": "browser",
            "tool": "browse",
            "result": {"content": [{"type": "text", "text": "browser ok"}]},
            "structured": {
                "summary": "browser ok",
                "route_candidates": [],
                "param_candidates": [],
                "forms": [],
                "upload_candidates": [],
            },
        }

    def call_browser_task_safe(self, task, url, timeout=None):
        return {"status": "error", "message": "unused"}

    def flatten_tool_result(self, result):
        return "browser ok"

    def tool_digest(self):
        return []


class _ApprovalWebSolver(WebSolver):
    def __init__(self, mcp_registry):
        super().__init__(
            http_tool=None,
            file_tool=WorkspaceManager("."),
            shell_tool=None,
            oob_tool=type("OOB", (), {"is_enabled": lambda self: False})(),
            verifier=_FakeVerifier(),
            toolkit_tool=None,
            remote_tool=None,
            mcp_registry=mcp_registry,
        )

    def _collect(self, challenge, workspace, memory, context):
        return

    def _recon_target(self, challenge, workspace, memory, context):
        return

    def _analyze_login_forms(self, challenge, memory, context):
        return

    def _analyze_upload_points(self, challenge, memory, context):
        return

    def _probe_candidates(self, challenge, memory, context):
        return

    def _run_sqli_automation(self, challenge, memory, context):
        return

    def _run_oob_checks(self, challenge, memory, context):
        return

    def _choose_best_plan(self, state, executed_plan_keys):
        return None

    def _write_context_artifacts(self, workspace, context):
        return

    def _write_notes(self, challenge, workspace, state):
        return

    def _write_solution_stub(self, challenge, workspace, state):
        return

    def _write_board(self, challenge, workspace, state, context):
        return


class _RemoteTemplateRegistry(object):
    def recommended_templates(self, category=""):
        return ["plugin-remote-template", "binary-checksec"]


class SolverApprovalPluginV4Tests(unittest.TestCase):
    def test_web_solver_persists_and_resumes_solver_approval_session(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir) / "workspace"
            workspace.mkdir(parents=True, exist_ok=True)
            solver = _ApprovalWebSolver(_FakeMCPRegistry())
            challenge = Challenge(
                contest_id="demo",
                challenge_id="web-approval",
                title="web approval",
                category="web",
                description="approval flow",
                target="http://example.test",
                metadata={"run_id": "run-web-approval"},
            )

            state = solver.solve(challenge, workspace)
            self.assertEqual("needs_approval", state.phase)
            self.assertTrue((workspace / "agent_session.json").exists())
            self.assertTrue((workspace / "solver_context.json").exists())

            WorkspaceManager(workspace.parent).save_approval_status(
                workspace,
                {
                    "enabled": True,
                    "pending_requests": [],
                    "recent_requests": [{"id": "req-browser-1", "status": "approved"}],
                    "counts": {"approved": 1},
                },
            )
            resumed = solver.continue_solve(challenge, workspace)
            self.assertEqual("report", resumed.phase)
            self.assertFalse((workspace / "agent_session.json").exists())
            self.assertFalse((workspace / "solver_context.json").exists())

    def test_binary_recommended_templates_include_remote_registry_contributions(self):
        solver = BinarySolver(
            file_tool=None,
            shell_tool=None,
            verifier=_FakeVerifier(),
            toolkit_tool=None,
            remote_tool=_RemoteTemplateRegistry(),
            mcp_registry=None,
        )
        templates = solver._recommended_remote_templates("reverse", {"host": "demo"})
        self.assertEqual(["plugin-remote-template", "binary-checksec", "reverse-runner"], templates)


if __name__ == "__main__":
    unittest.main()
