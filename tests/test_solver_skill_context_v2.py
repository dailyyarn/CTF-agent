import json
import tempfile
import unittest
from pathlib import Path

from ctf_agent.core.models import Challenge, ChallengeState
from ctf_agent.core.verifier import FlagVerifier
from ctf_agent.knowledge import SkillResolver
from ctf_agent.solvers.binary import BinarySolver
from ctf_agent.solvers.triage import TriageSolver
from ctf_agent.solvers.web import WebSolver
from ctf_agent.tools.file_tool import FileTool


class _DummyOOBTool(object):
    def is_enabled(self):
        return False

    def can_poll(self):
        return False

    def generate_callback(self):
        return {}


class SolverSkillContextV2Tests(unittest.TestCase):
    def test_triage_uses_skill_resolution_without_legacy_autopilot_knowledge(self):
        with tempfile.TemporaryDirectory() as workspace_dir:
            workspace = Path(workspace_dir)
            solver = TriageSolver(
                file_tool=FileTool(),
                shell_tool=None,
                verifier=FlagVerifier(),
            )
            challenge = Challenge(
                contest_id="demo",
                challenge_id="triage-skill-resolution",
                title="triage-skill-resolution",
                category="misc",
                description="rsa crypto challenge",
                metadata={
                    "skill_resolution": SkillResolver().resolve(
                        task_text="rsa crypto challenge",
                        explicit_category="crypto",
                        speed_mode="standard",
                    ),
                    "autopilot_plan": {},
                },
            )

            solver.solve(challenge, workspace)

            board = json.loads((workspace / "triage_board.json").read_text(encoding="utf-8-sig"))
            notes = (workspace / "notes.md").read_text(encoding="utf-8-sig")

            self.assertEqual("crypto", board["knowledge"]["selected_skill_category"])
            self.assertEqual("CTF Crypto Playbook", board["knowledge"]["pack_name"])
            self.assertIn("python", board["tool_usage"]["recommended_tools"])
            self.assertIn("Selected category: crypto", notes)
            self.assertEqual(
                "crypto",
                challenge.metadata["autopilot_plan"]["knowledge"]["selected_skill_category"],
            )

    def test_web_board_and_notes_use_skill_resolution_without_legacy_autopilot_knowledge(self):
        with tempfile.TemporaryDirectory() as workspace_dir:
            workspace = Path(workspace_dir)
            solver = WebSolver(
                http_tool=None,
                file_tool=FileTool(),
                shell_tool=None,
                oob_tool=_DummyOOBTool(),
                verifier=FlagVerifier(),
            )
            challenge = Challenge(
                contest_id="demo",
                challenge_id="web-skill-resolution",
                title="web-skill-resolution",
                category="misc",
                description="jwt auth bypass",
                target="http://example.com",
                metadata={
                    "skill_resolution": SkillResolver().resolve(
                        task_text="jwt auth bypass",
                        target="http://example.com",
                        explicit_category="web",
                        speed_mode="standard",
                    ),
                    "autopilot_plan": {},
                    "use_browser_mcp": False,
                },
            )
            state = ChallengeState(phase="report")
            context = {
                "autopilot": {},
                "knowledge": {},
                "browser_state": {},
                "browser_reports": [],
                "upload_attempts": [],
                "sqli_checks": [],
                "oob_checks": [],
                "remote_reports": [],
                "mcp_digest": [],
            }

            solver._write_board(challenge, workspace, state, context)
            solver._write_notes(challenge, workspace, state)

            board = json.loads((workspace / "triage_board.json").read_text(encoding="utf-8-sig"))
            notes = (workspace / "notes.md").read_text(encoding="utf-8-sig")

            self.assertEqual("web", board["knowledge"]["selected_skill_category"])
            self.assertEqual("CTF Web Playbook", board["knowledge"]["pack_name"])
            self.assertIn("browser-use", board["mcp_usage"]["recommended_mcp"])
            self.assertIn("Selected category: web", notes)
            self.assertEqual(
                "web",
                challenge.metadata["autopilot_plan"]["knowledge"]["selected_skill_category"],
            )

    def test_binary_board_uses_skill_resolution_without_legacy_autopilot_knowledge(self):
        with tempfile.TemporaryDirectory() as workspace_dir:
            workspace = Path(workspace_dir)
            solver = BinarySolver(
                file_tool=FileTool(),
                shell_tool=None,
                verifier=FlagVerifier(),
            )
            challenge = Challenge(
                contest_id="demo",
                challenge_id="binary-skill-resolution",
                title="binary-skill-resolution",
                category="misc",
                description="pwn overflow challenge",
                metadata={
                    "skill_resolution": SkillResolver().resolve(
                        task_text="pwn overflow challenge",
                        explicit_category="pwn",
                        speed_mode="standard",
                    ),
                    "autopilot_plan": {},
                },
            )

            solver.solve(challenge, workspace)

            board = json.loads((workspace / "triage_board.json").read_text(encoding="utf-8-sig"))

            self.assertEqual("pwn", board["knowledge"]["selected_skill_category"])
            self.assertEqual("CTF Pwn Playbook", board["knowledge"]["pack_name"])
            self.assertEqual(
                "pwn",
                challenge.metadata["autopilot_plan"]["knowledge"]["selected_skill_category"],
            )


if __name__ == "__main__":
    unittest.main()
