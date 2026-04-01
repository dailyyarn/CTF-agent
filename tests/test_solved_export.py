import tempfile
import unittest
from pathlib import Path

from ctf_agent.core.models import Challenge
from ctf_agent.core.solved_export import export_solved_workspace, load_workspace_export_summary


class SolvedExportTests(unittest.TestCase):
    def test_export_solved_workspace_creates_package_and_increment_suffix(self):
        with tempfile.TemporaryDirectory() as workspace_dir, tempfile.TemporaryDirectory() as export_root:
            workspace = Path(workspace_dir)
            (workspace / "notes.md").write_text("# Notes\n", encoding="utf-8-sig")
            (workspace / "solution.py").write_text("print('ok')\n", encoding="utf-8-sig")
            (workspace / "state.json").write_text('{"candidate_flags": [{"value": "flag{demo}"}]}\n', encoding="utf-8-sig")
            (workspace / "triage_board.json").write_text('{"binary": {"best_path": "ret2win"}}\n', encoding="utf-8-sig")

            challenge = Challenge(
                contest_id="demo",
                challenge_id="chal-1",
                title="test",
                category="web",
                description="demo",
            )
            result = {
                "status": "solved",
                "workspace": str(workspace),
                "solver": "binary",
                "flag": "flag{demo}",
            }

            summary1 = export_solved_workspace(challenge, result, policy={"root": export_root, "duplicate_policy": "increment"})
            summary2 = export_solved_workspace(challenge, result, policy={"root": export_root, "duplicate_policy": "increment"})

            self.assertTrue(summary1["wp_exported"])
            self.assertTrue(Path(summary1["wp_package_path"]).exists())
            self.assertTrue(Path(summary1["wp_package_path"], "flag.txt").exists())
            self.assertTrue(Path(summary1["wp_package_path"], "wp.md").exists())
            self.assertTrue(Path(summary1["wp_package_path"], "poc.md").exists())
            self.assertTrue(Path(summary1["wp_package_path"], "code", "solution.py").exists())
            self.assertTrue(summary1["flag_first_text"].startswith("flag: flag{demo}"))
            self.assertNotEqual(summary1["wp_package_path"], summary2["wp_package_path"])
            self.assertTrue(summary2["wp_package_path"].endswith("_2"))

            persisted = load_workspace_export_summary(workspace)
            self.assertEqual(summary2["wp_package_path"], persisted["wp_package_path"])


if __name__ == "__main__":
    unittest.main()
