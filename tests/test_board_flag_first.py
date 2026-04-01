import json
import tempfile
import unittest
from pathlib import Path

from ctf_agent.core.board import build_board_summary


class BoardFlagFirstTests(unittest.TestCase):
    def test_board_summary_prefers_flag_first_text(self):
        with tempfile.TemporaryDirectory() as workspace_dir:
            workspace = Path(workspace_dir)
            (workspace / "triage_board.json").write_text(
                json.dumps(
                    {
                        "run": {"meta": {"status": "solved", "solver": "binary", "category": "web", "title": "test"}},
                        "input_summary": {"title": "test"},
                        "target_summary": {"target": "http://127.0.0.1", "recommended_path": "web:path"},
                        "knowledge": {},
                        "binary": {},
                        "next_actions": [],
                        "blockers": [],
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8-sig",
            )
            (workspace / "wp_export.json").write_text(
                json.dumps(
                    {
                        "flag": "flag{board}",
                        "wp_exported": True,
                        "wp_package_path": r".\agent-wp\web_test_wp",
                        "wp_root": r".\agent-wp",
                        "flag_first_text": "flag: flag{board}\nwp_package_path: .\\agent-wp\\web_test_wp",
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8-sig",
            )

            summary = build_board_summary(workspace)
            lines = summary["text"].splitlines()

            self.assertEqual("flag: flag{board}", lines[0])
            self.assertEqual(r"wp_package_path: .\agent-wp\web_test_wp", lines[1])
            self.assertTrue(summary["wp_exported"])


if __name__ == "__main__":
    unittest.main()
