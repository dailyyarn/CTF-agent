import json
import tempfile
import unittest
from pathlib import Path

from ctf_agent.core.task_protocol import build_sync_envelope


class TaskProtocolWpTests(unittest.TestCase):
    def test_sync_envelope_surfaces_wp_fields_and_flag_first_text(self):
        with tempfile.TemporaryDirectory() as workspace_dir:
            workspace = Path(workspace_dir)
            (workspace / "wp_export.json").write_text(
                json.dumps(
                    {
                        "flag": "flag{proto}",
                        "wp_exported": True,
                        "wp_package_path": r".\agent-wp\web_test_wp",
                        "wp_root": r".\agent-wp",
                        "wp_warning": "",
                        "flag_first_text": "flag: flag{proto}\nwp_package_path: .\\agent-wp\\web_test_wp",
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8-sig",
            )
            resolved = {"category": "web", "title": "test", "speed_mode": "standard"}
            result = {
                "status": "solved",
                "workspace": str(workspace),
                "solver": "binary",
                "flag": "flag{proto}",
                "wp_exported": True,
                "wp_package_path": r".\agent-wp\web_test_wp",
                "wp_root": r".\agent-wp",
                "flag_first_text": "flag: flag{proto}\nwp_package_path: .\\agent-wp\\web_test_wp",
            }

            payload = build_sync_envelope("demo task", resolved, result)

            self.assertTrue(payload["execution"]["wp_exported"])
            self.assertEqual(r".\agent-wp\web_test_wp", payload["summary"]["wp_package_path"])
            self.assertTrue(payload["summary"]["flag_first_text"].startswith("flag: flag{proto}"))
            self.assertEqual(r".\agent-wp", payload["artifacts"]["wp_root"])


if __name__ == "__main__":
    unittest.main()
