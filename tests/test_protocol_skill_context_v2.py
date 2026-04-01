import json
import tempfile
import unittest
from pathlib import Path

from ctf_agent.core.board import load_workspace_board
from ctf_agent.core.task_protocol import build_needs_input_envelope, build_sync_envelope
from ctf_agent.knowledge import SkillResolver
from ctf_agent.mcp_server import CTFMCPServer


def _write_json(path, payload):
    Path(path).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8-sig")


class ProtocolSkillContextV2Tests(unittest.TestCase):
    def test_build_needs_input_envelope_uses_skill_resolution_when_autopilot_knowledge_missing(self):
        resolution = SkillResolver().resolve(
            task_text="jwt auth bypass",
            target="http://example.com",
            explicit_category="web",
            speed_mode="standard",
        )
        payload = build_needs_input_envelope(
            "jwt auth bypass",
            {
                "target": "http://example.com",
                "attachments": [],
                "speed_mode": "standard",
                "skill_resolution": resolution,
                "autopilot_plan": {},
            },
            {
                "ok": False,
                "errors": ["missing target"],
                "warnings": [],
                "next_actions": ["supply a valid target"],
            },
        )

        self.assertEqual("web", payload["summary"]["knowledge"]["selected_skill_category"])
        self.assertEqual("CTF Web Playbook", payload["summary"]["knowledge"]["pack_name"])
        self.assertTrue(payload["summary"]["knowledge"]["top_tactics"])
        self.assertEqual("web", payload["board"]["knowledge"]["selected_skill_category"])

    def test_load_workspace_board_fallback_uses_metadata_skill_resolution(self):
        with tempfile.TemporaryDirectory() as workspace_dir:
            workspace = Path(workspace_dir)
            resolution = SkillResolver().resolve(
                task_text="jwt auth bypass",
                target="http://example.com",
                explicit_category="web",
                speed_mode="standard",
            )

            _write_json(
                workspace / "metadata.json",
                {
                    "contest_id": "demo",
                    "challenge_id": "workspace-fallback",
                    "title": "workspace-fallback",
                    "category": "web",
                    "description": "jwt auth bypass",
                    "attachments": [],
                    "target": "http://example.com",
                    "metadata": {
                        "speed_mode": "standard",
                        "input_summary": {
                            "task": "Category: web",
                            "task_body": "jwt auth bypass",
                        },
                        "skill_resolution": resolution,
                        "autopilot_plan": {},
                    },
                },
            )
            _write_json(
                workspace / "state.json",
                {
                    "phase": "triage",
                    "findings": [],
                    "tried_actions": [],
                    "candidate_flags": [],
                    "exploit_plans": [],
                    "subagents": [],
                },
            )

            board = load_workspace_board(workspace)
            envelope = build_sync_envelope(
                "jwt auth bypass",
                {
                    "category": "web",
                    "title": "workspace-fallback",
                    "speed_mode": "standard",
                },
                {
                    "status": "running",
                    "workspace": str(workspace),
                    "solver": "agent-loop",
                },
            )

        self.assertEqual("web", board["knowledge"]["selected_skill_category"])
        self.assertEqual("CTF Web Playbook", board["knowledge"]["pack_name"])
        self.assertIn("browser-use", board["mcp_usage"]["recommended_mcp"])
        self.assertEqual("web", board["run"]["meta"]["category"])
        self.assertEqual("web", envelope["summary"]["knowledge"]["selected_skill_category"])
        self.assertEqual("CTF Web Playbook", envelope["summary"]["knowledge"]["pack_name"])

    def test_preview_payload_uses_skill_resolution_when_autopilot_knowledge_missing(self):
        resolution = SkillResolver().resolve(
            task_text="jwt auth bypass",
            target="http://example.com",
            explicit_category="web",
            speed_mode="standard",
        )
        payload = CTFMCPServer()._build_preview_payload(
            {
                "task": "jwt auth bypass",
                "target": "http://example.com",
                "attachments": [],
            },
            {
                "category": "web",
                "target": "http://example.com",
                "attachments": [],
                "title": "preview-web",
                "description": "jwt auth bypass",
                "speed_mode": "standard",
                "skill_resolution": resolution,
                "autopilot_plan": {},
            },
            {
                "effective_mode": "sync",
                "reason": "test",
                "signals": ["unit-test"],
            },
            {
                "ok": True,
                "errors": [],
                "warnings": [],
                "next_actions": [],
            },
        )

        self.assertEqual("web", payload["routing"]["selected_skill_category"])
        self.assertEqual("CTF Web Playbook", payload["routing"]["pack_name"])
        self.assertTrue(payload["routing"]["top_tactics"])
        self.assertIn("browser-use", payload["routing"]["recommended_mcp"])


if __name__ == "__main__":
    unittest.main()
