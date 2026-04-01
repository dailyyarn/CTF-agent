import json
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from ctf_agent.core.board import build_board_summary
from ctf_agent.core.regression import render_regression_markdown
from ctf_agent.core.task_protocol import summarize_board
from ctf_agent.solvers.binary import BinarySolver
from ctf_agent.tools.remote_tool import RemoteTool


def _execute_rendered_template(content, args):
    with TemporaryDirectory() as temp_dir:
        script_path = Path(temp_dir) / "probe.py"
        script_path.write_text(content, encoding="utf-8")
        completed = subprocess.run(
            [sys.executable, str(script_path)] + list(args),
            capture_output=True,
            text=True,
            timeout=20,
        )
        if completed.returncode != 0:
            raise AssertionError(completed.stderr or completed.stdout)
        return json.loads(completed.stdout)


class PwnWave4Tests(unittest.TestCase):
    def test_classify_pwn_family_prefers_seccomp_orw(self):
        solver = BinarySolver(file_tool=None, shell_tool=None, verifier=object(), toolkit_tool=None, remote_tool=None, mcp_registry=None)
        family = solver._classify_pwn_family(
            {"subtype": "rop", "summary": "ROP-oriented"},
            {"relro": "Partial RELRO", "nx": "enabled", "pie": "disabled"},
            "seccomp open read write sandbox",
            "",
            "",
            {
                "functions": ["seccomp_init", "read_flag"],
                "imports": ["prctl", "open", "read", "write"],
                "interesting_strings": ["seccomp sandbox active", "open/read/write only"],
            },
            {},
        )
        self.assertEqual("seccomp-orw", family["family"])
        self.assertGreaterEqual(family["confidence"], 0.8)
        self.assertTrue(family["evidence"])

    def test_build_pwn_hard_lane_specs_limits_fastest_fanout(self):
        solver = BinarySolver(file_tool=None, shell_tool=None, verifier=object(), toolkit_tool=None, remote_tool=None, mcp_registry=None)
        challenge = SimpleNamespace(metadata={"speed_mode": "fastest"})
        specs = solver._build_pwn_hard_lane_specs(
            challenge,
            {
                "pwn_family": "seccomp-orw",
                "pwn_family_candidates": [
                    {"family": "seccomp-orw", "confidence": 0.9},
                    {"family": "srop", "confidence": 0.82},
                    {"family": "fsop", "confidence": 0.79},
                ],
            },
        )
        self.assertLessEqual(len(specs), 2)
        self.assertEqual("seccomp-orw-probe", specs[0]["lane"])

    def test_render_template_supports_wave4_hard_templates(self):
        tool = RemoteTool()
        payload = tool.render_template(
            "orw-pwntools-probe",
            sample_path="/tmp/chall",
            binary_name="chall",
            target_host="127.0.0.1",
            target_port=1337,
            family_name="seccomp-orw",
            protections={"relro": "Partial RELRO"},
            probe_summary={"interesting_strings": ["seccomp sandbox", "open read write"]},
            candidate_inputs=["AAAA"],
        )
        self.assertEqual("ok", payload["status"])
        self.assertIn("stage2_payload", payload["content"])
        self.assertIn("Ret2dlresolvePayload", tool.render_template("ret2dlresolve-pwntools-probe", sample_path="/tmp/chall")["content"])
        missing = tool.render_template("no-such-wave4-template")
        self.assertIn("orw-pwntools-probe", missing["available"])
        self.assertIn("heap-pwntools-skeleton", missing["available"])

    def test_heap_skeleton_promotes_stage1_with_menu_and_targets(self):
        tool = RemoteTool()
        rendered = tool.render_template(
            "heap-pwntools-skeleton",
            sample_path="/tmp/chall",
            binary_name="chall",
            family_name="heap-tcache-poison",
            protections={"relro": "Partial RELRO"},
            probe_summary={
                "functions": ["malloc", "free", "show", "edit"],
                "imports": ["malloc", "free", "puts"],
                "interesting_strings": [
                    "1. add",
                    "2. delete",
                    "3. edit",
                    "4. show",
                    "choice:",
                    "index:",
                    "size:",
                    "content:",
                    "tcache",
                    "__free_hook",
                    "main_arena",
                ],
            },
            candidate_inputs=["AAAA"],
        )
        payload = _execute_rendered_template(
            rendered["content"],
            [
                "/tmp/chall",
                "chall",
                "",
                "0",
                "heap-tcache-poison",
                json.dumps({"relro": "Partial RELRO"}),
                json.dumps(
                    {
                        "functions": ["malloc", "free", "show", "edit"],
                        "imports": ["malloc", "free", "puts"],
                        "interesting_strings": [
                            "1. add",
                            "2. delete",
                            "3. edit",
                            "4. show",
                            "choice:",
                            "index:",
                            "size:",
                            "content:",
                            "tcache",
                            "__free_hook",
                            "main_arena",
                        ],
                    }
                ),
                json.dumps(["AAAA"]),
            ],
        )
        self.assertEqual("heap-tcache-poison", payload["primary_family"])
        self.assertEqual("stage1-ready", payload["stage_status"])
        self.assertIn("__free_hook", payload["stage1_payload"]["write_targets"])
        self.assertIn("alloc", payload["stage1_payload"]["menu_primitives"])
        self.assertEqual("__free_hook", payload["stage1_payload"]["preferred_write_path"])
        self.assertEqual("main_arena", payload["stage1_payload"]["preferred_leak_path"])
        self.assertEqual(1, payload["stage1_payload"]["menu_choices"]["alloc"])
        self.assertIn("tcache", payload["stage1_payload"]["family_strategy"].lower())
        self.assertIn("MENU_PRIMITIVES", payload["skeleton"])
        self.assertIn("perform_leak_round", payload["skeleton"])
        self.assertIn("perform_write_round", payload["skeleton"])

    def test_fsop_skeleton_surfaces_targets_and_triggers(self):
        tool = RemoteTool()
        rendered = tool.render_template(
            "fsop-pwntools-skeleton",
            sample_path="/tmp/chall",
            binary_name="chall",
            family_name="fsop",
            protections={"relro": "Partial RELRO"},
            probe_summary={
                "functions": ["fflush", "fclose"],
                "imports": ["puts", "exit"],
                "interesting_strings": [
                    "_IO_2_1_stdout_",
                    "_IO_list_all",
                    "_IO_wide_data",
                    "vtable",
                    "fflush",
                    "fclose",
                    "exit",
                ],
            },
            candidate_inputs=["AAAA"],
        )
        payload = _execute_rendered_template(
            rendered["content"],
            [
                "/tmp/chall",
                "chall",
                "",
                "0",
                "fsop",
                json.dumps({"relro": "Partial RELRO"}),
                json.dumps(
                    {
                        "functions": ["fflush", "fclose"],
                        "imports": ["puts", "exit"],
                        "interesting_strings": [
                            "_IO_2_1_stdout_",
                            "_IO_list_all",
                            "_IO_wide_data",
                            "vtable",
                            "fflush",
                            "fclose",
                            "exit",
                        ],
                    }
                ),
                json.dumps(["AAAA"]),
            ],
        )
        self.assertEqual("stage1-ready", payload["stage_status"])
        self.assertIn("_IO_2_1_stdout_", payload["stage1_payload"]["file_targets"])
        self.assertIn("fflush", payload["stage1_payload"]["trigger_paths"])
        self.assertEqual("_IO_2_1_stdout_", payload["stage1_payload"]["preferred_file_target"])
        self.assertEqual("fflush", payload["stage1_payload"]["preferred_trigger_path"])
        self.assertIn("_flags", payload["stage1_payload"]["fake_file_fields"])
        self.assertIn("FILE_TARGETS", payload["skeleton"])
        self.assertIn("build_fake_file(libc_base=0, system_addr=0, binsh_addr=0)", payload["skeleton"])
        self.assertIn("place_fake_file", payload["skeleton"])

    def test_board_and_protocol_summary_surface_wave4_fields(self):
        with TemporaryDirectory() as workspace_dir:
            workspace = Path(workspace_dir)
            (workspace / "triage_board.json").write_text(
                json.dumps(
                    {
                        "run": {"meta": {"status": "unresolved", "solver": "binary", "category": "pwn", "title": "wave4"}},
                        "input_summary": {"title": "wave4"},
                        "target_summary": {"target": "", "recommended_path": "pwn:seccomp-orw"},
                        "binary": {
                            "subtype": "rop",
                            "summary": "hard pwn",
                            "build_profile": "usable",
                            "build_missing": ["multilib_32"],
                            "debug_trace": {"payload": {"signal": "SIGSEGV", "trace_summary": "gdb batch trace collected"}},
                            "pwn_family": "seccomp-orw",
                            "pwn_family_confidence": 0.91,
                            "pwn_stage_status": {"status": "stage2-synthesized", "source_lane": "seccomp-orw-probe"},
                            "exploit_stub_generated": True,
                            "stage2_generated": True,
                            "pwn_hard_reports": [{"lane": "seccomp-orw-probe", "status": "ok"}],
                        },
                        "findings": [],
                        "candidate_flags": [],
                        "exploit_plans": [],
                        "next_actions": ["hard-pwn family=seccomp-orw, stage=stage2-synthesized"],
                        "blockers": [],
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8-sig",
            )
            (workspace / "task_protocol_summary.json").write_text(
                json.dumps({"execution": {"status": "unresolved"}, "summary": {"headline": "wave4"}}, ensure_ascii=False, indent=2),
                encoding="utf-8-sig",
            )
            summary = build_board_summary(workspace)
            self.assertEqual("seccomp-orw", summary["pwn_family"])
            self.assertTrue(summary["exploit_stub_generated"])
            self.assertEqual("stage2-synthesized", dict(summary["pwn_stage_status"]).get("status"))
            self.assertEqual("usable", summary["build_profile"])

            board_summary = summarize_board(json.loads((workspace / "triage_board.json").read_text(encoding="utf-8-sig")))
            self.assertEqual("seccomp-orw", board_summary["pwn_family"])
            self.assertTrue(board_summary["stage2_generated"])
            self.assertEqual("usable", board_summary["build_profile"])

    def test_regression_markdown_includes_wave4_fields(self):
        markdown = render_regression_markdown(
            {
                "status": "ok",
                "started_at": "2026-03-31T00:00:00",
                "finished_at": "2026-03-31T00:00:01",
                "report_dir": "F:/tmp",
                "case_count": 1,
                "solved_count": 0,
                "unresolved_count": 1,
                "failed_count": 0,
                "expected_flag_match_count": 0,
                "expected_flag_count": 0,
                "by_category": {"pwn": {"total": 1, "solved": 0, "unresolved": 1, "failed": 0, "matched_expected_flag": 0, "expected_flag_count": 0, "solve_rate": 0.0, "expected_flag_match_rate": 0.0}},
                "review": {"failed": [], "unresolved": [], "mismatched_flags": []},
                "cases": [
                    {
                        "status": "unresolved",
                        "category": "pwn",
                        "title": "wave4-case",
                        "workspace": "F:/tmp/workspace",
                        "flag": "",
                        "expected_flag": "",
                        "board_summary": {"headline": "wave4", "tool_usage": {}, "mcp_usage": {}, "remote_usage": {}, "recommended_path": "pwn:seccomp-orw"},
                        "pwn_family": "seccomp-orw",
                        "pwn_family_confidence": 0.88,
                        "pwn_stage_status": {"status": "stage2-synthesized"},
                        "build_profile": "usable",
                        "build_missing": ["multilib_32"],
                        "exploit_stub_generated": True,
                        "stage2_generated": True,
                    }
                ],
            }
        )
        self.assertIn("family=seccomp-orw", markdown)
        self.assertIn("stage=stage2-synthesized", markdown)
        self.assertIn("build=usable", markdown)


if __name__ == "__main__":
    unittest.main()
