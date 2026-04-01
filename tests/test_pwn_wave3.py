import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from ctf_agent.core.doctor import _check_remote_hosts, _probe_remote_pwn_runtime
from ctf_agent.core.memory import StateMemory
from ctf_agent.core.models import ChallengeState
from ctf_agent.core.regression import run_pwn_live_smoke
from ctf_agent.solvers.binary import BinarySolver
from ctf_agent.tools.remote_tool import RemoteTool


class _FakeRemoteTool(object):
    def __init__(self, probes):
        self._probes = dict(probes or {})
        self.run_template_calls = []

    def list_hosts(self):
        return sorted(self._probes.keys())

    def probe(self, host_name, timeout=0):
        return dict(self._probes[host_name])

    def run_template(self, host_name, template_kind, timeout=0, **kwargs):
        self.run_template_calls.append((host_name, template_kind, timeout, dict(kwargs or {})))
        return {
            "status": "ok",
            "execute": {"stdout": "{\"status\": \"ok\", \"final_probe\": {\"parity_profile\": \"ready\"}}"},
        }


class _FakeFileTool(object):
    def write_json(self, path, payload):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


class _FakeRemoteBuildTool(object):
    def __init__(self):
        self.run_command_calls = []
        self.run_template_calls = []
        self.upload_calls = []
        self.download_calls = []

    def probe(self, host_name, timeout=0):
        return {
            "status": "ok",
            "host": host_name,
            "pwn_capabilities": {
                "build_profile": "ready",
                "build_capabilities": {"multilib_32": True},
                "build_missing": [],
                "build_recommended": [],
                "suggested_build_template": "pwn-build-multilib",
            },
        }

    def ensure_workspace(self, host_name, run_id=None, timeout=0):
        return {
            "status": "ok",
            "workspace_root": "/tmp/ctf agent/run-demo",
            "input_dir": "/tmp/ctf agent/run-demo/input",
            "artifact_dir": "/tmp/ctf agent/run-demo/artifacts",
        }

    def run_command(self, host_name, command, timeout=0, cwd=None, env=None):
        self.run_command_calls.append(command)
        return {"status": "ok", "command": command}

    def upload(self, host_name, local_path, remote_path=None, timeout=0):
        self.upload_calls.append((str(local_path), str(remote_path)))
        return {"status": "ok", "remote_path": str(remote_path)}

    def run_template(self, host_name, template_kind, remote_workspace=None, timeout=0, **kwargs):
        self.run_template_calls.append((host_name, template_kind, dict(kwargs or {})))
        return {
            "status": "ok",
            "execute": {
                "stdout": json.dumps(
                    {"status": "ok", "binary_path": "/tmp/ctf agent/run-demo/artifacts/build/chall_built"},
                    ensure_ascii=False,
                )
            },
        }

    def download(self, host_name, remote_path=None, local_path=None, timeout=0):
        local_path = Path(local_path)
        local_path.parent.mkdir(parents=True, exist_ok=True)
        local_path.write_bytes(b"\x7fELFfake")
        self.download_calls.append((str(remote_path), str(local_path)))
        return {"status": "ok", "remote_path": str(remote_path), "local_path": str(local_path)}


class _FakeDebugRemoteTool(object):
    def __init__(self):
        self.calls = []

    def run_template(self, host_name, template_kind, remote_workspace=None, timeout=0, **kwargs):
        self.calls.append((host_name, template_kind, dict(kwargs or {})))
        if template_kind == "pwn-rr-record":
            payload = {
                "status": "ok",
                "trace_dir": "/tmp/ctf-agent-rr-demo",
                "signal": "SIGSEGV",
                "replay_hint": "rr replay /tmp/ctf-agent-rr-demo",
                "trace_summary": "rr trace recorded for chall",
            }
        else:
            payload = {
                "status": "ok",
                "signal": "SIGSEGV",
                "trace_summary": "cleaned gdb batch trace collected for chall",
                "trace_excerpt": "Program received signal SIGSEGV",
                "registers_excerpt": "rax 0x0",
                "stack_excerpt": "0x7fffffffe000",
                "backtrace_excerpt": "#0 main",
            }
        return {"status": "ok", "execute": {"stdout": json.dumps(payload, ensure_ascii=False)}}


class _CaptureBootstrapRemoteTool(RemoteTool):
    def __init__(self):
        super().__init__(
            hosts={
                "buildbox_primary": {
                    "host": "10.0.0.10",
                    "port": 22,
                    "username": "builder",
                    "password": "builder",
                    "base_dir": "/tmp/ctf-agent",
                    "python_bin": "python3",
                }
            }
        )
        self.run_calls = []

    def stage_template(self, host_name, template_payload, remote_workspace=None, remote_path=None, timeout=0):
        return {
            "status": "ok",
            "host": host_name,
            "remote_path": remote_path or "/tmp/ctf-agent/bootstrap.py",
            "template_kind": template_payload.get("template_kind", ""),
        }

    def run(self, host_name, command, timeout=30, cwd=None, env=None):
        self.run_calls.append(
            {
                "host": host_name,
                "command": command,
                "timeout": timeout,
                "cwd": cwd,
                "env": dict(env or {}),
            }
        )
        secret = str((env or {}).get("CTF_AGENT_REMOTE_SUDO_PASSWORD") or "")
        return {
            "status": "ok",
            "host": host_name,
            "command": "export CTF_AGENT_REMOTE_SUDO_PASSWORD='{0}' && {1}".format(secret, command),
            "stdout": "sudo password={0}".format(secret),
            "stderr": "",
            "returncode": 0,
        }


class PwnWave3Tests(unittest.TestCase):
    def test_finalize_pwn_capabilities_classifies_profiles(self):
        tool = RemoteTool()
        base_ready = {name: True for name in tool.PWN_CORE_CAPABILITIES + tool.PWN_ADVANCED_CAPABILITIES}
        base_ready["pwndbg_or_gef"] = True
        for name in tool.PWN_BUILD_CAPABILITIES:
            base_ready[name] = True

        ready = tool._finalize_pwn_capabilities(
            dict(base_ready),
            python_bin="python3",
            host_profile={"os_id": "ubuntu", "os_like": "debian", "apt_get": "/usr/bin/apt-get"},
        )
        self.assertEqual("ready", ready["parity_profile"])
        self.assertEqual("ready", ready["build_profile"])
        self.assertNotIn("rr", ready["build_missing"])
        self.assertIn("pwn-rr-record", tool._build_pwn_recommended_templates(dict(base_ready)))

        rr_missing_matrix = dict(base_ready)
        rr_missing_matrix["rr"] = False
        rr_missing = tool._finalize_pwn_capabilities(
            rr_missing_matrix,
            python_bin="python3",
            host_profile={"os_id": "ubuntu", "os_like": "debian", "apt_get": "/usr/bin/apt-get"},
        )
        self.assertEqual("ready", rr_missing["parity_profile"])
        self.assertEqual("usable", rr_missing["build_profile"])
        self.assertIn("rr", rr_missing["build_missing"])

        usable_matrix = dict(base_ready)
        usable_matrix["one_gadget"] = False
        usable_matrix["pwndbg_or_gef"] = False
        usable = tool._finalize_pwn_capabilities(
            usable_matrix,
            python_bin="python3",
            host_profile={"os_id": "ubuntu", "os_like": "debian", "apt_get": "/usr/bin/apt-get"},
        )
        self.assertEqual("usable", usable["parity_profile"])
        self.assertTrue(usable["bootstrap_recommended"])
        self.assertEqual("pwn-ubuntu-bootstrap", usable["suggested_template"])
        self.assertEqual("usable", usable["build_profile"])

        weak_matrix = dict(base_ready)
        weak_matrix["checksec"] = False
        weak = tool._finalize_pwn_capabilities(
            weak_matrix,
            python_bin="python3",
            host_profile={"os_id": "ubuntu", "os_like": "debian", "apt_get": "/usr/bin/apt-get"},
        )
        self.assertEqual("weak", weak["parity_profile"])
        self.assertIn("checksec", weak["core_missing"])
        self.assertEqual("weak", weak["build_profile"])

    def test_render_template_supports_pwn_ubuntu_bootstrap(self):
        tool = RemoteTool()
        payload = tool.render_template("pwn-ubuntu-bootstrap")
        self.assertEqual("ok", payload["status"])
        self.assertIn("apt-get\", \"update", payload["content"])
        self.assertIn("install.pwndbg.re", payload["content"])
        self.assertIn("api.github.com/repos/io12/pwninit/releases/latest", payload["content"])
        self.assertIn("CTF_AGENT_REMOTE_SUDO_PASSWORD", payload["content"])
        self.assertIn("\"-S\", \"-p\", \"\"", payload["content"])
        self.assertIn("\"--fix-broken\", \"install\", \"-y\"", payload["content"])
        self.assertIn("\"--user\", \"--break-system-packages\"", payload["content"])

        missing = tool.render_template("no-such-template")
        self.assertIn("pwn-ubuntu-bootstrap", missing["available"])

    def test_render_template_supports_kali_bootstrap_and_build_templates(self):
        tool = RemoteTool()
        kali = tool.render_template("pwn-kali-bootstrap")
        self.assertEqual("ok", kali["status"])
        self.assertIn("gcc-multilib", kali["content"])
        self.assertIn("libc6-dev-i386", kali["content"])
        self.assertIn("name == \"pwninit\"", kali["content"])
        self.assertIn("install_gef_fallback", kali["content"])
        self.assertIn("archive.kali.org/archive-keyring.gpg", kali["content"])
        self.assertIn("repair_kali_archive_keyring", kali["content"])
        self.assertIn("apt_update_text = (apt_update.get(\"stdout\") or \"\") + \"\\n\"", kali["content"])
        self.assertIn("apt-get\", \"--fix-broken\", \"install\", \"-y\"", kali["content"])
        self.assertIn("\"Dpkg::Options::=--force-overwrite\"", kali["content"])
        self.assertIn("externally-managed-environment", kali["content"])
        self.assertIn("\"--user\", \"--break-system-packages\"", kali["content"])
        self.assertIn("apt_result_looks_broken", kali["content"])
        self.assertIn("\"rr\"", kali["content"])
        self.assertIn("pwn-kali-bootstrap", tool.render_template("pwn-env-doctor")["content"])

        build_native = tool.render_template("pwn-build-native", source_dir="/tmp/src", build_dir="/tmp/build", binary_name="chall")
        self.assertEqual("ok", build_native["status"])
        self.assertIn("compile_strategy", build_native["content"])
        gdb_trace = tool.render_template("pwn-gdb-batch-trace", sample_path="/tmp/chall")
        self.assertEqual("ok", gdb_trace["status"])
        self.assertIn("===REGISTERS===", gdb_trace["content"])
        self.assertIn("clean_trace_text", gdb_trace["content"])
        self.assertIn("raw_trace_excerpt", gdb_trace["content"])
        self.assertLess(gdb_trace["content"].index('"run'), gdb_trace["content"].index('===REGISTERS==='))
        rr_trace = tool.render_template("pwn-rr-record", sample_path="/tmp/chall")
        self.assertEqual("ok", rr_trace["status"])
        self.assertIn("trace_root = tempfile.mkdtemp", rr_trace["content"])
        self.assertIn("trace_dir = os.path.join(trace_root, \"trace\")", rr_trace["content"])
        self.assertIn("command = [rr, \"record\"", rr_trace["content"])
        self.assertIn("\"replay_hint\": \"rr replay {0}\".format(trace_dir)", rr_trace["content"])
        self.assertIn("replay_hint", rr_trace["content"])
        libc_ident = tool.render_template("pwn-libc-ident", sample_path="/tmp/chall", libc_path="/tmp/libc.so.6", leaks=["puts=0x41414141"])
        self.assertEqual("ok", libc_ident["status"])
        self.assertIn("normalized_leaks", libc_ident["content"])
        self.assertIn("stage2_generated", libc_ident["content"])
        self.assertIn("collect_symbol_offsets", libc_ident["content"])
        regress_pack = tool.render_template("pwn-regress-build-pack")
        self.assertEqual("ok", regress_pack["status"])
        self.assertNotIn("gets(buf)", regress_pack["content"])
        self.assertIn("read(0, buf, 256)", regress_pack["content"])

    def test_run_template_injects_and_redacts_sudo_password_for_bootstrap(self):
        tool = _CaptureBootstrapRemoteTool()
        payload = tool.run_template("buildbox_primary", "pwn-kali-bootstrap", timeout=1)
        self.assertEqual("ok", payload["status"])
        self.assertEqual("builder", tool.run_calls[0]["env"]["CTF_AGENT_REMOTE_SUDO_PASSWORD"])
        self.assertIn("***", payload["execute"]["command"])
        self.assertNotIn("builder", payload["execute"]["command"])

    def test_pwn_env_doctor_template_surfaces_parity_fields(self):
        tool = RemoteTool()
        payload = tool.render_template("pwn-env-doctor")
        self.assertEqual("ok", payload["status"])
        self.assertIn("parity_profile", payload["content"])
        self.assertIn("bootstrap_recommended", payload["content"])
        self.assertIn("build_profile", payload["content"])
        self.assertIn("suggested_build_template", payload["content"])
        self.assertIn("echo gdb-batch-ready", payload["content"])
        self.assertIn("\"rr\"", payload["content"])

    def test_probe_remote_pwn_runtime_maps_probe_result(self):
        probe_result = {
            "status": "ok",
            "python_bin": "python3",
            "pwn_capabilities": {
                "parity_profile": "usable",
                "core_missing": [],
                "advanced_missing": ["one_gadget"],
                "debugger_missing": ["pwndbg_or_gef"],
                "bootstrap_recommended": True,
                "suggested_template": "pwn-ubuntu-bootstrap",
                "build_profile": "usable",
                "build_capabilities": {"gcc": True, "gxx": True, "make": True, "gdb": True, "multilib_32": False},
                "build_missing": ["multilib_32"],
                "build_recommended": ["multilib_32", "rr"],
                "suggested_build_template": "pwn-build-native",
                "python_bin": "python3",
                "host_profile": {"os_id": "ubuntu", "apt_compatible": True},
                "pwntools": True,
                "angr": True,
                "r2pipe": True,
                "gdb": True,
                "patchelf": True,
                "checksec": True,
                "radare2": True,
            },
        }
        runtime = _probe_remote_pwn_runtime(_FakeRemoteTool({"linux_primary": probe_result}), "linux_primary", probe_result=probe_result)
        self.assertEqual("usable", runtime["profile"])
        self.assertTrue(runtime["bootstrap_recommended"])
        self.assertEqual("pwn-ubuntu-bootstrap", runtime["suggested_template"])
        self.assertEqual("usable", runtime["build_profile"])
        self.assertEqual(["multilib_32"], runtime["build_missing"])

    def test_check_remote_hosts_ignores_centos_fallback_for_mainline_ready(self):
        ready_caps = {
            "parity_profile": "ready",
            "core_missing": [],
            "advanced_missing": [],
            "debugger_missing": [],
            "build_profile": "ready",
            "build_capabilities": {"gcc": True, "gxx": True, "make": True, "gdb": True, "multilib_32": True},
            "build_missing": [],
            "build_recommended": [],
            "bootstrap_recommended": False,
            "suggested_template": "",
            "python_bin": "python3",
            "host_profile": {"os_id": "ubuntu", "apt_compatible": True},
            "pwntools": True,
            "angr": True,
            "r2pipe": True,
            "gdb": True,
            "patchelf": True,
            "checksec": True,
            "radare2": True,
        }
        weak_caps = {
            "parity_profile": "weak",
            "core_missing": ["checksec"],
            "advanced_missing": ["one_gadget"],
            "debugger_missing": ["pwndbg_or_gef"],
            "build_profile": "weak",
            "build_capabilities": {"gcc": False, "gxx": False, "make": False, "gdb": True},
            "build_missing": ["gcc", "gxx", "make"],
            "build_recommended": ["gcc", "gxx", "make"],
            "bootstrap_recommended": False,
            "suggested_template": "",
            "python_bin": "python3",
            "host_profile": {"os_id": "centos", "apt_compatible": False},
            "pwntools": True,
            "angr": True,
            "r2pipe": True,
            "gdb": True,
            "patchelf": True,
            "checksec": False,
            "radare2": True,
        }
        service = {
            "remote_tool": _FakeRemoteTool(
                    {
                        "linux_primary": {"status": "ok", "target": "127.0.0.1", "username": "ubuntu", "python_version": "Python 3.11", "pwn_capabilities": ready_caps},
                        "centos_fallback": {"status": "ok", "target": "127.0.0.2", "username": "centos", "python_version": "Python 3.11", "pwn_capabilities": weak_caps},
                    }
                ),
            "config": SimpleNamespace(
                remote_hosts={
                    "linux_primary": {"preferred_for": ["pwn"]},
                    "centos_fallback": {"preferred_for": ["pwn"]},
                },
                remote_policy={"preferred_hosts_by_category": {"pwn": ["linux_primary"]}},
            ),
        }
        payload = _check_remote_hosts(service, timeout=1)
        self.assertEqual("ok", payload["status"])
        by_name = {item["name"]: item for item in payload["hosts"]}
        self.assertEqual("ready", by_name["linux_primary"]["pwn_runtime"]["profile"])
        self.assertEqual("weak", by_name["centos_fallback"]["pwn_runtime"]["profile"])

    def test_merge_pwn_stage_status_deep_merges_wave2_context(self):
        solver = BinarySolver(file_tool=None, shell_tool=None, verifier=object(), toolkit_tool=None, remote_tool=None, mcp_registry=None)
        merged = solver._merge_pwn_stage_status(
            {
                "status": "stage1-ready",
                "resolved_libc_context": {"leak_symbol": "puts", "debug_trace": {"signal": "SIGSEGV"}},
                "stage1_payload": {"kind": "ret2libc", "preview": "stage1"},
            },
            {
                "status": "stage2-synthesized",
                "resolved_libc_context": {"symbol_offsets": {"system": "0x1234"}},
                "stage2_payload": {"kind": "ret2libc-stage2"},
                "exploit_transcript": {"preview": "libc_base = leak_puts - 0x123"},
            },
        )
        self.assertEqual("stage2-synthesized", merged["status"])
        self.assertEqual("puts", merged["resolved_libc_context"]["leak_symbol"])
        self.assertEqual("0x1234", merged["resolved_libc_context"]["symbol_offsets"]["system"])
        self.assertEqual("SIGSEGV", merged["resolved_libc_context"]["debug_trace"]["signal"])
        self.assertEqual("ret2libc-stage2", merged["stage2_payload"]["kind"])

    def test_maybe_collect_pwn_debug_trace_records_rr_artifact_when_available(self):
        remote_tool = _FakeDebugRemoteTool()
        solver = BinarySolver(
            file_tool=_FakeFileTool(),
            shell_tool=None,
            verifier=SimpleNamespace(discover_from_text=lambda *_args, **_kwargs: []),
            toolkit_tool=None,
            remote_tool=remote_tool,
            mcp_registry=None,
        )
        memory = StateMemory(ChallengeState(phase="attempt"))
        challenge = SimpleNamespace(metadata={"speed_mode": "standard"})
        with TemporaryDirectory() as workspace_dir:
            artifact_root = Path(workspace_dir)
            trace = solver._maybe_collect_pwn_debug_trace(
                challenge,
                artifact_root / "chall",
                artifact_root,
                {
                    "host": "buildbox_primary",
                    "binary_path": "/tmp/ctf-agent/chall",
                    "workspace": {"workspace_root": "/tmp/ctf-agent/run-demo"},
                    "pwn_capabilities": {"build_capabilities": {"gdb_batch": True, "rr": True}},
                },
                memory,
                {
                    "candidate_inputs": [{"value": "AAAA"}],
                    "exploit_stub_generated": True,
                    "stage2_generated": False,
                    "pwn_hard_reports": [],
                    "pwn_stage_status": {},
                },
            )
        self.assertEqual("pwn-gdb-batch-trace", trace["template_kind"])
        self.assertEqual("/tmp/ctf-agent-rr-demo", trace["rr_trace"]["payload"]["trace_dir"])
        self.assertEqual("rr replay /tmp/ctf-agent-rr-demo", trace["rr_trace"]["payload"]["replay_hint"])
        self.assertEqual(["pwn-rr-record", "pwn-gdb-batch-trace"], [item[1] for item in remote_tool.calls])

    def test_binary_weak_parity_blocker_mentions_bootstrap(self):
        solver = BinarySolver(file_tool=None, shell_tool=None, verifier=object(), toolkit_tool=None, remote_tool=None, mcp_registry=None)
        parity = {
            "profile": "weak",
            "core_missing": ["checksec", "radare2"],
            "advanced_missing": ["one_gadget"],
            "debugger_missing": ["pwndbg_or_gef"],
            "bootstrap_recommended": True,
            "suggested_template": "pwn-ubuntu-bootstrap",
        }
        blockers = solver._build_pwn_board_blockers("pwn", parity, selected_host="linux_primary")
        self.assertEqual(1, len(blockers))
        self.assertIn("pwn-helper-weak", blockers[0])
        self.assertIn("pwn-ubuntu-bootstrap", blockers[0])
        self.assertIn("linux_primary", blockers[0])

    def test_binary_solver_recognizes_source_build_inputs(self):
        solver = BinarySolver(file_tool=None, shell_tool=None, verifier=object(), toolkit_tool=None, remote_tool=None, mcp_registry=None)
        self.assertTrue(solver._is_source_build_attachment(Path("chall.c")))
        self.assertTrue(solver._is_source_build_attachment(Path("Makefile")))
        self.assertTrue(solver._is_source_build_attachment(Path("CMakeLists.txt")))
        self.assertEqual("pwn-build-multilib", solver._choose_source_build_template([{"preview_text": "CFLAGS += -m32"}], {"multilib_32": True}))

    def test_source_build_lane_builds_remote_binary_and_quotes_paths(self):
        with TemporaryDirectory() as workspace_dir:
            workspace = Path(workspace_dir)
            artifact_root = workspace / "artifacts"
            artifact_root.mkdir(parents=True, exist_ok=True)
            source_path = workspace / "chall.c"
            source_path.write_text("int main(){return 0;}", encoding="utf-8")
            remote_tool = _FakeRemoteBuildTool()
            solver = BinarySolver(
                file_tool=_FakeFileTool(),
                shell_tool=None,
                verifier=object(),
                toolkit_tool=None,
                remote_tool=remote_tool,
                mcp_registry=None,
            )
            memory = StateMemory(ChallengeState(phase="collect"))
            payload = solver._maybe_build_source_binary(
                SimpleNamespace(metadata={"run_id": "run demo"}, title="Heap Lab"),
                workspace,
                artifact_root,
                [{"path": str(source_path), "preview_text": "CFLAGS += -m32"}],
                {"selected_host": "buildbox_primary"},
                [],
                memory,
            )
            self.assertEqual("ok", payload["status"])
            self.assertEqual("remote-source-build", payload["candidate"]["generated_by"])
            self.assertTrue(Path(payload["candidate"]["path"]).exists())
            self.assertEqual("pwn-build-multilib", remote_tool.run_template_calls[0][1])
            self.assertIn("'/tmp/ctf agent/run-demo/input/source'", remote_tool.run_command_calls[0])
            self.assertIn("'/tmp/ctf agent/run-demo/artifacts/build'", remote_tool.run_command_calls[0])

    def test_run_pwn_live_smoke_skips_without_host_or_env_switch(self):
        with TemporaryDirectory() as workspace_dir:
            service = {
                "workspace_dir": Path(workspace_dir),
                "remote_tool": _FakeRemoteTool({}),
            }
            payload = run_pwn_live_smoke(service, hosts=[], timeout=1)
            self.assertEqual("skipped", payload["status"])

    def test_run_pwn_live_smoke_uses_explicit_host_and_writes_report(self):
        with TemporaryDirectory() as workspace_dir:
            service = {
                "workspace_dir": Path(workspace_dir),
                "remote_tool": _FakeRemoteTool(
                    {
                        "linux_primary": {
                            "status": "ok",
                            "pwn_capabilities": {
                                "parity_profile": "ready",
                                "core_missing": [],
                                "advanced_missing": [],
                                "debugger_missing": [],
                                "bootstrap_recommended": False,
                                "suggested_template": "",
                            },
                        }
                    }
                ),
            }
            payload = run_pwn_live_smoke(service, hosts=["linux_primary"], timeout=1)
            self.assertEqual("ok", payload["status"])
            self.assertEqual(["linux_primary"], payload["selected_hosts"])
            self.assertTrue((Path(payload["report_dir"]) / "pwn_live_smoke.json").exists())


if __name__ == "__main__":
    unittest.main()
