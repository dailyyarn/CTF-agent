import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ctf_agent.core.approval import ApprovalManager
from ctf_agent.core.doctor import format_self_check_report, run_self_check
from ctf_agent.core.plugin_registry import PluginRegistry
from ctf_agent.core.workspace import WorkspaceManager, load_workspace_plugin_status


def _stub_ok(*args, **kwargs):
    return {"status": "ok"}


def _stub_skipped(*args, **kwargs):
    return {"status": "skipped"}


class _DoctorConfig(object):
    def __init__(self, toolkit_root, remote_subagents=None):
        self.toolkit_root = str(toolkit_root)
        self.remote_subagents = dict(remote_subagents or {})


class _DoctorAgentLoop(object):
    def _create_remote_bundle(self, sub_workspace):
        sub_workspace = Path(sub_workspace)
        sub_workspace.mkdir(parents=True, exist_ok=True)
        bundle_path = sub_workspace / "remote_subagent_bundle.zip"
        bundle_path.write_bytes(b"bundle-ready")
        return bundle_path, "remote_subagent_runner.py"


class _DoctorRemoteTool(object):
    def list_hosts(self):
        return ["stub-remote"]


class PluginDoctorRuntimeV3Tests(unittest.TestCase):
    def _write_plugin(self, root, name, payload):
        plugin_root = Path(root) / name
        plugin_root.mkdir(parents=True, exist_ok=True)
        (plugin_root / "plugin.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return plugin_root

    def test_plugin_registry_prefers_user_override_and_persists_status(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            bundled_root = temp_root / "bundled"
            user_root = temp_root / "user"
            workspace = temp_root / "workspace"
            workspace.mkdir(parents=True, exist_ok=True)

            bundled_plugin = self._write_plugin(
                bundled_root,
                "sample",
                {
                    "name": "sample",
                    "version": "1.0.0",
                    "enabled_by_default": True,
                    "tools": [{"name": "sample-shell", "kind": "shell_template", "command": "echo bundled"}],
                    "remote_templates": [{"name": "bundled-template", "template_kind": "binary-checksec"}],
                },
            )
            user_plugin = self._write_plugin(
                user_root,
                "sample",
                {
                    "name": "sample",
                    "version": "2.0.0",
                    "enabled_by_default": True,
                    "tools": [{"name": "sample-python", "kind": "python_entry", "script": "entry.py"}],
                    "doctor_checks": [{"kind": "path_exists", "path": "data.txt"}],
                },
            )
            (user_plugin / "entry.py").write_text("print('ok')\n", encoding="utf-8")
            (user_plugin / "data.txt").write_text("doctor\n", encoding="utf-8")
            self._write_plugin(
                user_root,
                "broken",
                {
                    "name": "broken",
                    "version": "0.1.0",
                    "enabled_by_default": True,
                    "tools": [{"name": "broken", "kind": "not-supported"}],
                },
            )

            registry = PluginRegistry(
                bundled_root=bundled_root,
                plugin_roots=[user_root],
                workspace_manager=WorkspaceManager(temp_root),
            )
            discovered = registry.discover()
            self.assertEqual(2, len(discovered))

            sample = next(item for item in discovered if item["name"] == "sample")
            broken = next(item for item in discovered if item["name"] == "broken")
            self.assertEqual("user", sample["source_kind"])
            self.assertEqual("2.0.0", sample["version"])
            self.assertTrue(sample["enabled"])
            self.assertTrue(broken["invalid"])
            self.assertFalse(broken["enabled"])

            status_payload = registry.persist_workspace_status(workspace)
            self.assertEqual(1, status_payload["counts"]["enabled"])
            self.assertEqual(1, status_payload["counts"]["invalid"])
            self.assertIn("sample-python", status_payload["tool_names"])

            persisted = load_workspace_plugin_status(workspace)
            self.assertEqual(1, persisted["counts"]["enabled"])
            self.assertEqual(1, persisted["counts"]["invalid"])
            self.assertTrue((workspace / "plugin_status.json").exists())

    def test_run_self_check_surfaces_approval_plugin_and_remote_runtime_sections(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            workspace = temp_root / "workspace"
            workspace.mkdir(parents=True, exist_ok=True)
            plugin_root = temp_root / "plugins"
            plugin = self._write_plugin(
                plugin_root,
                "doctor-sample",
                {
                    "name": "doctor-sample",
                    "version": "1.0.0",
                    "enabled_by_default": True,
                    "doctor_checks": [{"kind": "path_exists", "path": "data.txt"}],
                },
            )
            (plugin / "data.txt").write_text("ok\n", encoding="utf-8")

            registry = PluginRegistry(
                bundled_root=None,
                plugin_roots=[plugin_root],
                workspace_manager=WorkspaceManager(temp_root),
            )
            registry.discover()
            approval_manager = ApprovalManager(
                workspace_manager=WorkspaceManager(temp_root),
                workspace=str(workspace),
                run_id="run-doctor-v3",
                approval_policy={
                    "enabled": True,
                    "default_scope": "workspace_session",
                    "session_ttl_sec": 1800,
                    "auto_resume": True,
                    "ask_categories": ["remote_subagent"],
                },
            )
            service = {
                "config": _DoctorConfig(
                    toolkit_root=temp_root / "toolkit",
                    remote_subagents={"enabled": True, "poll_interval_sec": 7, "mirror_artifacts": True},
                ),
                "workspace_dir": workspace,
                "plugin_registry": registry,
                "approval_manager": approval_manager,
                "agent_loop": _DoctorAgentLoop(),
                "remote_tool": _DoctorRemoteTool(),
            }

            with patch("ctf_agent.core.doctor.build_service", return_value=service), patch(
                "ctf_agent.core.doctor.close_service"
            ), patch.multiple(
                "ctf_agent.core.doctor",
                _check_python_environment=_stub_ok,
                _check_config=_stub_ok,
                _check_knowledge_pack=_stub_ok,
                _check_toolkit_capabilities=_stub_ok,
                _check_sidecar_environment=_stub_ok,
                _check_specialized_completeness=_stub_ok,
                _check_binary_path_completeness=_stub_ok,
                _check_environment_variables=_stub_ok,
                _check_oob=_stub_skipped,
                _check_osint_path=_stub_skipped,
                _check_misc_tools=_stub_skipped,
                _check_web_console=_stub_skipped,
            ):
                payload = run_self_check(
                    config_path=str(temp_root / "config.json"),
                    workspace_root=str(workspace),
                    include_mcp=False,
                    include_remote=False,
                    include_web=False,
                )

            self.assertIn("approval_runtime", payload["checks"])
            self.assertIn("plugin_registry", payload["checks"])
            self.assertIn("remote_subagent_runtime", payload["checks"])
            self.assertTrue(payload["checks"]["approval_runtime"]["enabled"])
            self.assertEqual(1, payload["checks"]["plugin_registry"]["counts"]["enabled"])
            self.assertEqual("ok", payload["checks"]["plugin_registry"]["doctor_checks"][0]["status"])
            self.assertTrue(payload["checks"]["remote_subagent_runtime"]["bundle_ready"])
            self.assertTrue((workspace / "plugin_status.json").exists())

            report = format_self_check_report(payload)
            self.assertIn("[approval_runtime]", report)
            self.assertIn("[plugin_registry]", report)
            self.assertIn("[remote_subagent_runtime]", report)


if __name__ == "__main__":
    unittest.main()
