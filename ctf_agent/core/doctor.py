import json
import os
import shutil
import socket
import subprocess
import sys
import sysconfig
import tempfile
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from urllib.error import URLError
from urllib.request import ProxyHandler, build_opener, urlopen

from ctf_agent.core.config import _read_env_value
from ctf_agent.core.runtime import build_service, close_service, run_payload
from ctf_agent.knowledge.skillpacks import (
    EMBEDDED_SKILLS_ROOT,
    KNOWLEDGE_PACK_MODE,
    KNOWLEDGE_PACK_NAME,
    KNOWLEDGE_PACK_VERSION,
    supported_categories,
)
from ctf_agent.oob_mock_server import LocalOOBServer
from ctf_agent.solvers.specialized import CryptoSolver, ForensicsSolver, MalwareSolver, MiscSolver, OsintSolver
from ctf_agent.tools.oob_tool import OOBTool
from ctf_agent.tools.mcp_runtime import MCPError


STATUS_ORDER = {
    "ok": 0,
    "warn": 1,
    "error": 2,
    "skipped": 3,
}

OPTIONAL_OOB_VARS = [
    "CTF_AGENT_OOB_BASE_URL",
    "CTF_AGENT_OOB_POLL_URL_TEMPLATE",
    "CTF_AGENT_OOB_AUTH_TOKEN",
]
NO_PROXY_OPENER = build_opener(ProxyHandler({}))


def run_self_check(
    config_path=None,
    workspace_root=None,
    include_remote=True,
    include_mcp=True,
    include_web=True,
    remote_timeout=12.0,
    web_timeout=15.0,
):
    service = build_service(config_path=config_path, workspace_root=workspace_root)
    try:
        config = service["config"]
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "config_path": str(Path(config_path).expanduser().absolute()) if config_path else str((service["project_root"] / "local_config.json").absolute()),
            "workspace_root": str(service["workspace_dir"]),
            "checks": {},
        }

        payload["checks"]["python"] = _check_python_environment()
        payload["checks"]["config"] = _check_config(service, payload["config_path"])
        payload["checks"]["approval_runtime"] = _check_approval_runtime(service)
        payload["checks"]["plugin_registry"] = _check_plugin_registry(service)
        payload["checks"]["remote_subagent_runtime"] = _check_remote_subagent_runtime(service)
        payload["checks"]["knowledge_pack"] = _check_knowledge_pack(service)
        payload["checks"]["toolkit_capabilities"] = _check_toolkit_capabilities(service)
        payload["checks"]["sidecar_environment"] = _check_sidecar_environment(service)
        payload["checks"]["specialized_completeness"] = _check_specialized_completeness(service)
        payload["checks"]["binary_path_completeness"] = _check_binary_path_completeness(service)
        payload["checks"]["environment"] = _check_environment_variables(config)
        payload["checks"]["oob"] = _check_oob(service, timeout=float(web_timeout))
        payload["checks"]["mcp"] = _check_mcp(service) if include_mcp else _skipped("MCP checks skipped by caller.")
        payload["checks"]["osint_path"] = _check_osint_path(service)
        payload["checks"]["misc_tools"] = _check_misc_tools(service)
        payload["checks"]["remote_hosts"] = (
            _check_remote_hosts(service, timeout=float(remote_timeout)) if include_remote else _skipped("Remote host checks skipped by caller.")
        )
        payload["checks"]["web_console"] = (
            _check_web_console(config_path=payload["config_path"], workspace_root=payload["workspace_root"], timeout=float(web_timeout))
            if include_web
            else _skipped("Web console check skipped by caller.")
        )

        payload["overall_status"] = _merge_status(item.get("status", "skipped") for item in payload["checks"].values())
        payload["summary"] = _build_summary(payload)
        return payload
    finally:
        close_service(service)


def format_self_check_report(payload):
    checks = payload.get("checks", {})
    lines = []
    lines.append("overall_status: {0}".format(payload.get("overall_status", "unknown")))
    lines.append("config_path: {0}".format(payload.get("config_path", "")))
    lines.append("workspace_root: {0}".format(payload.get("workspace_root", "")))
    lines.append("")

    python_check = checks.get("python", {})
    lines.append("[python] {0}".format(python_check.get("status", "unknown")))
    lines.append("  executable: {0}".format(python_check.get("executable", "")))
    lines.append("  version: {0}".format(python_check.get("version", "")))
    for item in python_check.get("commands", []):
        suffix = ""
        if item.get("same_environment") is False:
            suffix = " (mismatch)"
        lines.append("  {0}: {1} [{2}]{3}".format(item.get("name"), item.get("path") or "-", item.get("status"), suffix))
    lines.append("")

    config_check = checks.get("config", {})
    lines.append("[config] {0}".format(config_check.get("status", "unknown")))
    lines.append("  config_exists: {0}".format(config_check.get("config_exists")))
    lines.append("  workspace_exists: {0}".format(config_check.get("workspace_exists")))
    lines.append("  toolkit_exists: {0}".format(config_check.get("toolkit_exists")))
    lines.append("  toolkit_root: {0}".format(config_check.get("toolkit_root", "")))
    lines.append("")

    approval_check = checks.get("approval_runtime", {})
    lines.append("[approval_runtime] {0}".format(approval_check.get("status", "unknown")))
    lines.append("  enabled: {0}".format(approval_check.get("enabled")))
    lines.append("  default_scope: {0}".format(approval_check.get("default_scope", "")))
    lines.append("  session_ttl_sec: {0}".format(approval_check.get("session_ttl_sec", 0)))
    lines.append("  auto_resume: {0}".format(approval_check.get("auto_resume")))
    lines.append("  ask_categories: {0}".format(", ".join(approval_check.get("ask_categories", []))))
    lines.append("  pending_request_count: {0}".format(approval_check.get("pending_request_count", 0)))
    lines.append("  active_grant_count: {0}".format(approval_check.get("active_grant_count", 0)))
    if approval_check.get("status_path"):
        lines.append("  status_path: {0}".format(approval_check.get("status_path", "")))
    if approval_check.get("message"):
        lines.append("  message: {0}".format(approval_check.get("message", "")))
    lines.append("")

    plugin_check = checks.get("plugin_registry", {})
    lines.append("[plugin_registry] {0}".format(plugin_check.get("status", "unknown")))
    lines.append("  loaded: {0}".format(plugin_check.get("loaded")))
    counts = dict(plugin_check.get("counts") or {})
    lines.append("  counts: total={0} enabled={1} invalid={2} disabled={3}".format(
        counts.get("total", 0),
        counts.get("enabled", 0),
        counts.get("invalid", 0),
        counts.get("disabled", 0),
    ))
    if plugin_check.get("tool_names"):
        lines.append("  tool_names: {0}".format(", ".join(plugin_check.get("tool_names", []))))
    if plugin_check.get("remote_template_names"):
        lines.append("  remote_template_names: {0}".format(", ".join(plugin_check.get("remote_template_names", []))))
    if plugin_check.get("doctor_checks"):
        for item in plugin_check.get("doctor_checks", [])[:10]:
            lines.append(
                "  doctor_check[{0}/{1}]: {2} {3}".format(
                    item.get("plugin_name", ""),
                    item.get("kind", ""),
                    item.get("status", "unknown"),
                    item.get("message", ""),
                ).rstrip()
            )
    if plugin_check.get("workspace_status_path"):
        lines.append("  workspace_status_path: {0}".format(plugin_check.get("workspace_status_path", "")))
    lines.append("")

    remote_subagent_check = checks.get("remote_subagent_runtime", {})
    lines.append("[remote_subagent_runtime] {0}".format(remote_subagent_check.get("status", "unknown")))
    lines.append("  enabled: {0}".format(remote_subagent_check.get("enabled")))
    lines.append("  host_count: {0}".format(remote_subagent_check.get("host_count", 0)))
    lines.append("  poll_interval_sec: {0}".format(remote_subagent_check.get("poll_interval_sec", 0)))
    lines.append("  mirror_artifacts: {0}".format(remote_subagent_check.get("mirror_artifacts")))
    lines.append("  bundle_ready: {0}".format(remote_subagent_check.get("bundle_ready")))
    if remote_subagent_check.get("bundle_path"):
        lines.append("  bundle_path: {0}".format(remote_subagent_check.get("bundle_path", "")))
    if remote_subagent_check.get("runner_name"):
        lines.append("  runner_name: {0}".format(remote_subagent_check.get("runner_name", "")))
    if remote_subagent_check.get("available_hosts"):
        lines.append("  available_hosts: {0}".format(", ".join(remote_subagent_check.get("available_hosts", []))))
    if remote_subagent_check.get("message"):
        lines.append("  message: {0}".format(remote_subagent_check.get("message", "")))
    lines.append("")

    knowledge_check = checks.get("knowledge_pack", {})
    lines.append("[knowledge_pack] {0}".format(knowledge_check.get("status", "unknown")))
    lines.append("  enabled: {0}".format(knowledge_check.get("enabled")))
    lines.append("  mode: {0}".format(knowledge_check.get("mode", "")))
    lines.append("  pack_name: {0}".format(knowledge_check.get("pack_name", "")))
    lines.append("  version: {0}".format(knowledge_check.get("version", "")))
    lines.append("  root_exists: {0}".format(knowledge_check.get("root_exists")))
    lines.append("  supported_categories: {0}".format(", ".join(knowledge_check.get("supported_categories", []))))
    lines.append("  reference_doc_count: {0}".format(knowledge_check.get("reference_doc_count", 0)))
    lines.append("")

    toolkit_check = checks.get("toolkit_capabilities", {})
    lines.append("[toolkit_capabilities] {0}".format(toolkit_check.get("status", "unknown")))
    lines.append("  toolkit_root: {0}".format(toolkit_check.get("toolkit_root", "")))
    lines.append("  fast_lane: {0}".format(", ".join(toolkit_check.get("layers", {}).get("fast_lane", []))))
    lines.append("  bounded_heavy_lane: {0}".format(", ".join(toolkit_check.get("layers", {}).get("bounded_heavy_lane", []))))
    lines.append("  sidecar_lane: {0}".format(", ".join(toolkit_check.get("layers", {}).get("sidecar_lane", []))))
    lines.append("  binary_tools: {0}".format(", ".join(toolkit_check.get("categories", {}).get("binary_tools", []))))
    lines.append("  crypto_runtime: {0}".format(", ".join(toolkit_check.get("categories", {}).get("crypto_runtime", []))))
    lines.append("  forensics_tools: {0}".format(", ".join(toolkit_check.get("categories", {}).get("forensics_tools", []))))
    lines.append("  stego_tools: {0}".format(", ".join(toolkit_check.get("categories", {}).get("stego_tools", []))))
    lines.append("  sidecar_tools: {0}".format(", ".join(toolkit_check.get("categories", {}).get("sidecar_tools", []))))
    if toolkit_check.get("tool_health", {}).get("sage"):
        lines.append("  sage_health: {0}".format(toolkit_check.get("tool_health", {}).get("sage")))
    if toolkit_check.get("tool_health", {}).get("yafu"):
        lines.append("  yafu_health: {0}".format(toolkit_check.get("tool_health", {}).get("yafu")))
    lines.append("")

    sidecar_check = checks.get("sidecar_environment", {})
    lines.append("[sidecar_environment] {0}".format(sidecar_check.get("status", "unknown")))
    lines.append("  ida_enabled: {0}".format(sidecar_check.get("ida_enabled")))
    lines.append("  ida_command_exists: {0}".format(sidecar_check.get("ida_command_exists")))
    lines.append("  ida_server_script_exists: {0}".format(sidecar_check.get("ida_server_script_exists")))
    lines.append("  ida64_exists: {0}".format(sidecar_check.get("ida64_exists")))
    lines.append("  idat64_exists: {0}".format(sidecar_check.get("idat64_exists")))
    lines.append("  idapyswitch_exists: {0}".format(sidecar_check.get("idapyswitch_exists")))
    lines.append("  ida_plugin_installed: {0}".format(sidecar_check.get("ida_plugin_installed")))
    lines.append("  ida_compat_shim_exists: {0}".format(sidecar_check.get("ida_compat_shim_exists")))
    lines.append("  x64dbg_exists: {0}".format(sidecar_check.get("x64dbg_exists")))
    lines.append("  x32dbg_exists: {0}".format(sidecar_check.get("x32dbg_exists")))
    lines.append("  x64dbg_mcp_enabled: {0}".format(sidecar_check.get("x64dbg_mcp_enabled")))
    lines.append("  x64dbg_mcp_command_exists: {0}".format(sidecar_check.get("x64dbg_mcp_command_exists")))
    lines.append("  x64dbg_plugin_x64_installed: {0}".format(sidecar_check.get("x64dbg_plugin_x64_installed")))
    lines.append("  x64dbg_plugin_x32_installed: {0}".format(sidecar_check.get("x64dbg_plugin_x32_installed")))
    if sidecar_check.get("ida_tool_count") is not None:
        lines.append("  ida_tool_count: {0}".format(sidecar_check.get("ida_tool_count")))
    if sidecar_check.get("x64dbg_tool_count") is not None:
        lines.append("  x64dbg_tool_count: {0}".format(sidecar_check.get("x64dbg_tool_count")))
    if sidecar_check.get("ida_connection_status"):
        lines.append("  ida_connection_status: {0}".format(sidecar_check.get("ida_connection_status")))
    if sidecar_check.get("ida_connection_message"):
        lines.append("  ida_connection_message: {0}".format(sidecar_check.get("ida_connection_message", "")))
    if sidecar_check.get("ida_live_probe_status"):
        lines.append("  ida_live_probe_status: {0}".format(sidecar_check.get("ida_live_probe_status", "")))
    if sidecar_check.get("ida_live_probe_message"):
        lines.append("  ida_live_probe_message: {0}".format(sidecar_check.get("ida_live_probe_message", "")))
    if sidecar_check.get("ida_live_connected") is not None:
        lines.append("  ida_live_connected: {0}".format(sidecar_check.get("ida_live_connected")))
    if sidecar_check.get("ida_template_available") is not None:
        lines.append("  ida_template_available: {0}".format(sidecar_check.get("ida_template_available")))
    if sidecar_check.get("reverse_mcp_default_path"):
        lines.append("  reverse_mcp_default_path: {0}".format(sidecar_check.get("reverse_mcp_default_path", "")))
    if sidecar_check.get("x64dbg_session_probe_status"):
        lines.append("  x64dbg_session_probe_status: {0}".format(sidecar_check.get("x64dbg_session_probe_status", "")))
    if sidecar_check.get("x64dbg_session_probe_message"):
        lines.append("  x64dbg_session_probe_message: {0}".format(sidecar_check.get("x64dbg_session_probe_message", "")))
    if sidecar_check.get("message"):
        lines.append("  message: {0}".format(sidecar_check.get("message", "")))
    lines.append("")

    specialized_check = checks.get("specialized_completeness", {})
    lines.append("[specialized_completeness] {0}".format(specialized_check.get("status", "unknown")))
    for item in specialized_check.get("solvers", []):
        lines.append(
            "  {0}: registered={1} samples={2} smoke={3} status={4}".format(
                item.get("name", ""),
                "yes" if item.get("registered") else "no",
                item.get("sample_count", 0),
                item.get("recent_smoke_count", 0),
                item.get("status", "unknown"),
            )
        )
    lines.append("")

    binary_check = checks.get("binary_path_completeness", {})
    lines.append("[binary_path_completeness] {0}".format(binary_check.get("status", "unknown")))
    for item in binary_check.get("paths", []):
        reverse_label = "yes" if item.get("reverse_mcp_available") else ("optional" if not item.get("reverse_mcp_required", False) else "no")
        lines.append(
            "  {0}: samples={1} smoke={2} templates={3} reverse_mcp={4} status={5}".format(
                item.get("name", ""),
                item.get("sample_count", 0),
                item.get("recent_smoke_count", 0),
                "yes" if item.get("remote_templates_available") else "no",
                reverse_label,
                item.get("status", "unknown"),
            )
        )
    lines.append("")

    env_check = checks.get("environment", {})
    lines.append("[environment] {0}".format(env_check.get("status", "unknown")))
    for item in env_check.get("variables", []):
        lines.append("  {0}: {1}{2}".format(item.get("name"), item.get("status"), " (optional)" if not item.get("required", False) else ""))
    lines.append("")

    oob_check = checks.get("oob", {})
    lines.append("[oob] {0}".format(oob_check.get("status", "unknown")))
    if oob_check.get("configured_mode"):
        lines.append("  configured_mode: {0}".format(oob_check.get("configured_mode", "")))
    if oob_check.get("callback_url"):
        lines.append("  callback_url: {0}".format(oob_check.get("callback_url", "")))
    if oob_check.get("poll_url"):
        lines.append("  poll_url: {0}".format(oob_check.get("poll_url", "")))
    if oob_check.get("message"):
        lines.append("  message: {0}".format(oob_check.get("message", "")))
    smoke = dict(oob_check.get("web_smoke") or {})
    if smoke:
        lines.append("  web_smoke: {0}".format(smoke.get("status", "unknown")))
        if smoke.get("workspace"):
            lines.append("    workspace: {0}".format(smoke.get("workspace", "")))
        if smoke.get("message"):
            lines.append("    message: {0}".format(smoke.get("message", "")))
    lines.append("")

    mcp_check = checks.get("mcp", {})
    lines.append("[mcp] {0}".format(mcp_check.get("status", "unknown")))
    lines.append("  top_level_command: {0}".format(mcp_check.get("top_level_command", "")))
    for item in mcp_check.get("servers", []):
        extra = ""
        if item.get("tool_count") is not None:
            extra = " tools={0}".format(item.get("tool_count"))
        lines.append("  {0}: {1}{2}".format(item.get("name"), item.get("status"), extra))
    browser_probe = dict(mcp_check.get("browser_probe") or {})
    if browser_probe:
        lines.append("  browser_probe: {0}".format(browser_probe.get("status", "unknown")))
        if browser_probe.get("message"):
            lines.append("    message: {0}".format(browser_probe.get("message")))
        if browser_probe.get("title"):
            lines.append("    title: {0}".format(browser_probe.get("title")))
        if browser_probe.get("engine"):
            lines.append("    engine: {0}".format(browser_probe.get("engine")))
    lines.append("")

    osint_check = checks.get("osint_path", {})
    lines.append("[osint_path] {0}".format(osint_check.get("status", "unknown")))
    if osint_check.get("message"):
        lines.append("  message: {0}".format(osint_check.get("message", "")))
    if osint_check.get("http_status") is not None:
        lines.append("  http_status: {0}".format(osint_check.get("http_status")))
    if osint_check.get("browser_status"):
        lines.append("  browser_status: {0}".format(osint_check.get("browser_status")))
    lines.append("")

    misc_check = checks.get("misc_tools", {})
    lines.append("[misc_tools] {0}".format(misc_check.get("status", "unknown")))
    if misc_check.get("visible_tools"):
        lines.append("  visible_tools: {0}".format(", ".join(misc_check.get("visible_tools", []))))
    if misc_check.get("message"):
        lines.append("  message: {0}".format(misc_check.get("message", "")))
    lines.append("")

    remote_check = checks.get("remote_hosts", {})
    lines.append("[remote_hosts] {0}".format(remote_check.get("status", "unknown")))
    for item in remote_check.get("hosts", []):
        details = item.get("message") or item.get("python_version") or ""
        lines.append("  {0}: {1} {2}".format(item.get("name"), item.get("status"), details).rstrip())
        pwn_runtime = dict(item.get("pwn_runtime") or {})
        if pwn_runtime:
            lines.append(
                "    pwn_runtime: status={0} profile={1} build_profile={2} core_missing=[{3}] advanced_missing=[{4}] debugger_missing=[{5}] build_missing=[{6}]".format(
                    pwn_runtime.get("status", "unknown"),
                    pwn_runtime.get("profile", pwn_runtime.get("parity_profile", "unknown")),
                    pwn_runtime.get("build_profile", "unknown"),
                    ",".join(list(pwn_runtime.get("core_missing", []))) or "none",
                    ",".join(list(pwn_runtime.get("advanced_missing", []))) or "none",
                    ",".join(list(pwn_runtime.get("debugger_missing", []))) or "none",
                    ",".join(list(pwn_runtime.get("build_missing", []))) or "none",
                )
            )
            if pwn_runtime.get("bootstrap_recommended"):
                lines.append(
                    "    bootstrap: run {0} on this host to reach parity/build readiness".format(
                        pwn_runtime.get("suggested_template") or pwn_runtime.get("suggested_build_template") or "pwn-kali-bootstrap"
                    )
                )
            if pwn_runtime.get("message"):
                lines.append("    message: {0}".format(pwn_runtime.get("message", "")))
    if remote_check.get("message"):
        lines.append("  message: {0}".format(remote_check.get("message", "")))
    lines.append("")

    web_check = checks.get("web_console", {})
    lines.append("[web_console] {0}".format(web_check.get("status", "unknown")))
    if web_check.get("status") != "skipped":
        lines.append("  launch_mode: {0}".format(web_check.get("launch_mode", "")))
        lines.append("  root_status: {0}".format(web_check.get("root_status", "")))
        lines.append("  template_status: {0}".format(web_check.get("template_status", "")))
        if web_check.get("message"):
            lines.append("  message: {0}".format(web_check.get("message")))

    return "\n".join(lines)


def _check_python_environment():
    executable = str(Path(sys.executable).absolute())
    executable_dir = Path(sys.executable).absolute().parent
    scripts_dir = Path(sysconfig.get_path("scripts")).absolute()
    commands = []
    statuses = ["ok"]

    for name in ["python", "ctf-agent", "ctf-agent-mcp"]:
        found = shutil.which(name)
        status = "ok" if found else "error"
        same_environment = None
        if found:
            found_path = Path(found).absolute()
            if name == "python":
                same_environment = found_path.parent == executable_dir
            else:
                same_environment = found_path.parent == scripts_dir
            if same_environment is False and name != "python":
                status = "warn"
        else:
            found_path = None
        statuses.append(status)
        commands.append(
            {
                "name": name,
                "status": status,
                "path": str(found_path) if found_path else "",
                "same_environment": same_environment,
            }
        )

    return {
        "status": _merge_status(statuses),
        "executable": executable,
        "version": sys.version.replace("\n", " "),
        "scripts_dir": str(scripts_dir),
        "commands": commands,
    }


def _check_config(service, config_path):
    config = service["config"]
    workspace_dir = Path(service["workspace_dir"])
    toolkit_root = Path(config.toolkit_root).expanduser()
    config_file = Path(config_path).expanduser()
    config_exists = config_file.exists()
    workspace_dir.mkdir(parents=True, exist_ok=True)
    workspace_exists = workspace_dir.exists()
    toolkit_exists = toolkit_root.exists()

    statuses = []
    statuses.append("ok" if config_exists else "error")
    statuses.append("ok" if workspace_exists else "error")
    statuses.append("ok" if toolkit_exists else "warn")

    toolkit_tools = []
    try:
        toolkit_tools = service["toolkit_tool"].describe_tools()
    except Exception:
        toolkit_tools = []

    return {
        "status": _merge_status(statuses),
        "config_exists": config_exists,
        "workspace_exists": workspace_exists,
        "toolkit_exists": toolkit_exists,
        "toolkit_root": str(toolkit_root),
        "tool_count": len(toolkit_tools),
    }


def _check_knowledge_pack(service):
    config = service["config"]
    settings = dict(config.knowledge_pack or {})
    enabled = bool(settings.get("enabled", True))
    mode = str(settings.get("mode") or KNOWLEDGE_PACK_MODE).strip() or KNOWLEDGE_PACK_MODE
    version = str(settings.get("version") or KNOWLEDGE_PACK_VERSION).strip() or KNOWLEDGE_PACK_VERSION
    root_exists = EMBEDDED_SKILLS_ROOT.exists()
    categories = list(supported_categories())
    reference_doc_count = 0
    if root_exists:
        try:
            reference_doc_count = sum(1 for _ in EMBEDDED_SKILLS_ROOT.rglob("*.md"))
        except Exception:
            reference_doc_count = 0
    statuses = []
    statuses.append("ok" if enabled else "warn")
    statuses.append("ok" if mode == KNOWLEDGE_PACK_MODE else "warn")
    statuses.append("ok" if root_exists else "error")
    statuses.append("ok" if categories else "error")
    return {
        "status": _merge_status(statuses),
        "enabled": enabled,
        "mode": mode,
        "pack_name": KNOWLEDGE_PACK_NAME,
        "version": version,
        "root": str(EMBEDDED_SKILLS_ROOT),
        "root_exists": root_exists,
        "supported_categories": categories,
        "reference_doc_count": reference_doc_count,
    }


def _check_approval_runtime(service):
    approval_manager = service.get("approval_manager")
    workspace_dir = Path(service.get("workspace_dir", ""))
    if approval_manager is None:
        return {
            "status": "warn",
            "enabled": False,
            "default_scope": "",
            "session_ttl_sec": 0,
            "auto_resume": False,
            "ask_categories": [],
            "pending_request_count": 0,
            "active_grant_count": 0,
            "status_path": str(workspace_dir / "approval_status.json"),
            "requests_path": str(workspace_dir / "approvals" / "requests.jsonl"),
            "grants_path": str(workspace_dir / "approvals" / "grants.json"),
            "message": "approval manager unavailable",
        }

    approval_manager.configure(workspace=str(workspace_dir), run_id="")
    status_payload = approval_manager.get_status(workspace=str(workspace_dir))
    default_scope = str(approval_manager.default_scope() or "")
    session_ttl_sec = int(approval_manager.session_ttl_sec() or 0)
    statuses = []
    statuses.append("ok" if approval_manager.enabled() else "warn")
    statuses.append("ok" if default_scope in {"once", "run", "workspace_session"} else "error")
    statuses.append("ok" if session_ttl_sec > 0 else "error")
    return {
        "status": _merge_status(statuses),
        "enabled": approval_manager.enabled(),
        "default_scope": default_scope,
        "session_ttl_sec": session_ttl_sec,
        "auto_resume": approval_manager.auto_resume(),
        "ask_categories": sorted(list(approval_manager.ask_categories())),
        "pending_request_count": len(list(status_payload.get("pending_requests", []) or [])),
        "active_grant_count": len(list(status_payload.get("active_grants", []) or [])),
        "counts": dict(status_payload.get("counts") or {}),
        "status_path": str(workspace_dir / "approval_status.json"),
        "requests_path": str(workspace_dir / "approvals" / "requests.jsonl"),
        "grants_path": str(workspace_dir / "approvals" / "grants.json"),
        "message": "approval runtime ready" if approval_manager.enabled() else "approval runtime disabled by config",
    }


def _run_plugin_doctor_check(service, check):
    check = dict(check or {})
    kind = str(check.get("kind", "") or "").strip()
    plugin_name = str(check.get("plugin_name", "") or "")
    plugin_root = str(check.get("plugin_root", "") or "")
    required = bool(check.get("required", True))
    label = str(
        check.get("name")
        or check.get("command")
        or check.get("path")
        or check.get("server")
        or check.get("template_kind")
        or kind
    )
    status = "ok"
    message = ""
    details = {}
    try:
        if kind == "command_exists":
            command = str(check.get("command") or check.get("name") or "").strip()
            resolved = shutil.which(command) if command else None
            passed = bool(resolved)
            status = "ok" if passed else ("error" if required else "warn")
            message = resolved or "command not found"
            details["command"] = command
            details["resolved_path"] = resolved or ""
        elif kind == "path_exists":
            raw_path = str(check.get("path") or "").strip()
            path = Path(raw_path)
            if raw_path and not path.is_absolute() and plugin_root:
                path = Path(plugin_root) / raw_path
            passed = bool(raw_path) and path.exists()
            status = "ok" if passed else ("error" if required else "warn")
            message = "path exists" if passed else "path not found"
            details["path"] = str(path)
        elif kind == "env_var":
            env_name = str(check.get("env_var") or check.get("name") or "").strip()
            passed = bool(env_name) and bool(_read_env_value(env_name))
            status = "ok" if passed else ("error" if required else "warn")
            message = "env var present" if passed else "env var missing"
            details["env_var"] = env_name
        elif kind == "mcp_server":
            server_name = str(check.get("server") or check.get("name") or "").strip()
            registry = service.get("mcp_registry")
            available = []
            if registry is not None:
                available = list(registry.describe_mcp_servers() or [])
            matched = next((item for item in available if str(item.get("name", "") or "") == server_name), None)
            passed = matched is not None and bool(matched.get("enabled", True))
            status = "ok" if passed else ("error" if required else "warn")
            message = "mcp server registered" if passed else "mcp server missing"
            details["server"] = server_name
            details["server_status"] = dict(matched or {})
        elif kind == "remote_template":
            template_kind = str(check.get("template_kind") or check.get("name") or "").strip()
            remote_tool = service.get("remote_tool")
            rendered = (
                remote_tool.render_template(
                    template_kind,
                    sample_path="/tmp/sample.bin",
                    binary_name="sample.bin",
                    candidate_inputs=["AAAA"],
                    target_host="127.0.0.1",
                    target_port=31337,
                )
                if remote_tool is not None and template_kind
                else {}
            )
            passed = dict(rendered or {}).get("status") == "ok"
            status = "ok" if passed else ("error" if required else "warn")
            message = str(dict(rendered or {}).get("summary") or dict(rendered or {}).get("message") or ("template ready" if passed else "template unavailable"))
            details["template_kind"] = template_kind
        else:
            status = "warn"
            message = "unsupported doctor check kind"
    except Exception as exc:
        status = "error" if required else "warn"
        message = str(exc)
    return {
        "plugin_name": plugin_name,
        "kind": kind,
        "label": label,
        "required": required,
        "status": status,
        "message": message,
        "details": details,
    }


def _check_plugin_registry(service):
    registry = service.get("plugin_registry")
    workspace_dir = Path(service.get("workspace_dir", ""))
    if registry is None:
        return {
            "status": "warn",
            "loaded": False,
            "counts": {"total": 0, "enabled": 0, "invalid": 0, "disabled": 0},
            "plugins": [],
            "tool_names": [],
            "remote_template_names": [],
            "knowledge_roots": [],
            "doctor_checks": [],
            "workspace_status_path": str(workspace_dir / "plugin_status.json"),
            "message": "plugin registry unavailable",
        }

    payload = dict(registry.describe() or {})
    registry.persist_workspace_status(workspace_dir)
    doctor_results = [_run_plugin_doctor_check(service, item) for item in list(registry.doctor_checks() or [])]
    counts = dict(payload.get("counts") or {})
    statuses = ["ok" if payload.get("loaded") else "error"]
    invalid_count = int(counts.get("invalid", 0) or 0)
    enabled_count = int(counts.get("enabled", 0) or 0)
    statuses.append("warn" if invalid_count else "ok")
    statuses.append("warn" if enabled_count <= 0 else "ok")
    statuses.extend(item.get("status", "warn") for item in doctor_results)
    payload["status"] = _merge_status(statuses)
    payload["doctor_checks"] = doctor_results
    payload["workspace_status_path"] = str(workspace_dir / "plugin_status.json")
    payload["message"] = "plugin registry ready" if enabled_count > 0 else "no enabled plugins loaded"
    return payload


def _check_remote_subagent_runtime(service):
    config = service.get("config")
    agent_loop = service.get("agent_loop")
    remote_tool = service.get("remote_tool")
    workspace_dir = Path(service.get("workspace_dir", ""))
    settings = dict(getattr(config, "remote_subagents", {}) or {})
    enabled = bool(settings.get("enabled", True))
    poll_interval_sec = int(settings.get("poll_interval_sec", 5) or 5)
    mirror_artifacts = bool(settings.get("mirror_artifacts", True))
    available_hosts = []
    if remote_tool is not None:
        try:
            available_hosts = list(remote_tool.list_hosts() or [])
        except Exception:
            available_hosts = []

    bundle_path = ""
    runner_name = ""
    bundle_ready = False
    message = ""
    if agent_loop is not None:
        try:
            doctor_root = workspace_dir / "_doctor" / "remote_subagent_runtime"
            doctor_root.mkdir(parents=True, exist_ok=True)
            bundle, runner_name = agent_loop._create_remote_bundle(doctor_root)
            bundle_path = str(bundle)
            bundle_ready = Path(bundle).exists()
            message = "remote subagent bundle staged"
        except Exception as exc:
            message = str(exc)
    else:
        message = "agent loop unavailable"

    statuses = []
    statuses.append("ok" if bundle_ready else "error")
    statuses.append("warn" if not enabled else "ok")
    if enabled:
        statuses.append("ok" if available_hosts else "warn")
    return {
        "status": _merge_status(statuses),
        "enabled": enabled,
        "host_count": len(available_hosts),
        "available_hosts": available_hosts,
        "poll_interval_sec": poll_interval_sec,
        "mirror_artifacts": mirror_artifacts,
        "bundle_ready": bundle_ready,
        "bundle_path": bundle_path,
        "runner_name": runner_name,
        "message": message or ("remote subagent runtime disabled by config" if not enabled else ""),
    }


def _check_toolkit_capabilities(service):
    toolkit = service.get("toolkit_tool")
    if not toolkit:
        return {
            "status": "warn",
            "toolkit_root": "",
            "layers": {"fast_lane": [], "bounded_heavy_lane": [], "sidecar_lane": []},
            "categories": {},
            "message": "toolkit tool is not initialized",
        }

    digest = toolkit.capability_digest()
    layers = dict(digest.get("layers") or {})
    categories = dict(digest.get("categories") or {})
    sidecar_tools = sorted(
        {
            item
            for key in ["sidecar_tools", "debug_tools", "sidecar_runtime"]
            for item in list(categories.get(key, []))
            if item
        }
    )
    if sidecar_tools:
        categories["sidecar_tools"] = sidecar_tools
    statuses = []
    statuses.append("ok" if digest.get("configured") else "warn")
    statuses.append("ok" if layers.get("fast_lane") else "warn")
    statuses.append("ok" if (layers.get("bounded_heavy_lane") or categories.get("crypto_runtime")) else "warn")
    statuses.append("ok" if layers.get("sidecar_lane") else "warn")
    return {
        "status": _merge_status(statuses),
        "toolkit_root": digest.get("toolkit_root", ""),
        "layers": layers,
        "categories": categories,
        "tool_count": digest.get("tool_count", 0),
        "library_count": digest.get("library_count", 0),
        "runtime_count": digest.get("runtime_count", 0),
        "ida": dict(digest.get("ida") or {}),
        "x64dbg": dict(digest.get("x64dbg") or {}),
        "tool_health": dict(digest.get("tool_health") or {}),
    }


def _check_sidecar_environment(service):
    config = service["config"]
    registry = service.get("mcp_registry")
    toolkit = service.get("toolkit_tool")
    toolkit_digest = toolkit.capability_digest() if toolkit else {}
    ida_info = dict(toolkit_digest.get("ida") or {})
    x64dbg_info = dict(toolkit_digest.get("x64dbg") or {})

    ida_config = {}
    x64dbg_config = {}
    for item in list(getattr(registry, "server_configs", []) or []):
        server_name = str(item.get("name", "")).lower()
        if server_name == "ida-pro-mcp":
            ida_config = dict(item)
        elif server_name == "x64dbg-automate":
            x64dbg_config = dict(item)

    command_path = Path(str(ida_config.get("command", "") or "")).expanduser() if ida_config.get("command") else None
    x64dbg_command_path = Path(str(x64dbg_config.get("command", "") or "")).expanduser() if x64dbg_config.get("command") else None
    server_script = None
    if list(ida_config.get("args", [])):
        first_arg = str(list(ida_config.get("args", []))[0])
        if first_arg.endswith(".py"):
            server_script = Path(first_arg).expanduser()

    ida_tool_count = None
    ida_tool_names = []
    ida_connection_status = "unknown"
    ida_connection_message = ""
    ida_live_probe_status = ""
    ida_live_probe_message = ""
    ida_live_connected = False
    ida_template_available = False
    x64dbg_tool_count = None
    x64dbg_tool_names = []
    x64dbg_session_probe_status = ""
    x64dbg_session_probe_message = ""
    message = ""
    status_parts = []
    ida_enabled = bool(ida_config.get("enabled", False))
    x64dbg_enabled = bool(x64dbg_config.get("enabled", False))
    status_parts.append("ok" if toolkit_digest.get("configured") else "warn")
    status_parts.append("ok" if ida_info.get("ida64") and ida_info.get("idat64") else "warn")
    status_parts.append("ok" if x64dbg_info.get("x64dbg") else "warn")
    status_parts.append("ok" if x64dbg_info.get("x32dbg") else "warn")
    status_parts.append("ok" if x64dbg_info.get("automate_plugin_x64") else "warn")
    status_parts.append("ok" if x64dbg_info.get("automate_plugin_x32") else "warn")
    if ida_enabled:
        status_parts.append("ok" if command_path and command_path.exists() else "error")
        status_parts.append("ok" if server_script and server_script.exists() else "error")
        status_parts.append("ok" if ida_info.get("compat_shim") else "warn")
        try:
            tools = registry.get_client("ida-pro-mcp").list_tools()
            ida_tool_count = len(tools)
            ida_tool_names = [str(item.get("name", "") or "") for item in list(tools or []) if item.get("name")]
            required_template_tools = {"get_metadata", "list_strings", "list_imports", "list_functions", "get_entry_points"}
            ida_template_available = required_template_tools.issubset(set(ida_tool_names))
            status_parts.append("ok" if ida_tool_count else "warn")
            status_parts.append("ok" if ida_template_available else "warn")
            try:
                connection = registry.call_tool("ida-pro-mcp", "check_connection", arguments={}, timeout=10)
                text = registry.flatten_tool_result(connection)
                ida_connection_message = text
                ida_connection_status = "connected" if "Successfully connected to IDA Pro" in text else "idle"
                ida_live_connected = ida_connection_status == "connected"
            except MCPError as exc:
                ida_connection_status = "error"
                ida_connection_message = str(exc)
        except MCPError as exc:
            message = str(exc)
            status_parts.append("warn")

        if (
            ida_connection_status != "connected"
            and toolkit
            and hasattr(toolkit, "launch_ida_live")
            and ida_info.get("idat64")
        ):
            sample_path = Path(service["project_root"]) / "examples" / "mock_re.bin"
            if sample_path.exists():
                launch = toolkit.launch_ida_live(sample_path, headless=True)
                ida_live_probe_status = launch.get("status", "")
                ida_live_probe_message = launch.get("message", "") or launch.get("command_preview", "")
                if launch.get("status") == "ok":
                    for _ in range(20):
                        time.sleep(1.0)
                        try:
                            connection = registry.call_tool("ida-pro-mcp", "check_connection", arguments={}, timeout=10)
                            text = registry.flatten_tool_result(connection)
                            ida_connection_message = text
                            if "Successfully connected to IDA Pro" in text:
                                ida_connection_status = "connected"
                                ida_live_probe_status = "connected"
                                ida_live_probe_message = text
                                ida_live_connected = True
                                break
                        except MCPError as exc:
                            ida_connection_message = str(exc)
                    else:
                        ida_live_probe_status = "idle"
                        if not ida_live_probe_message:
                            ida_live_probe_message = ida_connection_message or "IDA live probe remained idle after launch"
    else:
        message = "ida-pro-mcp is not enabled in local_config.json"
        status_parts.append("warn")

    if x64dbg_enabled:
        status_parts.append("ok" if x64dbg_command_path and x64dbg_command_path.exists() else "error")
        try:
            x64dbg_tools = registry.get_client("x64dbg-automate").list_tools()
            x64dbg_tool_count = len(x64dbg_tools)
            x64dbg_tool_names = [str(item.get("name", "") or "") for item in list(x64dbg_tools or []) if item.get("name")]
            status_parts.append("ok" if x64dbg_tool_count else "warn")
            if "list_sessions" in x64dbg_tool_names:
                try:
                    session_probe = registry.call_tool("x64dbg-automate", "list_sessions", arguments={}, timeout=10)
                    x64dbg_session_probe_status = "ok"
                    x64dbg_session_probe_message = registry.flatten_tool_result(session_probe) or "x64dbg MCP responded"
                except MCPError as exc:
                    x64dbg_session_probe_status = "warn"
                    x64dbg_session_probe_message = str(exc)
                    status_parts.append("warn")
            else:
                x64dbg_session_probe_status = "warn"
                x64dbg_session_probe_message = "list_sessions tool is not exposed by x64dbg-automate"
                status_parts.append("warn")
        except MCPError as exc:
            if message:
                message += "; "
            message += str(exc)
            status_parts.append("warn")
    else:
        status_parts.append("warn")

    reverse_descriptor = registry.pick_reverse_tool(config.preferred_reverse_mcp) if registry else None
    reverse_mcp_default_path = ""
    if ida_enabled and ida_template_available:
        reverse_mcp_default_path = "ida-pro-mcp::ida-template"
    elif reverse_descriptor:
        reverse_mcp_default_path = "{0}::{1}".format(
            reverse_descriptor.get("server", ""),
            (reverse_descriptor.get("tool", {}) or {}).get("name", ""),
        ).strip(":")

    return {
        "status": _merge_status(status_parts),
        "ida_enabled": ida_enabled,
        "ida_command": str(command_path) if command_path else "",
        "ida_command_exists": bool(command_path and command_path.exists()),
        "ida_server_script": str(server_script) if server_script else "",
        "ida_server_script_exists": bool(server_script and server_script.exists()),
        "ida64_exists": bool(ida_info.get("ida64")),
        "idat64_exists": bool(ida_info.get("idat64")),
        "idapyswitch_exists": bool(ida_info.get("idapyswitch")),
        "ida_plugin_installed": bool(ida_info.get("plugin_path")),
        "ida_compat_dir": str(ida_info.get("compat_dir", "")),
        "ida_compat_shim": str(ida_info.get("compat_shim", "")),
        "ida_compat_shim_exists": bool(ida_info.get("compat_shim")),
        "x64dbg_exists": bool(x64dbg_info.get("x64dbg")),
        "x32dbg_exists": bool(x64dbg_info.get("x32dbg")),
        "x64dbg_plugin_x64_installed": bool(x64dbg_info.get("automate_plugin_x64")),
        "x64dbg_plugin_x32_installed": bool(x64dbg_info.get("automate_plugin_x32")),
        "x64dbg_mcp_enabled": x64dbg_enabled,
        "x64dbg_mcp_command": str(x64dbg_command_path) if x64dbg_command_path else "",
        "x64dbg_mcp_command_exists": bool(x64dbg_command_path and x64dbg_command_path.exists()),
        "x64dbg_tool_count": x64dbg_tool_count,
        "x64dbg_tool_names": x64dbg_tool_names[:16],
        "x64dbg_session_probe_status": x64dbg_session_probe_status,
        "x64dbg_session_probe_message": x64dbg_session_probe_message,
        "ida_tool_count": ida_tool_count,
        "ida_tool_names": ida_tool_names[:16],
        "ida_connection_status": ida_connection_status,
        "ida_connection_message": ida_connection_message,
        "ida_live_probe_status": ida_live_probe_status,
        "ida_live_probe_message": ida_live_probe_message,
        "ida_live_connected": ida_live_connected,
        "ida_template_available": ida_template_available,
        "reverse_mcp_default_path": reverse_mcp_default_path,
        "preferred_reverse_mcp": config.preferred_reverse_mcp,
        "message": message,
    }


def _check_specialized_completeness(service):
    project_root = Path(service["project_root"])
    workspace_root = Path(service["workspace_dir"])
    examples_root = project_root / "examples"
    registry = {
        "crypto": CryptoSolver,
        "forensics": ForensicsSolver,
        "osint": OsintSolver,
        "malware": MalwareSolver,
        "misc": MiscSolver,
    }
    sample_globs = {
        "crypto": ["crypto_*"],
        "forensics": ["forensics_*"],
        "osint": ["osint_*", "osint_site"],
        "malware": ["malware_*"],
        "misc": ["misc_*"],
    }
    results = []
    statuses = []

    for name, solver_cls in registry.items():
        sample_paths = []
        for pattern in sample_globs.get(name, []):
            sample_paths.extend(examples_root.glob(pattern))
        normalized_samples = []
        seen_samples = set()
        for item in sample_paths:
            marker = str(item)
            if marker in seen_samples:
                continue
            seen_samples.add(marker)
            normalized_samples.append(item)

        smoke_paths = []
        manual_root = workspace_root / "manual"
        if manual_root.exists():
            for path in manual_root.iterdir():
                if not path.is_dir():
                    continue
                lower_name = path.name.lower()
                if name not in lower_name:
                    continue
                if (path / "triage_board.json").exists():
                    smoke_paths.append(path)
        status_parts = [
            "ok" if solver_cls is not None else "error",
            "ok" if normalized_samples else "warn",
            "ok" if smoke_paths else "warn",
        ]
        status = _merge_status(status_parts)
        statuses.append(status)
        results.append(
            {
                "name": name,
                "registered": solver_cls is not None,
                "sample_count": len(normalized_samples),
                "recent_smoke_count": len(smoke_paths),
                "sample_examples": [item.name for item in normalized_samples[:5]],
                "recent_smoke_workspaces": [item.name for item in sorted(smoke_paths, key=lambda p: p.stat().st_mtime, reverse=True)[:5]],
                "status": status,
            }
        )

    return {
        "status": _merge_status(statuses),
        "solvers": results,
    }


def _check_binary_path_completeness(service):
    project_root = Path(service["project_root"])
    workspace_root = Path(service["workspace_dir"])
    examples_root = project_root / "examples"
    remote_tool = service.get("remote_tool")
    registry = service.get("mcp_registry")
    expected = {
        "pwn": ["mock_pwn_ret2win.elf", "mock_pwn_format.elf"],
        "reverse": ["mock_reverse_xor.bin", "mock_re.bin"],
    }
    template_ready = True
    template_probe = []
    if remote_tool:
        for name in ["binary-checksec", "input-bruteforce-lite", "pwntools-probe", "reverse-runner"]:
            rendered = remote_tool.render_template(
                name,
                sample_path="/tmp/chall",
                binary_name="chall",
                candidate_inputs=["AAAA"],
                target_host="127.0.0.1",
                target_port=31337,
            )
            item_status = rendered.get("status", "error") if isinstance(rendered, dict) else "error"
            template_probe.append(
                {
                    "name": name,
                    "status": item_status,
                    "message": rendered.get("message", "") if isinstance(rendered, dict) else "non-dict payload",
                }
            )
            if item_status != "ok":
                template_ready = False
                break
    else:
        template_ready = False
        template_probe.append({"name": "remote_tool", "status": "missing", "message": "remote tool not configured"})

    reverse_servers_enabled = []
    if registry:
        for item in getattr(registry, "server_configs", []) or []:
            name = str(item.get("name", "")).lower()
            if not item.get("enabled", True):
                continue
            if any(keyword in name for keyword in ["ida", "ghidra", "reverse"]):
                reverse_servers_enabled.append(item.get("name", ""))

    reverse_mcp_required = bool(reverse_servers_enabled)
    reverse_mcp_available = bool(registry and registry.has_servers() and registry.pick_reverse_tool())
    results = []
    statuses = []
    manual_root = workspace_root / "manual"
    for name, sample_names in sorted(expected.items()):
        samples = [item for item in sample_names if (examples_root / item).exists()]
        smoke_paths = []
        if manual_root.exists():
            for path in manual_root.iterdir():
                if not path.is_dir():
                    continue
                lower_name = path.name.lower()
                matches = any(token in lower_name for token in ([name] if name == "pwn" else ["reverse", "mock_re", "re-"]))
                if matches and (path / "triage_board.json").exists():
                    smoke_paths.append(path)
        parts = [
            "ok" if samples else "warn",
            "ok" if smoke_paths else "warn",
            "ok" if template_ready else "warn",
            "ok" if (name == "pwn" or not reverse_mcp_required or reverse_mcp_available) else "warn",
        ]
        status = _merge_status(parts)
        statuses.append(status)
        results.append(
            {
                "name": name,
                "sample_count": len(samples),
                "sample_examples": samples,
                "recent_smoke_count": len(smoke_paths),
                "recent_smoke_workspaces": [item.name for item in sorted(smoke_paths, key=lambda p: p.stat().st_mtime, reverse=True)[:5]],
                "remote_templates_available": template_ready,
                "template_probe": list(template_probe),
                "reverse_mcp_available": reverse_mcp_available,
                "reverse_mcp_required": reverse_mcp_required,
                "reverse_mcp_enabled_servers": list(reverse_servers_enabled),
                "status": status,
            }
        )
    return {"status": _merge_status(statuses or ["warn"]), "paths": results}


def _check_environment_variables(config):
    variables = []
    statuses = []
    seen = set()

    for host_name, host in sorted(dict(config.remote_hosts or {}).items()):
        env_name = str(host.get("password_env") or "").strip()
        if not env_name or env_name in seen:
            continue
        seen.add(env_name)
        present = bool(_read_env_value(env_name))
        status = "ok" if present else "error"
        statuses.append(status)
        variables.append(
            {
                "name": env_name,
                "required": True,
                "status": status,
                "used_by": [name for name, item in dict(config.remote_hosts or {}).items() if str(item.get("password_env") or "").strip() == env_name],
            }
        )

    for env_name in OPTIONAL_OOB_VARS:
        present = bool(_read_env_value(env_name))
        status = "ok" if present else "warn"
        statuses.append(status)
        variables.append(
            {
                "name": env_name,
                "required": False,
                "status": status,
                "used_by": ["oob"],
            }
        )

    return {
        "status": _merge_status(statuses or ["ok"]),
        "variables": variables,
    }


def _check_oob(service, timeout=15.0):
    configured = service["oob_tool"].describe()
    local_server = None
    probe_tool = service["oob_tool"]
    statuses = []
    message = ""
    callback = {}
    poll_result = {}
    web_smoke = {}
    configured_mode = "configured" if configured.get("enabled") and configured.get("can_poll") else "ephemeral-local-mock"

    try:
        probe_tool, local_server, configured_mode = _prepare_oob_probe(service)
        callback = probe_tool.generate_callback()
        if not callback.get("url"):
            statuses.append("warn")
            message = "OOB callback URL is not available."
        else:
            with NO_PROXY_OPENER.open(callback["url"], timeout=max(3.0, float(timeout))):
                pass
            poll_result = probe_tool.poll(callback["token"])
            statuses.append("ok" if poll_result.get("matched") else "error")
            message = "OOB callback and polling succeeded." if poll_result.get("matched") else "OOB polling did not observe the callback token."
        web_smoke = _run_oob_web_smoke(service, probe_tool, timeout=max(6.0, float(timeout)))
        statuses.append(web_smoke.get("status", "error"))
    except Exception as exc:
        statuses.append("error")
        message = str(exc)
    finally:
        if local_server:
            local_server.stop()

    return {
        "status": _merge_status(statuses),
        "configured": configured,
        "configured_mode": configured_mode,
        "callback_url": callback.get("url", ""),
        "poll_url": poll_result.get("url", ""),
        "poll_result": poll_result,
        "message": message,
        "web_smoke": web_smoke,
    }


def _check_mcp(service):
    registry = service["mcp_registry"]
    top_level = shutil.which("ctf-agent-mcp")
    statuses = ["ok" if top_level else "error"]
    servers = []
    browser_probe = {}
    browser_server_name = str(service["config"].preferred_browser_mcp or "").strip().lower()

    for item in registry.server_configs:
        name = item.get("name", "")
        enabled = bool(item.get("enabled", True))
        if not enabled:
            servers.append(
                {
                    "name": name,
                    "status": "skipped",
                    "enabled": False,
                    "message": "server disabled in config",
                }
            )
            continue

        try:
            tools = registry.get_client(name).list_tools()
            status = "ok"
            message = ""
            tool_count = len(tools)
        except MCPError as exc:
            status = "error"
            message = str(exc)
            tool_count = None
        statuses.append(status)
        servers.append(
            {
                "name": name,
                "enabled": True,
                "status": status,
                "tool_count": tool_count,
                "message": message,
                "command": item.get("command", ""),
            }
        )
        if status == "ok" and (name.lower() == browser_server_name or "browser" in name.lower()):
            browser_probe = _probe_browser_mcp(registry)
            statuses.append(browser_probe.get("status", "warn"))

    if not registry.enabled_servers():
        statuses.append("warn")

    return {
        "status": _merge_status(statuses),
        "top_level_command": top_level or "",
        "servers": servers,
        "preferred_browser_mcp": service["config"].preferred_browser_mcp,
        "preferred_reverse_mcp": service["config"].preferred_reverse_mcp,
        "browser_probe": browser_probe,
    }


def _check_osint_path(service):
    http_status = None
    message = ""
    statuses = []
    try:
        response = service["http_tool"].request("GET", "https://example.com")
        http_status = response.get("status")
        statuses.append("ok" if http_status else "warn")
        message = "HTTP path reachable" if http_status else (response.get("error") or "HTTP fetch did not return a status")
    except Exception as exc:
        statuses.append("warn")
        message = str(exc)
    browser_probe = dict((service.get("mcp_registry") and _probe_browser_mcp(service["mcp_registry"])) or {})
    browser_status = browser_probe.get("status", "")
    if browser_status:
        statuses.append(browser_status)
    return {
        "status": _merge_status(statuses or ["warn"]),
        "http_status": http_status,
        "browser_status": browser_status,
        "message": message,
    }


def _check_misc_tools(service):
    toolkit = service["toolkit_tool"]
    visible = []
    digest = {}
    if toolkit and toolkit.is_configured():
        visible = toolkit.available_tools()
        digest = toolkit.capability_digest()
    interesting = [name for name in ["strings", "7z", "exiftool", "snow", "stegsolve", "steghide", "pngdebugger", "pcapfix"] if name in visible]
    status = "ok" if interesting else ("warn" if visible else "warn")
    message = "misc low-cost tooling visible" if interesting else "misc fallback will rely on Python-only helpers"
    return {
        "status": status,
        "visible_tools": interesting,
        "layers": dict(digest.get("layers", {})) if digest else {},
        "message": message,
    }


def _check_remote_hosts(service, timeout=12.0):
    remote_tool = service["remote_tool"]
    config = service["config"]
    hosts = []
    statuses = []
    messages = []
    available = remote_tool.list_hosts()
    preferred_hosts_by_category = dict(getattr(config, "remote_policy", {}) or {}).get("preferred_hosts_by_category", {}) or {}
    pwn_focus_hosts = {
        str(item).strip().lower()
        for key in ["pwn", "re", "reverse"]
        for item in list(preferred_hosts_by_category.get(key, []))
        if str(item).strip()
    }

    if not available:
        return {
            "status": "warn",
            "hosts": [],
            "message": "no remote hosts configured",
        }

    for host_name in available:
        result = remote_tool.probe(host_name, timeout=timeout)
        status = str(result.get("status") or "error").lower()
        if status not in {"ok", "warn", "error", "skipped"}:
            status = "error"
        statuses.append(status)
        host_config = dict(config.remote_hosts.get(host_name, {}) or {})
        preferred_for = [str(item).strip().lower() for item in list(host_config.get("preferred_for", []))]
        pwn_runtime = {}
        is_binary_focus_host = any(item in preferred_for for item in {"pwn", "re", "reverse"}) or str(host_name).lower() in pwn_focus_hosts
        if status == "ok" and is_binary_focus_host:
            pwn_runtime = _probe_remote_pwn_runtime(remote_tool, host_name, timeout=max(20.0, float(timeout)), probe_result=result)
            if _is_primary_pwn_host(host_name, pwn_runtime):
                statuses.append(str(pwn_runtime.get("status") or "warn"))
                if pwn_runtime.get("profile") != "ready" or pwn_runtime.get("build_profile") != "ready":
                    messages.append(
                        "{0} parity={1} build={2}; run {3}".format(
                            host_name,
                            pwn_runtime.get("profile", "weak"),
                            pwn_runtime.get("build_profile", "weak"),
                            pwn_runtime.get("suggested_template") or pwn_runtime.get("suggested_build_template") or "pwn-kali-bootstrap",
                        )
                    )
        hosts.append(
            {
                "name": host_name,
                "status": status,
                "host": result.get("target") or host_config.get("host", ""),
                "username": result.get("username") or host_config.get("username", ""),
                "python_version": result.get("python_version", ""),
                "message": result.get("message", ""),
                "pwn_runtime": pwn_runtime,
            }
        )

    return {
        "status": _merge_status(statuses),
        "hosts": hosts,
        "message": "; ".join(messages),
    }


def _probe_remote_pwn_runtime(remote_tool, host_name, timeout=25.0, probe_result=None):
    probe_result = dict(probe_result or {})
    pwn_capabilities = dict(probe_result.get("pwn_capabilities") or {})
    if not pwn_capabilities:
        probe_result = remote_tool.probe(host_name, timeout=timeout)
        pwn_capabilities = dict(probe_result.get("pwn_capabilities") or {})
    if not pwn_capabilities:
        return {
            "status": "error",
            "profile": "weak",
            "parity_profile": "weak",
            "build_profile": "weak",
            "tools": [],
            "healthy_modules": [],
            "missing_modules": ["pwntools", "angr", "r2pipe"],
            "python_bin": str(probe_result.get("python_bin") or ""),
            "core_missing": [],
            "advanced_missing": [],
            "debugger_missing": [],
            "build_capabilities": {},
            "build_missing": [],
            "build_recommended": [],
            "bootstrap_recommended": False,
            "suggested_template": "",
            "suggested_build_template": "",
            "message": "remote probe did not return pwn_capabilities",
        }

    profile = str(pwn_capabilities.get("parity_profile") or "weak")
    status = "ok" if profile == "ready" else "warn"
    if str(probe_result.get("status") or "").lower() not in {"ok", "warn", ""}:
        status = "error"

    available_tools = []
    for key in ["gdb", "gdbserver", "patchelf", "checksec", "radare2", "ropper", "one_gadget", "pwninit", "qemu_user", "tmux", "socat"]:
        if pwn_capabilities.get(key):
            available_tools.append(key)
    healthy_modules = [name for name in ["pwntools", "angr", "r2pipe"] if pwn_capabilities.get(name)]
    missing_modules = [name for name in ["pwntools", "angr", "r2pipe"] if not pwn_capabilities.get(name)]
    message = ""
    if pwn_capabilities.get("bootstrap_recommended"):
        message = "run {0} and re-run doctor/probe".format(
            pwn_capabilities.get("suggested_template") or pwn_capabilities.get("suggested_build_template") or "pwn-kali-bootstrap"
        )

    return {
        "status": status,
        "profile": profile,
        "parity_profile": profile,
        "build_profile": str(pwn_capabilities.get("build_profile") or "weak"),
        "tools": available_tools,
        "healthy_modules": healthy_modules,
        "missing_modules": missing_modules,
        "python_bin": str(pwn_capabilities.get("python_bin") or probe_result.get("python_bin") or ""),
        "core_missing": list(pwn_capabilities.get("core_missing", [])),
        "advanced_missing": list(pwn_capabilities.get("advanced_missing", [])),
        "debugger_missing": list(pwn_capabilities.get("debugger_missing", [])),
        "build_capabilities": dict(pwn_capabilities.get("build_capabilities") or {}),
        "build_missing": list(pwn_capabilities.get("build_missing", [])),
        "build_recommended": list(pwn_capabilities.get("build_recommended", [])),
        "bootstrap_recommended": bool(pwn_capabilities.get("bootstrap_recommended")),
        "suggested_template": str(pwn_capabilities.get("suggested_template") or ""),
        "suggested_build_template": str(pwn_capabilities.get("suggested_build_template") or ""),
        "host_profile": dict(pwn_capabilities.get("host_profile") or {}),
        "recommended_templates": list(pwn_capabilities.get("recommended_templates", [])),
        "message": message,
    }


def _is_primary_pwn_host(host_name, pwn_runtime):
    host_name = str(host_name or "").strip().lower()
    host_profile = dict((pwn_runtime or {}).get("host_profile") or {})
    os_id = str(host_profile.get("os_id") or "").strip().lower()
    if any(token in host_name for token in ["kali", "ubuntu", "debian"]):
        return True
    if host_profile.get("kali_like"):
        return True
    return bool(host_profile.get("apt_compatible") and os_id not in {"centos", "rhel", "rocky", "almalinux", "fedora"})


def _check_web_console(config_path, workspace_root, timeout=15.0):
    port = _find_free_port()
    command = [
        sys.executable,
        "-m",
        "ctf_agent",
        "serve-web",
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--config",
        str(config_path),
        "--workspace-root",
        str(workspace_root),
    ]
    process = subprocess.Popen(
        command,
        env=dict(
            os.environ,
            PYTHONUNBUFFERED="1",
            PYTHONIOENCODING="utf-8",
            PYTHONUTF8="1",
        ),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    stdout_text = ""
    stderr_text = ""
    root_status = None
    template_status = None
    launch_mode = "unknown"
    message = ""
    status = "error"

    try:
        deadline = time.time() + max(timeout, 5.0)
        while time.time() < deadline:
            if process.poll() is not None:
                break
            try:
                root_status = _http_status("http://127.0.0.1:{0}/".format(port))
                template_status = _http_status("http://127.0.0.1:{0}/api/task-template".format(port))
                if template_status == 200:
                    break
            except (URLError, OSError, socket.timeout):
                time.sleep(0.5)
                continue
            time.sleep(0.2)

        if template_status == 200:
            status = "ok"
            if root_status == 200:
                message = "web console reachable"
            elif root_status is None:
                message = "web console API reachable; root probe inconclusive"
            else:
                message = "web console API reachable; root probe returned status {0}".format(root_status)
        else:
            if process.poll() is not None:
                message = "web console exited before becoming ready"
            else:
                message = "web console did not become ready"
    finally:
        try:
            _terminate_process(process)
            stdout_text, stderr_text = process.communicate(timeout=2)
        except Exception:
            stdout_text = stdout_text or ""
            stderr_text = stderr_text or ""
        if "fallback web console listening" in stdout_text.lower():
            launch_mode = "fallback"
        elif "uvicorn" in stderr_text.lower() or "application startup complete" in stderr_text.lower():
            launch_mode = "uvicorn"
        _terminate_process(process)

    return {
        "status": status,
        "command": command,
        "port": port,
        "launch_mode": launch_mode,
        "root_status": root_status,
        "template_status": template_status,
        "message": message,
        "stdout_tail": _tail_lines(stdout_text),
        "stderr_tail": _tail_lines(stderr_text),
    }


def _build_summary(payload):
    checks = payload.get("checks", {})
    status = payload.get("overall_status", "unknown")
    parts = []
    for name in [
        "python",
        "config",
        "approval_runtime",
        "plugin_registry",
        "remote_subagent_runtime",
        "knowledge_pack",
        "toolkit_capabilities",
        "sidecar_environment",
        "specialized_completeness",
        "binary_path_completeness",
        "environment",
        "oob",
        "mcp",
        "osint_path",
        "misc_tools",
        "remote_hosts",
        "web_console",
    ]:
        item = checks.get(name, {})
        parts.append("{0}={1}".format(name, item.get("status", "unknown")))
    return {
        "headline": "doctor finished with overall_status={0}".format(status),
        "checks": parts,
    }


def _probe_browser_mcp(registry):
    handle = tempfile.NamedTemporaryFile(prefix="ctf-agent-browser-probe-", suffix=".html", delete=False)
    probe_path = Path(handle.name)
    html = """<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>CTF Browser Probe</title>
</head>
<body>
  <form id="login-form" action="/session" method="post">
    <input type="hidden" name="csrf" value="doctor-token">
    <input type="text" name="username" value="">
    <input type="password" name="password" value="">
    <button type="submit">Login</button>
  </form>
  <form id="upload-form" action="/upload" method="post" enctype="multipart/form-data">
    <input type="file" name="file">
    <button type="submit">Upload</button>
  </form>
  <a href="/dashboard">dashboard</a>
  <script>
    window.__CTF_PROBE__ = { route: "/api/probe", param: "token" };
  </script>
</body>
</html>
"""
    try:
        handle.write(html.encode("utf-8"))
        handle.flush()
        handle.close()
        result = registry.call_browser_flow(
            probe_path.as_uri(),
            action="recon",
            task="Open the page and summarize forms, routes, hidden parameters, and upload/login indicators.",
            timeout=45.0,
        )
        structured = dict(result.get("structured") or {})
        forms = structured.get("forms", [])
        routes = structured.get("route_candidates", [])
        if structured.get("status") != "ok":
            return {
                "status": "error",
                "message": structured.get("message", "browser MCP returned non-ok status"),
                "raw": structured,
            }
        if not forms:
            return {
                "status": "warn",
                "message": "browser MCP ran but did not extract forms",
                "engine": structured.get("engine", ""),
                "title": structured.get("title", ""),
                "route_count": len(routes),
            }
        return {
            "status": "ok",
            "message": "browser MCP executed a real browser task",
            "engine": structured.get("engine", ""),
            "title": structured.get("title", ""),
            "form_count": len(forms),
            "route_count": len(routes),
            "upload_forms": structured.get("upload_forms", 0),
            "login_forms": structured.get("login_forms", 0),
        }
    except MCPError as exc:
        return {
            "status": "error",
            "message": str(exc),
            "details": exc.to_dict(),
        }
    except Exception as exc:
        return {
            "status": "error",
            "message": str(exc),
        }
    finally:
        try:
            probe_path.unlink()
        except Exception:
            pass


def _merge_status(statuses):
    values = [item for item in list(statuses or []) if item in STATUS_ORDER]
    if not values:
        return "skipped"
    if "error" in values:
        return "error"
    if "warn" in values:
        return "warn"
    if "ok" in values:
        return "ok"
    return "skipped"


def _skipped(message):
    return {
        "status": "skipped",
        "message": message,
    }


def _find_free_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def _http_status(url):
    try:
        response = NO_PROXY_OPENER.open(url, timeout=5.0)
    except (URLError, OSError, socket.timeout):
        return None
    try:
        return int(getattr(response, "status", response.getcode()))
    finally:
        response.close()


def _tail_lines(text, limit=20):
    lines = [item for item in str(text or "").splitlines() if item.strip()]
    return lines[-limit:]


def _terminate_process(process):
    if not process:
        return
    if process.poll() is not None:
        return
    try:
        process.terminate()
        process.wait(timeout=3)
    except Exception:
        try:
            process.kill()
        except Exception:
            return


def _read_json_if_exists(path):
    path = Path(path)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return {}


def _prepare_oob_probe(service):
    config = service["config"]
    tool = service["oob_tool"]
    if tool.is_enabled() and tool.can_poll():
        parsed = urlparse(tool.base_url or "")
        if parsed.scheme in {"http", "https"} and (parsed.hostname in {"127.0.0.1", "localhost"}):
            local = LocalOOBServer(
                host=parsed.hostname or "127.0.0.1",
                port=int(parsed.port or 80),
                auth_token=tool.auth_token or "",
                auth_header=tool.auth_header or "Authorization",
            ).start()
            return tool, local, "configured-local-mock"
        return tool, None, "configured"

    local = LocalOOBServer(
        host="127.0.0.1",
        port=0,
        auth_token="ctf-agent-doctor-oob",
        auth_header=config.oob_auth_header or "Authorization",
    ).start()
    tool = OOBTool(
        base_url=local.callback_url(),
        poll_url_template=local.poll_url_template(),
        auth_token=local.auth_token,
        auth_header=local.auth_header,
        timeout=8.0,
    )
    return tool, local, "ephemeral-local-mock"


def _run_oob_web_smoke(service, probe_tool, timeout=15.0):
    solver = service["orchestrator"].solvers.get("web")
    if solver is None:
        return {"status": "skipped", "message": "web solver unavailable"}

    smoke_server = _LocalSSRFSmokeServer(port=0).start()
    original_tool = service["oob_tool"]
    original_solver_tool = solver.oob_tool
    original_common_paths = list(getattr(solver, "COMMON_PATHS", []))
    original_policy = dict(getattr(solver, "web_policy", {}) or {})
    try:
        service["oob_tool"] = probe_tool
        solver.oob_tool = probe_tool
        solver.COMMON_PATHS = ["/", "/fetch", "/api/fetch", "/app.js"]
        solver.web_policy = dict(original_policy)
        solver.web_policy.update(
            {
                "probe_path_limit": 2,
                "probe_param_limit": 2,
                "sqli_target_limit": 1,
                "upload_probe_limit": 1,
                "login_attempt_limit": 1,
            }
        )
        result = run_payload(
            service,
            {
                "category": "web",
                "url": smoke_server.base_url(),
                "title": "doctor-oob-smoke",
                "challenge_id": "doctor-oob-smoke",
                "contest_id": "doctor",
                "description": "Local blind SSRF smoke driven by doctor.",
                "flag_format": r"flag\{[^{}\n]+\}",
                "max_rounds": 2,
                "use_browser_mcp": False,
                "use_remote_host": "",
            },
            source="doctor-oob-smoke",
        )
        workspace = Path(result.get("workspace", ""))
        oob_checks = _read_json_if_exists(workspace / "artifacts" / "oob_checks.json")
        board = _read_json_if_exists(workspace / "triage_board.json")
        matched = False
        if isinstance(oob_checks, list):
            matched = any(bool(item.get("matched")) for item in oob_checks if isinstance(item, dict))
        board_matched = bool(board.get("oob_usage", {}).get("matched")) if isinstance(board, dict) else False
        smoke_status = "ok" if matched or board_matched else "error"
        return {
            "status": smoke_status,
            "workspace": str(workspace),
            "message": "local SSRF smoke observed OOB token" if smoke_status == "ok" else "local SSRF smoke did not produce an OOB hit",
            "matched": bool(matched or board_matched),
            "board_path": str(workspace / "triage_board.json") if workspace else "",
        }
    except Exception as exc:
        return {"status": "error", "message": str(exc)}
    finally:
        service["oob_tool"] = original_tool
        solver.oob_tool = original_solver_tool
        solver.COMMON_PATHS = original_common_paths
        solver.web_policy = original_policy
        smoke_server.stop()


class _LocalSSRFSmokeServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, host="127.0.0.1", port=0):
        ThreadingHTTPServer.__init__(self, (host, int(port or 0)), _LocalSSRFSmokeHandler)
        self.host = host
        self.port = int(self.server_address[1])
        self.thread = None

    def start(self):
        if self.thread:
            return self
        self.thread = threading.Thread(target=self.serve_forever, name="ctf-agent-ssrf-smoke", daemon=True)
        self.thread.start()
        return self

    def stop(self):
        try:
            self.shutdown()
        except Exception:
            pass
        try:
            self.server_close()
        except Exception:
            pass
        if self.thread:
            self.thread.join(timeout=2.0)
        self.thread = None

    def base_url(self):
        return "http://{0}:{1}/".format(self.host, self.port)


class _LocalSSRFSmokeHandler(BaseHTTPRequestHandler):
    server_version = "CTFAgentSSRFSmoke/1.0"
    opener = NO_PROXY_OPENER

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/":
            body = """<!doctype html>
<html>
<head><meta charset="utf-8"><title>Blind SSRF Smoke</title></head>
<body>
  <h1>Blind SSRF Smoke</h1>
  <form action="/fetch" method="get">
    <input type="text" name="url" value="">
    <button type="submit">Fetch</button>
  </form>
  <a href="/fetch?url=http://127.0.0.1/">Fetch route</a>
  <script src="/app.js"></script>
</body>
</html>"""
            return self._send(200, body, "text/html; charset=utf-8")
        if parsed.path == "/app.js":
            body = """window.__SSRF__ = { route: "/api/fetch", param: "url" };
fetch("/api/fetch?url=http://127.0.0.1/").catch(() => {});
"""
            return self._send(200, body, "application/javascript; charset=utf-8")
        if parsed.path in {"/fetch", "/api/fetch"}:
            params = parse_qs(parsed.query, keep_blank_values=True)
            target = ""
            for key in ["url", "callback", "target", "redirect"]:
                values = params.get(key, [])
                if values:
                    target = values[0]
                    break
            if not target:
                return self._send(400, "missing url parameter", "text/plain; charset=utf-8")
            try:
                with self.opener.open(target, timeout=4.0) as response:
                    response.read(256)
                return self._send(200, "blind fetch attempted", "text/plain; charset=utf-8")
            except Exception as exc:
                return self._send(502, "fetch failed: {0}".format(exc), "text/plain; charset=utf-8")
        return self._send(404, "missing", "text/plain; charset=utf-8")

    def log_message(self, format, *args):  # pragma: no cover
        return

    def _send(self, status, body, content_type):
        payload = body.encode("utf-8", errors="replace")
        self.send_response(int(status))
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
