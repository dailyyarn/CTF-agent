import argparse
import json
import sys
import time
from pathlib import Path

from ctf_agent.core.board import build_board_summary, format_board_summary
from ctf_agent.core.doctor import format_self_check_report, run_self_check
from ctf_agent.core.editor_integration import export_editor_assets, install_editor_integration
from ctf_agent.core.intake import IntakeService
from ctf_agent.core.regression import run_pwn_live_smoke, run_regression_suite, scaffold_regression_corpus
from ctf_agent.core.runtime import RUN_MANAGER, build_service, close_service, run_payload
from ctf_agent.core.task_protocol import (
    build_needs_input_envelope,
    build_sync_envelope,
    build_validation_view,
)
from ctf_agent.core.task_template import build_task_template_payload, render_task_from_fields
from ctf_agent.oob_mock_server import main as run_oob_mock_server


def build_parser():
    parser = argparse.ArgumentParser(description="CTF Agent")
    subparsers = parser.add_subparsers(dest="command", required=True)

    solve = subparsers.add_parser("solve", help="Solve a challenge from a JSON file")
    solve.add_argument("source", help="Path to a challenge JSON file")
    solve.add_argument("--workspace-root", default=None, help="Directory used to store per-challenge workspaces")
    solve.add_argument("--timeout", type=float, default=8.0, help="HTTP timeout in seconds")
    solve.add_argument("--max-js-assets", type=int, default=8, help="Maximum number of JavaScript assets to fetch during recon")
    solve.add_argument("--submit", action="store_true", help="Attempt submission through the active adapter")
    solve.add_argument("--config", default=None, help="Optional path to a local JSON config file")

    solve_web = subparsers.add_parser("solve-web", help="Solve a web challenge from a URL or local files")
    solve_web.add_argument("--url", default=None, help="Target URL or host")
    solve_web.add_argument("--target", default=None, help="Optional generic target field; URL or local path")
    solve_web.add_argument("--title", default=None, help="Challenge title")
    solve_web.add_argument("--challenge-id", default=None, help="Challenge identifier")
    solve_web.add_argument("--contest-id", default="manual", help="Contest identifier")
    solve_web.add_argument("--description", default="", help="Challenge description")
    solve_web.add_argument("--hint", default="", help="Short hint or prompt text")
    solve_web.add_argument("--attachment", action="append", default=[], help="Optional attachment path; can be repeated")
    solve_web.add_argument("--flag-format", default=r"flag\{[^{}\n]+\}", help="Regex used to validate candidate flags")
    solve_web.add_argument("--workspace-root", default=None, help="Directory used to store per-challenge workspaces")
    solve_web.add_argument("--timeout", type=float, default=8.0, help="HTTP timeout in seconds")
    solve_web.add_argument("--max-js-assets", type=int, default=8, help="Maximum number of JavaScript assets to fetch during recon")
    solve_web.add_argument("--max-rounds", type=int, default=None, help="Override solver iteration rounds")
    solve_web.add_argument("--use-browser-mcp", action="store_true", help="Force browser MCP on")
    solve_web.add_argument("--no-browser-mcp", action="store_true", help="Force browser MCP off")
    solve_web.add_argument("--use-remote-host", default=None, help="Preferred remote helper host name")
    solve_web.add_argument("--config", default=None, help="Optional path to a local JSON config file")

    solve_ctf = subparsers.add_parser("solve-ctf", help="Solve a challenge from category + URL/attachments")
    solve_ctf.add_argument("--category", required=True, help="Challenge category: web/misc/pwn/re/reverse")
    solve_ctf.add_argument("--url", default=None, help="Optional target URL")
    solve_ctf.add_argument("--target", default=None, help="Generic target field; URL or local path")
    solve_ctf.add_argument("--title", default=None, help="Challenge title")
    solve_ctf.add_argument("--challenge-id", default=None, help="Challenge identifier")
    solve_ctf.add_argument("--contest-id", default="manual", help="Contest identifier")
    solve_ctf.add_argument("--description", default="", help="Challenge description")
    solve_ctf.add_argument("--hint", default="", help="Short hint or prompt text")
    solve_ctf.add_argument("--attachment", action="append", default=[], help="Optional attachment path; can be repeated")
    solve_ctf.add_argument("--flag-format", default=r"flag\{[^{}\n]+\}", help="Regex used to validate candidate flags")
    solve_ctf.add_argument("--workspace-root", default=None, help="Directory used to store per-challenge workspaces")
    solve_ctf.add_argument("--timeout", type=float, default=8.0, help="HTTP timeout in seconds")
    solve_ctf.add_argument("--max-js-assets", type=int, default=8, help="Maximum number of JavaScript assets to fetch during recon")
    solve_ctf.add_argument("--max-rounds", type=int, default=None, help="Override solver iteration rounds")
    solve_ctf.add_argument("--use-browser-mcp", action="store_true", help="Force browser MCP on")
    solve_ctf.add_argument("--no-browser-mcp", action="store_true", help="Force browser MCP off")
    solve_ctf.add_argument("--use-remote-host", default=None, help="Preferred remote helper host name")
    solve_ctf.add_argument("--config", default=None, help="Optional path to a local JSON config file")

    solve_brief = subparsers.add_parser("solve-brief", help="One-button solve entry from a short task prompt plus optional target/attachments")
    solve_brief.add_argument("--task", default=None, help="Short task prompt, hint, copied problem statement, or the canonical CTF task template")
    solve_brief.add_argument("--task-file", default=None, help="Path to a local text file containing the task prompt")
    solve_brief.add_argument("--category", default=None, help="Optional category override")
    solve_brief.add_argument("--target", default=None, help="Optional target URL, host, or local path")
    solve_brief.add_argument("--title", default=None, help="Optional title override")
    solve_brief.add_argument("--challenge-id", default=None, help="Optional challenge identifier")
    solve_brief.add_argument("--contest-id", default="manual", help="Contest identifier")
    solve_brief.add_argument("--description", default="", help="Optional description override")
    solve_brief.add_argument("--hint", default="", help="Optional hint override")
    solve_brief.add_argument("--attachment", action="append", default=[], help="Optional attachment path; can be repeated")
    solve_brief.add_argument("--flag-format", default=r"flag\{[^{}\n]+\}", help="Regex used to validate candidate flags")
    solve_brief.add_argument("--workspace-root", default=None, help="Directory used to store per-challenge workspaces")
    solve_brief.add_argument("--timeout", type=float, default=8.0, help="HTTP timeout in seconds")
    solve_brief.add_argument("--max-js-assets", type=int, default=8, help="Maximum number of JavaScript assets to fetch during recon")
    solve_brief.add_argument("--max-rounds", type=int, default=None, help="Override solver iteration rounds")
    solve_brief.add_argument("--use-browser-mcp", action="store_true", help="Force browser MCP on")
    solve_brief.add_argument("--no-browser-mcp", action="store_true", help="Force browser MCP off")
    solve_brief.add_argument("--use-remote-host", default=None, help="Preferred remote helper host name")
    solve_brief.add_argument("--config", default=None, help="Optional path to a local JSON config file")

    auto_solve = subparsers.add_parser("auto-solve", help="Single-entry solve command from task + optional target/attachments; CLI runs sync only")
    auto_solve.add_argument("--task", default=None, help="Short task prompt, copied problem statement, or the canonical CTF task template")
    auto_solve.add_argument("--task-file", default=None, help="Path to a local text file containing the task prompt")
    auto_solve.add_argument("--category", default=None, help="Optional category override")
    auto_solve.add_argument("--target", default=None, help="Optional target URL, host, or local path")
    auto_solve.add_argument("--title", default=None, help="Optional title override")
    auto_solve.add_argument("--challenge-id", default=None, help="Optional challenge identifier")
    auto_solve.add_argument("--contest-id", default="manual", help="Contest identifier")
    auto_solve.add_argument("--description", default="", help="Optional description override")
    auto_solve.add_argument("--hint", default="", help="Optional hint override")
    auto_solve.add_argument("--attachment", action="append", default=[], help="Optional attachment path; can be repeated")
    auto_solve.add_argument("--flag-format", default=r"flag\{[^{}\n]+\}", help="Regex used to validate candidate flags")
    auto_solve.add_argument("--workspace-root", default=None, help="Directory used to store per-challenge workspaces")
    auto_solve.add_argument("--timeout", type=float, default=8.0, help="HTTP timeout in seconds")
    auto_solve.add_argument("--max-js-assets", type=int, default=8, help="Maximum number of JavaScript assets to fetch during recon")
    auto_solve.add_argument("--max-rounds", type=int, default=None, help="Override solver iteration rounds")
    auto_solve.add_argument("--use-browser-mcp", action="store_true", help="Force browser MCP on")
    auto_solve.add_argument("--no-browser-mcp", action="store_true", help="Force browser MCP off")
    auto_solve.add_argument("--use-remote-host", default=None, help="Preferred remote helper host name")
    auto_solve.add_argument("--background", action="store_true", help="Unsupported in CLI; use MCP tool auto_solve_ctf for persistent background runs")
    auto_solve.add_argument("--config", default=None, help="Optional path to a local JSON config file")

    run_session = subparsers.add_parser("run-session", help="Preview and execute a chat-style CTF task in one command; CLI runs sync only")
    run_session.add_argument("--task", default=None, help="Short task prompt, copied problem statement, or the canonical/quick CTF task template")
    run_session.add_argument("--task-file", default=None, help="Path to a local text file containing the task prompt")
    run_session.add_argument("--category", default=None, help="Optional category override")
    run_session.add_argument("--target", default=None, help="Optional target URL, host, or local path")
    run_session.add_argument("--title", default=None, help="Optional title override")
    run_session.add_argument("--challenge-id", default=None, help="Optional challenge identifier")
    run_session.add_argument("--contest-id", default="manual", help="Contest identifier")
    run_session.add_argument("--description", default="", help="Optional description override")
    run_session.add_argument("--hint", default="", help="Optional hint override")
    run_session.add_argument("--attachment", action="append", default=[], help="Optional attachment path; can be repeated")
    run_session.add_argument("--flag-format", default=r"flag\{[^{}\n]+\}", help="Regex used to validate candidate flags")
    run_session.add_argument("--workspace-root", default=None, help="Directory used to store per-challenge workspaces")
    run_session.add_argument("--timeout", type=float, default=8.0, help="HTTP timeout in seconds")
    run_session.add_argument("--max-js-assets", type=int, default=8, help="Maximum number of JavaScript assets to fetch during recon")
    run_session.add_argument("--max-rounds", type=int, default=None, help="Override solver iteration rounds")
    run_session.add_argument("--use-browser-mcp", action="store_true", help="Force browser MCP on")
    run_session.add_argument("--no-browser-mcp", action="store_true", help="Force browser MCP off")
    run_session.add_argument("--use-remote-host", default=None, help="Preferred remote helper host name")
    run_session.add_argument("--background", action="store_true", help="Unsupported in CLI; use MCP tool run_ctf_session for persistent background runs")
    run_session.add_argument("--config", default=None, help="Optional path to a local JSON config file")

    continue_session = subparsers.add_parser("continue-session", help="Poll an existing CTF session and return a chat-friendly summary")
    continue_session.add_argument("--run-id", default=None, help="Existing background run id")
    continue_session.add_argument("--workspace", default=None, help="Optional workspace override")
    continue_session.add_argument("--findings-limit", type=int, default=5, help="Maximum findings shown in the summary digest")

    preview_task = subparsers.add_parser("preview-task", help="Normalize a short task prompt into a stable draft without executing the solver")
    preview_task.add_argument("--task", default=None, help="Short task prompt, copied problem statement, or the canonical/quick CTF task template")
    preview_task.add_argument("--task-file", default=None, help="Path to a local text file containing the task prompt")
    preview_task.add_argument("--category", default=None, help="Optional category override")
    preview_task.add_argument("--target", default=None, help="Optional target URL, host, or local path")
    preview_task.add_argument("--title", default=None, help="Optional title override")
    preview_task.add_argument("--challenge-id", default=None, help="Optional challenge identifier")
    preview_task.add_argument("--contest-id", default="manual", help="Contest identifier")
    preview_task.add_argument("--description", default="", help="Optional description override")
    preview_task.add_argument("--hint", default="", help="Optional hint override")
    preview_task.add_argument("--attachment", action="append", default=[], help="Optional attachment path; can be repeated")
    preview_task.add_argument("--flag-format", default=r"flag\{[^{}\n]+\}", help="Regex used to validate candidate flags")
    preview_task.add_argument("--workspace-root", default=None, help="Directory used to store per-challenge workspaces")
    preview_task.add_argument("--timeout", type=float, default=8.0, help="HTTP timeout in seconds")
    preview_task.add_argument("--max-js-assets", type=int, default=8, help="Maximum number of JavaScript assets to fetch during recon")
    preview_task.add_argument("--max-rounds", type=int, default=None, help="Override solver iteration rounds")
    preview_task.add_argument("--use-browser-mcp", action="store_true", help="Force browser MCP on")
    preview_task.add_argument("--no-browser-mcp", action="store_true", help="Force browser MCP off")
    preview_task.add_argument("--use-remote-host", default=None, help="Preferred remote helper host name")
    preview_task.add_argument("--background", default="auto", help="Preview dispatch mode decision: auto|sync|async|true|false")
    preview_task.add_argument("--config", default=None, help="Optional path to a local JSON config file")

    mcp_list = subparsers.add_parser("mcp-list", help="List configured MCP servers and tools")
    mcp_list.add_argument("--config", default=None, help="Optional path to a local JSON config file")
    mcp_list.add_argument("--server", default=None, help="Only show tools for one MCP server")
    mcp_list.add_argument("--refresh", action="store_true", help="Refresh tool listing from the MCP server")
    mcp_list.add_argument("--workspace-root", default=None, help="Optional workspace root override")

    mcp_call = subparsers.add_parser("mcp-call", help="Call one MCP tool directly")
    mcp_call.add_argument("--config", default=None, help="Optional path to a local JSON config file")
    mcp_call.add_argument("--workspace-root", default=None, help="Optional workspace root override")
    mcp_call.add_argument("--server", required=True, help="MCP server name")
    mcp_call.add_argument("--tool", required=True, help="MCP tool name")
    mcp_call.add_argument("--arguments", default="{}", help="JSON arguments passed to the MCP tool")
    mcp_call.add_argument("--timeout", type=float, default=None, help="Optional per-call timeout")

    remote_probe = subparsers.add_parser("remote-probe", help="Probe one configured remote helper host")
    remote_probe.add_argument("--host", required=True, help="Remote helper host name")
    remote_probe.add_argument("--config", default=None, help="Optional path to a local JSON config file")
    remote_probe.add_argument("--workspace-root", default=None, help="Optional workspace root override")
    remote_probe.add_argument("--timeout", type=float, default=20.0, help="Probe timeout in seconds")

    remote_recommend = subparsers.add_parser("remote-recommend", help="Recommend a remote helper host for one category/target pair")
    remote_recommend.add_argument("--category", required=True, help="Challenge category")
    remote_recommend.add_argument("--target", default="", help="Target URL, host:port, or local path")
    remote_recommend.add_argument("--preferred", default=None, help="Optional explicitly requested host")
    remote_recommend.add_argument("--config", default=None, help="Optional path to a local JSON config file")
    remote_recommend.add_argument("--workspace-root", default=None, help="Optional workspace root override")

    remote_python = subparsers.add_parser("remote-python", help="Run inline Python on a configured remote helper host")
    remote_python.add_argument("--host", required=True, help="Remote helper host name")
    remote_python.add_argument("--code", default=None, help="Inline Python code")
    remote_python.add_argument("--code-file", default=None, help="Path to a local Python script file")
    remote_python.add_argument("--arg", action="append", default=[], help="Argument passed to the remote Python script")
    remote_python.add_argument("--cwd", default=None, help="Optional remote working directory")
    remote_python.add_argument("--python-bin", default=None, help="Override remote python executable")
    remote_python.add_argument("--timeout", type=float, default=120.0, help="Execution timeout in seconds")
    remote_python.add_argument("--config", default=None, help="Optional path to a local JSON config file")
    remote_python.add_argument("--workspace-root", default=None, help="Optional workspace root override")

    remote_template = subparsers.add_parser("remote-template", help="Render or execute one reusable remote helper template")
    remote_template.add_argument("--kind", required=True, help="Template kind: binary-analysis/binary-checksec/http-replay/input-bruteforce-lite/pwn-env-doctor/pwn-ubuntu-bootstrap/pwntools/pwntools-probe/reverse-runner")
    remote_template.add_argument("--host", default=None, help="Remote helper host name; required with --execute")
    remote_template.add_argument("--execute", action="store_true", help="Upload and execute the rendered template remotely")
    remote_template.add_argument("--filename", default=None, help="Optional template filename override")
    remote_template.add_argument("--remote-path", default=None, help="Optional remote script path override")
    remote_template.add_argument("--remote-workspace", default=None, help="Optional remote workspace root used for staging/execution")
    remote_template.add_argument("--cwd", default=None, help="Optional remote working directory")
    remote_template.add_argument("--python-bin", default=None, help="Override remote python executable")
    remote_template.add_argument("--timeout", type=float, default=120.0, help="Template execution timeout in seconds")
    remote_template.add_argument("--var", action="append", default=[], help="Template variable in key=value or key:=json format")
    remote_template.add_argument("--config", default=None, help="Optional path to a local JSON config file")
    remote_template.add_argument("--workspace-root", default=None, help="Optional workspace root override")

    ida_launch = subparsers.add_parser("ida-launch", help="Launch IDA through the agent bootstrap/compat chain and optionally probe MCP connectivity")
    ida_launch.add_argument("binary_path", help="Path to the binary opened by IDA")
    ida_launch.add_argument("--gui", action="store_true", help="Launch ida64 GUI instead of headless idat64")
    ida_launch.add_argument("--wait", type=float, default=20.0, help="Seconds to wait for ida-pro-mcp connectivity after launch")
    ida_launch.add_argument("--config", default=None, help="Optional path to a local JSON config file")
    ida_launch.add_argument("--workspace-root", default=None, help="Optional workspace root override")

    editor_export = subparsers.add_parser("editor-export", help="Export Codex/Cursor/Windsurf integration files")
    editor_export.add_argument("--editor", choices=["codex", "cursor", "windsurf", "all"], required=True, help="Editor to export files for")
    editor_export.add_argument("--project-root", default=None, help="Workspace root where AGENTS/rules should target")
    editor_export.add_argument("--output-dir", default=None, help="Directory used to store exported samples")
    editor_export.add_argument("--config", default=None, help="Optional path to a local JSON config file")
    editor_export.add_argument("--workspace-root", default=None, help="Optional workspace root override")
    editor_export.add_argument("--server-name", default=None, help="Optional MCP server name override")

    editor_install = subparsers.add_parser("editor-install", help="Install Codex/Cursor/Windsurf integration into the official locations")
    editor_install.add_argument("--editor", choices=["codex", "cursor", "windsurf", "all"], required=True, help="Editor to install for")
    editor_install.add_argument("--project-root", default=None, help="Workspace root where AGENTS/rules should be written")
    editor_install.add_argument("--config", default=None, help="Optional path to a local JSON config file")
    editor_install.add_argument("--workspace-root", default=None, help="Optional workspace root override")
    editor_install.add_argument("--server-name", default=None, help="Optional MCP server name override")
    editor_install.add_argument("--force", action="store_true", help="Replace existing Codex MCP entry when present")

    serve_web = subparsers.add_parser("serve-web", help="Start the local FastAPI intake console")
    serve_web.add_argument("--host", default="127.0.0.1", help="Bind host")
    serve_web.add_argument("--port", type=int, default=8765, help="Bind port")
    serve_web.add_argument("--config", default=None, help="Optional path to a local JSON config file")
    serve_web.add_argument("--workspace-root", default=None, help="Optional workspace root override")
    serve_web.add_argument("--reload", action="store_true", help="Enable uvicorn reload for local development")

    serve_oob = subparsers.add_parser("serve-oob-mock", help="Start the local OOB mock service used for doctor and local blind/SSRF smoke")
    serve_oob.add_argument("--host", default="127.0.0.1", help="Bind host")
    serve_oob.add_argument("--port", type=int, default=18788, help="Bind port")
    serve_oob.add_argument("--auth-token", default="", help="Optional auth token required by /poll/{token}")
    serve_oob.add_argument("--auth-header", default="Authorization", help="Header name used for poll auth")

    doctor = subparsers.add_parser("doctor", help="Run a unified self-check for Python, config, MCP, remote hosts, env vars, and the local web console")
    doctor.add_argument("--config", default=None, help="Optional path to a local JSON config file")
    doctor.add_argument("--workspace-root", default=None, help="Optional workspace root override")
    doctor.add_argument("--skip-mcp", action="store_true", help="Skip nested MCP server checks")
    doctor.add_argument("--skip-remote", action="store_true", help="Skip remote host probe checks")
    doctor.add_argument("--skip-web", action="store_true", help="Skip local web console startup check")
    doctor.add_argument("--remote-timeout", type=float, default=12.0, help="Per-host remote probe timeout in seconds")
    doctor.add_argument("--web-timeout", type=float, default=15.0, help="Local web console startup timeout in seconds")
    doctor.add_argument("--json", action="store_true", help="Print the full structured report as JSON")

    board_summary = subparsers.add_parser("board-summary", help="Render a compact run/workspace summary for chat-style UIs")
    board_summary.add_argument("--run-id", default=None, help="Existing run id")
    board_summary.add_argument("--workspace", default=None, help="Workspace path; used when run id is not available")
    board_summary.add_argument("--findings-limit", type=int, default=5, help="Maximum findings shown in the summary digest")
    board_summary.add_argument("--json", action="store_true", help="Print the structured summary as JSON")

    regress = subparsers.add_parser("regress", help="Run a batch regression suite against a manifest or challenge corpus")
    regress_group = regress.add_mutually_exclusive_group(required=True)
    regress_group.add_argument("--manifest", default=None, help="Path to a regression manifest JSON file")
    regress_group.add_argument("--cases-root", default=None, help="Root directory containing category subdirectories and case folders")
    regress.add_argument("--report-dir", default=None, help="Directory used to store regression_report.json and regression_report.md")
    regress.add_argument("--category", action="append", default=[], help="Optional category filter; can be repeated")
    regress.add_argument("--limit", type=int, default=None, help="Optional maximum number of cases to execute")
    regress.add_argument("--findings-limit", type=int, default=5, help="Maximum findings stored in per-case board summaries")
    regress.add_argument("--workspace-root", default=None, help="Directory used to store per-challenge workspaces")
    regress.add_argument("--config", default=None, help="Optional path to a local JSON config file")
    regress.add_argument("--timeout", type=float, default=8.0, help="HTTP timeout in seconds")
    regress.add_argument("--max-js-assets", type=int, default=8, help="Maximum number of JavaScript assets to fetch during recon")
    regress.add_argument("--json", action="store_true", help="Print the structured regression summary as JSON")

    regress_init = subparsers.add_parser("regress-init", help="Scaffold a regression corpus directory with per-category case templates")
    regress_init.add_argument("destination", help="Directory where the regression corpus template should be created")
    regress_init.add_argument("--json", action="store_true", help="Print the scaffold result as JSON")

    pwn_live_smoke = subparsers.add_parser("pwn-live-smoke", help="Explicitly probe selected Ubuntu pwn helpers and optionally run bootstrap")
    pwn_live_smoke.add_argument("--host", action="append", default=[], help="Explicit host to smoke; can be repeated")
    pwn_live_smoke.add_argument("--bootstrap", action="store_true", help="Explicitly execute pwn-ubuntu-bootstrap before the final probe")
    pwn_live_smoke.add_argument("--report-dir", default=None, help="Directory used to store pwn_live_smoke.json and pwn_live_smoke.md")
    pwn_live_smoke.add_argument("--timeout", type=float, default=25.0, help="Per-host probe timeout in seconds")
    pwn_live_smoke.add_argument("--config", default=None, help="Optional path to a local JSON config file")
    pwn_live_smoke.add_argument("--workspace-root", default=None, help="Optional workspace root override")
    pwn_live_smoke.add_argument("--json", action="store_true", help="Print the structured live smoke report as JSON")

    task_template = subparsers.add_parser("task-template", help="Print the canonical task template used by submit_ctf_task/start_ctf_task")
    task_template.add_argument("--format", choices=["markdown", "quick", "json"], default="markdown", help="Output format")
    return parser


def print_result(result):
    lines = []
    lines.append("status: {0}".format(result["status"]))
    lines.append("workspace: {0}".format(result["workspace"]))
    if result.get("solver"):
        lines.append("solver: {0}".format(result["solver"]))
    if result.get("flag"):
        lines.append("flag: {0}".format(result["flag"]))
    if result.get("submit_result"):
        lines.append("submit_result: {0}".format(result["submit_result"]))
    _write_stdout("\n".join(lines))


def print_json(payload):
    _write_stdout(json.dumps(payload, ensure_ascii=False, indent=2))


def _write_stdout(text):
    data = str(text or "")
    if not data.endswith("\n"):
        data += "\n"
    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    buffer = getattr(sys.stdout, "buffer", None)
    if buffer is not None:
        buffer.write(data.encode(encoding, errors="replace"))
        buffer.flush()
        return
    sys.stdout.write(data)
    sys.stdout.flush()


def _normalize_cli_payload(args, category=None):
    payload = {
        "category": category or getattr(args, "category", None) or "web",
        "target": getattr(args, "target", None) or getattr(args, "url", None),
        "url": getattr(args, "url", None),
        "attachments": list(getattr(args, "attachment", []) or []),
        "title": getattr(args, "title", None),
        "challenge_id": getattr(args, "challenge_id", None),
        "contest_id": getattr(args, "contest_id", "manual"),
        "description": getattr(args, "description", ""),
        "hint": getattr(args, "hint", ""),
        "flag_format": getattr(args, "flag_format", r"flag\{[^{}\n]+\}"),
        "workspace_root": getattr(args, "workspace_root", None),
        "config_path": getattr(args, "config", None),
        "timeout": float(getattr(args, "timeout", 8.0)),
        "max_js_assets": int(getattr(args, "max_js_assets", 8)),
        "max_rounds": getattr(args, "max_rounds", None),
        "use_remote_host": getattr(args, "use_remote_host", None),
    }
    if getattr(args, "use_browser_mcp", False):
        payload["use_browser_mcp"] = True
    if getattr(args, "no_browser_mcp", False):
        payload["use_browser_mcp"] = False

    service = build_service(
        config_path=payload.get("config_path"),
        workspace_root=payload.get("workspace_root"),
        timeout=payload["timeout"],
        max_js_assets=payload["max_js_assets"],
    )
    try:
        intake = IntakeService(service["config"], service["workspace_dir"])
        return intake.normalize(payload)
    finally:
        close_service(service)


def _solve_manual_payload(args, category=None):
    payload = _normalize_cli_payload(args, category=category)
    service = build_service(
        config_path=payload.get("config_path"),
        workspace_root=payload.get("output_root") or payload.get("workspace_root"),
        timeout=float(payload.get("timeout", 8.0)),
        max_js_assets=int(payload.get("max_js_assets", 8)),
    )
    try:
        result = run_payload(service, payload, source="cli")
        print_result(result)
        return 0
    finally:
        close_service(service)


def _solve_brief_payload(args):
    task = args.task
    if args.task_file:
        task = Path(args.task_file).read_text(encoding="utf-8-sig")
    payload = {
        "task": task or "",
        "category": getattr(args, "category", None),
        "target": getattr(args, "target", None),
        "attachments": list(getattr(args, "attachment", []) or []),
        "title": getattr(args, "title", None),
        "challenge_id": getattr(args, "challenge_id", None),
        "contest_id": getattr(args, "contest_id", "manual"),
        "description": getattr(args, "description", ""),
        "hint": getattr(args, "hint", ""),
        "flag_format": getattr(args, "flag_format", r"flag\{[^{}\n]+\}"),
        "workspace_root": getattr(args, "workspace_root", None),
        "config_path": getattr(args, "config", None),
        "timeout": float(getattr(args, "timeout", 8.0)),
        "max_js_assets": int(getattr(args, "max_js_assets", 8)),
        "max_rounds": getattr(args, "max_rounds", None),
        "use_remote_host": getattr(args, "use_remote_host", None),
    }
    if getattr(args, "use_browser_mcp", False):
        payload["use_browser_mcp"] = True
    if getattr(args, "no_browser_mcp", False):
        payload["use_browser_mcp"] = False

    service = build_service(
        config_path=payload.get("config_path"),
        workspace_root=payload.get("workspace_root"),
        timeout=payload["timeout"],
        max_js_assets=payload["max_js_assets"],
    )
    try:
        intake = IntakeService(service["config"], service["workspace_dir"])
        normalized = intake.normalize_brief(payload)
    finally:
        close_service(service)

    service = build_service(
        config_path=normalized.get("config_path"),
        workspace_root=normalized.get("output_root") or normalized.get("workspace_root"),
        timeout=float(normalized.get("timeout", 8.0)),
        max_js_assets=int(normalized.get("max_js_assets", 8)),
    )
    try:
        result = run_payload(service, normalized, source="cli-brief")
        print_result(result)
        return 0
    finally:
        close_service(service)


def _auto_solve_payload(args):
    if args.background:
        print_json(
            {
                "status": "unsupported",
                "message": "CLI background mode is not persistent. Use MCP tool auto_solve_ctf with background=true, or use start_ctf_task from Cursor/Codex/Windsurf.",
            }
        )
        return 1

    task = args.task
    if args.task_file:
        task = Path(args.task_file).read_text(encoding="utf-8-sig")
    payload = {
        "task": task or "",
        "category": getattr(args, "category", None),
        "target": getattr(args, "target", None),
        "attachments": list(getattr(args, "attachment", []) or []),
        "title": getattr(args, "title", None),
        "challenge_id": getattr(args, "challenge_id", None),
        "contest_id": getattr(args, "contest_id", "manual"),
        "description": getattr(args, "description", ""),
        "hint": getattr(args, "hint", ""),
        "flag_format": getattr(args, "flag_format", r"flag\{[^{}\n]+\}"),
        "workspace_root": getattr(args, "workspace_root", None),
        "config_path": getattr(args, "config", None),
        "timeout": float(getattr(args, "timeout", 8.0)),
        "max_js_assets": int(getattr(args, "max_js_assets", 8)),
        "max_rounds": getattr(args, "max_rounds", None),
        "use_remote_host": getattr(args, "use_remote_host", None),
    }
    if getattr(args, "use_browser_mcp", False):
        payload["use_browser_mcp"] = True
    if getattr(args, "no_browser_mcp", False):
        payload["use_browser_mcp"] = False

    service = build_service(
        config_path=payload.get("config_path"),
        workspace_root=payload.get("workspace_root"),
        timeout=payload["timeout"],
        max_js_assets=payload["max_js_assets"],
    )
    try:
        intake = IntakeService(service["config"], service["workspace_dir"])
        normalized = intake.normalize_brief(payload)
    finally:
        close_service(service)

    validation = build_validation_view(normalized)
    if not validation.get("ok", False):
        print_json(build_needs_input_envelope(task or "", normalized, validation, mode="sync"))
        return 1

    service = build_service(
        config_path=normalized.get("config_path"),
        workspace_root=normalized.get("output_root") or normalized.get("workspace_root"),
        timeout=float(normalized.get("timeout", 8.0)),
        max_js_assets=int(normalized.get("max_js_assets", 8)),
    )
    try:
        result = run_payload(service, normalized, source="cli-auto")
        print_json(build_sync_envelope(task or "", normalized, result))
        return 0
    finally:
        close_service(service)


def _preview_task_payload(args):
    task = args.task
    if args.task_file:
        task = Path(args.task_file).read_text(encoding="utf-8-sig")

    payload = {
        "task": task or "",
        "category": getattr(args, "category", None),
        "target": getattr(args, "target", None),
        "attachments": list(getattr(args, "attachment", []) or []),
        "title": getattr(args, "title", None),
        "challenge_id": getattr(args, "challenge_id", None),
        "contest_id": getattr(args, "contest_id", "manual"),
        "description": getattr(args, "description", ""),
        "hint": getattr(args, "hint", ""),
        "flag_format": getattr(args, "flag_format", r"flag\{[^{}\n]+\}"),
        "workspace_root": getattr(args, "workspace_root", None),
        "config_path": getattr(args, "config", None),
        "timeout": float(getattr(args, "timeout", 8.0)),
        "max_js_assets": int(getattr(args, "max_js_assets", 8)),
        "max_rounds": getattr(args, "max_rounds", None),
        "use_remote_host": getattr(args, "use_remote_host", None),
        "background": getattr(args, "background", "auto"),
    }
    if getattr(args, "use_browser_mcp", False):
        payload["use_browser_mcp"] = True
    if getattr(args, "no_browser_mcp", False):
        payload["use_browser_mcp"] = False

    from ctf_agent.mcp_server import CTFMCPServer

    server = CTFMCPServer()
    preview = server._preview_ctf_task(payload)
    print_json(preview)
    return 0


def _run_session_payload(args):
    if args.background:
        print_json(
            {
                "status": "unsupported",
                "message": "CLI background mode is not persistent. Use MCP tool run_ctf_session for background execution.",
            }
        )
        return 1

    task = args.task
    if args.task_file:
        task = Path(args.task_file).read_text(encoding="utf-8-sig")

    payload = {
        "task": task or "",
        "category": getattr(args, "category", None),
        "target": getattr(args, "target", None),
        "attachments": list(getattr(args, "attachment", []) or []),
        "title": getattr(args, "title", None),
        "challenge_id": getattr(args, "challenge_id", None),
        "contest_id": getattr(args, "contest_id", "manual"),
        "description": getattr(args, "description", ""),
        "hint": getattr(args, "hint", ""),
        "flag_format": getattr(args, "flag_format", r"flag\{[^{}\n]+\}"),
        "workspace_root": getattr(args, "workspace_root", None),
        "config_path": getattr(args, "config", None),
        "timeout": float(getattr(args, "timeout", 8.0)),
        "max_js_assets": int(getattr(args, "max_js_assets", 8)),
        "max_rounds": getattr(args, "max_rounds", None),
        "use_remote_host": getattr(args, "use_remote_host", None),
        "background": "auto",
    }
    if getattr(args, "use_browser_mcp", False):
        payload["use_browser_mcp"] = True
    if getattr(args, "no_browser_mcp", False):
        payload["use_browser_mcp"] = False

    from ctf_agent.mcp_server import CTFMCPServer

    server = CTFMCPServer()
    session = server._run_ctf_session(payload)
    print_json(session)
    return 0


def _continue_session_payload(args):
    from ctf_agent.mcp_server import CTFMCPServer

    if not args.run_id and not args.workspace:
        print_json(
            {
                "status": "missing_input",
                "message": "--run-id or --workspace is required",
            }
        )
        return 1

    server = CTFMCPServer()
    payload = server._continue_ctf_session(
        {
            "run_id": args.run_id,
            "workspace": args.workspace,
            "findings_limit": int(args.findings_limit),
        }
    )
    print_json(payload)
    return 0


def _serve_web(args):
    try:
        import uvicorn
    except ImportError as exc:
        raise SystemExit('uvicorn 未安装，请先执行: python -m pip install -e ".[web]"') from exc
    except TypeError as exc:
        from ctf_agent.simple_web_console import serve_simple_console

        print(
            "当前 uvicorn 版本与 Python 3.8 不兼容，自动回退到内置本地 Web 控制台。"
        )
        serve_simple_console(
            host=args.host,
            port=int(args.port),
            config_path=args.config,
            workspace_root=args.workspace_root,
        )
        return 0

    try:
        from ctf_agent.web_app import create_app

        app = create_app(
            config_path=args.config,
            workspace_root=args.workspace_root,
        )
    except (ImportError, TypeError) as exc:
        from ctf_agent.simple_web_console import serve_simple_console

        print(
            "当前 FastAPI Web 栈不可用，自动回退到内置本地 Web 控制台: {0}".format(exc)
        )
        serve_simple_console(
            host=args.host,
            port=int(args.port),
            config_path=args.config,
            workspace_root=args.workspace_root,
        )
        return 0

    uvicorn.run(app, host=args.host, port=int(args.port), reload=bool(args.reload))
    return 0



def _serve_oob_mock(args):
    return run_oob_mock_server(
        [
            "--host",
            str(args.host),
            "--port",
            str(int(args.port)),
            "--auth-token",
            str(args.auth_token or ""),
            "--auth-header",
            str(args.auth_header or "Authorization"),
        ]
    )


def _remote_probe(args):
    service = build_service(
        config_path=args.config,
        workspace_root=args.workspace_root,
    )
    try:
        payload = service["remote_tool"].probe(args.host, timeout=float(args.timeout))
        print_json(payload)
        return 0
    finally:
        close_service(service)


def _remote_recommend(args):
    service = build_service(
        config_path=args.config,
        workspace_root=args.workspace_root,
    )
    try:
        payload = service["remote_tool"].recommend_host(
            category=args.category,
            target=args.target,
            preferred=args.preferred,
        )
        print_json(payload)
        return 0
    finally:
        close_service(service)


def _remote_python(args):
    if not args.code and not args.code_file:
        raise SystemExit("璇锋彁渚?--code 鎴?--code-file")

    code = args.code
    if args.code_file:
        code = Path(args.code_file).read_text(encoding="utf-8-sig")

    service = build_service(
        config_path=args.config,
        workspace_root=args.workspace_root,
    )
    try:
        payload = service["remote_tool"].run_python(
            args.host,
            code,
            args=list(args.arg or []),
            cwd=args.cwd,
            python_bin=args.python_bin,
            timeout=float(args.timeout),
        )
        print_json(payload)
        return 0
    finally:
        close_service(service)


def _parse_template_variables(items):
    payload = {}
    for item in list(items or []):
        if ":=" in item:
            key, raw_value = item.split(":=", 1)
            payload[key.strip()] = json.loads(raw_value)
            continue
        if "=" not in item:
            raise SystemExit("template variable must use key=value or key:=json")
        key, raw_value = item.split("=", 1)
        payload[key.strip()] = raw_value
    return payload


def _remote_template(args):
    variables = _parse_template_variables(args.var)
    service = build_service(
        config_path=args.config,
        workspace_root=args.workspace_root,
    )
    try:
        remote_workspace = None
        if args.remote_workspace:
            remote_workspace = {"workspace_root": args.remote_workspace, "artifact_dir": args.remote_workspace}
        if args.execute:
            if not args.host:
                raise SystemExit("--host is required with --execute")
            payload = service["remote_tool"].run_template(
                args.host,
                args.kind,
                filename=args.filename,
                remote_workspace=remote_workspace,
                remote_path=args.remote_path,
                cwd=args.cwd,
                python_bin=args.python_bin,
                timeout=float(args.timeout),
                **variables
            )
        else:
            payload = service["remote_tool"].render_template(
                args.kind,
                filename=args.filename,
                **variables
            )
        print_json(payload)
        return 0
    finally:
        close_service(service)


def _ida_launch(args):
    binary_path = Path(args.binary_path).expanduser().resolve()
    service = build_service(
        config_path=args.config,
        workspace_root=args.workspace_root,
    )
    try:
        payload = service["toolkit_tool"].launch_ida_live(binary_path, headless=not bool(args.gui))
        if payload.get("status") != "ok":
            print_json(payload)
            return 1

        probe = {
            "status": "skipped",
            "message": "ida-pro-mcp is not configured",
        }
        registry = service.get("mcp_registry")
        if registry and registry.has_servers():
            deadline = time.time() + max(1.0, float(args.wait))
            while time.time() < deadline:
                result = registry.call_tool_safe("ida-pro-mcp", "check_connection", arguments={}, timeout=10)
                probe_text = registry.flatten_tool_result(result.get("result") if result.get("ok") else result.get("error"))
                if result.get("ok") and "Successfully connected to IDA Pro" in probe_text:
                    probe = {
                        "status": "connected",
                        "message": probe_text,
                    }
                    break
                probe = {
                    "status": "waiting",
                    "message": probe_text or "ida-pro-mcp is still waiting for a live IDA session",
                }
                time.sleep(1.0)

        payload["connection_probe"] = probe
        print_json(payload)
        return 0 if probe.get("status") in {"connected", "skipped", "waiting"} else 1
    finally:
        close_service(service)


def _editor_export(args):
    payload = export_editor_assets(
        editor=args.editor,
        project_root=args.project_root,
        output_dir=args.output_dir,
        config_path=args.config,
        workspace_root=args.workspace_root,
        server_name=args.server_name,
    )
    print_json(payload)
    return 0


def _editor_install(args):
    payload = install_editor_integration(
        editor=args.editor,
        project_root=args.project_root,
        config_path=args.config,
        workspace_root=args.workspace_root,
        server_name=args.server_name,
        force=bool(args.force),
    )
    print_json(payload)
    return 0


def _print_task_template(args):
    payload = build_task_template_payload()
    if args.format == "json":
        print_json(payload)
        return 0
    if args.format == "quick":
        print(payload["quick_markdown"])
        return 0
    print(payload["markdown"])
    return 0


def _doctor(args):
    payload = run_self_check(
        config_path=args.config,
        workspace_root=args.workspace_root,
        include_mcp=not bool(args.skip_mcp),
        include_remote=not bool(args.skip_remote),
        include_web=not bool(args.skip_web),
        remote_timeout=float(args.remote_timeout),
        web_timeout=float(args.web_timeout),
    )
    if args.json:
        print_json(payload)
    else:
        print(format_self_check_report(payload))
    return 0 if payload.get("overall_status") in {"ok", "warn"} else 1


def _board_summary(args):
    run_payload = None
    workspace = args.workspace
    if args.run_id:
        run_payload = RUN_MANAGER.get(args.run_id)
        if not run_payload:
            raise SystemExit("run id not found: {0}".format(args.run_id))
        workspace = run_payload.get("workspace") or workspace
    if not workspace:
        raise SystemExit("either --run-id or --workspace is required")

    payload = build_board_summary(
        workspace,
        run_meta=run_payload,
        findings_limit=int(args.findings_limit),
    )
    if args.json:
        print_json(payload)
    else:
        _write_stdout(payload.get("text", ""))
    return 0


def _regress(args):
    service = build_service(
        config_path=args.config,
        workspace_root=args.workspace_root,
        timeout=float(args.timeout),
        max_js_assets=int(args.max_js_assets),
    )
    try:
        payload = run_regression_suite(
            service,
            manifest_path=args.manifest,
            cases_root=args.cases_root,
            report_dir=args.report_dir,
            category_filters=list(args.category or []),
            limit=args.limit,
            findings_limit=int(args.findings_limit),
        )
    finally:
        close_service(service)

    if args.json:
        print_json(payload)
    else:
        _write_stdout(
            "status: {0}\nreport_dir: {1}\ncase_count: {2}\nsolved_count: {3}\nunresolved_count: {4}\nfailed_count: {5}\nexpected_flag_match_count: {6}/{7}\n".format(
                payload.get("status", ""),
                payload.get("report_dir", ""),
                payload.get("case_count", 0),
                payload.get("solved_count", 0),
                payload.get("unresolved_count", 0),
                payload.get("failed_count", 0),
                payload.get("expected_flag_match_count", 0),
                payload.get("expected_flag_count", 0),
            )
        )
    return 0 if payload.get("failed_count", 0) == 0 else 1


def _regress_init(args):
    payload = scaffold_regression_corpus(args.destination)
    if args.json:
        print_json(payload)
    else:
        _write_stdout(
            "status: {0}\ndestination: {1}\ncategories: {2}\n".format(
                payload.get("status", ""),
                payload.get("destination", ""),
                ", ".join(list(payload.get("categories") or [])),
            )
        )
    return 0


def _pwn_live_smoke(args):
    service = build_service(
        config_path=args.config,
        workspace_root=args.workspace_root,
    )
    try:
        payload = run_pwn_live_smoke(
            service,
            hosts=list(args.host or []),
            report_dir=args.report_dir,
            timeout=float(args.timeout),
            bootstrap=bool(args.bootstrap),
        )
        if args.json:
            print_json(payload)
        else:
            _write_stdout(
                "status: {0}\nmessage: {1}\nreport_dir: {2}\nselected_hosts: {3}\n".format(
                    payload.get("status", ""),
                    payload.get("message", ""),
                    payload.get("report_dir", ""),
                    ", ".join(list(payload.get("selected_hosts", []))) or "none",
                )
            )
        return 0 if payload.get("status") in {"ok", "warn", "skipped"} else 1
    finally:
        close_service(service)


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "solve":
        service = build_service(
            config_path=args.config,
            workspace_root=args.workspace_root,
            timeout=float(args.timeout),
            max_js_assets=int(args.max_js_assets),
        )
        try:
            result = service["orchestrator"].solve_path(Path(args.source), auto_submit=args.submit)
            print_result(result)
        finally:
            close_service(service)
        return 0

    if args.command == "solve-web":
        return _solve_manual_payload(args, category="web")

    if args.command == "solve-ctf":
        return _solve_manual_payload(args)

    if args.command == "solve-brief":
        return _solve_brief_payload(args)

    if args.command == "auto-solve":
        return _auto_solve_payload(args)
    if args.command == "run-session":
        return _run_session_payload(args)
    if args.command == "continue-session":
        return _continue_session_payload(args)
    if args.command == "preview-task":
        return _preview_task_payload(args)

    if args.command == "mcp-list":
        service = build_service(
            config_path=args.config,
            workspace_root=args.workspace_root,
        )
        try:
            payload = {
                "servers": service["mcp_registry"].list_servers(),
                "tools": service["mcp_registry"].list_tools(server_name=args.server, refresh=args.refresh),
            }
            print_json(payload)
        finally:
            close_service(service)
        return 0

    if args.command == "mcp-call":
        service = build_service(
            config_path=args.config,
            workspace_root=args.workspace_root,
        )
        try:
            arguments = json.loads(args.arguments)
            payload = service["mcp_registry"].call_tool(
                args.server,
                args.tool,
                arguments=arguments,
                timeout=args.timeout,
            )
            print_json(payload)
        finally:
            close_service(service)
        return 0

    if args.command == "remote-probe":
        return _remote_probe(args)

    if args.command == "remote-recommend":
        return _remote_recommend(args)

    if args.command == "remote-python":
        return _remote_python(args)

    if args.command == "remote-template":
        return _remote_template(args)

    if args.command == "ida-launch":
        return _ida_launch(args)

    if args.command == "editor-export":
        return _editor_export(args)

    if args.command == "editor-install":
        return _editor_install(args)

    if args.command == "serve-web":
        return _serve_web(args)

    if args.command == "serve-oob-mock":
        return _serve_oob_mock(args)

    if args.command == "doctor":
        return _doctor(args)

    if args.command == "board-summary":
        return _board_summary(args)

    if args.command == "regress":
        return _regress(args)

    if args.command == "regress-init":
        return _regress_init(args)

    if args.command == "pwn-live-smoke":
        return _pwn_live_smoke(args)

    if args.command == "task-template":
        return _print_task_template(args)

    parser.error("Unsupported command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
