import argparse
import json
import re
import sys
import time
import traceback
from pathlib import Path

from ctf_agent.core.agent_loop import _load_session
from ctf_agent.core.board import build_board_summary, format_board_summary
from ctf_agent.core.config import load_agent_config
from ctf_agent.core.doctor import run_self_check
from ctf_agent.core.intake import IntakeService
from ctf_agent.core.models import Challenge
from ctf_agent.core.regression import run_pwn_live_smoke
from ctf_agent.core.runtime import RUN_MANAGER, build_service as _shared_build_service, close_service, run_payload
from ctf_agent.core.skill_context import resolve_skill_context
from ctf_agent.core.task_protocol import (
    TASK_PROTOCOL_VERSION,
    build_async_start_envelope,
    build_needs_input_envelope,
    build_status_envelope,
    build_sync_envelope,
    build_validation_view,
)
from ctf_agent.core.task_template import build_task_template_payload, render_task_from_fields
from ctf_agent.tools.mcp_runtime import MCPError, MCPRuntimeRegistry

SERVER_INFO = {
    "name": "ctf-agent-mcp",
    "version": "1.0.0",
}
PROTOCOL_VERSION = "2025-03-26"
DEFAULT_SERVER_CONFIG_PATH = None
DEFAULT_SERVER_WORKSPACE_ROOT = None


def _normalize_cli_path(value):
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    return path.absolute()


def _tool_result(payload):
    text = json.dumps(payload, ensure_ascii=False, indent=2)
    return {
        "content": [
            {
                "type": "text",
                "text": text,
            }
        ],
        "structuredContent": payload,
    }


def _build_service(config_path=None, workspace_root=None, timeout=8.0, max_js_assets=8):
    return _shared_build_service(
        config_path=config_path or DEFAULT_SERVER_CONFIG_PATH,
        workspace_root=workspace_root or DEFAULT_SERVER_WORKSPACE_ROOT,
        timeout=timeout,
        max_js_assets=max_js_assets,
    )


class CTFMCPServer(object):
    def __init__(self):
        self.tools = self._build_tools()

    def _build_tools(self):
        return [
            {
                "name": "run_ctf_session",
                "description": "High-level chat-session entry: preview and normalize task input first, then execute the solve flow and return a conversation-friendly wrapper.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "task": {"type": "string"},
                        "target": {"type": "string"},
                        "attachment": {"type": ["string", "array"], "items": {"type": "string"}},
                        "attachments": {"type": "array", "items": {"type": "string"}, "default": []},
                        "title": {"type": "string"},
                        "config_path": {"type": "string"},
                        "output_root": {"type": "string"},
                        "timeout": {"type": "number", "default": 8.0},
                        "max_js_assets": {"type": "integer", "default": 8},
                        "max_rounds": {"type": "integer"},
                        "use_browser_mcp": {"type": "boolean"},
                        "use_remote_host": {"type": "string"},
                        "speed_mode": {"type": "string", "enum": ["standard", "fastest"]},
                        "background": {"type": ["boolean", "string"], "default": "auto"}
                    },
                    "required": ["task"],
                },
            },
            {
                "name": "continue_ctf_session",
                "description": "High-level session poller: combine task status and board summary into one chat-friendly follow-up payload.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "run_id": {"type": "string"},
                        "workspace": {"type": "string"},
                        "findings_limit": {"type": "integer", "default": 5}
                    }
                },
            },
            {
                "name": "list_ctf_approval_requests",
                "description": "List approval requests for one run or workspace.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "run_id": {"type": "string"},
                        "workspace": {"type": "string"},
                        "status": {"type": "string"},
                    },
                },
            },
            {
                "name": "respond_ctf_approval_request",
                "description": "Approve or deny one pending approval request and optionally auto-resume the paused run.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "request_id": {"type": "string"},
                        "decision": {"type": "string", "enum": ["approve", "deny"]},
                        "scope": {"type": "string", "enum": ["once", "run", "workspace_session"]},
                        "ttl_sec": {"type": "integer"},
                        "reason": {"type": "string"},
                        "auto_resume": {"type": "boolean", "default": True},
                    },
                    "required": ["request_id", "decision"],
                },
            },
            {
                "name": "get_ctf_approval_status",
                "description": "Read the approval status snapshot for one run or workspace.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "run_id": {"type": "string"},
                        "workspace": {"type": "string"},
                    },
                },
            },
            {
                "name": "doctor_self_check",
                "description": "Run a unified self-check for Python, config, env vars, nested MCP servers, remote hosts, and the local web console.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "config_path": {"type": "string"},
                        "workspace_root": {"type": "string"},
                        "skip_mcp": {"type": "boolean", "default": False},
                        "skip_remote": {"type": "boolean", "default": False},
                        "skip_web": {"type": "boolean", "default": False},
                        "remote_timeout": {"type": "number", "default": 12.0},
                        "web_timeout": {"type": "number", "default": 15.0}
                    },
                },
            },
            {
                "name": "run_pwn_live_smoke",
                "description": "Explicitly probe selected Ubuntu pwn helpers and optionally run pwn-ubuntu-bootstrap before the final probe.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "hosts": {"type": "array", "items": {"type": "string"}, "default": []},
                        "bootstrap": {"type": "boolean", "default": False},
                        "report_dir": {"type": "string"},
                        "timeout": {"type": "number", "default": 25.0},
                        "config_path": {"type": "string"},
                        "workspace_root": {"type": "string"}
                    },
                },
            },
            {
                "name": "get_ctf_task_template",
                "description": "Return both the canonical full task template and a short chat-friendly quick template for submit_ctf_task/start_ctf_task/auto_solve_ctf.",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                },
            },
            {
                "name": "auto_solve_ctf",
                "description": "Single-entry protocol tool: accept task + optional target/attachments, including the short Type/Target/Files/Hint chat format, and choose sync or background mode internally.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "task": {"type": "string"},
                        "target": {"type": "string"},
                        "attachment": {"type": ["string", "array"], "items": {"type": "string"}},
                        "attachments": {"type": "array", "items": {"type": "string"}, "default": []},
                        "title": {"type": "string"},
                        "config_path": {"type": "string"},
                        "output_root": {"type": "string"},
                        "timeout": {"type": "number", "default": 8.0},
                        "max_js_assets": {"type": "integer", "default": 8},
                        "max_rounds": {"type": "integer"},
                        "use_browser_mcp": {"type": "boolean"},
                        "use_remote_host": {"type": "string"},
                        "speed_mode": {"type": "string", "enum": ["standard", "fastest"]},
                        "background": {"type": ["boolean", "string"], "default": "auto"}
                    },
                    "required": ["task"],
                },
            },
            {
                "name": "preview_ctf_task",
                "description": "Normalize a short task prompt into a stable draft before execution. Useful for noisy chat input or when the editor should preview routing first.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "task": {"type": "string"},
                        "target": {"type": "string"},
                        "attachment": {"type": ["string", "array"], "items": {"type": "string"}},
                        "attachments": {"type": "array", "items": {"type": "string"}, "default": []},
                        "title": {"type": "string"},
                        "config_path": {"type": "string"},
                        "output_root": {"type": "string"},
                        "timeout": {"type": "number", "default": 8.0},
                        "max_js_assets": {"type": "integer", "default": 8},
                        "max_rounds": {"type": "integer"},
                        "use_browser_mcp": {"type": "boolean"},
                        "use_remote_host": {"type": "string"},
                        "speed_mode": {"type": "string", "enum": ["standard", "fastest"]},
                        "background": {"type": ["boolean", "string"], "default": "auto"}
                    },
                    "required": ["task"],
                },
            },
            {
                "name": "submit_ctf_task",
                "description": "Task-feed protocol entry: accept only task + optional target/attachments and return a fixed summary envelope for editor plan mode.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "task": {"type": "string"},
                        "target": {"type": "string"},
                        "attachment": {"type": ["string", "array"], "items": {"type": "string"}},
                        "attachments": {"type": "array", "items": {"type": "string"}, "default": []},
                        "title": {"type": "string"},
                        "config_path": {"type": "string"},
                        "output_root": {"type": "string"},
                        "timeout": {"type": "number", "default": 8.0},
                        "max_js_assets": {"type": "integer", "default": 8},
                        "max_rounds": {"type": "integer"},
                        "use_browser_mcp": {"type": "boolean"},
                        "use_remote_host": {"type": "string"},
                        "speed_mode": {"type": "string", "enum": ["standard", "fastest"]}
                    },
                    "required": ["task"],
                },
            },
            {
                "name": "start_ctf_task",
                "description": "Async task-feed protocol entry: start a background run from task + optional target/attachments and return a polling envelope.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "task": {"type": "string"},
                        "target": {"type": "string"},
                        "attachment": {"type": ["string", "array"], "items": {"type": "string"}},
                        "attachments": {"type": "array", "items": {"type": "string"}, "default": []},
                        "title": {"type": "string"},
                        "config_path": {"type": "string"},
                        "output_root": {"type": "string"},
                        "timeout": {"type": "number", "default": 8.0},
                        "max_js_assets": {"type": "integer", "default": 8},
                        "max_rounds": {"type": "integer"},
                        "use_browser_mcp": {"type": "boolean"},
                        "use_remote_host": {"type": "string"},
                        "speed_mode": {"type": "string", "enum": ["standard", "fastest"]}
                    },
                    "required": ["task"],
                },
            },
            {
                "name": "get_ctf_task_status",
                "description": "Return a fixed task-feed summary envelope for an existing background run.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "run_id": {"type": "string"},
                    },
                    "required": ["run_id"],
                },
            },
            {
                "name": "solve_ctf",
                "description": "Run the local CTF agent from category + URL/attachments and return the final workspace/result.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "category": {"type": "string"},
                        "url": {"type": "string"},
                        "attachments": {"type": "array", "items": {"type": "string"}, "default": []},
                        "title": {"type": "string"},
                        "challenge_id": {"type": "string"},
                        "contest_id": {"type": "string"},
                        "description": {"type": "string"},
                        "flag_format": {"type": "string"},
                        "output_root": {"type": "string"},
                        "config_path": {"type": "string"},
                        "timeout": {"type": "number", "default": 8.0},
                        "max_js_assets": {"type": "integer", "default": 8},
                        "max_rounds": {"type": "integer", "default": 6},
                        "use_browser_mcp": {"type": "boolean", "default": True},
                        "use_remote_host": {"type": "string"},
                    },
                    "required": ["category"],
                },
            },
            {
                "name": "solve_ctf_brief",
                "description": "One-button CTF intake: accept a short task prompt plus optional target/attachments and infer the rest.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "task": {"type": "string"},
                        "category": {"type": "string"},
                        "target": {"type": "string"},
                        "attachments": {"type": "array", "items": {"type": "string"}, "default": []},
                        "title": {"type": "string"},
                        "hint": {"type": "string"},
                        "description": {"type": "string"},
                        "flag_format": {"type": "string"},
                        "output_root": {"type": "string"},
                        "config_path": {"type": "string"},
                        "timeout": {"type": "number", "default": 8.0},
                        "max_js_assets": {"type": "integer", "default": 8},
                        "max_rounds": {"type": "integer"},
                        "use_browser_mcp": {"type": "boolean"},
                        "use_remote_host": {"type": "string"},
                        "speed_mode": {"type": "string", "enum": ["standard", "fastest"]}
                    }
                }
            },
            {
                "name": "solve_ctf_template",
                "description": "High-level one-button template for editors: provide only category + target/attachments/hint and let the hub infer the rest.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "category": {"type": "string"},
                        "target": {"type": "string"},
                        "attachments": {"type": "array", "items": {"type": "string"}, "default": []},
                        "title": {"type": "string"},
                        "hint": {"type": "string"},
                        "description": {"type": "string"},
                        "flag_format": {"type": "string"},
                        "output_root": {"type": "string"},
                        "config_path": {"type": "string"},
                        "timeout": {"type": "number", "default": 8.0},
                        "max_js_assets": {"type": "integer", "default": 8},
                        "max_rounds": {"type": "integer"},
                        "use_browser_mcp": {"type": "boolean"},
                        "use_remote_host": {"type": "string"},
                    },
                    "required": ["category"],
                },
            },
            {
                "name": "solve_web_ctf",
                "description": "Compatibility wrapper for running the web solver against an authorized target URL.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string"},
                        "title": {"type": "string"},
                        "challenge_id": {"type": "string"},
                        "contest_id": {"type": "string"},
                        "description": {"type": "string"},
                        "attachments": {"type": "array", "items": {"type": "string"}, "default": []},
                        "flag_format": {"type": "string"},
                        "workspace_root": {"type": "string"},
                        "config_path": {"type": "string"},
                        "timeout": {"type": "number", "default": 8.0},
                        "max_js_assets": {"type": "integer", "default": 8},
                    },
                    "required": ["url"],
                },
            },
            {
                "name": "solve_json_ctf",
                "description": "Run the local CTF agent against a challenge JSON file.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "source": {"type": "string"},
                        "workspace_root": {"type": "string"},
                        "config_path": {"type": "string"},
                        "timeout": {"type": "number", "default": 8.0},
                        "max_js_assets": {"type": "integer", "default": 8},
                        "submit": {"type": "boolean", "default": False},
                    },
                    "required": ["source"],
                },
            },
            {
                "name": "start_ctf_run",
                "description": "Start a background CTF run and return a run id for polling.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "category": {"type": "string"},
                        "url": {"type": "string"},
                        "attachments": {"type": "array", "items": {"type": "string"}, "default": []},
                        "title": {"type": "string"},
                        "challenge_id": {"type": "string"},
                        "contest_id": {"type": "string"},
                        "description": {"type": "string"},
                        "flag_format": {"type": "string"},
                        "output_root": {"type": "string"},
                        "config_path": {"type": "string"},
                        "timeout": {"type": "number", "default": 8.0},
                        "max_js_assets": {"type": "integer", "default": 8},
                        "max_rounds": {"type": "integer", "default": 6},
                        "use_browser_mcp": {"type": "boolean", "default": True},
                        "use_remote_host": {"type": "string"},
                    },
                    "required": ["category"],
                },
            },
            {
                "name": "start_ctf_brief_run",
                "description": "Background version of solve_ctf_brief for editor plan/agent modes.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "task": {"type": "string"},
                        "category": {"type": "string"},
                        "target": {"type": "string"},
                        "attachments": {"type": "array", "items": {"type": "string"}, "default": []},
                        "title": {"type": "string"},
                        "hint": {"type": "string"},
                        "description": {"type": "string"},
                        "flag_format": {"type": "string"},
                        "output_root": {"type": "string"},
                        "config_path": {"type": "string"},
                        "timeout": {"type": "number", "default": 8.0},
                        "max_js_assets": {"type": "integer", "default": 8},
                        "max_rounds": {"type": "integer"},
                        "use_browser_mcp": {"type": "boolean"},
                        "use_remote_host": {"type": "string"},
                        "speed_mode": {"type": "string", "enum": ["standard", "fastest"]}
                    }
                }
            },
            {
                "name": "start_ctf_template_run",
                "description": "Background version of solve_ctf_template for editor plan/agent modes.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "category": {"type": "string"},
                        "target": {"type": "string"},
                        "attachments": {"type": "array", "items": {"type": "string"}, "default": []},
                        "title": {"type": "string"},
                        "hint": {"type": "string"},
                        "description": {"type": "string"},
                        "flag_format": {"type": "string"},
                        "output_root": {"type": "string"},
                        "config_path": {"type": "string"},
                        "timeout": {"type": "number", "default": 8.0},
                        "max_js_assets": {"type": "integer", "default": 8},
                        "max_rounds": {"type": "integer"},
                        "use_browser_mcp": {"type": "boolean"},
                        "use_remote_host": {"type": "string"},
                    },
                    "required": ["category"],
                },
            },
            {
                "name": "get_ctf_run_status",
                "description": "Get the latest status for a background CTF run.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "run_id": {"type": "string"},
                    },
                    "required": ["run_id"],
                },
            },
            {
                "name": "cancel_ctf_run",
                "description": "Request cancellation for a background CTF run.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "run_id": {"type": "string"},
                    },
                    "required": ["run_id"],
                },
            },
            {
                "name": "read_ctf_run_artifact",
                "description": "Read one artifact relative to a background run workspace.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "run_id": {"type": "string"},
                        "path": {"type": "string"},
                        "limit_bytes": {"type": "integer", "default": 200000},
                    },
                    "required": ["run_id", "path"],
                },
            },
            {
                "name": "get_ctf_board_summary",
                "description": "Return a compact chat-friendly summary derived from triage_board.json, task_protocol_summary.json, and run state.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "run_id": {"type": "string"},
                        "workspace": {"type": "string"},
                        "findings_limit": {"type": "integer", "default": 5}
                    },
                },
            },
            {
                "name": "browse_target",
                "description": "Use browser MCP when available, otherwise perform a lightweight HTTP browse summary.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string"},
                        "task": {"type": "string"},
                        "config_path": {"type": "string"},
                        "timeout": {"type": "number", "default": 8.0},
                    },
                    "required": ["url"],
                },
            },
            {
                "name": "analyze_with_ida",
                "description": "Run a reverse-analysis task through the preferred IDA MCP server.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "binary_path": {"type": "string"},
                        "task": {"type": "string"},
                        "config_path": {"type": "string"},
                        "timeout": {"type": "number", "default": 25.0},
                    },
                    "required": ["binary_path"],
                },
            },
            {
                "name": "analyze_with_ghidra",
                "description": "Run a reverse-analysis task through the preferred Ghidra MCP server.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "binary_path": {"type": "string"},
                        "task": {"type": "string"},
                        "config_path": {"type": "string"},
                        "timeout": {"type": "number", "default": 25.0},
                    },
                    "required": ["binary_path"],
                },
            },
            {
                "name": "list_local_tools",
                "description": "List tools discovered under the configured local CTF toolkit root.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "config_path": {"type": "string"},
                    },
                },
            },
            {
                "name": "run_local_tool",
                "description": "Run one named toolkit tool or an explicit local executable path.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "tool": {"type": "string"},
                        "path": {"type": "string"},
                        "args": {"type": "array", "items": {"type": "string"}, "default": []},
                        "cwd": {"type": "string"},
                        "timeout": {"type": "number", "default": 120.0},
                        "config_path": {"type": "string"},
                    },
                },
            },
            {
                "name": "list_remote_hosts",
                "description": "List remote helper hosts configured in local_config.json.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "config_path": {"type": "string"},
                    },
                },
            },
            {
                "name": "recommend_remote_host",
                "description": "Return the best remote helper host for a category/target pair, plus ranking reasons.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "category": {"type": "string"},
                        "target": {"type": "string"},
                        "preferred": {"type": "string"},
                        "config_path": {"type": "string"},
                    },
                },
            },
            {
                "name": "run_remote_command",
                "description": "Run one command on a configured remote helper host.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "host": {"type": "string"},
                        "command": {"type": "string"},
                        "timeout": {"type": "number", "default": 30.0},
                        "config_path": {"type": "string"},
                    },
                    "required": ["host", "command"],
                },
            },
            {
                "name": "probe_remote_host",
                "description": "Probe one configured remote helper host and return environment details.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "host": {"type": "string"},
                        "timeout": {"type": "number", "default": 20.0},
                        "config_path": {"type": "string"},
                    },
                    "required": ["host"],
                },
            },
            {
                "name": "ensure_remote_workspace",
                "description": "Create or reuse a structured remote workspace on a helper host.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "host": {"type": "string"},
                        "run_id": {"type": "string"},
                        "remote_dir": {"type": "string"},
                        "timeout": {"type": "number", "default": 30.0},
                        "config_path": {"type": "string"},
                    },
                    "required": ["host"],
                },
            },
            {
                "name": "run_remote_python",
                "description": "Run inline Python on a configured remote helper host.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "host": {"type": "string"},
                        "code": {"type": "string"},
                        "args": {"type": "array", "items": {"type": "string"}, "default": []},
                        "cwd": {"type": "string"},
                        "env": {"type": "object", "additionalProperties": {"type": "string"}},
                        "python_bin": {"type": "string"},
                        "timeout": {"type": "number", "default": 120.0},
                        "config_path": {"type": "string"},
                    },
                    "required": ["host", "code"],
                },
            },
            {
                "name": "upload_remote_file",
                "description": "Upload one local file to a configured remote helper host.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "host": {"type": "string"},
                        "local_path": {"type": "string"},
                        "remote_path": {"type": "string"},
                        "timeout": {"type": "number", "default": 45.0},
                        "config_path": {"type": "string"},
                    },
                    "required": ["host", "local_path"],
                },
            },
            {
                "name": "upload_remote_text",
                "description": "Upload inline text content to a configured remote helper host.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "host": {"type": "string"},
                        "content": {"type": "string"},
                        "remote_path": {"type": "string"},
                        "timeout": {"type": "number", "default": 30.0},
                        "config_path": {"type": "string"},
                    },
                    "required": ["host", "content"],
                },
            },
            {
                "name": "download_remote_file",
                "description": "Download one remote file from a configured helper host.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "host": {"type": "string"},
                        "remote_path": {"type": "string"},
                        "local_path": {"type": "string"},
                        "timeout": {"type": "number", "default": 45.0},
                        "config_path": {"type": "string"},
                    },
                    "required": ["host", "remote_path", "local_path"],
                },
            },
            {
                "name": "render_remote_template",
                "description": "Render one reusable remote helper template locally without executing it.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "template_kind": {"type": "string"},
                        "filename": {"type": "string"},
                        "variables": {"type": "object", "default": {}},
                        "config_path": {"type": "string"},
                    },
                    "required": ["template_kind"],
                },
            },
            {
                "name": "run_remote_template",
                "description": "Render, stage, and optionally execute one remote helper template on a configured host.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "host": {"type": "string"},
                        "template_kind": {"type": "string"},
                        "filename": {"type": "string"},
                        "variables": {"type": "object", "default": {}},
                        "remote_workspace": {"type": "object"},
                        "remote_path": {"type": "string"},
                        "cwd": {"type": "string"},
                        "env": {"type": "object", "additionalProperties": {"type": "string"}},
                        "python_bin": {"type": "string"},
                        "timeout": {"type": "number", "default": 120.0},
                        "config_path": {"type": "string"},
                    },
                    "required": ["host", "template_kind"],
                },
            },
            {
                "name": "list_nested_mcp_servers",
                "description": "List nested MCP servers configured in local_config.json.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "config_path": {"type": "string"},
                    },
                },
            },
            {
                "name": "list_nested_mcp_tools",
                "description": "List tools from nested MCP servers configured for the local CTF agent.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "config_path": {"type": "string"},
                        "server": {"type": "string"},
                        "refresh": {"type": "boolean", "default": False},
                    },
                },
            },
            {
                "name": "call_nested_mcp_tool",
                "description": "Proxy one call into a nested MCP server such as IDA, Ghidra, or browser-use.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "config_path": {"type": "string"},
                        "server": {"type": "string"},
                        "tool": {"type": "string"},
                        "arguments": {"type": "object", "default": {}},
                        "timeout": {"type": "number"},
                    },
                    "required": ["server", "tool"],
                },
            },
            {
                "name": "search_ctf_knowledge",
                "description": "Search the CTF knowledge base (curated playbooks + personal wiki writeups) using BM25 retrieval. Use this to find techniques, tool usage, exploit patterns, or prior CTF writeup experience before solving a challenge.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Search query in Chinese or English"},
                        "category": {"type": "string", "description": "CTF category hint: pwn/web/reverse/misc/crypto/forensics/osint/malware"},
                        "source": {"type": "string", "enum": ["skills", "wiki"], "description": "Limit to one source: 'skills' for playbooks, 'wiki' for personal writeups (default: search both)"},
                        "top_k": {"type": "integer", "default": 5, "description": "Number of results to return"},
                        "config_path": {"type": "string"},
                    },
                    "required": ["query"],
                },
            },
            {
                "name": "run_ctf_code",
                "description": "Execute a Python script in a sandboxed subprocess and return stdout/stderr. Use this for decoding, cryptanalysis, data processing, exploit scripting, or any computation needed to solve a CTF challenge.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "description": "Python source code to execute"},
                        "description": {"type": "string", "description": "Brief description of what the code does"},
                        "timeout": {"type": "integer", "default": 30, "description": "Execution timeout in seconds"},
                        "workspace": {"type": "string", "description": "Workspace path to save artifacts (optional)"},
                        "config_path": {"type": "string"},
                    },
                    "required": ["code"],
                },
            },
            {
                "name": "scan_ctf_flags",
                "description": "Scan text for CTF flags matching common patterns (flag{...}, FLAG{...}, ctf{...}, aliyunctf{...}). Use after decoding, extracting, or receiving output to check if a flag is present.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "text": {"type": "string", "description": "Text to scan for flags"},
                    },
                    "required": ["text"],
                },
            },
            {
                "name": "continue_ctf_solve",
                "description": "Resume a paused AI agent solve session with a user hint. The session must have been previously started via run_ctf_session or auto_solve_ctf with ai_solver enabled.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "workspace": {"type": "string", "description": "Workspace path of the paused session"},
                        "hint": {"type": "string", "description": "User hint or new direction to try"},
                        "config_path": {"type": "string"},
                    },
                    "required": ["workspace"],
                },
            },
            {
                "name": "get_agent_session_info",
                "description": "Get summary info about a saved AI agent session without resuming it.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "workspace": {"type": "string", "description": "Workspace path"},
                    },
                    "required": ["workspace"],
                },
            },
        ]

    def serve(self):
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
                self._handle_message(message)
            except Exception as exc:
                self._send_error(None, -32000, str(exc), traceback.format_exc())

    def _handle_message(self, message):
        method = message.get("method")
        request_id = message.get("id")

        if method == "initialize":
            self._send(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "protocolVersion": PROTOCOL_VERSION,
                        "capabilities": {"tools": {}},
                        "serverInfo": SERVER_INFO,
                    },
                }
            )
            return

        if method == "notifications/initialized":
            return

        if method == "tools/list":
            self._send({"jsonrpc": "2.0", "id": request_id, "result": {"tools": self.tools}})
            return

        if method == "tools/call":
            params = message.get("params", {})
            tool_name = params.get("name")
            arguments = params.get("arguments", {})
            try:
                result = self._dispatch_tool(tool_name, arguments)
                self._send({"jsonrpc": "2.0", "id": request_id, "result": _tool_result(result)})
            except Exception as exc:
                self._send_error(request_id, -32001, str(exc), traceback.format_exc())
            return

        self._send_error(request_id, -32601, "Unknown method: {0}".format(method), "")

    def _dispatch_tool(self, tool_name, arguments):
        if tool_name == "doctor_self_check":
            return self._doctor_self_check(arguments)
        if tool_name == "run_pwn_live_smoke":
            return self._run_pwn_live_smoke(arguments)
        if tool_name == "run_ctf_session":
            return self._run_ctf_session(arguments)
        if tool_name == "continue_ctf_session":
            return self._continue_ctf_session(arguments)
        if tool_name == "list_ctf_approval_requests":
            return self._list_ctf_approval_requests(arguments)
        if tool_name == "respond_ctf_approval_request":
            return self._respond_ctf_approval_request(arguments)
        if tool_name == "get_ctf_approval_status":
            return self._get_ctf_approval_status(arguments)
        if tool_name == "get_ctf_task_template":
            return self._get_ctf_task_template(arguments)
        if tool_name == "preview_ctf_task":
            return self._preview_ctf_task(arguments)
        if tool_name == "auto_solve_ctf":
            return self._auto_solve_ctf(arguments)
        if tool_name == "solve_ctf":
            return self._solve_ctf(arguments)
        if tool_name == "submit_ctf_task":
            return self._submit_ctf_task(arguments)
        if tool_name == "start_ctf_task":
            return self._start_ctf_task(arguments)
        if tool_name == "get_ctf_task_status":
            return self._get_ctf_task_status(arguments)
        if tool_name == "solve_ctf_brief":
            return self._solve_ctf_brief(arguments)
        if tool_name == "solve_ctf_template":
            return self._solve_ctf_template(arguments)
        if tool_name == "solve_web_ctf":
            arguments = dict(arguments or {})
            arguments["category"] = "web"
            arguments["attachments"] = arguments.get("attachments", [])
            arguments["output_root"] = arguments.get("workspace_root")
            return self._solve_ctf(arguments)
        if tool_name == "solve_json_ctf":
            return self._solve_json(arguments)
        if tool_name == "start_ctf_run":
            return self._start_ctf_run(arguments)
        if tool_name == "start_ctf_brief_run":
            return self._start_ctf_brief_run(arguments)
        if tool_name == "start_ctf_template_run":
            return self._start_ctf_template_run(arguments)
        if tool_name == "get_ctf_run_status":
            return self._get_ctf_run_status(arguments)
        if tool_name == "cancel_ctf_run":
            return self._cancel_ctf_run(arguments)
        if tool_name == "read_ctf_run_artifact":
            return self._read_ctf_run_artifact(arguments)
        if tool_name == "get_ctf_board_summary":
            return self._get_ctf_board_summary(arguments)
        if tool_name == "browse_target":
            return self._browse_target(arguments)
        if tool_name == "analyze_with_ida":
            return self._analyze_with_reverse(arguments, server_keyword="ida")
        if tool_name == "analyze_with_ghidra":
            return self._analyze_with_reverse(arguments, server_keyword="ghidra")
        if tool_name == "list_local_tools":
            return self._list_local_tools(arguments)
        if tool_name == "run_local_tool":
            return self._run_local_tool(arguments)
        if tool_name == "list_remote_hosts":
            return self._list_remote_hosts(arguments)
        if tool_name == "recommend_remote_host":
            return self._recommend_remote_host(arguments)
        if tool_name == "run_remote_command":
            return self._run_remote_command(arguments)
        if tool_name == "probe_remote_host":
            return self._probe_remote_host(arguments)
        if tool_name == "ensure_remote_workspace":
            return self._ensure_remote_workspace(arguments)
        if tool_name == "run_remote_python":
            return self._run_remote_python(arguments)
        if tool_name == "upload_remote_file":
            return self._upload_remote_file(arguments)
        if tool_name == "upload_remote_text":
            return self._upload_remote_text(arguments)
        if tool_name == "download_remote_file":
            return self._download_remote_file(arguments)
        if tool_name == "render_remote_template":
            return self._render_remote_template(arguments)
        if tool_name == "run_remote_template":
            return self._run_remote_template(arguments)
        if tool_name == "list_nested_mcp_servers":
            return self._list_nested_servers(arguments)
        if tool_name == "list_nested_mcp_tools":
            return self._list_nested_tools(arguments)
        if tool_name == "call_nested_mcp_tool":
            return self._call_nested_tool(arguments)
        if tool_name == "search_ctf_knowledge":
            return self._search_ctf_knowledge(arguments)
        if tool_name == "run_ctf_code":
            return self._run_ctf_code(arguments)
        if tool_name == "scan_ctf_flags":
            return self._scan_ctf_flags(arguments)
        if tool_name == "continue_ctf_solve":
            return self._continue_ctf_solve(arguments)
        if tool_name == "get_agent_session_info":
            return self._get_agent_session_info(arguments)
        raise ValueError("Unknown tool: {0}".format(tool_name))

    def _doctor_self_check(self, arguments):
        return run_self_check(
            config_path=arguments.get("config_path"),
            workspace_root=arguments.get("workspace_root"),
            include_mcp=not bool(arguments.get("skip_mcp", False)),
            include_remote=not bool(arguments.get("skip_remote", False)),
            include_web=not bool(arguments.get("skip_web", False)),
            remote_timeout=float(arguments.get("remote_timeout", 12.0)),
            web_timeout=float(arguments.get("web_timeout", 15.0)),
        )

    def _run_pwn_live_smoke(self, arguments):
        service = _build_service(
            config_path=arguments.get("config_path"),
            workspace_root=arguments.get("workspace_root"),
        )
        try:
            return run_pwn_live_smoke(
                service,
                hosts=list(arguments.get("hosts") or []),
                report_dir=arguments.get("report_dir"),
                timeout=float(arguments.get("timeout", 25.0)),
                bootstrap=bool(arguments.get("bootstrap", False)),
            )
        finally:
            close_service(service)

    def _normalize_arguments(self, arguments):
        arguments = dict(arguments or {})
        service = _build_service(
            config_path=arguments.get("config_path"),
            workspace_root=arguments.get("output_root") or arguments.get("workspace_root"),
            timeout=float(arguments.get("timeout", 8.0)),
            max_js_assets=int(arguments.get("max_js_assets", 8)),
        )
        try:
            intake = IntakeService(service["config"], service["workspace_dir"])
            return intake.normalize(arguments)
        finally:
            close_service(service)

    def _normalize_brief_arguments(self, arguments):
        arguments = dict(arguments or {})
        service = _build_service(
            config_path=arguments.get("config_path"),
            workspace_root=arguments.get("output_root") or arguments.get("workspace_root"),
            timeout=float(arguments.get("timeout", 8.0)),
            max_js_assets=int(arguments.get("max_js_assets", 8)),
        )
        try:
            intake = IntakeService(service["config"], service["workspace_dir"])
            return intake.normalize_brief(arguments)
        finally:
            close_service(service)

    def _prepare_brief_request(self, arguments):
        resolved = self._normalize_brief_arguments(arguments)
        background_policy = self._resolve_background_policy(arguments, resolved)
        resolved["background_policy"] = background_policy
        validation = build_validation_view(resolved)
        return resolved, background_policy, validation

    def _dispatch_brief_request(self, task, resolved, background_policy):
        background = background_policy.get("effective_mode") == "async"
        if background:
            category = (resolved.get("category") or "web").strip().lower()

            def runner(run_id, cancel_event):
                return self._run_solve_payload(resolved, run_id=run_id, cancel_event=cancel_event)

            payload = RUN_MANAGER.start(category, dict(resolved or {}), runner)
            return build_async_start_envelope(task, resolved, payload)

        result = self._run_solve_payload(resolved)
        return build_sync_envelope(task, resolved, result)

    def _solve_ctf(self, arguments):
        resolved = self._normalize_arguments(arguments)
        return self._run_solve_payload(resolved)

    def _submit_ctf_task(self, arguments):
        resolved, _, validation = self._prepare_brief_request(arguments)
        if not validation.get("ok", False):
            return build_needs_input_envelope(arguments.get("task", ""), resolved, validation, mode="sync")
        result = self._run_solve_payload(resolved)
        return build_sync_envelope(arguments.get("task", ""), resolved, result)

    def _get_ctf_task_template(self, arguments):
        return build_task_template_payload()

    def _run_ctf_session(self, arguments):
        resolved, background_policy, validation = self._prepare_brief_request(arguments)
        speed_mode = str(resolved.get("speed_mode") or "standard").strip().lower()
        speed_profile = dict(resolved.get("speed_profile") or {})
        skip_preview = speed_mode == "fastest" and bool(speed_profile.get("skip_preview", True))
        preview = self._build_preview_payload(arguments, resolved, background_policy, validation)
        if not validation.get("ok", False):
            return {
                "protocol": {
                    "name": "ctf-session",
                    "version": "2026-03-22",
                },
                "mode": "session",
                "status": "needs_input",
                "preview": preview,
                "solve": {},
                "board_summary": {},
                "next_step_tools": ["preview_ctf_task", "run_ctf_session"],
            }

        if skip_preview:
            solve = self._dispatch_brief_request(arguments.get("task", ""), resolved, background_policy)
        else:
            solve_arguments = {
                "task": (preview.get("suggested_task") or {}).get("quick_markdown") or arguments.get("task", ""),
                "target": resolved.get("target") or "",
                "attachments": list(resolved.get("attachments") or []),
                "title": resolved.get("title") or arguments.get("title"),
                "config_path": arguments.get("config_path"),
                "output_root": arguments.get("output_root"),
                "timeout": arguments.get("timeout", 8.0),
                "max_js_assets": arguments.get("max_js_assets", 8),
                "max_rounds": resolved.get("max_rounds"),
                "use_browser_mcp": resolved.get("use_browser_mcp"),
                "use_remote_host": resolved.get("use_remote_host"),
                "speed_mode": resolved.get("speed_mode"),
                "background": arguments.get("background", "auto"),
            }
            solve = self._auto_solve_ctf(solve_arguments)
        board_summary = {}
        workspace = (((solve.get("artifacts") or {}).get("workspace")) or "")
        run_id = (((solve.get("polling") or {}).get("run_id")) or "")
        if workspace:
            board_summary = build_board_summary(workspace)
        elif run_id:
            try:
                board_summary = self._get_ctf_board_summary({"run_id": run_id})
            except Exception:
                board_summary = {}
        if not board_summary or board_summary.get("status") == "missing_input":
            normalized = dict(preview.get("normalized") or {})
            routing = dict(preview.get("routing") or {})
            solve_execution = dict(solve.get("execution") or {})
            headline = "会话已启动，优先轮询状态并在产物落盘后读取答题板。"
            if solve_execution.get("status") == "needs_input":
                headline = "输入不足，先根据 validation.errors 补齐目标或附件。"
            board_summary = {
                "run_id": run_id,
                "workspace": workspace,
                "title": normalized.get("title", ""),
                "category": normalized.get("category", ""),
                "status": solve_execution.get("status", ""),
                "solver": solve_execution.get("solver", ""),
                "target": normalized.get("target", ""),
                "headline": headline,
                "flag_found": bool(solve_execution.get("flag")),
                "flag": solve_execution.get("flag", ""),
                "wp_exported": bool(solve_execution.get("wp_exported", False)),
                "wp_package_path": solve_execution.get("wp_package_path", ""),
                "wp_root": solve_execution.get("wp_root", ""),
                "wp_warning": solve_execution.get("wp_warning", ""),
                "flag_first_text": solve_execution.get("flag_first_text", ""),
                "recommended_path": "",
                "selected_remote_host": routing.get("selected_remote_host", ""),
                "autopilot_summary": routing.get("autopilot_summary", ""),
                "dispatch_mode": routing.get("dispatch_mode", ""),
                "dispatch_reason": routing.get("dispatch_reason", ""),
                "next_actions": [
                    "调用 get_ctf_task_status 轮询运行状态。",
                    "运行稳定后调用 get_ctf_board_summary 获取聊天摘要。",
                ],
                "blockers": list((preview.get("validation") or {}).get("errors", []))[:5],
                "recommended_tools": list(routing.get("recommended_tools", []))[:8],
                "recommended_mcp": list(routing.get("recommended_mcp", []))[:8],
                "knowledge": {
                    "selected_skill_category": routing.get("selected_skill_category", ""),
                    "pack_name": routing.get("pack_name", ""),
                    "top_tactics": list(routing.get("top_tactics", []))[:5],
                    "reference_docs": list(routing.get("reference_docs", []))[:5],
                    "category_confidence": routing.get("category_confidence", 0.0),
                },
                "subagents": [],
                "mcp_status": {
                    "available_servers": [],
                    "connected_servers": [],
                    "resource_enabled_servers": [],
                    "failed_servers": [],
                    "fallback_reasons": [],
                    "counts": {"pending": 0, "connected": 0, "failed": 0, "disabled": 0},
                    "servers": [],
                },
                "recent_mcp_calls": [],
                "recent_actions": [],
                "recent_activity": [],
                "resource_enabled_servers": [],
                "counts": {
                    "findings": 0,
                    "candidate_flags": 0,
                    "exploit_plans": 0,
                    "artifacts": 0,
                },
                "findings_digest": [],
            }
            board_summary["text"] = format_board_summary(board_summary)

        return {
            "protocol": {
                "name": "ctf-session",
                "version": "2026-03-22",
            },
            "mode": "session",
            "status": ((solve.get("execution") or {}).get("status")) or "running",
            "preview": preview,
            "solve": solve,
            "board_summary": board_summary,
            "next_step_tools": ["continue_ctf_session", "read_ctf_run_artifact"],
        }

    def _continue_ctf_session(self, arguments):
        run_id = str(arguments.get("run_id") or "").strip()
        workspace = str(arguments.get("workspace") or "").strip()
        if not run_id and not workspace:
            return {
                "protocol": {
                    "name": "ctf-session",
                    "version": "2026-03-22",
                },
                "mode": "continue",
                "status": "missing_input",
                "status_view": {
                    "execution": {"status": "missing_input", "run_id": "", "workspace": ""},
                    "validation": {
                        "ok": False,
                        "errors": ["run_id or workspace is required"],
                        "warnings": [],
                        "next_actions": ["Provide the run_id returned by run_ctf_session, or point to an existing workspace."],
                    },
                },
                "board_summary": {},
                "next_step_tools": ["run_ctf_session"],
            }

        run_payload = RUN_MANAGER.get(run_id)
        status_view = None
        if run_id:
            status_view = self._get_ctf_task_status({"run_id": run_id})
        else:
            status_view = {
                "protocol": {"name": "ctf-task-feed", "version": TASK_PROTOCOL_VERSION},
                "mode": "status",
                "execution": {"status": "", "run_id": "", "workspace": workspace},
                "validation": {"ok": True, "errors": [], "warnings": [], "next_actions": []},
                "summary": {"headline": "", "status": ""},
            }
        execution = dict(status_view.get("execution") or {})
        workspace = (
            workspace
            or execution.get("workspace", "")
            or str((status_view.get("artifacts") or {}).get("workspace") or "").strip()
        )

        missing_run = execution.get("status") == "missing"

        board_summary = {}
        if workspace:
            board_summary = build_board_summary(
                workspace,
                run_meta=run_payload,
                findings_limit=int(arguments.get("findings_limit", 5)),
            )
        elif run_payload:
            try:
                board_summary = self._get_ctf_board_summary(
                    {
                        "run_id": run_id,
                        "findings_limit": int(arguments.get("findings_limit", 5)),
                    }
                )
            except Exception:
                board_summary = {}

        if (missing_run or not run_id) and board_summary:
            execution_status = board_summary.get("status", "") or "recovered"
            status_view = {
                "protocol": {"name": "ctf-task-feed", "version": TASK_PROTOCOL_VERSION},
                "mode": "status",
                "execution": {
                    "status": execution_status,
                    "run_id": run_id,
                    "workspace": workspace,
                    "solver": board_summary.get("solver", ""),
                    "flag": board_summary.get("flag", ""),
                    "wp_exported": bool(board_summary.get("wp_exported", False)),
                    "wp_package_path": board_summary.get("wp_package_path", ""),
                    "wp_root": board_summary.get("wp_root", ""),
                    "wp_warning": board_summary.get("wp_warning", ""),
                    "flag_first_text": board_summary.get("flag_first_text", ""),
                    "error": "",
                },
                "validation": {"ok": True, "errors": [], "warnings": ["Recovered session from workspace artifacts."], "next_actions": []},
                "summary": {
                    "headline": board_summary.get("headline", ""),
                    "status": execution_status,
                    "flag": board_summary.get("flag", ""),
                    "wp_exported": bool(board_summary.get("wp_exported", False)),
                    "wp_package_path": board_summary.get("wp_package_path", ""),
                    "wp_root": board_summary.get("wp_root", ""),
                    "wp_warning": board_summary.get("wp_warning", ""),
                    "flag_first_text": board_summary.get("flag_first_text", ""),
                },
            }

        execution_status = dict(status_view.get("execution") or {}).get("status", "")
        if execution_status == "needs_approval":
            next_step_tools = ["list_ctf_approval_requests", "respond_ctf_approval_request", "get_ctf_approval_status"]
        elif execution_status in {"solved", "unresolved", "failed", "cancelled"}:
            next_step_tools = ["get_ctf_board_summary", "read_ctf_run_artifact"]
        elif execution_status in {"missing", "missing_input", "needs_input"}:
            next_step_tools = ["preview_ctf_task", "run_ctf_session"]
        else:
            next_step_tools = ["continue_ctf_session", "read_ctf_run_artifact", "cancel_ctf_run"]

        return {
            "protocol": {
                "name": "ctf-session",
                "version": "2026-03-22",
            },
            "mode": "continue",
            "status": execution_status or "running",
            "run_id": run_id,
            "status_view": status_view,
            "board_summary": board_summary,
            "subagents": list((board_summary or {}).get("subagents", [])),
            "remote_subagents": list((board_summary or {}).get("remote_subagents", [])),
            "mcp_status": dict((board_summary or {}).get("mcp_status", {})),
            "approval_status": dict((board_summary or {}).get("approval_status", {})),
            "plugin_status": dict((board_summary or {}).get("plugin_status", {})),
            "recent_activity": list((board_summary or {}).get("recent_activity", []))[:5],
            "next_step_tools": next_step_tools,
        }

    def _resolve_workspace_from_run(self, run_id="", workspace=""):
        run_id = str(run_id or "").strip()
        workspace = str(workspace or "").strip()
        run_payload = RUN_MANAGER.get(run_id) if run_id else None
        if run_payload and not workspace:
            workspace = str(run_payload.get("workspace", "") or "").strip()
        return run_payload, workspace

    def _load_challenge_from_session(self, workspace):
        session = _load_session(workspace)
        if not session:
            return None
        challenge_payload = dict(session.get("challenge") or {})
        return Challenge(
            contest_id=challenge_payload.get("contest_id", ""),
            challenge_id=challenge_payload.get("challenge_id", ""),
            title=challenge_payload.get("title", ""),
            category=challenge_payload.get("category", ""),
            description=challenge_payload.get("description", ""),
            attachments=[Path(item) for item in list(challenge_payload.get("attachments", []) or [])],
            target=challenge_payload.get("target"),
            flag_format=challenge_payload.get("flag_format"),
            metadata=dict(challenge_payload.get("metadata") or {}),
        )

    def _resume_paused_run(self, resolved, run_id=None, cancel_event=None):
        resolved = dict(resolved or {})
        output_root = resolved.get("output_root") or resolved.get("workspace_root")
        service = _build_service(
            config_path=resolved.get("config_path"),
            workspace_root=output_root,
            timeout=float(resolved.get("timeout", 8.0)),
            max_js_assets=int(resolved.get("max_js_assets", 8)),
        )
        try:
            workspace = ""
            if run_id:
                run_payload = RUN_MANAGER.get(run_id) or {}
                workspace = str(run_payload.get("workspace", "") or "").strip()
            workspace = workspace or str(resolved.get("workspace", "") or "").strip()
            if not workspace:
                return {"status": "missing_workspace", "run_id": run_id or "", "message": "workspace is required to resume"}
            challenge = self._load_challenge_from_session(workspace)
            if challenge is None:
                return {"status": "missing_session", "run_id": run_id or "", "workspace": workspace, "message": "agent_session.json not found"}
            if run_id:
                challenge.metadata["run_id"] = run_id
            if cancel_event is not None:
                challenge.metadata["cancel_event"] = cancel_event
            agent_loop = service.get("agent_loop")
            if not agent_loop:
                return {"status": "missing_agent_loop", "run_id": run_id or "", "workspace": workspace}
            state = agent_loop.continue_solve(workspace, challenge=challenge)
            best_flag = service["verifier"].choose_best(state, challenge)
            service["workspace_manager"].save_state(workspace, state)
            result = {
                "status": "solved" if best_flag else state.phase,
                "workspace": str(workspace),
                "solver": "agent-loop",
                "state_path": str(Path(workspace) / "state.json"),
                "notes_path": str(Path(workspace) / "agent_loop_notes.md"),
                "solution_path": str(Path(workspace) / "artifacts" / "solution_generated.py"),
                "agent_loop_stats": agent_loop.llm.stats,
            }
            if state.phase == "needs_approval":
                result["status"] = "needs_approval"
            if best_flag:
                result["flag"] = best_flag.value
            return result
        finally:
            close_service(service)

    def _list_ctf_approval_requests(self, arguments):
        run_payload, workspace = self._resolve_workspace_from_run(arguments.get("run_id"), arguments.get("workspace"))
        if not workspace:
            return {"status": "missing_input", "message": "run_id or workspace is required"}
        service = _build_service(
            config_path=arguments.get("config_path"),
            workspace_root=Path(workspace).parent.parent if Path(workspace).parent.parent.exists() else None,
        )
        try:
            approval_manager = service["approval_manager"].configure(
                workspace=workspace,
                run_id=str((run_payload or {}).get("run_id", "") or ""),
            )
            return {
                "workspace": workspace,
                "run_id": str((run_payload or {}).get("run_id", "") or ""),
                "requests": approval_manager.list_requests(
                    workspace=workspace,
                    run_id=str((run_payload or {}).get("run_id", "") or ""),
                    status=arguments.get("status"),
                ),
                "approval_status": approval_manager.get_status(
                    workspace=workspace,
                    run_id=str((run_payload or {}).get("run_id", "") or ""),
                ),
            }
        finally:
            close_service(service)

    def _get_ctf_approval_status(self, arguments):
        run_payload, workspace = self._resolve_workspace_from_run(arguments.get("run_id"), arguments.get("workspace"))
        if not workspace:
            return {"status": "missing_input", "message": "run_id or workspace is required"}
        service = _build_service(
            config_path=arguments.get("config_path"),
            workspace_root=Path(workspace).parent.parent if Path(workspace).parent.parent.exists() else None,
        )
        try:
            approval_manager = service["approval_manager"].configure(
                workspace=workspace,
                run_id=str((run_payload or {}).get("run_id", "") or ""),
            )
            return approval_manager.get_status(
                workspace=workspace,
                run_id=str((run_payload or {}).get("run_id", "") or ""),
            )
        finally:
            close_service(service)

    def _respond_ctf_approval_request(self, arguments):
        request_id = str(arguments.get("request_id") or "").strip()
        if not request_id:
            return {"status": "missing_input", "message": "request_id is required"}
        service = _build_service(
            config_path=arguments.get("config_path"),
            workspace_root=arguments.get("workspace_root"),
        )
        try:
            approval_manager = service["approval_manager"]
            request = None
            for run in RUN_MANAGER.list_runs():
                workspace = str(run.get("workspace", "") or "").strip()
                if not workspace:
                    continue
                approval_manager.configure(workspace=workspace, run_id=str(run.get("run_id", "") or ""))
                request = approval_manager.get_request(request_id, workspace=workspace)
                if request:
                    break
            if request is None:
                for requests_path in Path(service["workspace_dir"]).rglob("requests.jsonl"):
                    workspace = str(requests_path.parent.parent)
                    approval_manager.configure(workspace=workspace, run_id="")
                    request = approval_manager.get_request(request_id, workspace=workspace)
                    if request:
                        break
            if request is None:
                return {"status": "missing", "request_id": request_id}

            approval_manager.configure(workspace=request.workspace, run_id=request.run_id)
            response = approval_manager.respond(
                request_id,
                decision=arguments.get("decision"),
                scope=arguments.get("scope"),
                ttl_sec=arguments.get("ttl_sec"),
                reason=arguments.get("reason", ""),
                workspace=request.workspace,
                auto_resume=arguments.get("auto_resume"),
            )
            auto_resume = bool(arguments.get("auto_resume", True))
            resume_payload = None
            if response.get("status") == "approved" and auto_resume and request.run_id:
                request_payload = (RUN_MANAGER.get(request.run_id) or {}).get("request") or {}

                def runner(run_id, cancel_event):
                    return self._resume_paused_run(request_payload, run_id=run_id, cancel_event=cancel_event)

                resume_payload = RUN_MANAGER.resume(request.run_id, runner)
            session_summary = self._continue_ctf_session(
                {
                    "run_id": request.run_id,
                    "workspace": request.workspace,
                    "findings_limit": int(arguments.get("findings_limit", 5) or 5),
                }
            )
            return {
                "request_id": request_id,
                "response": response,
                "auto_resume": auto_resume,
                "resume": resume_payload,
                "session": session_summary,
            }
        finally:
            close_service(service)

    def _preview_ctf_task(self, arguments):
        resolved, background_policy, validation = self._prepare_brief_request(arguments)
        return self._build_preview_payload(arguments, resolved, background_policy, validation)

    def _build_preview_payload(self, arguments, resolved, background_policy, validation):
        skill_context = resolve_skill_context(
            payload=resolved,
            metadata=dict(resolved.get("metadata") or {}),
            category=resolved.get("category", ""),
            target=resolved.get("target") or resolved.get("url") or "",
            attachments=list(resolved.get("attachments", []) or []),
            speed_mode=resolved.get("speed_mode"),
            task_text=str(arguments.get("task") or resolved.get("description") or ""),
        )
        autopilot = dict(skill_context.get("autopilot") or resolved.get("autopilot_plan") or {})
        knowledge = dict(skill_context.get("knowledge") or autopilot.get("knowledge") or {})
        recommendations = dict(skill_context.get("recommendations") or {})
        return {
            "mode": "preview",
            "request": {
                "task": arguments.get("task", ""),
                "target": arguments.get("target") or "",
                "attachment_count": len(list(arguments.get("attachments") or [])) + (1 if arguments.get("attachment") and not isinstance(arguments.get("attachment"), list) else 0),
            },
            "normalized": {
                "category": resolved.get("category", ""),
                "target": resolved.get("target") or resolved.get("url") or "",
                "attachments": list(resolved.get("attachments") or []),
                "title": resolved.get("title", ""),
                "description": resolved.get("description", ""),
                "hint": resolved.get("hint", ""),
                "flag_format": resolved.get("flag_format", ""),
                "max_rounds": resolved.get("max_rounds"),
                "use_browser_mcp": resolved.get("use_browser_mcp"),
                "use_remote_host": resolved.get("use_remote_host", ""),
                "speed_mode": resolved.get("speed_mode", "standard"),
                "speed_profile": dict(resolved.get("speed_profile") or {}),
            },
            "validation": validation,
            "routing": {
                "autopilot_summary": autopilot.get("summary", ""),
                "execution_profile": autopilot.get("execution_profile", ""),
                "speed_mode": skill_context.get("speed_mode", resolved.get("speed_mode", "standard")),
                "speed_profile": dict(resolved.get("speed_profile") or autopilot.get("speed_profile") or {}),
                "recommended_tools": list(autopilot.get("local_tools") or recommendations.get("recommended_tools", [])),
                "recommended_mcp": list(autopilot.get("recommended_mcp") or recommendations.get("recommended_mcp", [])),
                "capability_plan": dict(autopilot.get("capability_plan") or {}),
                "selected_lanes": list((autopilot.get("capability_plan") or {}).get("selected_lanes", [])),
                "recommended_sidecars": list((autopilot.get("capability_plan") or {}).get("recommended_sidecars", [])),
                "selected_remote_host": resolved.get("use_remote_host", ""),
                "dispatch_mode": background_policy.get("effective_mode", "sync"),
                "dispatch_reason": background_policy.get("reason", ""),
                "dispatch_signals": list(background_policy.get("signals", [])),
                "selected_skill_category": knowledge.get("selected_skill_category", ""),
                "category_confidence": knowledge.get("category_confidence", 0.0),
                "category_evidence": list(knowledge.get("category_evidence", [])),
                "pack_name": knowledge.get("pack_name", ""),
                "top_tactics": list(knowledge.get("top_tactics", []))[:5],
                "reference_docs": list(knowledge.get("reference_docs", []))[:5],
            },
            "suggested_task": {
                "markdown": render_task_from_fields(resolved, quick=False),
                "quick_markdown": render_task_from_fields(resolved, quick=True),
            },
        }

    def _auto_solve_ctf(self, arguments):
        resolved, background_policy, validation = self._prepare_brief_request(arguments)
        background = background_policy.get("effective_mode") == "async"
        if not validation.get("ok", False):
            return build_needs_input_envelope(arguments.get("task", ""), resolved, validation, mode="async" if background else "sync")
        return self._dispatch_brief_request(arguments.get("task", ""), resolved, background_policy)

    def _resolve_background_policy(self, arguments, resolved):
        requested_mode = self._normalize_background_request(arguments)
        if requested_mode == "async":
            return {
                "requested_mode": "async",
                "effective_mode": "async",
                "reason": "background was explicitly requested by the caller.",
                "signals": ["explicit-async"],
            }
        if requested_mode == "sync":
            return {
                "requested_mode": "sync",
                "effective_mode": "sync",
                "reason": "sync execution was explicitly requested by the caller.",
                "signals": ["explicit-sync"],
            }
        speed_mode = str(resolved.get("speed_mode") or ((resolved.get("autopilot_plan") or {}).get("speed_mode")) or "standard").strip().lower()
        if speed_mode == "fastest":
            return {
                "requested_mode": "auto",
                "effective_mode": "sync",
                "reason": "fastest mode keeps execution in the foreground to avoid preview/background overhead.",
                "signals": ["speed:fastest"],
            }

        config = self._load_config(arguments.get("config_path"), resolved.get("output_root") or resolved.get("workspace_root"))
        policy = dict((config.editor_policy or {}).get("auto_background_policy") or {})
        category = str(resolved.get("category") or "web").strip().lower()
        attachments = list(resolved.get("attachments") or [])
        max_rounds = int(resolved.get("max_rounds") or 0)
        use_remote_host = str(resolved.get("use_remote_host") or "").strip()
        use_browser_mcp = bool(resolved.get("use_browser_mcp"))
        execution_profile = str(((resolved.get("autopilot_plan") or {}).get("execution_profile") or "")).strip().lower()

        categories = {str(item).strip().lower() for item in list(policy.get("categories") or ["re", "reverse", "pwn"]) if str(item).strip()}
        attachment_count_threshold = int(policy.get("attachment_count_threshold", 4) or 4)
        attachment_bytes_threshold = int(policy.get("attachment_bytes_threshold", 15 * 1024 * 1024) or (15 * 1024 * 1024))
        round_threshold = int(policy.get("round_threshold", 8) or 8)
        auto_with_remote = bool(policy.get("remote_host", True))
        auto_with_browser_web = bool(policy.get("browser_mcp_for_web", False))
        default_mode = str(policy.get("default_mode", "sync") or "sync").strip().lower()

        signals = []
        total_attachment_bytes = 0
        for item in attachments:
            try:
                total_attachment_bytes += Path(item).stat().st_size
            except OSError:
                continue

        if category in categories:
            signals.append("category:{0}".format(category))
        if execution_profile in {"reverse-analysis", "pwn-analysis"}:
            signals.append("profile:{0}".format(execution_profile))
        if max_rounds >= round_threshold:
            signals.append("rounds:{0}".format(max_rounds))
        if len(attachments) >= attachment_count_threshold:
            signals.append("attachments:{0}".format(len(attachments)))
        if total_attachment_bytes >= attachment_bytes_threshold:
            signals.append("attachment-bytes:{0}".format(total_attachment_bytes))
        if auto_with_remote and use_remote_host:
            signals.append("remote:{0}".format(use_remote_host))
        if auto_with_browser_web and category == "web" and use_browser_mcp:
            signals.append("browser-mcp")

        if signals:
            reason = "auto background selected from signals: {0}".format(", ".join(signals))
            effective_mode = "async"
        else:
            reason = "auto background kept sync; no long-running signals matched."
            effective_mode = "async" if default_mode == "async" else "sync"

        return {
            "requested_mode": "auto",
            "effective_mode": effective_mode,
            "reason": reason,
            "signals": signals,
        }

    def _normalize_background_request(self, arguments):
        arguments = dict(arguments or {})
        if "background" not in arguments:
            return "auto"
        value = arguments.get("background")
        if isinstance(value, bool):
            return "async" if value else "sync"
        text = str(value or "").strip().lower()
        if text in {"", "auto", "default"}:
            return "auto"
        if text in {"1", "true", "yes", "on", "async", "background"}:
            return "async"
        if text in {"0", "false", "no", "off", "sync", "foreground"}:
            return "sync"
        return "auto"

    def _load_config(self, config_path=None, workspace_root=None):
        project_root = Path(__file__).resolve().parents[1]
        resolved_config = Path(config_path).expanduser() if config_path else (project_root / "local_config.json")
        if not resolved_config.is_absolute():
            resolved_config = Path.cwd() / resolved_config
        return load_agent_config(resolved_config.resolve())

    def _start_ctf_task(self, arguments):
        resolved, _, validation = self._prepare_brief_request(arguments)
        if not validation.get("ok", False):
            return build_needs_input_envelope(arguments.get("task", ""), resolved, validation, mode="async")
        category = (resolved.get("category") or "web").strip().lower()

        def runner(run_id, cancel_event):
            return self._run_solve_payload(resolved, run_id=run_id, cancel_event=cancel_event)

        payload = RUN_MANAGER.start(category, dict(resolved or {}), runner)
        return build_async_start_envelope(arguments.get("task", ""), resolved, payload)

    def _get_ctf_task_status(self, arguments):
        payload = RUN_MANAGER.get(arguments["run_id"])
        if not payload:
            return {
                "protocol": {"name": "ctf-task-feed", "version": TASK_PROTOCOL_VERSION},
                "mode": "status",
                "execution": {"status": "missing", "run_id": arguments["run_id"]},
                "validation": {"ok": False, "errors": ["未找到对应 run。"], "warnings": [], "next_actions": ["确认 run_id 是否正确，或重新调用 start_ctf_task。"]},
                "summary": {"headline": "未找到对应 run。", "status": "missing"},
            }
        return build_status_envelope(payload)

    def _solve_ctf_brief(self, arguments):
        resolved, _, _ = self._prepare_brief_request(arguments)
        result = self._run_solve_payload(resolved)
        return {
            "mode": "brief",
            "resolved": resolved,
            "result": result,
        }

    def _solve_ctf_template(self, arguments):
        resolved = self._normalize_arguments(arguments)
        result = self._run_solve_payload(resolved)
        return {
            "mode": "template",
            "resolved": resolved,
            "result": result,
        }

    def _solve_json(self, arguments):
        service = _build_service(
            config_path=arguments.get("config_path"),
            workspace_root=arguments.get("workspace_root"),
            timeout=float(arguments.get("timeout", 8.0)),
            max_js_assets=int(arguments.get("max_js_assets", 8)),
        )
        try:
            result = service["orchestrator"].solve_path(Path(arguments["source"]), auto_submit=bool(arguments.get("submit", False)))
            return result
        finally:
            close_service(service)

    def _start_ctf_run(self, arguments):
        resolved = self._normalize_arguments(arguments)
        category = (resolved.get("category") or "web").strip().lower()

        def runner(run_id, cancel_event):
            return self._run_solve_payload(resolved, run_id=run_id, cancel_event=cancel_event)

        return RUN_MANAGER.start(category, dict(resolved or {}), runner)

    def _start_ctf_brief_run(self, arguments):
        resolved, _, _ = self._prepare_brief_request(arguments)
        category = (resolved.get("category") or "web").strip().lower()

        def runner(run_id, cancel_event):
            return self._run_solve_payload(resolved, run_id=run_id, cancel_event=cancel_event)

        payload = RUN_MANAGER.start(category, dict(resolved or {}), runner)
        return {
            "mode": "brief",
            "resolved": resolved,
            "run": payload,
        }

    def _start_ctf_template_run(self, arguments):
        resolved = self._normalize_arguments(arguments)
        category = (resolved.get("category") or "web").strip().lower()

        def runner(run_id, cancel_event):
            return self._run_solve_payload(resolved, run_id=run_id, cancel_event=cancel_event)

        payload = RUN_MANAGER.start(category, dict(resolved or {}), runner)
        return {
            "mode": "template",
            "resolved": resolved,
            "run": payload,
        }

    def _get_ctf_run_status(self, arguments):
        payload = RUN_MANAGER.get(arguments["run_id"])
        if not payload:
            return {"status": "missing", "run_id": arguments["run_id"]}
        return payload

    def _cancel_ctf_run(self, arguments):
        return RUN_MANAGER.cancel(arguments["run_id"])

    def _read_ctf_run_artifact(self, arguments):
        return RUN_MANAGER.read_artifact(
            arguments["run_id"],
            arguments["path"],
            limit_bytes=int(arguments.get("limit_bytes", 200000)),
        )

    def _get_ctf_board_summary(self, arguments):
        run_payload = None
        workspace = arguments.get("workspace")
        if arguments.get("run_id"):
            run_payload = RUN_MANAGER.get(arguments["run_id"])
            if not run_payload:
                return {"status": "missing", "run_id": arguments["run_id"], "message": "run id not found"}
            workspace = run_payload.get("workspace") or workspace
        if not workspace:
            return {"status": "missing_input", "message": "run_id or workspace is required"}
        return build_board_summary(
            workspace,
            run_meta=run_payload,
            findings_limit=int(arguments.get("findings_limit", 5)),
        )

    def _browse_target(self, arguments):
        service = _build_service(
            config_path=arguments.get("config_path"),
            timeout=float(arguments.get("timeout", 8.0)),
        )
        try:
            task = arguments.get("task") or "Open the target, summarize routes, forms, and suspicious client-side behaviors."
            registry = service["mcp_registry"]
            if registry.has_servers():
                try:
                    payload = registry.call_browser_flow(arguments["url"], action="recon", task=task, timeout=arguments.get("timeout"))
                    payload["text"] = registry.flatten_tool_result(payload["result"])
                    return payload
                except MCPError as exc:
                    return {"ok": False, "error": exc.to_dict()}

            response = service["http_tool"].request("GET", arguments["url"])
            return {
                "ok": True,
                "mode": "http-fallback",
                "response": {
                    "status": response.get("status"),
                    "url": response.get("url"),
                    "elapsed": response.get("elapsed"),
                    "summary": service["http_tool"].summarize_html(response.get("text", ""), response.get("url", arguments["url"])),
                },
            }
        finally:
            close_service(service)

    def _analyze_with_reverse(self, arguments, server_keyword):
        service = _build_service(
            config_path=arguments.get("config_path"),
            timeout=float(arguments.get("timeout", 25.0)),
        )
        try:
            registry = service["mcp_registry"]
            descriptor = registry.pick_reverse_tool(server_keyword=server_keyword)
            if not descriptor:
                return {"ok": False, "error": {"message": "no matching reverse MCP server", "server_keyword": server_keyword}}

            task = arguments.get("task") or "Open the binary, summarize key logic, input validation, and likely flag path."
            haystack = "{0} {1}".format(descriptor.get("server", ""), (descriptor.get("tool") or {}).get("name", "")).lower()
            if "ida" in haystack:
                probe = registry.call_tool_safe(descriptor["server"], "check_connection", arguments={}, timeout=10)
                probe_text = registry.flatten_tool_result(probe.get("result") if probe.get("ok") else probe.get("error"))
                binary_name = Path(arguments["binary_path"]).name
                if "Successfully connected to IDA Pro" not in probe_text or binary_name not in probe_text:
                    launch = service["toolkit_tool"].launch_ida_live(arguments["binary_path"], headless=True)
                    if launch.get("status") == "ok":
                        for _ in range(20):
                            time.sleep(1.0)
                            probe = registry.call_tool_safe(descriptor["server"], "check_connection", arguments={}, timeout=10)
                            probe_text = registry.flatten_tool_result(probe.get("result") if probe.get("ok") else probe.get("error"))
                            if "Successfully connected to IDA Pro" in probe_text and binary_name in probe_text:
                                break

            payload = registry.analyze_with_reverse(
                arguments["binary_path"],
                task=task,
                timeout=arguments.get("timeout"),
                server_keyword=server_keyword,
            )
            return {
                "ok": True,
                "server": payload.get("server", descriptor.get("server", "")),
                "tool": payload.get("tool", (descriptor.get("tool") or {}).get("name", "")),
                "arguments": payload.get("arguments", {"binary_path": arguments["binary_path"], "task": task}),
                "result": payload.get("result"),
                "text": registry.flatten_tool_result(payload.get("result")),
            }
        finally:
            close_service(service)

    def _list_local_tools(self, arguments):
        service = _build_service(config_path=arguments.get("config_path"))
        try:
            digest = service["toolkit_tool"].capability_digest()
            return {
                "configured": service["toolkit_tool"].is_configured(),
                "toolkit_root": str(service["toolkit_tool"].toolkit_root) if service["toolkit_tool"].toolkit_root else "",
                "tools": service["toolkit_tool"].describe_tools(),
                "libraries": list(digest.get("libraries", [])),
                "runtimes": list(digest.get("runtimes", [])),
                "layers": dict(digest.get("layers", {})),
                "categories": dict(digest.get("categories", {})),
                "ida": dict(digest.get("ida", {})),
                "x64dbg": dict(digest.get("x64dbg", {})),
            }
        finally:
            close_service(service)

    def _run_local_tool(self, arguments):
        service = _build_service(config_path=arguments.get("config_path"))
        try:
            toolkit_tool = service["toolkit_tool"]
            args = [str(item) for item in arguments.get("args", [])]
            if arguments.get("tool"):
                return toolkit_tool.run_named_tool(arguments["tool"], args=args, cwd=arguments.get("cwd"), timeout=float(arguments.get("timeout", 120.0)))
            if arguments.get("path"):
                return toolkit_tool.run_tool_path(arguments["path"], args=args, cwd=arguments.get("cwd"), timeout=float(arguments.get("timeout", 120.0)))
            raise ValueError("tool or path is required")
        finally:
            close_service(service)

    def _list_remote_hosts(self, arguments):
        service = _build_service(config_path=arguments.get("config_path"))
        try:
            return {
                "hosts": service["remote_tool"].describe_hosts(),
            }
        finally:
            close_service(service)

    def _recommend_remote_host(self, arguments):
        service = _build_service(config_path=arguments.get("config_path"))
        try:
            return service["remote_tool"].recommend_host(
                category=arguments.get("category", ""),
                target=arguments.get("target", ""),
                preferred=arguments.get("preferred"),
            )
        finally:
            close_service(service)

    def _run_remote_command(self, arguments):
        service = _build_service(config_path=arguments.get("config_path"))
        try:
            return service["remote_tool"].run(
                arguments["host"],
                arguments["command"],
                timeout=float(arguments.get("timeout", 30.0)),
            )
        finally:
            close_service(service)

    def _probe_remote_host(self, arguments):
        service = _build_service(config_path=arguments.get("config_path"))
        try:
            return service["remote_tool"].probe(
                arguments["host"],
                timeout=float(arguments.get("timeout", 20.0)),
            )
        finally:
            close_service(service)

    def _ensure_remote_workspace(self, arguments):
        service = _build_service(config_path=arguments.get("config_path"))
        try:
            return service["remote_tool"].ensure_workspace(
                arguments["host"],
                run_id=arguments.get("run_id"),
                remote_dir=arguments.get("remote_dir"),
                timeout=float(arguments.get("timeout", 30.0)),
            )
        finally:
            close_service(service)

    def _run_remote_python(self, arguments):
        service = _build_service(config_path=arguments.get("config_path"))
        try:
            return service["remote_tool"].run_python(
                arguments["host"],
                arguments["code"],
                args=arguments.get("args", []),
                cwd=arguments.get("cwd"),
                env=arguments.get("env"),
                python_bin=arguments.get("python_bin"),
                timeout=float(arguments.get("timeout", 120.0)),
            )
        finally:
            close_service(service)

    def _upload_remote_file(self, arguments):
        service = _build_service(config_path=arguments.get("config_path"))
        try:
            return service["remote_tool"].upload(
                arguments["host"],
                arguments["local_path"],
                remote_path=arguments.get("remote_path"),
                timeout=float(arguments.get("timeout", 45.0)),
            )
        finally:
            close_service(service)

    def _upload_remote_text(self, arguments):
        service = _build_service(config_path=arguments.get("config_path"))
        try:
            return service["remote_tool"].upload_text(
                arguments["host"],
                arguments["content"],
                remote_path=arguments.get("remote_path"),
                timeout=float(arguments.get("timeout", 30.0)),
            )
        finally:
            close_service(service)

    def _download_remote_file(self, arguments):
        service = _build_service(config_path=arguments.get("config_path"))
        try:
            return service["remote_tool"].download(
                arguments["host"],
                arguments["remote_path"],
                arguments["local_path"],
                timeout=float(arguments.get("timeout", 45.0)),
            )
        finally:
            close_service(service)

    def _render_remote_template(self, arguments):
        service = _build_service(config_path=arguments.get("config_path"))
        try:
            return service["remote_tool"].render_template(
                arguments["template_kind"],
                filename=arguments.get("filename"),
                **dict(arguments.get("variables") or {}),
            )
        finally:
            close_service(service)

    def _run_remote_template(self, arguments):
        service = _build_service(config_path=arguments.get("config_path"))
        try:
            return service["remote_tool"].run_template(
                arguments["host"],
                arguments["template_kind"],
                filename=arguments.get("filename"),
                remote_workspace=arguments.get("remote_workspace"),
                remote_path=arguments.get("remote_path"),
                timeout=float(arguments.get("timeout", 120.0)),
                cwd=arguments.get("cwd"),
                env=arguments.get("env"),
                python_bin=arguments.get("python_bin"),
                **dict(arguments.get("variables") or {}),
            )
        finally:
            close_service(service)

    def _list_nested_servers(self, arguments):
        service = _build_service(config_path=arguments.get("config_path"))
        try:
            return {"servers": service["mcp_registry"].list_servers()}
        finally:
            close_service(service)

    def _list_nested_tools(self, arguments):
        service = _build_service(config_path=arguments.get("config_path"))
        try:
            return {
                "servers": service["mcp_registry"].list_servers(),
                "tools": service["mcp_registry"].list_tools(
                    server_name=arguments.get("server"),
                    refresh=bool(arguments.get("refresh", False)),
                ),
            }
        finally:
            close_service(service)

    def _call_nested_tool(self, arguments):
        service = _build_service(config_path=arguments.get("config_path"))
        try:
            return service["mcp_registry"].call_tool_safe(
                arguments["server"],
                arguments["tool"],
                arguments=arguments.get("arguments", {}),
                timeout=arguments.get("timeout"),
            )
        finally:
            close_service(service)

    def _build_template_arguments(self, arguments):
        arguments = dict(arguments or {})
        category = (arguments.get("category") or "web").strip().lower()
        service = _build_service(
            config_path=arguments.get("config_path"),
            workspace_root=arguments.get("output_root"),
            timeout=float(arguments.get("timeout", 8.0)),
            max_js_assets=int(arguments.get("max_js_assets", 8)),
        )
        try:
            config = service["config"]
            target = (arguments.get("target") or "").strip()
            attachment_inputs = list(arguments.get("attachments", []) or [])
            if target and self._looks_like_local_path(target):
                attachment_inputs.append(target)

            attachments = self._expand_attachment_inputs(attachment_inputs)
            resolved_target = self._resolve_target(category, target)
            title = arguments.get("title") or self._infer_title(category, target, attachments)
            challenge_id = arguments.get("challenge_id") or self._slugify(title or "manual-{0}".format(category))
            contest_id = arguments.get("contest_id") or "manual"
            description = (
                arguments.get("description")
                or arguments.get("hint")
                or "单按钮模板自动生成的 {0} 题任务。".format(category)
            )

            use_browser_mcp = arguments.get("use_browser_mcp")
            if use_browser_mcp is None:
                use_browser_mcp = bool(
                    category == "web" and config.web_policy.get("auto_use_browser_mcp", True)
                )

            use_remote_host = arguments.get("use_remote_host") or self._choose_default_remote_host(config, category)
            max_rounds = arguments.get("max_rounds")
            if max_rounds is None:
                max_rounds = self._default_max_rounds(category, config)

            return {
                "category": category,
                "url": resolved_target,
                "attachments": [str(item) for item in attachments],
                "title": title,
                "challenge_id": challenge_id,
                "contest_id": contest_id,
                "description": description,
                "flag_format": arguments.get("flag_format", r"flag\{[^{}\n]+\}"),
                "output_root": arguments.get("output_root") or config.workspace_root,
                "config_path": arguments.get("config_path"),
                "timeout": float(arguments.get("timeout", 8.0)),
                "max_js_assets": int(arguments.get("max_js_assets", 8)),
                "max_rounds": int(max_rounds),
                "use_browser_mcp": bool(use_browser_mcp),
                "use_remote_host": use_remote_host,
            }
        finally:
            service["mcp_registry"].close()

    def _expand_attachment_inputs(self, attachment_inputs):
        expanded = []
        for item in attachment_inputs:
            if not item:
                continue
            path = Path(item).expanduser()
            if not path.exists():
                expanded.append(path.resolve())
                continue
            if path.is_dir():
                for child in sorted(candidate for candidate in path.rglob("*") if candidate.is_file()):
                    expanded.append(child.resolve())
                continue
            expanded.append(path.resolve())
        unique = []
        seen = set()
        for item in expanded:
            key = str(item).lower()
            if key in seen:
                continue
            seen.add(key)
            unique.append(item)
        return unique

    def _resolve_target(self, category, target):
        if not target:
            return None
        if self._looks_like_local_path(target):
            return None
        if category == "web" and re.match(r"^[A-Za-z0-9_.-]+:\d{1,5}$", target):
            return "http://{0}".format(target)
        return target

    def _infer_title(self, category, target, attachments):
        if attachments:
            first = Path(attachments[0])
            if first.is_file():
                return first.stem
        if target:
            text = str(target)
            text = re.sub(r"^[a-z]+://", "", text, flags=re.IGNORECASE)
            text = text.strip("/").replace("/", "-").replace(":", "-")
            if text:
                return text[:80]
        return "manual-{0}".format(category)

    def _looks_like_local_path(self, target):
        if not target:
            return False
        if re.match(r"^[a-z]+://", target, flags=re.IGNORECASE):
            return False
        text = str(target)
        if "\\" in text or "/" in text or re.match(r"^[A-Za-z]:", text):
            return True
        return Path(text).exists()

    def _choose_default_remote_host(self, config, category):
        if category not in {"pwn", "re", "reverse"}:
            return ""
        hosts = sorted(config.remote_hosts.keys())
        for name in hosts:
            if "ubuntu" in name.lower():
                return name
        return hosts[0] if hosts else ""

    def _default_max_rounds(self, category, config):
        if category == "web":
            return int(config.web_policy.get("max_rounds", 6))
        if category == "misc":
            return 5
        return 7

    def _slugify(self, value):
        text = re.sub(r"[^a-zA-Z0-9._-]+", "-", str(value or "item").strip())
        text = text.strip("-")
        return text or "item"

    def _run_solve_payload(self, arguments, run_id=None, cancel_event=None):
        arguments = dict(arguments or {})
        if arguments.get("autopilot_plan") and arguments.get("knowledge_selection"):
            resolved = arguments
        else:
            resolved = self._normalize_arguments(arguments)
        output_root = resolved.get("output_root") or resolved.get("workspace_root")
        service = _build_service(
            config_path=resolved.get("config_path"),
            workspace_root=output_root,
            timeout=float(resolved.get("timeout", 8.0)),
            max_js_assets=int(resolved.get("max_js_assets", 8)),
        )
        try:
            result = run_payload(
                service,
                resolved,
                run_id=run_id,
                cancel_event=cancel_event,
                source="mcp",
            )
            if run_id:
                payload = RUN_MANAGER.get(run_id)
                if payload and not payload.get("workspace"):
                    RUN_MANAGER._set_result(run_id, result)
            return result
        finally:
            close_service(service)

    def _send(self, payload):
        sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
        sys.stdout.flush()

    def _send_error(self, request_id, code, message, trace_text):
        self._send(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": code,
                    "message": message,
                    "data": {
                        "traceback": trace_text,
                    },
                },
            }
        )

    # ------------------------------------------------------------------
    # AI Solver MCP tools (Phase 0-5) — usable without a separate API key
    # ------------------------------------------------------------------

    def _search_ctf_knowledge(self, arguments):
        service = _build_service(config_path=arguments.get("config_path"))
        try:
            retriever = service.get("knowledge_retriever")
            if not retriever:
                return {"status": "error", "message": "Knowledge retriever not available. Check rag config in local_config.json."}
            if not retriever.is_loaded():
                retriever.load()

            query = str(arguments.get("query", "")).strip()
            if not query:
                return {"status": "error", "message": "query is required"}

            top_k = int(arguments.get("top_k", 5))
            category = arguments.get("category") or None
            source = arguments.get("source") or None

            results = retriever.query(query, top_k=top_k, category_hint=category, source_filter=source)

            items = []
            for r in results:
                items.append({
                    "source_type": r["source_type"],
                    "category": r["category"],
                    "heading": r.get("heading", ""),
                    "source_file": r["source_file"],
                    "score": round(r["score"], 2),
                    "text": r["text"][:1500],
                })

            return {
                "status": "ok",
                "query": query,
                "stats": retriever.stats,
                "results": items,
            }
        finally:
            close_service(service)

    def _run_ctf_code(self, arguments):
        service = _build_service(config_path=arguments.get("config_path"))
        try:
            executor = service.get("code_executor")
            if not executor:
                from ctf_agent.core.code_executor import CodeExecutor
                executor = CodeExecutor()

            code = str(arguments.get("code", "")).strip()
            if not code:
                return {"status": "error", "message": "code is required"}

            description = str(arguments.get("description", ""))
            timeout = int(arguments.get("timeout", 30))
            workspace = arguments.get("workspace") or None

            result = executor.execute(code, workspace=workspace, timeout=timeout, description=description)

            verifier = service.get("verifier")
            flags = []
            if verifier:
                for text in [result.stdout, result.stderr]:
                    for flag in verifier.discover_from_text(text):
                        flags.append(flag)

            return {
                "status": "ok" if result.success else "error",
                "exit_code": result.exit_code,
                "timed_out": result.timed_out,
                "elapsed_ms": result.elapsed_ms,
                "stdout": result.stdout[:50000],
                "stderr": result.stderr[:10000],
                "flags_found": flags,
            }
        finally:
            close_service(service)

    def _scan_ctf_flags(self, arguments):
        text = str(arguments.get("text", ""))
        if not text:
            return {"status": "error", "message": "text is required"}

        from ctf_agent.core.verifier import FlagVerifier
        verifier = FlagVerifier()
        found = verifier.discover_from_text(text)
        return {
            "status": "ok",
            "flags": found,
            "count": len(found),
        }

    def _continue_ctf_solve(self, arguments):
        workspace = arguments.get("workspace", "")
        hint = arguments.get("hint", "")
        if not workspace:
            return {"status": "error", "message": "workspace is required"}

        service = _build_service(config_path=arguments.get("config_path"))
        try:
            agent_loop = service.get("agent_loop")
            if not agent_loop:
                return {"status": "error", "message": "AI agent loop not available (no LLM configured)"}

            from ctf_agent.core.agent_loop import build_default_tools
            tools = build_default_tools(
                code_executor=service.get("code_executor"),
                knowledge_retriever=service.get("knowledge_retriever"),
                verifier=service.get("verifier"),
                file_tool=service.get("file_tool"),
                shell_tool=service.get("shell_tool"),
                toolkit_tool=service.get("toolkit_tool"),
                http_tool=service.get("http_tool"),
                remote_tool=service.get("remote_tool"),
                mcp_registry=service.get("mcp_registry"),
                oob_tool=service.get("oob_tool"),
                workspace=workspace,
            )
            agent_loop.tools = tools
            state = agent_loop.continue_solve(workspace, user_hint=hint)

            best_flag = service["verifier"].choose_best(state, type("C", (), {"flag_format": None})())
            return {
                "status": "solved" if best_flag else state.phase,
                "workspace": workspace,
                "flag": best_flag.value if best_flag else None,
                "n_flags": len(state.candidate_flags),
                "n_actions": len(state.tried_actions),
                "phase": state.phase,
            }
        finally:
            close_service(service)

    def _get_agent_session_info(self, arguments):
        workspace = arguments.get("workspace", "")
        if not workspace:
            return {"status": "error", "message": "workspace is required"}

        from ctf_agent.core.agent_loop import _load_session
        session = _load_session(workspace)
        if not session:
            return {"status": "not_found", "message": "No saved session in {0}".format(workspace)}

        sd = session.get("state", {})
        return {
            "status": "ok",
            "step": session.get("step", 0),
            "phase": sd.get("phase", "unknown"),
            "n_flags": len(sd.get("candidate_flags", [])),
            "n_actions": len(sd.get("tried_actions", [])),
            "n_hypotheses": len(sd.get("hypotheses", [])),
            "n_messages": len(session.get("messages", [])),
            "candidate_flags": [
                {"value": f.get("value", ""), "source": f.get("source", "")}
                for f in sd.get("candidate_flags", [])
            ],
        }


def build_parser():
    parser = argparse.ArgumentParser(description="CTF Agent MCP server")
    parser.add_argument("--stdio", action="store_true", help="Serve over stdio (default)")
    parser.add_argument("--config", default=None, help="Optional default local_config.json path used by the MCP hub")
    parser.add_argument("--workspace-root", default=None, help="Optional default workspace root used by the MCP hub")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    global DEFAULT_SERVER_CONFIG_PATH
    global DEFAULT_SERVER_WORKSPACE_ROOT
    DEFAULT_SERVER_CONFIG_PATH = str(_normalize_cli_path(args.config)) if args.config else None
    DEFAULT_SERVER_WORKSPACE_ROOT = str(_normalize_cli_path(args.workspace_root)) if args.workspace_root else None
    CTFMCPServer().serve()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
