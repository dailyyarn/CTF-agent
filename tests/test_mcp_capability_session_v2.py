import json
import sys
import tempfile
import unittest
from pathlib import Path

from ctf_agent.core.board import build_board_summary
from ctf_agent.core.task_protocol import build_sync_envelope
from ctf_agent.core.workspace import WorkspaceManager, load_workspace_mcp_status
from ctf_agent.mcp_server import CTFMCPServer
from ctf_agent.tools.mcp_runtime import MCPRuntimeRegistry


FAKE_MCP_SERVER = r"""
import json
import os
import sys

SUPPORT_RESOURCES = os.environ.get("SUPPORT_RESOURCES", "0") == "1"
TOOLS = [
    {
        "name": "browser_agent",
        "description": "browser recon",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "task": {"type": "string"}
            }
        }
    },
    {
        "name": "reverse_probe",
        "description": "ida decompile reverse helper",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string"},
                "task": {"type": "string"}
            }
        }
    }
]
RESOURCES = [
    {
        "uri": "memo://notes",
        "name": "notes",
        "mimeType": "text/plain"
    }
]


def send(payload):
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()


for raw in sys.stdin:
    raw = raw.strip()
    if not raw:
        continue
    payload = json.loads(raw)
    method = payload.get("method")
    request_id = payload.get("id")
    if not request_id:
        continue
    if method == "initialize":
        send({"jsonrpc": "2.0", "id": request_id, "result": {"serverInfo": {"name": "fake", "version": "1.0"}}})
        continue
    if method == "tools/list":
        send({"jsonrpc": "2.0", "id": request_id, "result": {"tools": TOOLS}})
        continue
    if method == "tools/call":
        tool_name = payload.get("params", {}).get("name")
        arguments = payload.get("params", {}).get("arguments", {})
        send(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": "{0}:{1}".format(tool_name, json.dumps(arguments, ensure_ascii=False, sort_keys=True))
                        }
                    ]
                },
            }
        )
        continue
    if method == "resources/list":
        if not SUPPORT_RESOURCES:
            send({"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": "Method not found"}})
            continue
        send({"jsonrpc": "2.0", "id": request_id, "result": {"resources": RESOURCES}})
        continue
    if method == "resources/read":
        if not SUPPORT_RESOURCES:
            send({"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": "Method not found"}})
            continue
        uri = payload.get("params", {}).get("uri", "")
        send(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": "text/plain",
                            "text": "resource body for " + uri
                        }
                    ]
                },
            }
        )
        continue
    send({"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": "Method not found"}})
"""


class MCPCapabilitySessionV2Tests(unittest.TestCase):
    def _write_fake_server(self, root):
        script_path = Path(root) / "fake_mcp_server.py"
        script_path.write_text(FAKE_MCP_SERVER, encoding="utf-8")
        return script_path

    def test_prefetch_capabilities_persists_status_snapshot(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            workspace = temp_root / "workspace"
            workspace.mkdir(parents=True, exist_ok=True)
            script = self._write_fake_server(temp_root)
            manager = WorkspaceManager(temp_root)
            registry = MCPRuntimeRegistry(
                server_configs=[
                    {
                        "name": "good-server",
                        "command": sys.executable,
                        "args": [str(script)],
                        "env": {"SUPPORT_RESOURCES": "1"},
                        "enabled": True,
                    },
                    {
                        "name": "unsupported-server",
                        "command": sys.executable,
                        "args": [str(script)],
                        "env": {"SUPPORT_RESOURCES": "0"},
                        "enabled": True,
                    },
                    {
                        "name": "missing-server",
                        "command": "__missing_mcp_command__",
                        "enabled": True,
                    },
                    {
                        "name": "disabled-server",
                        "command": sys.executable,
                        "args": [str(script)],
                        "env": {"SUPPORT_RESOURCES": "1"},
                        "enabled": False,
                    },
                ],
                workspace_manager=manager,
                workspace=str(workspace),
            )
            try:
                payload = registry.prefetch_mcp_capabilities()
            finally:
                registry.close()

            status_by_name = {item["name"]: item["status"] for item in payload}
            self.assertEqual("connected", status_by_name["good-server"])
            self.assertEqual("connected", status_by_name["unsupported-server"])
            self.assertEqual("failed", status_by_name["missing-server"])
            self.assertEqual("disabled", status_by_name["disabled-server"])

            snapshot = load_workspace_mcp_status(workspace)
            self.assertEqual(2, snapshot["counts"]["connected"])
            self.assertEqual(1, snapshot["counts"]["failed"])
            self.assertEqual(1, snapshot["counts"]["disabled"])
            self.assertEqual(["good-server"], snapshot["resource_enabled_servers"])
            self.assertTrue(any(item["server"] == "unsupported-server" for item in snapshot["fallback_reasons"]))

    def test_resources_supported_and_unsupported_return_structured_payloads(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            workspace = temp_root / "workspace"
            workspace.mkdir(parents=True, exist_ok=True)
            script = self._write_fake_server(temp_root)
            manager = WorkspaceManager(temp_root)
            registry = MCPRuntimeRegistry(
                server_configs=[
                    {
                        "name": "good-server",
                        "command": sys.executable,
                        "args": [str(script)],
                        "env": {"SUPPORT_RESOURCES": "1"},
                        "enabled": True,
                    },
                    {
                        "name": "unsupported-server",
                        "command": sys.executable,
                        "args": [str(script)],
                        "env": {"SUPPORT_RESOURCES": "0"},
                        "enabled": True,
                    },
                ],
                workspace_manager=manager,
                workspace=str(workspace),
            )
            try:
                registry.prefetch_mcp_capabilities()
                listed = registry.list_mcp_resources("good-server")
                self.assertTrue(listed["ok"])
                self.assertEqual("connected", listed["status"])
                self.assertFalse(listed.get("unsupported"))
                self.assertEqual(1, len(listed["resources"]))

                read_payload = registry.read_mcp_resource("good-server", "memo://notes")
                self.assertTrue(read_payload["ok"])
                self.assertEqual("connected", read_payload["status"])
                self.assertEqual("memo://notes", read_payload["resource_uri"])
                self.assertTrue(Path(read_payload["saved_to"]).exists())

                unsupported_list = registry.list_mcp_resources("unsupported-server")
                self.assertFalse(unsupported_list["ok"])
                self.assertEqual("connected", unsupported_list["status"])
                self.assertTrue(unsupported_list.get("unsupported"))

                unsupported_read = registry.read_mcp_resource("unsupported-server", "memo://notes")
                self.assertFalse(unsupported_read["ok"])
                self.assertEqual("connected", unsupported_read["status"])
                self.assertTrue(unsupported_read.get("unsupported"))
            finally:
                registry.close()

    def test_board_protocol_and_continue_session_include_mcp_state(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            workspace = temp_root / "workspace"
            workspace.mkdir(parents=True, exist_ok=True)
            manager = WorkspaceManager(temp_root)

            (workspace / "triage_board.json").write_text(
                json.dumps(
                    {
                        "run": {"meta": {"status": "running", "solver": "agent-loop", "category": "web", "title": "mcp-demo"}},
                        "input_summary": {"title": "mcp-demo"},
                        "target_summary": {"target": "http://127.0.0.1", "recommended_path": "web:path"},
                        "knowledge": {},
                        "binary": {},
                        "findings": [],
                        "candidate_flags": [],
                        "exploit_plans": [],
                        "next_actions": ["check recent mcp calls"],
                        "blockers": [],
                        "subagents": [{"id": "sa-1", "status": "completed", "summary": {"what_was_found": "routes"}}],
                        "action_timeline": [
                            {"phase": "recon", "action": "http-get", "status": "ok", "summary": "fetched index", "artifact": ""}
                        ],
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8-sig",
            )

            manager.save_mcp_status(
                workspace,
                {
                    "available_servers": ["browser-mcp", "ida-mcp"],
                    "connected_servers": ["browser-mcp"],
                    "resource_enabled_servers": ["browser-mcp"],
                    "failed_servers": [{"name": "ida-mcp", "last_error": "spawn failed"}],
                    "fallback_reasons": [{"server": "ida-mcp", "reason": "resource probe failed; falling back to tools/call"}],
                    "counts": {"pending": 0, "connected": 1, "failed": 1, "disabled": 0},
                    "servers": [
                        {"name": "browser-mcp", "transport": "stdio", "status": "connected", "enabled": True, "tool_count": 1, "has_resources": True, "resource_unsupported": False, "resource_count": 1, "last_error": "", "last_checked_at": 1},
                        {"name": "ida-mcp", "transport": "stdio", "status": "failed", "enabled": True, "tool_count": 0, "has_resources": False, "resource_unsupported": False, "resource_count": 0, "last_error": "spawn failed", "last_checked_at": 2},
                    ],
                },
            )
            manager.append_mcp_call_log(
                workspace,
                {
                    "ts": 1,
                    "ok": True,
                    "status": "connected",
                    "server": "browser-mcp",
                    "tool": "browser_agent",
                    "resource_uri": "",
                    "summary": "browser_agent opened target",
                    "saved_to": "",
                    "truncated": False,
                    "elapsed_ms": 50,
                    "arguments": {"url": "http://127.0.0.1"},
                },
            )
            manager.append_mcp_call_log(
                workspace,
                {
                    "ts": 2,
                    "ok": False,
                    "status": "failed",
                    "server": "ida-mcp",
                    "tool": "resources/list",
                    "resource_uri": "",
                    "summary": "resource list failed",
                    "saved_to": "",
                    "truncated": False,
                    "elapsed_ms": 10,
                    "arguments": {},
                    "error": {"message": "spawn failed"},
                },
            )

            board_summary = build_board_summary(workspace)
            self.assertEqual(1, board_summary["mcp_status"]["counts"]["connected"])
            self.assertEqual(3, len(board_summary["recent_activity"]))
            self.assertEqual("browser-mcp", board_summary["resource_enabled_servers"][0])

            envelope = build_sync_envelope(
                "demo task",
                {"category": "web", "title": "mcp-demo", "speed_mode": "standard"},
                {"status": "running", "workspace": str(workspace), "solver": "agent-loop"},
            )
            self.assertEqual(1, envelope["summary"]["mcp_status"]["counts"]["connected"])
            self.assertEqual(3, len(envelope["summary"]["recent_activity"]))
            self.assertEqual(str(workspace / "mcp_status.json"), envelope["artifacts"]["mcp_status_path"])

            payload = CTFMCPServer()._continue_ctf_session({"workspace": str(workspace)})
            self.assertEqual(1, payload["mcp_status"]["counts"]["connected"])
            self.assertEqual(1, len(payload["subagents"]))
            self.assertEqual(3, len(payload["recent_activity"]))


if __name__ == "__main__":
    unittest.main()
