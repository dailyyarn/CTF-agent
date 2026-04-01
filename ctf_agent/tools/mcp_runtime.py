import json
import os
import subprocess
import sys
import threading
import time
from itertools import count
from pathlib import Path


PROTOCOL_VERSION = "2025-03-26"
MCP_SERVER_STATUS_PENDING = "pending"
MCP_SERVER_STATUS_CONNECTED = "connected"
MCP_SERVER_STATUS_FAILED = "failed"
MCP_SERVER_STATUS_DISABLED = "disabled"
UNSUPPORTED_METHOD_CODES = {-32601}
UNSUPPORTED_METHOD_MARKERS = [
    "method not found",
    "unsupported",
    "not supported",
    "unknown method",
]


class MCPError(RuntimeError):
    def __init__(self, message, server=None, method=None, details=None):
        RuntimeError.__init__(self, message)
        self.server = server
        self.method = method
        self.details = details or {}

    def to_dict(self):
        return {
            "message": str(self),
            "server": self.server,
            "method": self.method,
            "details": self.details,
        }


class StdioMCPClient(object):
    def __init__(self, name, command, args=None, cwd=None, env=None, timeout=25.0):
        self.name = name
        self.command = str(command)
        self.args = [str(item) for item in (args or [])]
        self.cwd = str(cwd) if cwd else None
        self.env = dict(env or {})
        self.timeout = float(timeout)

        self.process = None
        self._pending = {}
        self._pending_lock = threading.Lock()
        self._request_id = count(1)
        self._reader_thread = None
        self._stderr_thread = None
        self._started = False
        self._tool_cache = None
        self._notifications = []
        self._stderr_lines = []
        self._parse_errors = []
        self._last_initialize = None
        self._restart_count = 0
        self._resource_list_cache = None
        self._resource_unsupported = None

    def describe(self):
        return {
            "name": self.name,
            "command": self.command,
            "args": list(self.args),
            "cwd": self.cwd,
            "started": self._started,
            "pid": self.process.pid if self.process else None,
            "tool_count": len(self._tool_cache or []),
            "resource_count": len(self._resource_list_cache or []),
            "resource_unsupported": bool(self._resource_unsupported),
            "stderr_tail": self._stderr_lines[-20:],
            "parse_errors": self._parse_errors[-10:],
            "restart_count": self._restart_count,
        }

    def is_alive(self):
        return self.process is not None and self.process.poll() is None

    def start(self, force_restart=False):
        if force_restart:
            self.close()

        if self.is_alive() and self._started:
            return

        command = [self.command] + self.args
        env = os.environ.copy()
        env.update({str(key): str(value) for key, value in self.env.items()})

        try:
            self.process = subprocess.Popen(
                command,
                cwd=self.cwd,
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
        except Exception as exc:
            raise MCPError(
                "failed to start MCP server",
                server=self.name,
                method="spawn",
                details={"command": command, "error": str(exc)},
            )

        self._reader_thread = threading.Thread(target=self._read_stdout, daemon=True)
        self._stderr_thread = threading.Thread(target=self._read_stderr, daemon=True)
        self._reader_thread.start()
        self._stderr_thread.start()

        try:
            result = self._request(
                "initialize",
                {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {
                        "name": "ctf-agent",
                        "version": "0.3.0",
                    },
                },
                timeout=self.timeout,
            )
            self._last_initialize = result
            self._notify("notifications/initialized", {})
            self._started = True
        except Exception:
            self.close()
            raise

    def restart(self):
        self._restart_count += 1
        self.start(force_restart=True)

    def close(self):
        if not self.process:
            return

        try:
            if self.process.poll() is None:
                self.process.terminate()
                self.process.wait(timeout=3)
        except Exception:
            try:
                self.process.kill()
            except Exception:
                pass

        with self._pending_lock:
            for holder in self._pending.values():
                holder["response"] = {
                    "error": {
                        "message": "server closed",
                    }
                }
                holder["event"].set()
            self._pending = {}

        for stream_name in ["stdin", "stdout", "stderr"]:
            stream = getattr(self.process, stream_name, None)
            if stream:
                try:
                    stream.close()
                except Exception:
                    pass

        self.process = None
        self._started = False

    def request(self, method, params=None, timeout=None):
        self.start()
        return self._request(method, params or {}, timeout=timeout or self.timeout)

    def list_tools(self, refresh=False):
        if self._tool_cache is not None and not refresh:
            return list(self._tool_cache)

        tools = []
        cursor = None
        while True:
            params = {}
            if cursor:
                params["cursor"] = cursor
            result = self.request("tools/list", params, timeout=self.timeout)
            tools.extend(result.get("tools", []))
            cursor = result.get("nextCursor")
            if not cursor:
                break

        self._tool_cache = tools
        return list(tools)

    def list_resources(self, refresh=False):
        if self._resource_list_cache is not None and not refresh:
            return list(self._resource_list_cache)

        resources = []
        cursor = None
        while True:
            params = {}
            if cursor:
                params["cursor"] = cursor
            result = self.request("resources/list", params, timeout=self.timeout)
            resources.extend(result.get("resources", []))
            cursor = result.get("nextCursor")
            if not cursor:
                break

        self._resource_list_cache = resources
        self._resource_unsupported = False
        return list(resources)

    def read_resource(self, uri, timeout=None):
        self._resource_unsupported = False
        return self.request("resources/read", {"uri": str(uri)}, timeout=timeout or self.timeout)

    def call_tool(self, tool_name, arguments=None, timeout=None):
        return self.request(
            "tools/call",
            {
                "name": tool_name,
                "arguments": arguments or {},
            },
            timeout=timeout or self.timeout,
        )

    def _request(self, method, params, timeout):
        if not self.is_alive():
            self.restart()

        request_id = next(self._request_id)
        holder = {
            "event": threading.Event(),
            "response": None,
        }
        with self._pending_lock:
            self._pending[request_id] = holder

        payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params or {},
        }
        self._send(payload)

        if not holder["event"].wait(timeout):
            with self._pending_lock:
                self._pending.pop(request_id, None)
            raise MCPError(
                "timed out waiting for MCP response",
                server=self.name,
                method=method,
                details={"stderr_tail": self._stderr_lines[-15:]},
            )

        response = holder["response"] or {}
        if "error" in response:
            details = response["error"].get("data", {}) or {}
            if "code" in response["error"] and "code" not in details:
                details["code"] = response["error"].get("code")
            raise MCPError(
                response["error"].get("message", "unknown MCP error"),
                server=self.name,
                method=method,
                details=details,
            )
        return response.get("result", {})

    def _notify(self, method, params):
        if not self.is_alive():
            raise MCPError("server is not running", server=self.name, method=method)
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
        }
        self._send(payload)

    def _send(self, payload):
        if not self.process or not self.process.stdin:
            raise MCPError("stdin is not available", server=self.name)
        wire = json.dumps(payload, ensure_ascii=False)
        self.process.stdin.write(wire + "\n")
        self.process.stdin.flush()

    def _read_stdout(self):
        while self.process and self.process.stdout:
            line = self.process.stdout.readline()
            if not line:
                break
            text = line.strip()
            if not text:
                continue
            try:
                payload = json.loads(text)
            except Exception:
                self._parse_errors.append(text)
                continue
            self._handle_message(payload)

    def _read_stderr(self):
        while self.process and self.process.stderr:
            line = self.process.stderr.readline()
            if not line:
                break
            self._stderr_lines.append(line.rstrip())

    def _handle_message(self, payload):
        if "id" in payload:
            with self._pending_lock:
                holder = self._pending.pop(payload["id"], None)
            if holder:
                holder["response"] = payload
                holder["event"].set()
            return

        if payload.get("method") == "notifications/tools/list_changed":
            self._tool_cache = None
        if payload.get("method") == "notifications/resources/list_changed":
            self._resource_list_cache = None
        self._notifications.append(payload)


class MCPRuntimeRegistry(object):
    def __init__(
        self,
        server_configs=None,
        timeout=25.0,
        preferred_browser=None,
        preferred_reverse=None,
        workspace_manager=None,
        workspace=None,
        policy=None,
        result_preview_bytes=4000,
    ):
        self.server_configs = self._normalize_configs(server_configs or [])
        self.timeout = float(timeout)
        self.preferred_browser = preferred_browser or ""
        self.preferred_reverse = preferred_reverse or ""
        self._clients = {}
        self.workspace_manager = workspace_manager
        self.workspace = str(workspace) if workspace else ""
        self.policy = policy
        self.result_preview_bytes = int(result_preview_bytes or 4000)
        self._transport_factories = {
            "stdio": self._build_stdio_client,
        }
        self._capability_cache = {}
        self._capabilities_prefetched = False
        self._initialize_capability_cache()
        self._load_status_snapshot()

    def configure_runtime(self, workspace=None, policy=None):
        if workspace is not None:
            self.workspace = str(workspace)
            self._load_status_snapshot()
        if policy is not None:
            self.policy = policy
        return self

    def _normalize_configs(self, server_configs):
        normalized = []
        for item in list(server_configs or []):
            config = dict(item or {})
            config.setdefault("enabled", True)
            config.setdefault("transport", "stdio")
            config.setdefault("priority", 100)
            normalized.append(config)
        normalized.sort(key=lambda item: (int(item.get("priority", 100)), item.get("name", "")))
        return normalized

    def _initialize_capability_cache(self):
        existing = dict(self._capability_cache or {})
        self._capability_cache = {}
        for config in self.server_configs:
            name = str(config.get("name", "") or "")
            capability = self._default_server_capability(config)
            cached = dict(existing.get(name, {}) or {})
            for key in [
                "status",
                "tool_count",
                "tool_names",
                "tools",
                "has_resources",
                "resource_unsupported",
                "resource_count",
                "last_error",
                "last_checked_at",
                "fallback_reason",
            ]:
                if key in cached:
                    capability[key] = cached.get(key)
            if not capability.get("enabled"):
                capability["status"] = MCP_SERVER_STATUS_DISABLED
            self._capability_cache[name] = capability

    def _default_server_capability(self, config):
        enabled = bool(config.get("enabled", True))
        return {
            "name": str(config.get("name", "") or ""),
            "transport": str(config.get("transport", "stdio") or "stdio"),
            "status": MCP_SERVER_STATUS_PENDING if enabled else MCP_SERVER_STATUS_DISABLED,
            "enabled": enabled,
            "tool_count": 0,
            "tool_names": [],
            "tools": None,
            "has_resources": False,
            "resource_unsupported": False,
            "resource_count": 0,
            "last_error": "",
            "last_checked_at": None,
            "fallback_reason": "",
        }

    def _public_capability_view(self, capability):
        capability = dict(capability or {})
        return {
            "name": capability.get("name", ""),
            "transport": capability.get("transport", "stdio"),
            "status": capability.get("status", MCP_SERVER_STATUS_PENDING),
            "enabled": bool(capability.get("enabled", True)),
            "tool_count": int(capability.get("tool_count", 0) or 0),
            "tool_names": list(capability.get("tool_names", []) or [])[:30],
            "has_resources": bool(capability.get("has_resources", False)),
            "resource_unsupported": bool(capability.get("resource_unsupported", False)),
            "resource_count": int(capability.get("resource_count", 0) or 0),
            "last_error": str(capability.get("last_error", "") or ""),
            "last_checked_at": capability.get("last_checked_at"),
            "fallback_reason": str(capability.get("fallback_reason", "") or ""),
        }

    def _find_server_config(self, name, include_disabled=True):
        for item in self.server_configs:
            if item.get("name") != name:
                continue
            if not include_disabled and not item.get("enabled", True):
                return None
            return item
        return None

    def _status_snapshot_path(self):
        if not self.workspace:
            return None
        return Path(self.workspace) / "mcp_status.json"

    def _load_status_snapshot(self):
        path = self._status_snapshot_path()
        if not path or not path.exists():
            return
        try:
            payload = json.loads(path.read_text(encoding="utf-8-sig"))
        except Exception:
            return
        for item in list(payload.get("servers", []) or []):
            name = str(item.get("name", "") or "")
            if name not in self._capability_cache:
                continue
            capability = self._capability_cache[name]
            for key in [
                "status",
                "tool_count",
                "tool_names",
                "has_resources",
                "resource_unsupported",
                "resource_count",
                "last_error",
                "last_checked_at",
                "fallback_reason",
            ]:
                if key in item:
                    capability[key] = item.get(key)

    def _build_status_snapshot(self):
        servers = [self._public_capability_view(self._capability_cache[item.get("name", "")]) for item in self.server_configs]
        counts = {
            MCP_SERVER_STATUS_PENDING: 0,
            MCP_SERVER_STATUS_CONNECTED: 0,
            MCP_SERVER_STATUS_FAILED: 0,
            MCP_SERVER_STATUS_DISABLED: 0,
        }
        failed_servers = []
        resource_enabled_servers = []
        fallback_reasons = []
        for item in servers:
            status = item.get("status", MCP_SERVER_STATUS_PENDING)
            counts[status] = counts.get(status, 0) + 1
            if status == MCP_SERVER_STATUS_FAILED:
                failed_servers.append(
                    {
                        "name": item.get("name", ""),
                        "last_error": item.get("last_error", ""),
                    }
                )
            if item.get("has_resources"):
                resource_enabled_servers.append(item.get("name", ""))
            if item.get("fallback_reason"):
                fallback_reasons.append(
                    {
                        "server": item.get("name", ""),
                        "reason": item.get("fallback_reason", ""),
                    }
                )
        return {
            "updated_at": time.time(),
            "workspace": str(self.workspace or ""),
            "available_servers": [item.get("name", "") for item in servers],
            "connected_servers": [item.get("name", "") for item in servers if item.get("status") == MCP_SERVER_STATUS_CONNECTED],
            "resource_enabled_servers": resource_enabled_servers,
            "failed_servers": failed_servers,
            "fallback_reasons": fallback_reasons,
            "counts": counts,
            "servers": servers,
        }

    def _persist_status_snapshot(self):
        path = self._status_snapshot_path()
        if not path:
            return
        payload = self._build_status_snapshot()
        if self.workspace_manager:
            self.workspace_manager.save_mcp_status(self.workspace, payload)
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8-sig")

    def _build_stdio_client(self, name, config):
        command = config["command"]
        if str(command).lower() in {"python", "python.exe"}:
            command = sys.executable
        return StdioMCPClient(
            name=name,
            command=command,
            args=config.get("args", []),
            cwd=config.get("cwd"),
            env=config.get("env", {}),
            timeout=float(config.get("timeout", self.timeout)),
        )

    def _error_text(self, exc):
        if hasattr(exc, "to_dict"):
            payload = exc.to_dict()
            message = str(payload.get("message", "") or "")
            details = dict(payload.get("details", {}) or {})
            if message and details.get("error"):
                return "{0}: {1}".format(message, details.get("error"))
            return message or str(exc)
        return str(exc)

    def _is_unsupported_error(self, exc):
        details = dict(getattr(exc, "details", {}) or {})
        code = details.get("code")
        if code in UNSUPPORTED_METHOD_CODES:
            return True
        haystack = " ".join(
            [
                str(exc or ""),
                str(details.get("message", "") or ""),
                str(details.get("error", "") or ""),
            ]
        ).lower()
        return any(marker in haystack for marker in UNSUPPORTED_METHOD_MARKERS)

    def _server_state_snapshot(self, name):
        capability = self._capability_cache.get(name)
        if capability:
            return self._public_capability_view(capability)
        config = self._find_server_config(name, include_disabled=True)
        if config:
            return self._public_capability_view(self._default_server_capability(config))
        return {
            "name": str(name or ""),
            "transport": "stdio",
            "status": MCP_SERVER_STATUS_FAILED,
            "enabled": False,
            "tool_count": 0,
            "tool_names": [],
            "has_resources": False,
            "resource_unsupported": False,
            "resource_count": 0,
            "last_error": "server not configured",
            "last_checked_at": None,
            "fallback_reason": "",
        }

    def _record_runtime_error(self, server_name, exc, fallback_reason=None):
        config = self._find_server_config(server_name, include_disabled=True)
        if not config:
            return
        capability = self._capability_cache.get(server_name)
        if not capability:
            capability = self._default_server_capability(config)
            self._capability_cache[server_name] = capability
        if not capability.get("enabled"):
            capability["status"] = MCP_SERVER_STATUS_DISABLED
        elif capability.get("status") != MCP_SERVER_STATUS_CONNECTED:
            capability["status"] = MCP_SERVER_STATUS_FAILED
        capability["last_error"] = self._error_text(exc)
        capability["last_checked_at"] = time.time()
        if fallback_reason is not None:
            capability["fallback_reason"] = str(fallback_reason or "")
        self._persist_status_snapshot()

    def _ensure_server_capability(self, name, refresh=False, probe_resources=True):
        config = self._find_server_config(name, include_disabled=True)
        if not config:
            raise MCPError("no MCP server named {0}".format(name), server=name)

        capability = self._capability_cache.get(name)
        if not capability:
            capability = self._default_server_capability(config)
            self._capability_cache[name] = capability

        capability["transport"] = str(config.get("transport", "stdio") or "stdio")
        capability["enabled"] = bool(config.get("enabled", True))
        if not capability.get("enabled"):
            capability["status"] = MCP_SERVER_STATUS_DISABLED
            capability["last_checked_at"] = time.time()
            capability["tools"] = None
            capability["tool_names"] = []
            capability["tool_count"] = 0
            capability["has_resources"] = False
            capability["resource_count"] = 0
            capability["resource_unsupported"] = False
            capability["fallback_reason"] = ""
            self._persist_status_snapshot()
            return capability

        ready_for_tools = capability.get("status") == MCP_SERVER_STATUS_CONNECTED and capability.get("tools") is not None
        ready_for_resources = capability.get("has_resources") or capability.get("resource_unsupported")
        if not refresh and ready_for_tools and (not probe_resources or ready_for_resources):
            return capability

        try:
            client = self.get_client(name)
            tools = client.list_tools(refresh=refresh)
            capability["status"] = MCP_SERVER_STATUS_CONNECTED
            capability["tool_count"] = len(list(tools or []))
            capability["tool_names"] = [str(item.get("name", "") or "") for item in list(tools or [])[:30]]
            capability["tools"] = list(tools or [])
            capability["last_error"] = ""
            capability["last_checked_at"] = time.time()
        except Exception as exc:
            capability["status"] = MCP_SERVER_STATUS_FAILED
            capability["tool_count"] = 0
            capability["tool_names"] = []
            capability["tools"] = []
            capability["has_resources"] = False
            capability["resource_unsupported"] = False
            capability["resource_count"] = 0
            capability["last_error"] = self._error_text(exc)
            capability["last_checked_at"] = time.time()
            capability["fallback_reason"] = ""
            self._persist_status_snapshot()
            return capability

        if probe_resources:
            self._probe_resource_support(capability, client, refresh=refresh)
        self._persist_status_snapshot()
        return capability

    def _probe_resource_support(self, capability, client, refresh=False):
        if not refresh and (capability.get("has_resources") or capability.get("resource_unsupported")):
            return
        try:
            resources = client.list_resources(refresh=refresh)
            capability["has_resources"] = True
            capability["resource_unsupported"] = False
            capability["resource_count"] = len(list(resources or []))
            capability["fallback_reason"] = ""
        except Exception as exc:
            capability["has_resources"] = False
            capability["resource_count"] = 0
            capability["last_checked_at"] = time.time()
            if self._is_unsupported_error(exc):
                capability["resource_unsupported"] = True
                capability["fallback_reason"] = "resources unsupported; falling back to tools/call"
            else:
                capability["resource_unsupported"] = False
                capability["fallback_reason"] = "resource probe failed; falling back to tools/call"
                if not capability.get("last_error"):
                    capability["last_error"] = self._error_text(exc)

    def list_servers(self):
        payload = []
        for config in self.server_configs:
            name = config.get("name", "")
            item = {
                "name": name,
                "transport": config.get("transport", "stdio"),
                "enabled": bool(config.get("enabled", True)),
                "priority": int(config.get("priority", 100)),
            }
            item.update(self._server_state_snapshot(name))
            client = self._clients.get(name)
            if client:
                item.update(client.describe())
            payload.append(item)
        return payload

    def describe_mcp_servers(self):
        return self.list_servers()

    def enabled_servers(self):
        return [item for item in self.server_configs if item.get("enabled", True)]

    def has_servers(self):
        return bool(self.enabled_servers())

    def has_server_keywords(self, keywords):
        keywords = [item.lower() for item in (keywords or []) if item]
        for item in self.enabled_servers():
            name = item.get("name", "").lower()
            if all(keyword in name for keyword in keywords):
                return True
        return False

    def get_server_config(self, name):
        return self._find_server_config(name, include_disabled=False)

    def find_server(self, keyword):
        needle = str(keyword or "").strip().lower()
        if not needle:
            return None
        for item in self.enabled_servers():
            if needle in str(item.get("name", "")).lower():
                return item
        return None

    def get_client(self, name):
        if name in self._clients:
            return self._clients[name]

        config = self.get_server_config(name)
        if not config:
            raise MCPError("no MCP server named {0}".format(name), server=name)
        transport = (config.get("transport") or "stdio").lower()
        factory = self._transport_factories.get(transport)
        if not factory:
            raise MCPError("only stdio MCP servers are supported right now", server=name, details={"transport": transport})

        client = factory(name, config)
        self._clients[name] = client
        return client

    def close(self):
        for client in self._clients.values():
            client.close()
        self._clients = {}
        self._persist_status_snapshot()

    def _status_error_payload(self, server_name, operation_name, message, capability=None, error=None, resource_uri=""):
        snapshot = capability or self._server_state_snapshot(server_name)
        payload = {
            "ok": False,
            "server": server_name,
            "tool": operation_name,
            "status": snapshot.get("status", MCP_SERVER_STATUS_FAILED),
            "resource_uri": str(resource_uri or ""),
            "summary": str(message or "MCP call failed"),
            "saved_to": "",
            "truncated": False,
            "result_preview": "",
            "server_state_snapshot": snapshot,
            "error": error
            or {
                "message": str(message or "MCP call failed"),
                "server": server_name,
                "details": {
                    "status": snapshot.get("status", MCP_SERVER_STATUS_FAILED),
                },
            },
        }
        if resource_uri:
            payload["uri"] = str(resource_uri)
        return payload

    def list_tools(self, server_name=None, refresh=False):
        if server_name:
            capability = self._ensure_server_capability(server_name, refresh=refresh, probe_resources=False)
            if capability.get("status") != MCP_SERVER_STATUS_CONNECTED:
                return {
                    "error": self._status_error_payload(
                        server_name,
                        "tools/list",
                        capability.get("last_error", "MCP server unavailable"),
                        capability=capability,
                    ).get("error")
                }
            return list(capability.get("tools") or [])

        payload = {}
        for item in self.server_configs:
            name = item.get("name", "")
            capability = self._ensure_server_capability(name, refresh=refresh, probe_resources=False)
            if capability.get("status") != MCP_SERVER_STATUS_CONNECTED:
                payload[name] = {
                    "error": self._status_error_payload(
                        name,
                        "tools/list",
                        capability.get("last_error", "MCP server unavailable"),
                        capability=capability,
                    ).get("error")
                }
                continue
            payload[name] = list(capability.get("tools") or [])
        return payload

    def _list_resources_for_server(self, server_name, refresh=False):
        capability = self._ensure_server_capability(server_name, refresh=refresh, probe_resources=True)
        if not capability.get("enabled"):
            payload = self._status_error_payload(server_name, "resources/list", "MCP server is disabled", capability=capability)
            payload["resources"] = []
            return payload
        if capability.get("status") != MCP_SERVER_STATUS_CONNECTED:
            payload = self._status_error_payload(
                server_name,
                "resources/list",
                capability.get("last_error", "MCP server unavailable"),
                capability=capability,
            )
            payload["resources"] = []
            return payload
        if capability.get("resource_unsupported"):
            payload = self._status_error_payload(
                server_name,
                "resources/list",
                "resources/list is not supported by this server",
                capability=capability,
            )
            payload["unsupported"] = True
            payload["status"] = MCP_SERVER_STATUS_CONNECTED
            payload["resources"] = []
            payload["summary"] = "resources/list unsupported; falling back to tools/call"
            self._log_mcp_call(payload, arguments={})
            return payload
        try:
            resources = self.get_client(server_name).list_resources(refresh=refresh)
            capability["has_resources"] = True
            capability["resource_unsupported"] = False
            capability["resource_count"] = len(list(resources or []))
            capability["last_error"] = ""
            capability["last_checked_at"] = time.time()
            capability["fallback_reason"] = ""
            self._persist_status_snapshot()
            payload = self._wrap_tool_result(server_name, "resources/list", {"resources": list(resources or [])}, always_persist=True)
            payload["resources"] = list(resources or [])
            payload["status"] = MCP_SERVER_STATUS_CONNECTED
            payload["unsupported"] = False
            payload["summary"] = "resources/list returned {0} resources".format(len(payload["resources"]))
            if payload.get("saved_to"):
                payload["summary"] = "{0} (full result saved to {1})".format(payload["summary"], payload["saved_to"])
            self._log_mcp_call(payload, arguments={})
            return payload
        except Exception as exc:
            if self._is_unsupported_error(exc):
                capability["has_resources"] = False
                capability["resource_unsupported"] = True
                capability["resource_count"] = 0
                capability["last_checked_at"] = time.time()
                capability["fallback_reason"] = "resources unsupported; falling back to tools/call"
                self._persist_status_snapshot()
                payload = self._status_error_payload(
                    server_name,
                    "resources/list",
                    "resources/list is not supported by this server",
                    capability=capability,
                )
                payload["unsupported"] = True
                payload["status"] = MCP_SERVER_STATUS_CONNECTED
                payload["resources"] = []
                payload["summary"] = "resources/list unsupported; falling back to tools/call"
                self._log_mcp_call(payload, arguments={})
                return payload
            self._record_runtime_error(server_name, exc, fallback_reason="resource list failed; falling back to tools/call")
            payload = self._status_error_payload(
                server_name,
                "resources/list",
                self._error_text(exc),
                capability=self._capability_cache.get(server_name),
                error=exc.to_dict() if hasattr(exc, "to_dict") else None,
            )
            payload["resources"] = []
            self._log_mcp_call(payload, arguments={})
            return payload

    def list_mcp_resources(self, server_name=None):
        if server_name:
            return self._list_resources_for_server(server_name)
        return [self._list_resources_for_server(item.get("name", "")) for item in self.server_configs]

    def read_mcp_resource(self, server_name, uri):
        capability = self._ensure_server_capability(server_name, probe_resources=True)
        resource_uri = str(uri or "")
        if not capability.get("enabled"):
            return self._status_error_payload(server_name, "resources/read", "MCP server is disabled", capability=capability, resource_uri=resource_uri)
        if capability.get("status") != MCP_SERVER_STATUS_CONNECTED:
            return self._status_error_payload(
                server_name,
                "resources/read",
                capability.get("last_error", "MCP server unavailable"),
                capability=capability,
                resource_uri=resource_uri,
            )
        if capability.get("resource_unsupported"):
            payload = self._status_error_payload(
                server_name,
                "resources/read",
                "resources/read is not supported by this server",
                capability=capability,
                resource_uri=resource_uri,
            )
            payload["unsupported"] = True
            payload["status"] = MCP_SERVER_STATUS_CONNECTED
            payload["summary"] = "resources/read unsupported; falling back to tools/call"
            self._log_mcp_call(payload, arguments={"uri": resource_uri})
            return payload
        try:
            result = self.get_client(server_name).read_resource(resource_uri, timeout=self.timeout)
            capability["has_resources"] = True
            capability["resource_unsupported"] = False
            capability["last_error"] = ""
            capability["last_checked_at"] = time.time()
            capability["fallback_reason"] = ""
            self._persist_status_snapshot()
            payload = self._wrap_tool_result(server_name, "resources/read", result, resource_uri=resource_uri, always_persist=True)
            payload["uri"] = resource_uri
            payload["status"] = MCP_SERVER_STATUS_CONNECTED
            payload["unsupported"] = False
            if payload.get("result_preview"):
                payload["summary"] = "read resource {0}: {1}".format(resource_uri, payload["result_preview"][:180])
            else:
                payload["summary"] = "read resource {0}".format(resource_uri)
            if payload.get("saved_to"):
                payload["summary"] = "{0} (full result saved to {1})".format(payload["summary"], payload["saved_to"])
            self._log_mcp_call(payload, arguments={"uri": resource_uri})
            return payload
        except Exception as exc:
            if self._is_unsupported_error(exc):
                capability["has_resources"] = False
                capability["resource_unsupported"] = True
                capability["resource_count"] = 0
                capability["last_checked_at"] = time.time()
                capability["fallback_reason"] = "resources unsupported; falling back to tools/call"
                self._persist_status_snapshot()
                payload = self._status_error_payload(
                    server_name,
                    "resources/read",
                    "resources/read is not supported by this server",
                    capability=capability,
                    resource_uri=resource_uri,
                )
                payload["unsupported"] = True
                payload["status"] = MCP_SERVER_STATUS_CONNECTED
                payload["summary"] = "resources/read unsupported; falling back to tools/call"
                self._log_mcp_call(payload, arguments={"uri": resource_uri})
                return payload
            self._record_runtime_error(server_name, exc, fallback_reason="resource read failed; falling back to tools/call")
            payload = self._status_error_payload(
                server_name,
                "resources/read",
                self._error_text(exc),
                capability=self._capability_cache.get(server_name),
                error=exc.to_dict() if hasattr(exc, "to_dict") else None,
                resource_uri=resource_uri,
            )
            self._log_mcp_call(payload, arguments={"uri": resource_uri})
            return payload

    def prefetch_mcp_capabilities(self):
        payload = []
        for item in self.server_configs:
            capability = self._ensure_server_capability(item.get("name", ""), refresh=True, probe_resources=True)
            payload.append(self._public_capability_view(capability))
        self._capabilities_prefetched = True
        self._persist_status_snapshot()
        return payload

    def call_tool(self, server_name, tool_name, arguments=None, timeout=None):
        if self.policy:
            decision = self.policy.evaluate_mcp_server(server_name, tool_name=tool_name)
            if getattr(decision, "decision", "") == "deny":
                raise MCPError(
                    getattr(decision, "reason", "MCP call blocked"),
                    server=server_name,
                    method="tools/call",
                    details=dict(getattr(decision, "details", {}) or {}),
                )
            if getattr(decision, "decision", "") == "ask":
                raise MCPError(
                    getattr(decision, "reason", "approval required"),
                    server=server_name,
                    method="tools/call",
                    details={
                        "status": "needs_approval",
                        "request_id": getattr(decision, "request_id", ""),
                        "approval": decision.to_dict() if hasattr(decision, "to_dict") else {},
                    },
                )
        capability = self._ensure_server_capability(server_name, probe_resources=False)
        if capability.get("status") != MCP_SERVER_STATUS_CONNECTED:
            raise MCPError(
                capability.get("last_error", "MCP server unavailable"),
                server=server_name,
                method="tools/call",
                details={"status": capability.get("status", MCP_SERVER_STATUS_FAILED)},
            )
        result = self.get_client(server_name).call_tool(tool_name, arguments=arguments, timeout=timeout)
        capability["status"] = MCP_SERVER_STATUS_CONNECTED
        capability["last_error"] = ""
        capability["last_checked_at"] = time.time()
        self._persist_status_snapshot()
        return result

    def call_tool_safe(self, server_name, tool_name, arguments=None, timeout=None):
        start = time.time()
        try:
            raw = self.call_tool(server_name, tool_name, arguments=arguments, timeout=timeout)
            payload = self._wrap_tool_result(server_name, tool_name, raw)
            payload["elapsed_ms"] = int((time.time() - start) * 1000)
            self._log_mcp_call(payload, arguments=arguments)
            return payload
        except Exception as exc:
            error = exc.to_dict() if hasattr(exc, "to_dict") else {"message": str(exc), "details": {}}
            if dict(error.get("details") or {}).get("status") == "needs_approval":
                payload = self._status_error_payload(
                    server_name,
                    tool_name,
                    error.get("message", "approval required"),
                    capability=self._capability_cache.get(server_name),
                    error=error,
                )
                payload["status"] = "needs_approval"
                payload["request_id"] = dict(error.get("details") or {}).get("request_id", "")
                payload["approval"] = dict(error.get("details") or {}).get("approval", {})
                payload["elapsed_ms"] = int((time.time() - start) * 1000)
                self._log_mcp_call(payload, arguments=arguments)
                return payload
            self._record_runtime_error(server_name, exc)
            payload = self._status_error_payload(
                server_name,
                tool_name,
                error.get("message", "MCP call failed"),
                capability=self._capability_cache.get(server_name),
                error=error,
            )
            payload["elapsed_ms"] = int((time.time() - start) * 1000)
            self._log_mcp_call(payload, arguments=arguments)
            return payload

    def _wrap_tool_result(self, server_name, tool_name, result, resource_uri="", always_persist=False):
        preview_text = self.flatten_tool_result(result)
        structured = self.extract_tool_data(result)
        serialized = result
        saved_to = ""
        truncated = False
        should_persist = always_persist or self._should_persist_full_result(result, preview_text)
        if should_persist:
            saved_to = self._persist_tool_result(server_name, tool_name, result, resource_uri=resource_uri)
            if len(preview_text or "") > self.result_preview_bytes:
                preview_text = preview_text[: self.result_preview_bytes]
                truncated = True
        snapshot = self._server_state_snapshot(server_name)
        return {
            "ok": True,
            "server": server_name,
            "tool": tool_name,
            "status": snapshot.get("status", MCP_SERVER_STATUS_CONNECTED),
            "resource_uri": str(resource_uri or ""),
            "summary": self._summarize_tool_result(tool_name, preview_text, structured, saved_to, resource_uri=resource_uri),
            "saved_to": str(saved_to or ""),
            "truncated": bool(truncated),
            "result_preview": preview_text[: self.result_preview_bytes],
            "result": serialized,
            "server_state_snapshot": snapshot,
        }

    def _should_persist_full_result(self, result, preview_text):
        if len(preview_text or "") > self.result_preview_bytes:
            return True
        if isinstance(result, dict):
            for key in ["content", "contents"]:
                content = result.get(key)
                if isinstance(content, list):
                    for item in content:
                        if not isinstance(item, dict):
                            continue
                        if item.get("blob") is not None:
                            return True
                        if item.get("type") not in {"text", "", None}:
                            return True
        return False

    def _persist_tool_result(self, server_name, tool_name, result, resource_uri=""):
        if not self.workspace:
            return ""
        safe_server = _slugify(server_name or "server")
        safe_tool = _slugify(tool_name or "tool")
        if resource_uri:
            safe_tool = "{0}-{1}".format(safe_tool, _slugify(resource_uri)[:80])
        artifacts_dir = Path(self.workspace) / "artifacts" / "mcp"
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        path = artifacts_dir / "{0}-{1}-{2}.json".format(safe_server, safe_tool, int(time.time() * 1000))
        if self.workspace_manager:
            self.workspace_manager.write_json(path, result)
        else:
            path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8-sig")
        return str(path)

    def _summarize_tool_result(self, tool_name, preview_text, structured, saved_to, resource_uri=""):
        label = resource_uri or tool_name
        text = str(preview_text or "").strip()
        if text:
            summary = text[:240]
        elif structured:
            summary = "{0} returned structured data".format(label)
        else:
            summary = "{0} returned an empty result".format(label)
        if saved_to:
            summary = "{0} (full result saved to {1})".format(summary, saved_to)
        return summary

    def _log_mcp_call(self, payload, arguments=None):
        if not self.workspace:
            return
        record = {
            "ts": time.time(),
            "ok": bool(payload.get("ok")),
            "status": payload.get("status", ""),
            "server": payload.get("server", ""),
            "tool": payload.get("tool", ""),
            "resource_uri": payload.get("resource_uri", ""),
            "summary": payload.get("summary", ""),
            "saved_to": payload.get("saved_to", ""),
            "truncated": bool(payload.get("truncated", False)),
            "elapsed_ms": int(payload.get("elapsed_ms", 0) or 0),
            "arguments": dict(arguments or {}),
        }
        if payload.get("error"):
            record["error"] = payload.get("error")
        if payload.get("server_state_snapshot"):
            record["server_state_snapshot"] = payload.get("server_state_snapshot")
        if self.workspace_manager:
            self.workspace_manager.append_mcp_call_log(self.workspace, record)
            return
        log_path = Path(self.workspace) / "logs" / "mcp_call_log.jsonl"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8-sig") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    def find_tools(self, tool_keywords=None, server_keywords=None, connected_only=True, refresh=False):
        if refresh or not self._capabilities_prefetched:
            self.prefetch_mcp_capabilities()
        tool_keywords = [item.lower() for item in (tool_keywords or []) if item]
        server_keywords = [item.lower() for item in (server_keywords or []) if item]
        matches = []
        for server in self.server_configs:
            server_name = server.get("name", "")
            if server_keywords and not all(keyword in server_name.lower() for keyword in server_keywords):
                continue
            capability = self._capability_cache.get(server_name) or self._default_server_capability(server)
            if not capability.get("enabled"):
                continue
            if capability.get("status") != MCP_SERVER_STATUS_CONNECTED:
                if not connected_only:
                    matches.append(
                        {
                            "server": server_name,
                            "status": capability.get("status", MCP_SERVER_STATUS_PENDING),
                            "error": {
                                "message": capability.get("last_error", "MCP server unavailable"),
                                "server": server_name,
                            },
                            "server_state_snapshot": self._server_state_snapshot(server_name),
                        }
                    )
                continue
            tools = list(capability.get("tools") or [])
            if refresh or not tools:
                capability = self._ensure_server_capability(server_name, refresh=refresh, probe_resources=False)
                tools = list(capability.get("tools") or [])
            for tool in tools:
                haystack = " ".join(
                    [
                        tool.get("name", ""),
                        tool.get("description", ""),
                        json.dumps(tool.get("inputSchema", {}), ensure_ascii=False),
                    ]
                ).lower()
                if tool_keywords and not all(keyword in haystack for keyword in tool_keywords):
                    continue
                matches.append({"server": server_name, "tool": tool, "server_state_snapshot": self._server_state_snapshot(server_name)})
        return matches

    def call_first_matching(self, tool_keywords=None, server_keywords=None, arguments=None, timeout=None):
        matches = [item for item in self.find_tools(tool_keywords=tool_keywords, server_keywords=server_keywords) if "tool" in item]
        if not matches:
            raise MCPError("no matching MCP tool found", method="find_tools")
        choice = matches[0]
        return {
            "server": choice["server"],
            "tool": choice["tool"]["name"],
            "result": self.call_tool(choice["server"], choice["tool"]["name"], arguments=arguments, timeout=timeout),
        }

    def tool_digest(self):
        if not self._capabilities_prefetched:
            self.prefetch_mcp_capabilities()
        digest = []
        for server in self.server_configs:
            capability = self._capability_cache.get(server.get("name", "")) or self._default_server_capability(server)
            if capability.get("status") != MCP_SERVER_STATUS_CONNECTED:
                digest.append(
                    {
                        "server": server.get("name", ""),
                        "status": capability.get("status", MCP_SERVER_STATUS_PENDING),
                        "error": {
                            "message": capability.get("last_error", "MCP server unavailable"),
                            "server": server.get("name", ""),
                        },
                    }
                )
                continue
            digest.append(
                {
                    "server": server.get("name", ""),
                    "status": capability.get("status", MCP_SERVER_STATUS_CONNECTED),
                    "tool_count": int(capability.get("tool_count", 0) or 0),
                    "tools": list(capability.get("tool_names", []))[:30],
                    "has_resources": bool(capability.get("has_resources", False)),
                }
            )
        return digest

    def pick_browser_tool(self):
        preferred_name = self.preferred_browser.lower()
        candidates = []
        for item in self.find_tools(tool_keywords=["browser"], server_keywords=[preferred_name] if preferred_name else None, connected_only=True):
            if "tool" in item:
                candidates.append(item)
        if not candidates:
            preferred = [
                ("browser", ["run_browser_agent"]),
                ("browser", ["browser", "agent"]),
                ("browser", ["browser"]),
                ("playwright", ["browser"]),
            ]
            for server_keyword, tool_keywords in preferred:
                matches = [
                    item
                    for item in self.find_tools(tool_keywords=tool_keywords, server_keywords=[server_keyword], connected_only=True)
                    if "tool" in item
                ]
                if matches:
                    return matches[0]
        return candidates[0] if candidates else None

    def pick_reverse_tool(self, server_keyword=None):
        preferred_name = (server_keyword or self.preferred_reverse).lower()
        candidates = []
        for item in self.find_tools(server_keywords=[preferred_name] if preferred_name else None, connected_only=True):
            if "tool" not in item:
                continue
            tool_name = str(item["tool"].get("name", "") or "")
            if tool_name == "check_connection":
                continue
            haystack = " ".join(
                [
                    item["server"],
                    tool_name,
                    item["tool"].get("description", ""),
                ]
            ).lower()
            if any(keyword in haystack for keyword in ["ida", "ghidra", "decompile", "disasm", "reverse"]):
                score = 0
                if "decompile" in haystack:
                    score += 8
                if "disasm" in haystack or "function" in haystack:
                    score += 6
                if "string" in haystack or "import" in haystack or "entry" in haystack:
                    score += 4
                if "ida" in item["server"].lower():
                    score += 3
                if "ghidra" in item["server"].lower():
                    score += 2
                candidates.append((score, item))
        if candidates:
            candidates.sort(key=lambda item: item[0], reverse=True)
            return candidates[0][1]
        return None

    def build_browser_arguments(self, tool_descriptor, task, url):
        tool = tool_descriptor.get("tool", {})
        schema = tool.get("inputSchema", {})
        properties = schema.get("properties", {})
        arguments = {}

        if "task" in properties:
            arguments["task"] = task
        if "prompt" in properties and "prompt" not in arguments:
            arguments["prompt"] = task
        if "instruction" in properties and "instruction" not in arguments:
            arguments["instruction"] = task
        if "goal" in properties and "goal" not in arguments:
            arguments["goal"] = task
        if "url" in properties:
            arguments["url"] = url
        if "start_url" in properties:
            arguments["start_url"] = url
        if "headless" in properties:
            arguments["headless"] = True
        if "allowed_domains" in properties:
            arguments["allowed_domains"] = [self._extract_domain(url)]

        for name in schema.get("required", []):
            if name not in arguments:
                arguments[name] = url if "url" in name else task
        return arguments

    def call_browser_task(self, task, url, timeout=None):
        descriptor = self.pick_browser_tool()
        if not descriptor:
            raise MCPError("no browser MCP tool available", method="pick_browser_tool")
        arguments = self.build_browser_arguments(descriptor, task, url)
        return {
            "server": descriptor["server"],
            "tool": descriptor["tool"]["name"],
            "arguments": arguments,
            "result": self.call_tool(descriptor["server"], descriptor["tool"]["name"], arguments=arguments, timeout=timeout),
        }

    def call_browser_task_safe(self, task, url, timeout=None):
        descriptor = self.pick_browser_tool()
        if not descriptor:
            return self._status_error_payload("", "", "no browser MCP tool available")
        arguments = self.build_browser_arguments(descriptor, task, url)
        payload = self.call_tool_safe(descriptor["server"], descriptor["tool"]["name"], arguments=arguments, timeout=timeout)
        payload.setdefault("server", descriptor["server"])
        payload.setdefault("tool", descriptor["tool"]["name"])
        payload["arguments"] = arguments
        payload["server_state_snapshot"] = dict(payload.get("server_state_snapshot") or self._server_state_snapshot(descriptor["server"]))
        return payload

    def call_browser_flow(self, url, action="recon", task=None, timeout=None, **extra_arguments):
        descriptor = self.pick_browser_tool()
        if not descriptor:
            raise MCPError("no browser MCP tool available", method="pick_browser_tool")

        tool = descriptor.get("tool", {})
        schema = tool.get("inputSchema", {})
        properties = dict(schema.get("properties", {}))
        default_task = task or "Open the target and summarize forms, routes, hidden parameters, CSRF tokens, upload flows, login transitions, and interesting DOM/API behavior."
        arguments = self.build_browser_arguments(descriptor, default_task, url)
        if "action" in properties:
            arguments["action"] = str(action or "recon")

        for key, value in dict(extra_arguments or {}).items():
            if value is None:
                continue
            if key in properties:
                arguments[key] = value

        for name in schema.get("required", []):
            if name not in arguments:
                if "url" in name:
                    arguments[name] = url
                elif name == "action":
                    arguments[name] = str(action or "recon")
                else:
                    arguments[name] = default_task

        result = self.call_tool(descriptor["server"], descriptor["tool"]["name"], arguments=arguments, timeout=timeout)
        return {
            "server": descriptor["server"],
            "tool": descriptor["tool"]["name"],
            "arguments": arguments,
            "result": result,
            "structured": self.extract_tool_data(result),
        }

    def call_browser_flow_safe(self, url, action="recon", task=None, timeout=None, **extra_arguments):
        descriptor = self.pick_browser_tool()
        if not descriptor:
            return self._status_error_payload("", "", "no browser MCP tool available")
        tool = descriptor.get("tool", {})
        schema = tool.get("inputSchema", {})
        properties = dict(schema.get("properties", {}))
        default_task = task or "Open the target and summarize forms, routes, hidden parameters, CSRF tokens, upload flows, login transitions, and interesting DOM/API behavior."
        arguments = self.build_browser_arguments(descriptor, default_task, url)
        if "action" in properties:
            arguments["action"] = str(action or "recon")
        for key, value in dict(extra_arguments or {}).items():
            if value is None:
                continue
            if key in properties:
                arguments[key] = value
        for name in schema.get("required", []):
            if name not in arguments:
                if "url" in name:
                    arguments[name] = url
                elif name == "action":
                    arguments[name] = str(action or "recon")
                else:
                    arguments[name] = default_task
        payload = self.call_tool_safe(descriptor["server"], descriptor["tool"]["name"], arguments=arguments, timeout=timeout)
        payload.setdefault("server", descriptor["server"])
        payload.setdefault("tool", descriptor["tool"]["name"])
        payload["arguments"] = arguments
        payload.setdefault("structured", self.extract_tool_data(payload.get("result")))
        payload["server_state_snapshot"] = dict(payload.get("server_state_snapshot") or self._server_state_snapshot(descriptor["server"]))
        return payload

    def analyze_with_reverse(self, binary_path, task=None, timeout=None, server_keyword=None):
        descriptor = self.pick_reverse_tool(server_keyword=server_keyword)
        if not descriptor:
            raise MCPError("no reverse MCP tool available", method="pick_reverse_tool")
        haystack = "{0} {1}".format(descriptor["server"], descriptor["tool"].get("name", "")).lower()
        if "ida" in haystack:
            return self._analyze_with_ida_template(descriptor["server"], binary_path, task=task, timeout=timeout)
        tool = descriptor["tool"]
        schema = tool.get("inputSchema", {})
        properties = schema.get("properties", {})
        arguments = {}
        task = task or "Open the binary, summarize key functions, input validation, and any obvious flag path."

        for key in ["path", "file", "binary_path", "target"]:
            if key in properties:
                arguments[key] = binary_path
                break
        for key in ["task", "prompt", "instruction"]:
            if key in properties:
                arguments[key] = task
                break
        for name in schema.get("required", []):
            if name not in arguments:
                arguments[name] = binary_path if "path" in name or "file" in name or "target" in name else task
        return {
            "server": descriptor["server"],
            "tool": tool["name"],
            "arguments": arguments,
            "result": self.call_tool(descriptor["server"], tool["name"], arguments=arguments, timeout=timeout),
        }

    def analyze_with_reverse_safe(self, binary_path, task=None, timeout=None, server_keyword=None):
        descriptor = self.pick_reverse_tool(server_keyword=server_keyword)
        if not descriptor:
            return self._status_error_payload("", "", "no reverse MCP tool available")
        haystack = "{0} {1}".format(descriptor["server"], descriptor["tool"].get("name", "")).lower()
        if "ida" in haystack:
            try:
                payload = self._analyze_with_ida_template(descriptor["server"], binary_path, task=task, timeout=timeout)
                payload["status"] = "ok"
                payload["server_state_snapshot"] = self._server_state_snapshot(descriptor["server"])
                return payload
            except Exception as exc:
                error = exc.to_dict() if hasattr(exc, "to_dict") else {"message": str(exc)}
                if dict(error.get("details") or {}).get("status") == "needs_approval":
                    return {
                        "status": "needs_approval",
                        "server": descriptor["server"],
                        "tool": descriptor["tool"].get("name", ""),
                        "request_id": dict(error.get("details") or {}).get("request_id", ""),
                        "approval": dict(error.get("details") or {}).get("approval", {}),
                        "message": error.get("message", "approval required"),
                        "server_state_snapshot": self._server_state_snapshot(descriptor["server"]),
                    }
                return self._status_error_payload(
                    descriptor["server"],
                    descriptor["tool"].get("name", ""),
                    error.get("message", "reverse analysis failed"),
                    capability=self._capability_cache.get(descriptor["server"]),
                    error=error,
                )
        tool = descriptor["tool"]
        schema = tool.get("inputSchema", {})
        properties = schema.get("properties", {})
        arguments = {}
        task = task or "Open the binary, summarize key functions, input validation, and any obvious flag path."
        for key in ["path", "file", "binary_path", "target"]:
            if key in properties:
                arguments[key] = binary_path
                break
        for key in ["task", "prompt", "instruction"]:
            if key in properties:
                arguments[key] = task
                break
        for name in schema.get("required", []):
            if name not in arguments:
                arguments[name] = binary_path if "path" in name or "file" in name or "target" in name else task
        payload = self.call_tool_safe(descriptor["server"], tool["name"], arguments=arguments, timeout=timeout)
        payload.setdefault("server", descriptor["server"])
        payload.setdefault("tool", tool["name"])
        payload["arguments"] = arguments
        payload["server_state_snapshot"] = dict(payload.get("server_state_snapshot") or self._server_state_snapshot(descriptor["server"]))
        return payload

    def _analyze_with_ida_template(self, server_name, binary_path, task=None, timeout=None):
        timeout = timeout or self.timeout
        task = task or "Open the binary, summarize key functions, input validation, and any obvious flag path."

        metadata_result = self.call_tool(server_name, "get_metadata", arguments={}, timeout=timeout)
        metadata = self._unwrap_tool_data(metadata_result)
        strings = self._ida_list_data(server_name, "list_strings", count=80, timeout=timeout)
        imports = self._ida_list_data(server_name, "list_imports", count=80, timeout=timeout)
        functions = self._ida_list_data(server_name, "list_functions", count=80, timeout=timeout)
        entry_points_result = self.call_tool(server_name, "get_entry_points", arguments={}, timeout=timeout)
        entry_points = self._unwrap_tool_data(entry_points_result)

        highlighted_functions = self._select_interesting_reverse_functions(functions)
        decompilations = []
        for item in highlighted_functions[:3]:
            address = str(item.get("address", "") or item.get("start_ea", "") or "").strip()
            if not address and item.get("name"):
                function_detail_result = self.call_tool(
                    server_name,
                    "get_function_by_name",
                    arguments={"name": str(item.get("name"))},
                    timeout=timeout,
                )
                function_detail = self._unwrap_tool_data(function_detail_result)
                if isinstance(function_detail, dict):
                    address = str(function_detail.get("address", "") or function_detail.get("start_ea", "") or "").strip()
            if not address:
                continue
            try:
                pseudo = self.call_tool(server_name, "decompile_function", arguments={"address": address}, timeout=timeout)
                decompilations.append(
                    {
                        "address": address,
                        "name": item.get("name", ""),
                        "text": self.flatten_tool_result(pseudo)[:12000],
                    }
                )
            except MCPError:
                try:
                    asm = self.call_tool(server_name, "disassemble_function", arguments={"start_address": address}, timeout=timeout)
                    decompilations.append(
                        {
                            "address": address,
                            "name": item.get("name", ""),
                            "text": self.flatten_tool_result(asm)[:12000],
                        }
                    )
                except MCPError:
                    continue

        summary = self._build_ida_summary(metadata, strings, imports, functions, entry_points, highlighted_functions, decompilations, task)
        structured = {
            "task": task,
            "binary_path": str(binary_path),
            "metadata": metadata,
            "strings": strings[:80],
            "imports": imports[:80],
            "functions": functions[:80],
            "entry_points": entry_points,
            "highlighted_functions": highlighted_functions[:10],
            "decompilations": decompilations,
            "summary": summary,
        }
        return {
            "server": server_name,
            "tool": "ida-template",
            "arguments": {"binary_path": binary_path, "task": task},
            "result": {
                "structuredContent": structured,
                "content": [{"type": "text", "text": summary}],
                "isError": False,
            },
        }

    def _ida_list_data(self, server_name, tool_name, count=80, timeout=None):
        result = self.call_tool(server_name, tool_name, arguments={"offset": 0, "count": int(count)}, timeout=timeout)
        data = self._unwrap_tool_data(result)
        if isinstance(data, dict):
            return list(data.get("data", []))
        if isinstance(data, list):
            return data
        return []

    def _unwrap_tool_data(self, result):
        data = self.extract_tool_data(result)
        if isinstance(data, dict) and list(data.keys()) == ["result"]:
            return data.get("result")
        return data

    def _select_interesting_reverse_functions(self, functions):
        candidates = []
        for item in list(functions or []):
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", "") or item.get("function_name", "") or "").strip()
            if not name:
                continue
            lowered = name.lower()
            score = 0
            for keyword in ["main", "win", "flag", "check", "validate", "decode", "decrypt", "auth", "cmp", "strcmp", "memcmp", "xor", "vm", "state"]:
                if keyword in lowered:
                    score += 10
            if lowered.startswith("sub_"):
                score -= 2
            candidates.append((score, item))
        candidates.sort(key=lambda entry: (entry[0], len(str(entry[1].get("name", "")))), reverse=True)
        return [item for _score, item in candidates[:12]]

    def _build_ida_summary(self, metadata, strings, imports, functions, entry_points, highlighted_functions, decompilations, task):
        module = ""
        if isinstance(metadata, dict):
            module = str(metadata.get("module", "") or metadata.get("path", "") or "")
        parts = [
            "IDA template summary",
            "module={0}".format(module or "?"),
            "functions={0}".format(len(list(functions or []))),
            "imports={0}".format(len(list(imports or []))),
            "strings={0}".format(len(list(strings or []))),
            "entry_points={0}".format(len(list(entry_points or [])) if isinstance(entry_points, list) else 0),
        ]
        if highlighted_functions:
            names = [str(item.get("name", "") or item.get("function_name", "")) for item in highlighted_functions[:6]]
            parts.append("highlighted={0}".format(", ".join([item for item in names if item])))
        if decompilations:
            parts.append("decompiled={0}".format(", ".join([str(item.get("name", "") or item.get("address", "")) for item in decompilations[:3]])))
        if task:
            parts.append("task={0}".format(task))
        return " | ".join(parts)

    def flatten_tool_result(self, result):
        if result is None:
            return ""
        if isinstance(result, str):
            return result
        if isinstance(result, dict):
            content = result.get("content")
            if not isinstance(content, list):
                content = result.get("contents")
            if isinstance(content, list):
                parts = []
                for item in content:
                    if isinstance(item, dict):
                        if "text" in item:
                            parts.append(str(item["text"]))
                        elif "data" in item:
                            parts.append(json.dumps(item["data"], ensure_ascii=False))
                        elif "blob" in item:
                            parts.append("[blob:{0}]".format(item.get("mimeType", "application/octet-stream")))
                        else:
                            parts.append(json.dumps(item, ensure_ascii=False))
                    else:
                        parts.append(str(item))
                return "\n".join(parts)
            return json.dumps(result, ensure_ascii=False, indent=2)
        if isinstance(result, list):
            return "\n".join(self.flatten_tool_result(item) for item in result)
        return str(result)

    def extract_tool_data(self, result):
        if result is None:
            return {}
        if isinstance(result, dict):
            structured = result.get("structuredContent")
            if isinstance(structured, dict):
                return structured
            content = result.get("content")
            if not isinstance(content, list):
                content = result.get("contents")
            if isinstance(content, list):
                for item in content:
                    if isinstance(item, dict) and isinstance(item.get("data"), dict):
                        return item["data"]
            if all(isinstance(key, str) for key in result.keys()):
                return result
        return {}

    def _extract_domain(self, url):
        text = str(url)
        for prefix in ["https://", "http://"]:
            if text.startswith(prefix):
                text = text[len(prefix):]
                break
        return text.split("/", 1)[0]


def _slugify(value):
    text = str(value or "item").strip()
    text = "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in text)
    text = text.strip("-")
    return text or "item"
