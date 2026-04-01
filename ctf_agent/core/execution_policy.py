import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse

from ctf_agent.core.approval import PolicyDecision


class PolicyError(PermissionError):
    def __init__(self, operation, reason, **details):
        self.operation = str(operation or "operation")
        self.reason = str(reason or "blocked by execution policy")
        self.details = dict(details or {})
        PermissionError.__init__(self, "{0}: {1}".format(self.operation, self.reason))

    def to_dict(self):
        payload = {
            "ok": False,
            "operation": self.operation,
            "reason": self.reason,
        }
        if self.details:
            payload["details"] = self.details
        return payload


@dataclass
class ExecutionPolicy:
    allowed_roots: List[str] = field(default_factory=list)
    denied_roots: List[str] = field(default_factory=list)
    max_file_read_bytes: int = 1024 * 1024
    max_shell_timeout_sec: int = 30
    allow_workspace_writes_only: bool = True
    allow_remote: bool = False
    allowed_remote_hosts: List[str] = field(default_factory=list)
    allow_public_web_targets_only: bool = True
    allow_background_remote: bool = False
    allow_mcp_servers: List[str] = field(default_factory=list)
    workspace_root: str = ""
    mode: str = "main"
    approval_policy: Dict[str, Any] = field(default_factory=dict)
    approval_manager: Any = None
    run_id: str = ""

    @classmethod
    def build_default(
        cls,
        workspace,
        attachments=None,
        category="",
        target="",
        remote_hosts=None,
        mcp_servers=None,
        mode="main",
        approval_policy=None,
        approval_manager=None,
        run_id="",
    ):
        workspace_path = Path(workspace).resolve()
        category = str(category or "").strip().lower()
        allowed = [str(workspace_path)]
        for item in list(attachments or []):
            try:
                allowed.append(str(Path(item).resolve()))
            except Exception:
                continue
        remote_host_names = [str(name) for name in list(remote_hosts or []) if str(name or "").strip()]
        enabled_mcp = [str(name) for name in list(mcp_servers or []) if str(name or "").strip()]
        allow_remote = category in {"pwn", "re", "reverse"} or (category == "web" and is_public_target(target))
        return cls(
            allowed_roots=_dedupe_paths(allowed),
            denied_roots=[],
            max_file_read_bytes=1024 * 1024,
            max_shell_timeout_sec=20 if mode == "subagent" else 45,
            allow_workspace_writes_only=True,
            allow_remote=allow_remote,
            allowed_remote_hosts=remote_host_names,
            allow_public_web_targets_only=True,
            allow_background_remote=False if mode == "subagent" else allow_remote,
            allow_mcp_servers=enabled_mcp,
            workspace_root=str(workspace_path),
            mode=mode,
            approval_policy=dict(approval_policy or {}),
            approval_manager=approval_manager,
            run_id=str(run_id or ""),
        )

    def for_subagent(self, workspace_dir):
        child_workspace = Path(workspace_dir).resolve()
        roots = [str(child_workspace)] + list(self.allowed_roots or [])
        return ExecutionPolicy(
            allowed_roots=_dedupe_paths(roots),
            denied_roots=list(self.denied_roots or []),
            max_file_read_bytes=min(int(self.max_file_read_bytes or 0) or 1024 * 1024, 256 * 1024),
            max_shell_timeout_sec=min(int(self.max_shell_timeout_sec or 0) or 20, 20),
            allow_workspace_writes_only=True,
            allow_remote=False,
            allowed_remote_hosts=[],
            allow_public_web_targets_only=bool(self.allow_public_web_targets_only),
            allow_background_remote=False,
            allow_mcp_servers=list(self.allow_mcp_servers or []),
            workspace_root=str(child_workspace),
            mode="subagent",
            approval_policy=dict(self.approval_policy or {}),
            approval_manager=self.approval_manager,
            run_id=str(self.run_id or ""),
        )

    def for_remote_subagent(self, workspace_dir, host_name):
        child_workspace = Path(workspace_dir).resolve()
        roots = [str(child_workspace)] + list(self.allowed_roots or [])
        remote_host = str(host_name or "").strip()
        allowed_remote_hosts = [remote_host] if remote_host else list(self.allowed_remote_hosts or [])
        return ExecutionPolicy(
            allowed_roots=_dedupe_paths(roots),
            denied_roots=list(self.denied_roots or []),
            max_file_read_bytes=min(int(self.max_file_read_bytes or 0) or 1024 * 1024, 256 * 1024),
            max_shell_timeout_sec=min(int(self.max_shell_timeout_sec or 0) or 20, 20),
            allow_workspace_writes_only=True,
            allow_remote=True,
            allowed_remote_hosts=[item for item in allowed_remote_hosts if str(item or "").strip()],
            allow_public_web_targets_only=bool(self.allow_public_web_targets_only),
            allow_background_remote=False,
            allow_mcp_servers=list(self.allow_mcp_servers or []),
            workspace_root=str(child_workspace),
            mode="subagent",
            approval_policy={"enabled": False},
            approval_manager=None,
            run_id=str(self.run_id or ""),
        )

    def apply_overlay(self, overlay=None):
        overlay = dict(overlay or {})
        if not overlay:
            return self
        allowed_remote_hosts = list(self.allowed_remote_hosts or [])
        if list(overlay.get("allowed_remote_hosts") or []):
            overlay_hosts = [str(item).strip() for item in list(overlay.get("allowed_remote_hosts") or []) if str(item).strip()]
            if allowed_remote_hosts:
                allowed_remote_hosts = [item for item in allowed_remote_hosts if item in set(overlay_hosts)]
            else:
                allowed_remote_hosts = overlay_hosts
        allowed_mcp_servers = list(self.allow_mcp_servers or [])
        if list(overlay.get("allow_mcp_servers") or []):
            overlay_servers = [str(item).strip() for item in list(overlay.get("allow_mcp_servers") or []) if str(item).strip()]
            if allowed_mcp_servers:
                allowed_mcp_servers = [item for item in allowed_mcp_servers if item in set(overlay_servers)]
            else:
                allowed_mcp_servers = overlay_servers
        return ExecutionPolicy(
            allowed_roots=_dedupe_paths(list(self.allowed_roots or [])),
            denied_roots=_dedupe_paths(list(self.denied_roots or []) + [str(item) for item in list(overlay.get("denied_roots") or []) if str(item or "").strip()]),
            max_file_read_bytes=min(
                int(self.max_file_read_bytes or 0) or 1024 * 1024,
                int(overlay.get("max_file_read_bytes", self.max_file_read_bytes) or self.max_file_read_bytes or 1024 * 1024),
            ),
            max_shell_timeout_sec=min(
                int(self.max_shell_timeout_sec or 0) or 30,
                int(overlay.get("max_shell_timeout_sec", self.max_shell_timeout_sec) or self.max_shell_timeout_sec or 30),
            ),
            allow_workspace_writes_only=bool(self.allow_workspace_writes_only or overlay.get("allow_workspace_writes_only", False)),
            allow_remote=bool(self.allow_remote and overlay.get("allow_remote", True)),
            allowed_remote_hosts=allowed_remote_hosts,
            allow_public_web_targets_only=bool(self.allow_public_web_targets_only or overlay.get("allow_public_web_targets_only", False)),
            allow_background_remote=bool(self.allow_background_remote and overlay.get("allow_background_remote", True)),
            allow_mcp_servers=allowed_mcp_servers,
            workspace_root=str(self.workspace_root or ""),
            mode=str(self.mode or "main"),
            approval_policy=dict(self.approval_policy or {}),
            approval_manager=self.approval_manager,
            run_id=str(self.run_id or ""),
        )

    def clamp_file_read(self, requested=None):
        if requested is None:
            return int(self.max_file_read_bytes)
        return max(1, min(int(requested), int(self.max_file_read_bytes)))

    def clamp_shell_timeout(self, requested=None):
        requested_timeout = int(requested or self.max_shell_timeout_sec or 1)
        return max(1, min(requested_timeout, int(self.max_shell_timeout_sec or 1)))

    def validate_file_read(self, path, requested_bytes=None):
        resolved = _safe_resolve(path)
        if not self._is_read_allowed(resolved):
            raise PolicyError(
                "file_read",
                "path is outside allowed roots",
                path=str(resolved),
                allowed_roots=list(self.allowed_roots or []),
            )
        return self.clamp_file_read(requested_bytes)

    def evaluate_file_write(self, path, category="file_write", pending_action=None):
        resolved = _safe_resolve(path)
        if self.allow_workspace_writes_only:
            workspace_root = self.workspace_path
            if not workspace_root:
                return self._deny("file_write", "workspace root is not configured", path=str(resolved))
            if not _is_relative_to(resolved, workspace_root):
                return self._deny(
                    "file_write",
                    "writes are restricted to the current workspace",
                    path=str(resolved),
                    workspace_root=str(workspace_root),
                )
        elif not self._is_read_allowed(resolved):
            return self._deny(
                "file_write",
                "path is outside allowed roots",
                path=str(resolved),
                allowed_roots=list(self.allowed_roots or []),
            )
        return self._ask_or_allow(
            operation="file_write",
            category=category,
            fingerprint=str(resolved),
            reason="file write requires approval",
            details={"path": str(resolved)},
            pending_action=pending_action,
        )

    def validate_file_write(self, path):
        decision = self.evaluate_file_write(path)
        if decision.decision == "deny":
            raise PolicyError(decision.operation, decision.reason, **dict(decision.details or {}))
        return _safe_resolve(path)

    def evaluate_shell(self, command, cwd=None, timeout=None, pending_action=None):
        resolved_cwd = None
        if cwd:
            resolved_cwd = _safe_resolve(cwd)
            if not self._is_read_allowed(resolved_cwd):
                return self._deny(
                    "shell",
                    "working directory is outside allowed roots",
                    cwd=str(resolved_cwd),
                    allowed_roots=list(self.allowed_roots or []),
                )

        timeout_sec = self.clamp_shell_timeout(timeout)
        command_text = _command_text(command)
        shell_category = "shell"
        if _looks_like_write_command(command_text):
            shell_category = "shell_mutation"
        elif _looks_like_network_command(command_text):
            shell_category = "shell_network"
        if self.allow_workspace_writes_only and _looks_like_write_command(command_text):
            workspace_root = self.workspace_path
            if not workspace_root:
                return self._deny("shell", "workspace root is not configured", command=command_text[:200])
            for candidate in _extract_shell_paths(command_text):
                candidate_path = _safe_resolve(candidate, base=resolved_cwd or workspace_root)
                if not _is_relative_to(candidate_path, workspace_root):
                    return self._deny(
                        "shell",
                        "write-like shell command targets a path outside the workspace",
                        command=command_text[:200],
                        path=str(candidate_path),
                        workspace_root=str(workspace_root),
                    )
        return self._ask_or_allow(
            operation="shell",
            category=shell_category,
            fingerprint=self._fingerprint_shell(command_text),
            reason="{0} requires approval".format(shell_category),
            details={
                "cwd": str(resolved_cwd) if resolved_cwd else None,
                "timeout": timeout_sec,
                "command": command_text[:400],
            },
            pending_action=pending_action,
        )

    def validate_shell(self, command, cwd=None, timeout=None):
        decision = self.evaluate_shell(command, cwd=cwd, timeout=timeout)
        if decision.decision == "deny":
            raise PolicyError(decision.operation, decision.reason, **dict(decision.details or {}))
        return {
            "cwd": (decision.details or {}).get("cwd"),
            "timeout": (decision.details or {}).get("timeout", self.clamp_shell_timeout(timeout)),
        }

    def evaluate_remote(
        self,
        host_name,
        category="",
        target="",
        background=False,
        operation_category="remote_exec",
        pending_action=None,
    ):
        host_name = str(host_name or "").strip()
        category = str(category or "").strip().lower()
        if not self.allow_remote:
            return self._deny("remote", "remote execution is disabled by policy", host=host_name, category=category)
        if host_name and self.allowed_remote_hosts and host_name not in self.allowed_remote_hosts:
            return self._deny(
                "remote",
                "remote host is not in the allowlist",
                host=host_name,
                allowed_remote_hosts=list(self.allowed_remote_hosts or []),
            )
        if background and not self.allow_background_remote:
            return self._deny("remote", "background remote execution is disabled", host=host_name)
        if self.allow_public_web_targets_only and category == "web" and target and not is_public_target(target):
            return self._deny(
                "remote",
                "web remote execution requires a public target",
                host=host_name,
                target=str(target),
            )
        return self._ask_or_allow(
            operation="remote",
            category=operation_category,
            fingerprint="{0}:{1}:{2}".format(operation_category, host_name, category or "-"),
            reason="{0} requires approval".format(operation_category),
            details={
                "host": host_name,
                "category": category,
                "target": str(target or ""),
                "background": bool(background),
            },
            pending_action=pending_action,
        )

    def validate_remote(self, host_name, category="", target="", background=False):
        decision = self.evaluate_remote(host_name, category=category, target=target, background=background)
        if decision.decision == "deny":
            raise PolicyError(decision.operation, decision.reason, **dict(decision.details or {}))
        return True

    def evaluate_remote_subagent(self, host_name, category="", target="", background=True, pending_action=None):
        return self.evaluate_remote(
            host_name,
            category=category,
            target=target,
            background=background,
            operation_category="remote_subagent",
            pending_action=pending_action,
        )

    def evaluate_mcp_server(self, server_name, tool_name="", pending_action=None):
        server_name = str(server_name or "").strip()
        if not server_name:
            return self._deny("mcp", "MCP server name is required")
        if self.allow_mcp_servers and server_name not in self.allow_mcp_servers:
            return self._deny(
                "mcp",
                "MCP server is not enabled by policy",
                server=server_name,
                allowed_servers=list(self.allow_mcp_servers or []),
            )
        category = "mcp_mutation" if _looks_like_mutating_mcp_tool(tool_name) else "mcp"
        return self._ask_or_allow(
            operation="mcp",
            category=category,
            fingerprint="{0}:{1}".format(server_name, str(tool_name or "").strip()),
            reason="{0} requires approval".format(category),
            details={"server": server_name, "tool": str(tool_name or "")},
            pending_action=pending_action,
        )

    def validate_mcp_server(self, server_name):
        decision = self.evaluate_mcp_server(server_name)
        if decision.decision == "deny":
            raise PolicyError(decision.operation, decision.reason, **dict(decision.details or {}))
        return True

    @property
    def workspace_path(self):
        if not self.workspace_root:
            return None
        return _safe_resolve(self.workspace_root)

    def _is_read_allowed(self, path):
        resolved = _safe_resolve(path)
        for denied in list(self.denied_roots or []):
            denied_path = _safe_resolve(denied)
            if _is_relative_to(resolved, denied_path):
                return False
        for allowed in list(self.allowed_roots or []):
            allowed_path = _safe_resolve(allowed)
            if _is_relative_to(resolved, allowed_path):
                return True
        return False

    def _approval_enabled_for(self, category):
        if not self.approval_manager or not bool(self.approval_policy.get("enabled", True)):
            return False
        return str(category or "").strip() in set(self.approval_manager.ask_categories())

    def _ask_or_allow(self, operation, category, fingerprint, reason, details=None, pending_action=None):
        details = dict(details or {})
        if not self._approval_enabled_for(category):
            return PolicyDecision("allow", operation, "allowed by execution policy", category=category, details=details, fingerprint=str(fingerprint or ""))
        grant = self.approval_manager.get_active_grant(
            operation=str(operation or ""),
            fingerprint=str(fingerprint or ""),
            workspace=str(self.workspace_root or ""),
            run_id=str(self.run_id or ""),
        )
        if grant:
            if getattr(grant, "scope", "") == "once":
                self.approval_manager.consume_grant(grant.id, workspace=str(self.workspace_root or ""))
            return PolicyDecision(
                "allow",
                operation,
                "approved grant matched",
                category=category,
                details=details,
                fingerprint=str(fingerprint or ""),
                scope=str(getattr(grant, "scope", "") or ""),
                grant_id=str(getattr(grant, "id", "") or ""),
            )
        request = self.approval_manager.create_request(
            operation=str(operation or ""),
            category=str(category or ""),
            fingerprint=str(fingerprint or ""),
            reason=str(reason or ""),
            subject=str(details.get("command") or details.get("path") or details.get("server") or details.get("host") or ""),
            details=details,
            pending_action=dict(pending_action or {}),
            workspace=str(self.workspace_root or ""),
            run_id=str(self.run_id or ""),
            default_scope=str(self.approval_policy.get("default_scope", "workspace_session") or "workspace_session"),
            ttl_sec=int(self.approval_policy.get("session_ttl_sec", 1800) or 1800),
            auto_resume=bool(self.approval_policy.get("auto_resume", True)),
        )
        return PolicyDecision(
            "ask",
            operation,
            reason,
            category=category,
            details=details,
            request_id=request.id,
            fingerprint=str(fingerprint or ""),
            scope=str(getattr(request, "default_scope", "") or ""),
        )

    def _deny(self, operation, reason, **details):
        return PolicyDecision("deny", operation, reason, details=dict(details or {}))

    def _fingerprint_shell(self, command_text):
        lowered = str(command_text or "").strip().lower()
        lowered = re.sub(r"\s+", " ", lowered)
        return lowered[:240]


def is_public_target(target):
    text = str(target or "").strip()
    if not text:
        return False
    parsed = urlparse(text if "://" in text else "tcp://{0}".format(text))
    host = parsed.hostname or text.split("/", 1)[0].split(":", 1)[0]
    host = str(host or "").strip()
    if not host:
        return False
    lowered = host.lower()
    if lowered in {"localhost", "127.0.0.1", "::1"} or lowered.endswith(".local"):
        return False
    try:
        ip_value = ipaddress.ip_address(host)
    except ValueError:
        return True
    return not any(
        [
            ip_value.is_loopback,
            ip_value.is_private,
            ip_value.is_reserved,
            ip_value.is_link_local,
            ip_value.is_multicast,
        ]
    )


def _dedupe_paths(values: Iterable[str]):
    deduped = []
    seen = set()
    for item in list(values or []):
        text = str(item or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        deduped.append(text)
    return deduped


def _safe_resolve(path, base=None):
    value = Path(path)
    if not value.is_absolute():
        if base is not None:
            value = Path(base) / value
        elif Path.cwd():
            value = Path.cwd() / value
    try:
        return value.resolve()
    except Exception:
        return value.absolute()


def _is_relative_to(path, root):
    path = _safe_resolve(path)
    root = _safe_resolve(root)
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return path == root


def _command_text(command):
    if isinstance(command, (list, tuple)):
        return " ".join(str(item) for item in command)
    return str(command or "")


def _looks_like_write_command(command_text):
    lowered = str(command_text or "").lower()
    markers = [
        ">",
        "out-file",
        "set-content",
        "add-content",
        "copy-item",
        "move-item",
        "remove-item",
        "new-item",
        "mkdir ",
        " md ",
        " tee ",
        " curl -o ",
        " wget -o ",
        " wget --output-document",
    ]
    return any(marker in lowered for marker in markers)


def _looks_like_network_command(command_text):
    lowered = str(command_text or "").lower()
    markers = [
        "curl ",
        "wget ",
        "invoke-webrequest",
        "invoke-restmethod",
        "http://",
        "https://",
        "nc ",
        "ncat ",
        "telnet ",
        "ftp ",
    ]
    return any(marker in lowered for marker in markers)


def _looks_like_mutating_mcp_tool(tool_name):
    lowered = str(tool_name or "").strip().lower()
    if not lowered:
        return False
    markers = [
        "write",
        "update",
        "create",
        "delete",
        "remove",
        "modify",
        "edit",
        "save",
        "execute",
        "run",
        "send",
        "post",
    ]
    return any(marker in lowered for marker in markers)


def _extract_shell_paths(command_text):
    text = str(command_text or "")
    patterns = [
        r'["\']([A-Za-z]:\\[^"\']+)["\']',
        r'["\'](/[^"\']+)["\']',
        r'>\s*([A-Za-z]:\\[^\s]+)',
        r'>\s*(/[^\s]+)',
    ]
    matches = []
    for pattern in patterns:
        matches.extend(re.findall(pattern, text))
    return matches
