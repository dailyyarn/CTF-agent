import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import winreg
except ImportError:  # pragma: no cover - non-Windows fallback
    winreg = None


DEFAULT_WORKSPACE_ROOT = "./ctf-agent-output"
DEFAULT_TOOLKIT_ROOT = "./ctf-toolkit"
DEFAULT_MCP_TIMEOUT = 25.0
DEFAULT_EXPORT_ROOT = "./agent-wp"


@dataclass
class AgentConfig:
    workspace_root: str = DEFAULT_WORKSPACE_ROOT
    toolkit_root: str = DEFAULT_TOOLKIT_ROOT
    oob_base_url: str = ""
    oob_poll_url_template: str = ""
    oob_auth_token: str = ""
    oob_auth_header: str = "Authorization"
    auto_run_sqlmap: bool = False
    language: str = "zh-CN"
    mcp_timeout: float = DEFAULT_MCP_TIMEOUT
    preferred_browser_mcp: str = ""
    preferred_reverse_mcp: str = ""
    browser: Dict[str, Any] = field(default_factory=dict)
    web_policy: Dict[str, Any] = field(default_factory=dict)
    remote_policy: Dict[str, Any] = field(default_factory=dict)
    editor_policy: Dict[str, Any] = field(default_factory=dict)
    speed_profiles: Dict[str, Any] = field(default_factory=dict)
    export_policy: Dict[str, Any] = field(default_factory=dict)
    knowledge_pack: Dict[str, Any] = field(default_factory=dict)
    plugin_roots: List[str] = field(default_factory=list)
    enabled_plugins: List[str] = field(default_factory=list)
    disabled_plugins: List[str] = field(default_factory=list)
    approval_policy: Dict[str, Any] = field(default_factory=dict)
    remote_subagents: Dict[str, Any] = field(default_factory=dict)
    mcp_servers: List[Dict[str, Any]] = field(default_factory=list)
    remote_hosts: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    # AI Solver (Phase 0-5)
    llm: Dict[str, Any] = field(default_factory=dict)
    rag: Dict[str, Any] = field(default_factory=dict)
    ai_solver: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, payload: Optional[Dict[str, Any]] = None) -> "AgentConfig":
        payload = payload or {}
        llm_raw = dict(payload.get("llm", {}))
        for key in ("api_key", "base_url", "model"):
            if key in llm_raw:
                llm_raw[key] = _expand_env_placeholder(llm_raw[key])
        return cls(
            workspace_root=_expand_env_placeholder(payload.get("workspace_root", DEFAULT_WORKSPACE_ROOT)),
            toolkit_root=_expand_env_placeholder(payload.get("toolkit_root", DEFAULT_TOOLKIT_ROOT)),
            oob_base_url=_expand_env_placeholder(payload.get("oob_base_url", "")),
            oob_poll_url_template=_expand_env_placeholder(payload.get("oob_poll_url_template", "")),
            oob_auth_token=_expand_env_placeholder(payload.get("oob_auth_token", "")),
            oob_auth_header=_expand_env_placeholder(payload.get("oob_auth_header", "Authorization")),
            auto_run_sqlmap=bool(payload.get("auto_run_sqlmap", False)),
            language=_expand_env_placeholder(payload.get("language", "zh-CN")),
            mcp_timeout=float(payload.get("mcp_timeout", DEFAULT_MCP_TIMEOUT)),
            preferred_browser_mcp=_expand_env_placeholder(payload.get("preferred_browser_mcp", "")),
            preferred_reverse_mcp=_expand_env_placeholder(payload.get("preferred_reverse_mcp", "")),
            browser=dict(payload.get("browser", {})),
            web_policy=dict(payload.get("web_policy", {})),
            remote_policy=dict(payload.get("remote_policy", {})),
            editor_policy=dict(payload.get("editor_policy", {})),
            speed_profiles=dict(payload.get("speed_profiles", {})),
            export_policy=dict(payload.get("export_policy", {})),
            knowledge_pack=dict(payload.get("knowledge_pack", {})),
            plugin_roots=[_expand_env_placeholder(item) for item in list(payload.get("plugin_roots", []) or [])],
            enabled_plugins=[str(item) for item in list(payload.get("enabled_plugins", []) or []) if str(item or "").strip()],
            disabled_plugins=[str(item) for item in list(payload.get("disabled_plugins", []) or []) if str(item or "").strip()],
            approval_policy=dict(payload.get("approval_policy", {})),
            remote_subagents=dict(payload.get("remote_subagents", {})),
            mcp_servers=_resolve_server_configs(payload.get("mcp_servers", [])),
            remote_hosts=_resolve_remote_hosts(payload.get("remote_hosts", {})),
            llm=llm_raw,
            rag=dict(payload.get("rag", {})),
            ai_solver=dict(payload.get("ai_solver", {})),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "workspace_root": self.workspace_root,
            "toolkit_root": self.toolkit_root,
            "oob_base_url": self.oob_base_url,
            "oob_poll_url_template": self.oob_poll_url_template,
            "oob_auth_token": self.oob_auth_token,
            "oob_auth_header": self.oob_auth_header,
            "auto_run_sqlmap": self.auto_run_sqlmap,
            "language": self.language,
            "mcp_timeout": self.mcp_timeout,
            "preferred_browser_mcp": self.preferred_browser_mcp,
            "preferred_reverse_mcp": self.preferred_reverse_mcp,
            "browser": self.browser,
            "web_policy": self.web_policy,
            "remote_policy": self.remote_policy,
            "editor_policy": self.editor_policy,
            "speed_profiles": self.speed_profiles,
            "export_policy": self.export_policy,
            "knowledge_pack": self.knowledge_pack,
            "plugin_roots": self.plugin_roots,
            "enabled_plugins": self.enabled_plugins,
            "disabled_plugins": self.disabled_plugins,
            "approval_policy": self.approval_policy,
            "remote_subagents": self.remote_subagents,
            "mcp_servers": self.mcp_servers,
            "remote_hosts": self.remote_hosts,
            "llm": self.llm,
            "rag": self.rag,
            "ai_solver": self.ai_solver,
        }


def load_agent_config(config_path: Optional[Path]) -> AgentConfig:
    if not config_path:
        return AgentConfig()

    config_path = Path(config_path)
    if not config_path.exists():
        return AgentConfig()

    payload = json.loads(config_path.read_text(encoding="utf-8"))
    return AgentConfig.from_dict(payload)


def _resolve_remote_hosts(payload: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    resolved = {}
    for name, config in dict(payload or {}).items():
        item = dict(config or {})
        for key, value in list(item.items()):
            item[key] = _expand_env_placeholder(value)
        for key in ["password", "token", "private_key", "passphrase"]:
            env_key = item.get("{0}_env".format(key))
            if env_key:
                item[key] = _read_env_value(str(env_key), item.get(key, ""))
        resolved[name] = item
    return resolved


def _resolve_server_configs(payload: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    resolved = []
    for item in list(payload or []):
        config = dict(item or {})
        for key in ["command", "transport", "notes", "name", "bearer_token"]:
            if key in config:
                config[key] = _expand_env_placeholder(config[key])
        config["args"] = [_expand_env_placeholder(value) for value in list(config.get("args", []))]
        env = dict(config.get("env", {}))
        for key, value in list(env.items()):
            env[key] = _expand_env_placeholder(value)
        config["env"] = env
        token_env = config.get("bearer_token_env")
        if token_env and "bearer_token" not in config:
            config["bearer_token"] = _read_env_value(str(token_env), "")
        resolved.append(config)
    return resolved


def _expand_env_placeholder(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    text = value.strip()
    if text.startswith("${") and text.endswith("}") and len(text) > 3:
        env_name = text[2:-1]
        return _read_env_value(env_name, "")
    return value


def _read_env_value(env_name: str, default: str = "") -> str:
    value = os.environ.get(env_name)
    if value:
        return value
    for scope in ("user", "machine"):
        scoped = _read_windows_env(env_name, scope)
        if scoped:
            return scoped
    return default


def _read_windows_env(env_name: str, scope: str) -> str:
    if winreg is None:
        return ""
    try:
        if scope == "user":
            root = winreg.HKEY_CURRENT_USER
            subkey = r"Environment"
        else:
            root = winreg.HKEY_LOCAL_MACHINE
            subkey = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
        with winreg.OpenKey(root, subkey) as handle:
            value, _ = winreg.QueryValueEx(handle, env_name)
            return str(value or "")
    except OSError:
        return ""
