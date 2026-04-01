import json
from pathlib import Path


VALID_PLUGIN_TOOL_KINDS = {"shell_template", "mcp_proxy", "remote_template", "python_entry"}
VALID_DOCTOR_CHECK_KINDS = {"command_exists", "path_exists", "mcp_server", "remote_template", "env_var"}


class PluginRegistry(object):
    def __init__(
        self,
        bundled_root=None,
        plugin_roots=None,
        enabled_plugins=None,
        disabled_plugins=None,
        workspace_manager=None,
    ):
        self.bundled_root = Path(bundled_root) if bundled_root else None
        self.plugin_roots = [Path(item) for item in list(plugin_roots or []) if str(item or "").strip()]
        self.enabled_plugins = {str(item).strip() for item in list(enabled_plugins or []) if str(item or "").strip()}
        self.disabled_plugins = {str(item).strip() for item in list(disabled_plugins or []) if str(item or "").strip()}
        self.workspace_manager = workspace_manager
        self._plugins = []
        self._loaded = False

    def discover(self, refresh=False):
        if self._loaded and not refresh:
            return list(self._plugins)

        discovered = []
        plugin_by_name = {}
        root_specs = []
        if self.bundled_root:
            root_specs.append(("bundled", self.bundled_root))
        for root in list(self.plugin_roots or []):
            root_specs.append(("user", root))

        for source_kind, root in root_specs:
            root = Path(root)
            if not root.exists():
                continue
            manifests = []
            if (root / "plugin.json").exists():
                manifests.append(root / "plugin.json")
            for path in sorted(root.glob("*/plugin.json")):
                manifests.append(path)
            for manifest_path in manifests:
                plugin = self._load_plugin_manifest(manifest_path, source_kind=source_kind)
                name = str(plugin.get("name", "") or "")
                if not name:
                    continue
                previous = plugin_by_name.get(name)
                if previous is None:
                    plugin_by_name[name] = plugin
                    discovered.append(plugin)
                    continue
                if name in self.enabled_plugins:
                    chosen = plugin if plugin["source_kind"] == "user" else previous
                elif previous["source_kind"] == "bundled" and plugin["source_kind"] == "user":
                    chosen = plugin
                else:
                    chosen = previous
                if chosen is not previous:
                    discovered = [item for item in discovered if item.get("name") != name]
                    discovered.append(chosen)
                    plugin_by_name[name] = chosen

        for item in discovered:
            name = str(item.get("name", "") or "")
            enabled = bool(item.get("enabled_by_default", True))
            if self.enabled_plugins:
                enabled = name in self.enabled_plugins
            if name in self.disabled_plugins:
                enabled = False
            item["enabled"] = enabled and not item.get("invalid", False)

        discovered.sort(key=lambda item: (0 if item.get("enabled") else 1, item.get("name", "")))
        self._plugins = discovered
        self._loaded = True
        return list(self._plugins)

    def _load_plugin_manifest(self, manifest_path, source_kind="bundled"):
        manifest_path = Path(manifest_path)
        plugin_root = manifest_path.parent
        try:
            payload = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
            if not isinstance(payload, dict):
                raise ValueError("plugin.json must contain a JSON object")
        except Exception as exc:
            return {
                "name": manifest_path.parent.name,
                "version": "",
                "enabled_by_default": False,
                "enabled": False,
                "invalid": True,
                "errors": [str(exc)],
                "manifest_path": str(manifest_path),
                "root": str(plugin_root),
                "source_kind": source_kind,
                "tools": [],
                "mcp_servers": [],
                "knowledge_roots": [],
                "remote_templates": [],
                "doctor_checks": [],
                "policy_overlay": {},
                "capabilities": {},
            }

        errors = []
        name = str(payload.get("name", "") or manifest_path.parent.name).strip()
        tools = []
        for item in list(payload.get("tools", []) or []):
            tool = dict(item or {})
            kind = str(tool.get("kind", "") or "").strip()
            if kind not in VALID_PLUGIN_TOOL_KINDS:
                errors.append("invalid tool kind: {0}".format(kind or "<empty>"))
                continue
            tool.setdefault("name", "")
            tool.setdefault("description", "")
            tool["kind"] = kind
            if kind == "python_entry" and tool.get("script"):
                script_path = plugin_root / str(tool.get("script"))
                tool["script_path"] = str(script_path)
            tools.append(tool)

        doctor_checks = []
        for item in list(payload.get("doctor_checks", []) or []):
            check = dict(item or {})
            kind = str(check.get("kind", "") or "").strip()
            if kind not in VALID_DOCTOR_CHECK_KINDS:
                errors.append("invalid doctor check kind: {0}".format(kind or "<empty>"))
                continue
            doctor_checks.append(check)

        knowledge_roots = []
        for item in list(payload.get("knowledge_roots", []) or []):
            path = plugin_root / str(item)
            knowledge_roots.append(str(path))

        remote_templates = []
        for item in list(payload.get("remote_templates", []) or []):
            remote_templates.append(dict(item or {}))

        mcp_servers = [dict(item or {}) for item in list(payload.get("mcp_servers", []) or [])]

        return {
            "name": name,
            "version": str(payload.get("version", "") or ""),
            "description": str(payload.get("description", "") or ""),
            "categories": list(payload.get("categories", []) or []),
            "enabled_by_default": bool(payload.get("enabled_by_default", True)),
            "enabled": False,
            "invalid": bool(errors),
            "errors": errors,
            "manifest_path": str(manifest_path),
            "root": str(plugin_root),
            "source_kind": source_kind,
            "tools": tools,
            "mcp_servers": mcp_servers,
            "knowledge_roots": knowledge_roots,
            "remote_templates": remote_templates,
            "doctor_checks": doctor_checks,
            "policy_overlay": dict(payload.get("policy_overlay") or {}),
            "capabilities": dict(payload.get("capabilities") or {}),
        }

    def enabled_plugins_view(self):
        return [item for item in self.discover() if item.get("enabled")]

    def plugin_tools(self):
        payload = []
        for plugin in self.enabled_plugins_view():
            for tool in list(plugin.get("tools", []) or []):
                enriched = dict(tool)
                enriched["plugin_name"] = plugin.get("name", "")
                enriched["plugin_root"] = plugin.get("root", "")
                payload.append(enriched)
        return payload

    def merged_mcp_servers(self, base_configs=None):
        merged = [dict(item or {}) for item in list(base_configs or [])]
        existing_names = {str(item.get("name", "") or "") for item in merged}
        for plugin in self.enabled_plugins_view():
            for item in list(plugin.get("mcp_servers", []) or []):
                name = str(item.get("name", "") or "")
                if not name or name in existing_names:
                    continue
                merged.append(dict(item or {}))
                existing_names.add(name)
        return merged

    def knowledge_roots(self):
        payload = []
        seen = set()
        for plugin in self.enabled_plugins_view():
            for item in list(plugin.get("knowledge_roots", []) or []):
                text = str(item or "").strip()
                if not text or text in seen:
                    continue
                seen.add(text)
                payload.append(text)
        return payload

    def merged_knowledge_roots(self, base_roots=None):
        payload = []
        seen = set()
        for item in list(base_roots or []):
            text = str(item or "").strip()
            if not text or text in seen:
                continue
            seen.add(text)
            payload.append(text)
        for item in self.knowledge_roots():
            if item in seen:
                continue
            seen.add(item)
            payload.append(item)
        return payload

    def remote_templates(self):
        payload = []
        for plugin in self.enabled_plugins_view():
            for item in list(plugin.get("remote_templates", []) or []):
                enriched = dict(item or {})
                enriched["plugin_name"] = plugin.get("name", "")
                enriched["plugin_root"] = plugin.get("root", "")
                payload.append(enriched)
        return payload

    def resolve_remote_template(self, template_name):
        requested = str(template_name or "").strip().lower()
        if not requested:
            return {}
        for item in self.remote_templates():
            aliases = {
                str(item.get("name", "") or "").strip().lower(),
                str(item.get("template_kind", "") or "").strip().lower(),
            }
            aliases.update({str(alias or "").strip().lower() for alias in list(item.get("aliases", []) or []) if str(alias or "").strip()})
            if requested in aliases:
                return dict(item)
        return {}

    def recommended_remote_templates(self, category=""):
        category = str(category or "").strip().lower()
        payload = []
        seen = set()
        for item in self.remote_templates():
            categories = {str(value or "").strip().lower() for value in list(item.get("categories", []) or []) if str(value or "").strip()}
            if categories and category and category not in categories:
                continue
            name = str(item.get("name", "") or item.get("template_kind", "") or "").strip()
            if not name or name in seen:
                continue
            seen.add(name)
            payload.append(name)
        return payload

    def doctor_checks(self):
        payload = []
        for plugin in self.enabled_plugins_view():
            for item in list(plugin.get("doctor_checks", []) or []):
                enriched = dict(item or {})
                enriched["plugin_name"] = plugin.get("name", "")
                enriched["plugin_root"] = plugin.get("root", "")
                payload.append(enriched)
        return payload

    def policy_overlay(self):
        merged = {}
        for plugin in self.enabled_plugins_view():
            merged.update(dict(plugin.get("policy_overlay") or {}))
        return merged

    def describe(self):
        self.discover()
        return {
            "loaded": True,
            "counts": {
                "total": len(self._plugins),
                "enabled": len([item for item in self._plugins if item.get("enabled")]),
                "invalid": len([item for item in self._plugins if item.get("invalid")]),
                "disabled": len([item for item in self._plugins if not item.get("enabled")]),
            },
            "plugins": [
                {
                    "name": item.get("name", ""),
                    "version": item.get("version", ""),
                    "enabled": bool(item.get("enabled", False)),
                    "invalid": bool(item.get("invalid", False)),
                    "source_kind": item.get("source_kind", ""),
                    "errors": list(item.get("errors", []) or [])[:5],
                    "tool_count": len(list(item.get("tools", []) or [])),
                    "mcp_server_count": len(list(item.get("mcp_servers", []) or [])),
                    "knowledge_root_count": len(list(item.get("knowledge_roots", []) or [])),
                    "remote_template_count": len(list(item.get("remote_templates", []) or [])),
                    "doctor_check_count": len(list(item.get("doctor_checks", []) or [])),
                }
                for item in self._plugins
            ],
            "tool_names": [item.get("name", "") for item in self.plugin_tools()],
            "remote_template_names": [item.get("name", "") or item.get("template_kind", "") for item in self.remote_templates()],
            "knowledge_roots": self.knowledge_roots(),
        }

    def persist_workspace_status(self, workspace):
        if not workspace:
            return {}
        payload = self.describe()
        path = Path(workspace) / "plugin_status.json"
        if self.workspace_manager:
            self.workspace_manager.write_json(path, payload)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8-sig")
        return payload
