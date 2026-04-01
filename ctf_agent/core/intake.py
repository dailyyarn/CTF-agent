import re
import uuid
from pathlib import Path

from ctf_agent.core.autopilot import build_autopilot_plan
from ctf_agent.core.task_template import parse_task_template
from ctf_agent.knowledge import SkillResolver, normalize_category, supported_categories
from ctf_agent.tools.remote_tool import RemoteTool
from ctf_agent.tools.shell_tool import ShellTool
from ctf_agent.tools.toolkit_tool import ToolkitTool


class IntakeService(object):
    CATEGORY_SET = set(supported_categories())
    FASTEST_KEYWORDS = ("fastest", "speedrun", "最快", "搏一把")

    def __init__(self, config, workspace_root):
        self.config = config
        self.workspace_root = Path(workspace_root).expanduser().absolute()
        self.incoming_root = self.workspace_root / "_incoming"
        self.incoming_root.mkdir(parents=True, exist_ok=True)
        self.skill_resolver = SkillResolver()
        self.remote_selector = RemoteTool(
            config.remote_hosts,
            policy=getattr(config, "remote_policy", {}),
        )
        self.toolkit_tool = ToolkitTool(config.toolkit_root, shell_tool=ShellTool())

    def normalize_brief(self, arguments):
        arguments = dict(arguments or {})
        raw_task = (
            arguments.get("task")
            or arguments.get("prompt")
            or arguments.get("hint")
            or arguments.get("description")
            or ""
        ).strip()
        task_template = parse_task_template(raw_task)
        template_fields = dict(task_template.get("fields") or {})
        task_body = (
            template_fields.get("description")
            or template_fields.get("hint")
            or task_template.get("body")
            or raw_task
        ).strip()
        speed_mode = self.resolve_speed_mode(
            arguments.get("speed_mode"),
            raw_task,
            task_body,
            arguments.get("title", ""),
            arguments.get("description", ""),
            arguments.get("hint", ""),
        )
        explicit_category = normalize_category(
            arguments.get("category") or template_fields.get("category") or ""
        )
        target = self.clean_target(
            (
                arguments.get("target")
                or arguments.get("url")
                or template_fields.get("target")
                or self.extract_target(task_body)
                or ""
            ).strip()
        )
        attachment_inputs = self.collect_attachment_inputs(arguments)
        attachment_inputs.extend(template_fields.get("attachments", []))
        if target and self.looks_like_local_path(target):
            attachment_inputs.append(target)
            target = ""

        attachments = self.expand_attachment_inputs(attachment_inputs)
        skill_resolution = self.skill_resolver.resolve(
            task_text=task_body,
            target=target,
            attachments=attachments,
            explicit_category=explicit_category,
            speed_mode=speed_mode,
        )
        inferred_category = (skill_resolution.get("category") or {}).get("selected_skill_category", explicit_category or "misc")
        inferred_title = (
            arguments.get("title")
            or template_fields.get("title")
            or self.infer_brief_title(task_body, target, attachments, inferred_category)
        )
        flag_format = arguments.get("flag_format") or template_fields.get("flag_format") or r"flag\{[^{}\n]+\}"
        payload = {
            "category": inferred_category,
            "url": target or None,
            "target": target or None,
            "attachments": [str(item) for item in attachments],
            "title": inferred_title,
            "challenge_id": arguments.get("challenge_id"),
            "contest_id": arguments.get("contest_id"),
            "description": arguments.get("description") or template_fields.get("description") or task_body or arguments.get("hint") or "",
            "hint": arguments.get("hint") or template_fields.get("hint") or task_body,
            "flag_format": flag_format,
            "output_root": arguments.get("output_root") or arguments.get("workspace_root") or self.config.workspace_root,
            "workspace_root": arguments.get("workspace_root") or arguments.get("output_root") or self.config.workspace_root,
            "config_path": arguments.get("config_path"),
            "timeout": float(arguments.get("timeout", 8.0)),
            "max_js_assets": int(arguments.get("max_js_assets", 8)),
            "max_rounds": arguments.get("max_rounds") if arguments.get("max_rounds") is not None else template_fields.get("max_rounds"),
            "use_browser_mcp": arguments.get("use_browser_mcp") if arguments.get("use_browser_mcp") is not None else template_fields.get("use_browser_mcp"),
            "use_remote_host": arguments.get("use_remote_host") or template_fields.get("use_remote_host"),
            "speed_mode": speed_mode,
            "skill_resolution": skill_resolution,
        }
        normalized = self.normalize(payload)
        normalized["input_summary"]["mode"] = "brief"
        normalized["input_summary"]["task"] = raw_task
        normalized["input_summary"]["explicit_category"] = explicit_category or ""
        normalized["input_summary"]["inferred_category"] = inferred_category
        normalized["input_summary"]["inferred_target"] = target or ""
        normalized["input_summary"]["task_body"] = task_body
        normalized["input_summary"]["template_detected"] = bool(task_template.get("detected"))
        normalized["input_summary"]["template_fields"] = list(task_template.get("field_names", []))
        normalized["input_summary"]["speed_mode"] = speed_mode
        normalized["task"] = raw_task
        normalized["task_body"] = task_body
        normalized["task_template"] = {
            "detected": bool(task_template.get("detected")),
            "field_names": list(task_template.get("field_names", [])),
            "protocol": dict(task_template.get("protocol") or {}),
        }
        return normalized

    def normalize(self, arguments):
        arguments = dict(arguments or {})
        explicit_category = normalize_category(arguments.get("category") or "")
        speed_mode = self.resolve_speed_mode(
            arguments.get("speed_mode"),
            arguments.get("task", ""),
            arguments.get("prompt", ""),
            arguments.get("title", ""),
            arguments.get("description", ""),
            arguments.get("hint", ""),
        )
        speed_profile = self.resolve_speed_profile(speed_mode)
        target = self.clean_target((arguments.get("target") or arguments.get("url") or "").strip())
        attachment_inputs = self.collect_attachment_inputs(arguments)
        if target and self.looks_like_local_path(target):
            attachment_inputs.append(target)
        attachments = self.expand_attachment_inputs(attachment_inputs)

        skill_resolution = dict(arguments.get("skill_resolution") or {})
        if str(((skill_resolution.get("runtime") or {}).get("speed_mode") or "")).strip().lower() != speed_mode:
            skill_resolution = self.skill_resolver.resolve(
                task_text="\n".join(
                    [
                        str(arguments.get("title") or ""),
                        str(arguments.get("description") or arguments.get("hint") or ""),
                    ]
                ),
                target=target,
                attachments=attachments,
                explicit_category=explicit_category,
                speed_mode=speed_mode,
            )
        knowledge_selection = self.skill_resolver.to_legacy_selection(skill_resolution)
        category = knowledge_selection.get("selected_skill_category", explicit_category or "misc")
        resolved_target = self.resolve_target(category, target)
        title = arguments.get("title") or self.infer_title(category, target, attachments)
        challenge_id = arguments.get("challenge_id") or self.slugify(title or "manual-{0}".format(category))
        contest_id = arguments.get("contest_id") or "manual"
        description = (
            arguments.get("description")
            or arguments.get("hint")
            or "Auto-generated {0} task from the local intake service.".format(category)
        )

        use_browser_mcp = arguments.get("use_browser_mcp")
        if use_browser_mcp is None:
            use_browser_mcp = bool(category == "web" and self.config.web_policy.get("auto_use_browser_mcp", True))

        remote_selection = self.select_remote_host(
            category=category,
            target=resolved_target or target,
            preferred=arguments.get("use_remote_host"),
        )
        use_remote_host = remote_selection.get("selected_host", "")
        toolkit_capability_plan = self.toolkit_tool.capability_plan(category=category)

        max_rounds = arguments.get("max_rounds")
        if max_rounds is None:
            max_rounds = self.default_max_rounds(category)

        autopilot_plan = build_autopilot_plan(
            self.config,
            category=category,
            target=resolved_target or target,
            attachments=attachments,
            remote_selection=remote_selection,
            use_browser_mcp=use_browser_mcp,
            toolkit_capability_plan=toolkit_capability_plan,
            speed_mode=speed_mode,
            speed_profile=speed_profile,
            skill_resolution=skill_resolution,
        )
        autopilot_knowledge = dict(autopilot_plan.get("knowledge") or {})
        autopilot_knowledge["selected_skill_category"] = knowledge_selection.get("selected_skill_category", category)
        autopilot_knowledge["auto_category"] = knowledge_selection.get("auto_category", "")
        autopilot_knowledge["explicit_category"] = knowledge_selection.get("explicit_category", "")
        autopilot_knowledge["category_confidence"] = knowledge_selection.get("category_confidence", 0.0)
        autopilot_knowledge["category_evidence"] = list(knowledge_selection.get("category_evidence", []))
        autopilot_knowledge["category_consistent"] = bool(knowledge_selection.get("category_consistent", False))
        autopilot_knowledge["knowledge_pack"] = dict(knowledge_selection.get("knowledge_pack", {}))
        autopilot_knowledge["pack_name"] = knowledge_selection.get("pack_name", "")
        autopilot_knowledge["knowledge_topics"] = list(knowledge_selection.get("knowledge_topics", []))
        autopilot_knowledge["top_tactics"] = list(knowledge_selection.get("top_tactics", []))
        autopilot_knowledge["reference_docs"] = list(knowledge_selection.get("reference_docs", []))
        autopilot_plan["knowledge"] = autopilot_knowledge
        autopilot_plan["skill_resolution"] = dict(skill_resolution)
        autopilot_plan["selected_skill_category"] = knowledge_selection.get("selected_skill_category", category)
        autopilot_plan["category_confidence"] = knowledge_selection.get("category_confidence", 0.0)
        autopilot_plan["category_evidence"] = list(knowledge_selection.get("category_evidence", []))
        autopilot_plan["top_tactics"] = list(knowledge_selection.get("top_tactics", []))
        autopilot_plan["reference_docs"] = list(knowledge_selection.get("reference_docs", []))
        autopilot_plan["speed_mode"] = speed_mode
        autopilot_plan["speed_profile"] = speed_profile

        return {
            "category": category,
            "url": resolved_target,
            "target": target or None,
            "attachments": [str(item) for item in attachments],
            "title": title,
            "challenge_id": challenge_id,
            "contest_id": contest_id,
            "description": description,
            "flag_format": arguments.get("flag_format", r"flag\{[^{}\n]+\}"),
            "output_root": arguments.get("output_root") or arguments.get("workspace_root") or self.config.workspace_root,
            "config_path": arguments.get("config_path"),
            "timeout": float(arguments.get("timeout", 8.0)),
            "max_js_assets": int(arguments.get("max_js_assets", 8)),
            "max_rounds": int(max_rounds),
            "use_browser_mcp": bool(use_browser_mcp),
            "use_remote_host": use_remote_host,
            "remote_selection": remote_selection,
            "speed_mode": speed_mode,
            "speed_profile": speed_profile,
            "skill_resolution": skill_resolution,
            "autopilot_plan": autopilot_plan,
            "knowledge_selection": knowledge_selection,
            "input_summary": {
                "category": category,
                "target": target or "",
                "attachment_count": len(attachments),
                "hint": arguments.get("hint", ""),
                "mode": arguments.get("mode", "standard"),
                "speed_mode": speed_mode,
                "autopilot_summary": autopilot_plan.get("summary", ""),
                "selected_skill_category": knowledge_selection.get("selected_skill_category", category),
                "category_confidence": knowledge_selection.get("category_confidence", 0.0),
                "capability_plan": toolkit_capability_plan,
            },
        }

    def create_incoming_dir(self, prefix="run"):
        path = self.incoming_root / "{0}-{1}".format(prefix, uuid.uuid4().hex[:12])
        path.mkdir(parents=True, exist_ok=True)
        return path

    def collect_attachment_inputs(self, arguments):
        values = []
        attachments = arguments.get("attachments", [])
        if isinstance(attachments, (str, Path)):
            values.append(str(attachments))
        else:
            values.extend(list(attachments or []))

        singular = arguments.get("attachment")
        if singular:
            if isinstance(singular, (list, tuple, set)):
                values.extend(str(item) for item in singular if item)
            else:
                values.append(str(singular))
        return values

    def expand_attachment_inputs(self, attachment_inputs):
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

    def clean_target(self, target):
        if not target:
            return ""
        text = str(target).strip().strip("`\"'")
        windows_file = re.match(r"^([A-Za-z]:\\.*?\.[A-Za-z0-9]{1,8})(?:[\s.,;:，。；：].*)?$", text)
        if windows_file:
            text = windows_file.group(1)
        return text.rstrip(".,;:!?)]}>，。；：！？）】》")

    def resolve_speed_mode(self, explicit_mode=None, *texts):
        explicit = str(explicit_mode or "").strip().lower()
        if explicit in {"fastest", "fast", "speedrun", "speed-run"}:
            return "fastest"
        if explicit in {"standard", "normal", "default"}:
            return "standard"

        for text in texts:
            blob = str(text or "")
            lowered = blob.lower()
            if any(keyword in lowered for keyword in ("fastest", "speedrun", "speed-run")):
                return "fastest"
            if any(keyword in blob for keyword in ("最快", "搏一把")):
                return "fastest"
        return "standard"

    def resolve_speed_profile(self, speed_mode):
        speed_mode = str(speed_mode or "standard").strip().lower() or "standard"
        configured_profiles = dict(getattr(self.config, "speed_profiles", {}) or {})
        configured_fastest = dict(configured_profiles.get("fastest") or {})

        if speed_mode != "fastest":
            return {
                "enabled": False,
                "skip_knowledge": False,
                "max_tool_calls": 0,
                "pwn_remote_only": False,
                "compact_output": False,
                "skip_preview": False,
                "prefer_one_shot_scripts": False,
            }

        profile = {
            "enabled": True,
            "skip_knowledge": True,
            "max_tool_calls": 4,
            "pwn_remote_only": True,
            "compact_output": True,
            "skip_preview": True,
            "prefer_one_shot_scripts": True,
        }
        profile.update(configured_fastest)
        profile["enabled"] = True
        profile["max_tool_calls"] = max(1, int(profile.get("max_tool_calls", 4) or 4))
        return profile

    def resolve_target(self, category, target):
        if not target:
            return None
        if self.looks_like_local_path(target):
            return None
        if category == "web" and re.match(r"^[A-Za-z0-9_.-]+:\d{1,5}$", target):
            return "http://{0}".format(target)
        return target

    def infer_title(self, category, target, attachments):
        if attachments:
            first = Path(attachments[0])
            if first.name:
                return first.stem
        if target:
            text = re.sub(r"^[a-z]+://", "", str(target), flags=re.IGNORECASE)
            text = text.strip("/").replace("/", "-").replace(":", "-")
            if text:
                return text[:80]
        return "manual-{0}".format(category)

    def infer_brief_title(self, task, target, attachments, category):
        for line in (task or "").splitlines():
            text = line.strip().strip("#").strip()
            if not text:
                continue
            if len(text) <= 80:
                return text
            return text[:80]
        return self.infer_title(category, target, attachments)

    def extract_target(self, task):
        if not task:
            return ""
        text = str(task)
        label_patterns = [
            r"(?im)(?:url|网址|网站链接|target|目标|题目链接)\s*[:：]\s*(\S+)",
            r"(?im)([a-z]+://[^\s'\"<>]+)",
            r"(?im)\b((?:\d{1,3}\.){3}\d{1,3}:\d{1,5})\b",
            r"(?im)\b([a-z0-9.-]+\.[a-z]{2,}:\d{1,5})\b",
            r"(?im)\b([A-Za-z]:\\[^\r\n]+)",
        ]
        for pattern in label_patterns:
            match = re.search(pattern, text)
            if match:
                return self.clean_target(match.group(1))
        return ""

    def infer_category(self, task, target, attachments):
        resolution = self.skill_resolver.resolve(
            task_text=task,
            target=target,
            attachments=attachments,
            explicit_category="",
            speed_mode="standard",
        )
        return (resolution.get("category") or {}).get("selected_skill_category", "misc")

    def looks_like_local_path(self, target):
        if not target:
            return False
        if re.match(r"^[a-z]+://", str(target), flags=re.IGNORECASE):
            return False
        text = str(target)
        if "\\" in text or "/" in text or re.match(r"^[A-Za-z]:", text):
            return True
        return Path(text).exists()

    def select_remote_host(self, category, target="", preferred=None):
        return self.remote_selector.recommend_host(
            category=category,
            target=target,
            preferred=preferred,
        )

    def choose_default_remote_host(self, category, target=""):
        return self.select_remote_host(category=category, target=target).get("selected_host", "")

    def default_max_rounds(self, category):
        if category == "web":
            return int(self.config.web_policy.get("max_rounds", 6))
        if category in {"re", "reverse", "pwn"}:
            return 7
        return 5

    def slugify(self, value):
        text = re.sub(r"[^a-zA-Z0-9._-]+", "-", str(value or "item").strip())
        text = text.strip("-")
        return text or "item"
