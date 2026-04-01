from pathlib import Path

from ctf_agent.core.board import build_triage_board
from ctf_agent.core.memory import StateMemory
from ctf_agent.core.models import ChallengeState
from ctf_agent.core.profiles import get_profile
from ctf_agent.solvers.base import BaseSolver


class TriageSolver(BaseSolver):
    SOLVER_NAME = "triage"
    TEXT_SUFFIXES = {
        ".txt", ".md", ".json", ".yaml", ".yml", ".xml", ".csv", ".log",
        ".pcap", ".pcapng", ".js", ".py", ".php", ".java", ".c", ".cpp",
        ".asm", ".ps1", ".sh", ".go", ".rs", ".html", ".htm", ".pem", ".pub",
        ".enc", ".sage", ".sage.py", ".bf", ".b64", ".sigmf-meta",
    }
    IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp"}
    ARCHIVE_SUFFIXES = {".zip", ".7z", ".rar", ".gz", ".tgz", ".tar", ".xz"}
    OFFICE_SUFFIXES = {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf"}
    BINARY_SUFFIXES = {".exe", ".dll", ".bin", ".elf", ".so", ".o", ".class", ".jar", ".apk", ".ipa", ".raw", ".img", ".dd", ".mem", ".vmem", ".iq", ".cu8", ".cfile", ".sigmf-data"}

    def __init__(self, file_tool, shell_tool, verifier, toolkit_tool=None, remote_tool=None, mcp_registry=None, profile=None, http_tool=None):
        self.file_tool = file_tool
        self.shell_tool = shell_tool
        self.verifier = verifier
        self.toolkit_tool = toolkit_tool
        self.remote_tool = remote_tool
        self.mcp_registry = mcp_registry
        self.profile = profile or {}
        self.http_tool = http_tool

    def solve(self, challenge, workspace):
        workspace = Path(workspace)
        state = ChallengeState(phase="collect")
        memory = StateMemory(state)
        solver_meta = self._resolve_solver_metadata(challenge)
        autopilot = dict(solver_meta.get("autopilot") or {})
        knowledge = dict(solver_meta.get("knowledge") or {})
        recommendations = dict(solver_meta.get("recommendations") or {})
        category = str(knowledge.get("selected_skill_category") or challenge.category or "misc").strip().lower() or "misc"
        profile = self.profile or get_profile(category)

        context = {
            "attachments": [],
            "configured_tools": self.toolkit_tool.available_tools() if self.toolkit_tool and self.toolkit_tool.is_configured() else [],
            "toolkit_capabilities": self.toolkit_tool.capability_digest() if self.toolkit_tool and self.toolkit_tool.is_configured() else {},
            "used_tools": [],
            "recommended_tools": sorted(
                set(
                    list(autopilot.get("local_tools", []))
                    + list(recommendations.get("recommended_tools", []))
                    + (
                        self.toolkit_tool.recommend_tools(category, subtype="")
                        if self.toolkit_tool and self.toolkit_tool.is_configured()
                        else []
                    )
                )
            ),
            "available_mcp_servers": [item.get("name", "") for item in self.mcp_registry.list_servers()] if self.mcp_registry and self.mcp_registry.has_servers() else [],
            "mcp_digest": self.mcp_registry.tool_digest() if self.mcp_registry and self.mcp_registry.has_servers() else [],
            "recommended_mcp": sorted(set(list(autopilot.get("recommended_mcp", [])) + list(recommendations.get("recommended_mcp", [])))),
            "used_mcp": [],
            "available_remote_hosts": self.remote_tool.list_hosts() if self.remote_tool else [],
            "selected_remote_host": autopilot.get("selected_remote_host", ""),
            "remote_selection_mode": "",
            "remote_selection_reason": "",
            "remote_selection_candidates": [],
            "remote_reports": [],
            "remote_placeholder": "Remote helper layer is available for later probe/upload/python execution.",
            "recommended_path": "",
            "next_actions": list(autopilot.get("solver_hints", [])),
            "blockers": [],
            "normalized_target": challenge.target or "",
            "autopilot": autopilot,
            "knowledge": dict(knowledge),
        }
        self._bind_runtime_context(challenge, workspace, memory=memory, context=context)

        if profile.get("goal"):
            memory.add_hypothesis(profile["goal"])
        for tactic in list(context["knowledge"].get("top_tactics", []))[:3]:
            memory.add_hypothesis(tactic)
        if autopilot.get("summary"):
            memory.add_finding("autopilot", "自动编排计划已生成", autopilot["summary"], 0.72)
        if context["knowledge"].get("pack_name"):
            memory.add_finding(
                "knowledge",
                "Selected embedded playbook",
                "{0} | confidence={1}".format(
                    context["knowledge"].get("pack_name", ""),
                    context["knowledge"].get("category_confidence", 0.0),
                ),
                0.78,
            )

        if context["configured_tools"]:
            memory.add_finding("toolkit", "Local toolkit connected", ", ".join(context["configured_tools"][:10]), 0.85)
        if context["available_mcp_servers"]:
            memory.add_finding("mcp", "Nested MCP servers available", ", ".join(context["available_mcp_servers"]), 0.70)
        if context["available_remote_hosts"]:
            memory.add_finding("remote", "Remote helper hosts available", ", ".join(context["available_remote_hosts"]), 0.58)
            remote_selection = self._select_remote_host(challenge, category)
            context["selected_remote_host"] = remote_selection.get("selected_host", "")
            context["remote_selection_mode"] = remote_selection.get("selection_mode", "")
            context["remote_selection_reason"] = remote_selection.get("reason", "")
            context["remote_selection_candidates"] = list(remote_selection.get("candidates", []))
            if context["selected_remote_host"]:
                memory.add_finding(
                    "remote",
                    "Recommended remote helper host",
                    "{0} | {1}".format(context["selected_remote_host"], context["remote_selection_reason"]),
                    0.52,
                )

        if not challenge.attachments and not challenge.target:
            state.blocked_reason = "Missing both target and attachments; triage cannot start."
            memory.record_action("collect", "intake", "blocked", state.blocked_reason)
            context["blockers"].append(state.blocked_reason)

        for attachment in challenge.attachments:
            summary = self._inspect_attachment(Path(attachment), workspace, memory, category, context)
            context["attachments"].append(summary)

        if challenge.target:
            if category == "web":
                context["recommended_path"] = "web-followup"
                memory.add_finding("target", "Remote target detected", challenge.target, 0.75)
            else:
                memory.add_finding("target", "Input includes remote target", challenge.target, 0.45)

        primary = self._pick_primary_attachment(context["attachments"])
        if primary:
            primary["primary"] = True
            memory.add_finding("triage", "Primary attachment candidate", primary["name"], 0.80)

        self._recommend_followup(challenge, category, context, memory, primary)
        self._specialized_analysis(challenge, category, workspace, state, memory, context, primary)

        state.phase = "report"
        self._write_notes(challenge, workspace, state, profile, context)
        self._write_solution_stub(challenge, workspace, context)
        run_status = "solved" if state.candidate_flags else "unresolved"
        board = build_triage_board(
            challenge,
            state,
            workspace,
            solver_name=getattr(self, "SOLVER_NAME", "triage"),
            context=context,
            run_meta={"run_id": challenge.metadata.get("run_id", ""), "status": run_status},
        )
        self.file_tool.write_json(workspace / "triage_board.json", board)
        return state

    def _specialized_analysis(self, challenge, category, workspace, state, memory, context, primary):
        return None

    def _inspect_attachment(self, attachment, workspace, memory, category, context):
        info = {
            "name": attachment.name,
            "path": str(attachment),
            "size": attachment.stat().st_size if attachment.exists() else 0,
            "kind": "unknown",
            "primary": False,
            "score": 0,
            "artifact": "",
            "notes": "",
        }
        artifact_root = workspace / "artifacts"

        if not attachment.exists():
            info["kind"] = "missing"
            info["notes"] = "attachment missing"
            memory.record_action("collect", "inspect {0}".format(attachment.name), "missing", info["notes"])
            return info

        kind = self._classify_attachment(attachment)
        info["kind"] = kind
        info["score"] = self._score_attachment(kind, category, attachment)
        memory.record_action("collect", "classify {0}".format(attachment.name), "ok", "classified as {0}".format(kind))

        if kind == "text":
            text = self.file_tool.read_text(attachment, limit_bytes=200000)
            artifact = artifact_root / "{0}_preview.txt".format(attachment.stem)
            self.file_tool.write_text(artifact, text[:80000])
            info["artifact"] = str(artifact)
            context["used_tools"].append("preview")
            memory.record_action("collect", "preview {0}".format(attachment.name), "ok", "preview text attachment", str(artifact))
            self._scan_text(text, attachment.name, memory)
        elif kind == "binary":
            if self.toolkit_tool and self.toolkit_tool.has_tool("strings"):
                result = self.toolkit_tool.run_named_tool("strings", [str(attachment)], timeout=120)
                artifact = artifact_root / "{0}_strings.txt".format(attachment.stem)
                payload = result.get("stdout", "") + ("\n" + result.get("stderr", "") if result.get("stderr") else "")
                self.file_tool.write_text(artifact, payload)
                info["artifact"] = str(artifact)
                context["used_tools"].append("strings")
                memory.record_action("collect", "strings {0}".format(attachment.name), str(result.get("status", "unknown")), "extract binary strings", str(artifact))
                self._scan_text(payload, attachment.name, memory)
        elif kind == "image":
            if self.toolkit_tool and self.toolkit_tool.has_tool("exiftool"):
                result = self.toolkit_tool.run_named_tool("exiftool", [str(attachment)], timeout=90)
                artifact = artifact_root / "{0}_exif.txt".format(attachment.stem)
                payload = result.get("stdout", "") + ("\n" + result.get("stderr", "") if result.get("stderr") else "")
                self.file_tool.write_text(artifact, payload)
                info["artifact"] = str(artifact)
                context["used_tools"].append("exiftool")
                memory.record_action("collect", "exiftool {0}".format(attachment.name), str(result.get("status", "unknown")), "extract image metadata", str(artifact))
                self._scan_text(payload, attachment.name, memory)
            info["notes"] = "good candidate for stego / metadata analysis"
        elif kind == "archive":
            info["notes"] = "unpack and feed extracted content back into triage"
            memory.add_finding("archive", "Archive attachment detected", attachment.name, 0.45)
        elif kind == "pcap":
            info["notes"] = "good candidate for flow extraction / protocol recovery"
            memory.add_finding("pcap", "Traffic capture detected", attachment.name, 0.62)
        elif kind == "office":
            info["notes"] = "inspect metadata, macros, embedded objects and hidden text"
            memory.add_finding("office", "Office or document attachment detected", attachment.name, 0.52)
        else:
            info["notes"] = "keep as context and continue triage manually if needed"

        return info

    def _classify_attachment(self, attachment):
        suffix = attachment.suffix.lower()
        if suffix in {".pcap", ".pcapng"}:
            return "pcap"
        if suffix in self.TEXT_SUFFIXES:
            return "text"
        if suffix in self.IMAGE_SUFFIXES:
            return "image"
        if suffix in self.ARCHIVE_SUFFIXES:
            return "archive"
        if suffix in self.OFFICE_SUFFIXES:
            return "office"
        if suffix in self.BINARY_SUFFIXES:
            return "binary"
        magic = self.file_tool.read_bytes(attachment, limit_bytes=8)
        if magic.startswith(b"\x7fELF") or magic.startswith(b"MZ") or magic.startswith(b"\xca\xfe\xba\xbe"):
            return "binary"
        if magic.startswith(b"PK\x03\x04"):
            return "archive"
        return "unknown"

    def _score_attachment(self, kind, category, attachment):
        score = 0
        if kind == "binary":
            score += 80 if category in {"pwn", "re", "reverse", "malware"} else 45
        elif kind == "pcap":
            score += 80 if category == "forensics" else 50
        elif kind == "image":
            score += 74 if category in {"forensics", "osint", "misc"} else 35
        elif kind == "text":
            score += 76 if category in {"web", "crypto", "osint"} else 52
        elif kind == "archive":
            score += 60
        elif kind == "office":
            score += 58 if category in {"forensics", "malware"} else 42
        score += min(20, int((attachment.stat().st_size if attachment.exists() else 0) / 50000))
        return score

    def _pick_primary_attachment(self, attachments):
        if not attachments:
            return None
        return sorted(attachments, key=lambda item: item.get("score", 0), reverse=True)[0]

    def _recommend_followup(self, challenge, category, context, memory, primary):
        recommended_tools = list(context.get("recommended_tools", []))
        recommended_mcp = list(context.get("recommended_mcp", []))
        next_actions = list(context.get("knowledge", {}).get("top_tactics", []))[:3]
        recommended_path = context.get("recommended_path", "")

        followup_by_category = {
            "web": "web-followup",
            "pwn": "binary-followup",
            "re": "binary-followup",
            "reverse": "binary-followup",
            "crypto": "crypto-followup",
            "forensics": "forensics-followup",
            "osint": "osint-followup",
            "malware": "malware-followup",
            "misc": "misc-followup",
        }
        if not recommended_path:
            recommended_path = followup_by_category.get(category, "manual-followup")

        if challenge.target and category == "web":
            next_actions.append("从目标 URL 继续做表单、路由、上传点和浏览器态侦察。")
        elif category == "crypto":
            next_actions.append("先识别编码/密码体制，再决定是否进入 RSA/PRNG 或 Sage 路线。")
        elif category == "forensics":
            next_actions.append("先抽时间线、对象文件、元数据和隐藏内容。")
        elif category == "osint":
            next_actions.append("先拆实体线索，再按社媒、DNS/Web、地理信息三条线推进。")
        elif category == "malware":
            next_actions.append("先恢复配置、C2 和协议，再决定是否进入深逆向。")
        elif category == "misc":
            next_actions.append("先强制分类到编码、jail、DNS、RF/SDR 或 stego 子路线。")

        if primary and not challenge.target:
            kind = primary.get("kind")
            if kind == "binary" and category not in {"pwn", "re", "reverse", "malware"}:
                recommended_path = "binary-followup"
                next_actions.append("主附件偏二进制，必要时切到 binary follow-up。")
            elif kind == "pcap" and category not in {"forensics"}:
                recommended_path = "pcap-followup"
                next_actions.append("主附件是流量包，优先提取会话与对象。")
            elif kind == "image" and category not in {"osint", "forensics"}:
                recommended_path = "stego-followup"
                next_actions.append("主附件是图片，优先检查 metadata 与隐写线索。")

        if self.mcp_registry and self.mcp_registry.has_servers():
            if recommended_path in {"binary-followup", "malware-followup"}:
                reverse_hint = self.mcp_registry.pick_reverse_tool()
                if reverse_hint:
                    recommended_mcp.append("{0}::{1}".format(reverse_hint["server"], reverse_hint["tool"]["name"]))
            if recommended_path in {"web-followup", "osint-followup"}:
                browser_hint = self.mcp_registry.pick_browser_tool()
                if browser_hint:
                    recommended_mcp.append("{0}::{1}".format(browser_hint["server"], browser_hint["tool"]["name"]))

        context["recommended_path"] = recommended_path
        context["recommended_tools"] = self._dedupe(recommended_tools)
        context["recommended_mcp"] = self._dedupe(recommended_mcp)
        context["next_actions"] = self._dedupe(next_actions)

        memory.add_finding("triage", "Recommended next path", recommended_path, 0.82)
        if context["recommended_tools"]:
            memory.add_finding("triage", "Recommended tools", ", ".join(context["recommended_tools"]), 0.60)
        if context["recommended_mcp"]:
            memory.add_finding("triage", "Recommended MCP", ", ".join(context["recommended_mcp"]), 0.58)

    def _write_notes(self, challenge, workspace, state, profile, context):
        knowledge = dict(context.get("knowledge") or {})
        lines = [
            "# Challenge Notes",
            "",
            "## Metadata",
            "- Title: {0}".format(challenge.title),
            "- Category: {0}".format(challenge.category),
            "- Target: {0}".format(challenge.target or "N/A"),
            "",
            "## Goal",
            "- {0}".format(profile.get("goal", "Keep pushing with Chinese output until a validated flag or a clear blocker appears.")),
            "",
            "## Knowledge Pack",
            "- Selected playbook: {0}".format(knowledge.get("pack_name", "N/A")),
            "- Selected category: {0}".format(knowledge.get("selected_skill_category", challenge.category)),
            "- Confidence: {0}".format(knowledge.get("category_confidence", 0.0)),
        ]
        for item in list(knowledge.get("top_tactics", []))[:5]:
            lines.append("- tactic: {0}".format(item))
        if knowledge.get("reference_docs"):
            lines.append("- reference_docs:")
            for item in list(knowledge.get("reference_docs", []))[:5]:
                lines.append("  - {0}".format(item))

        lines.extend(["", "## Attachment Triage"])
        if context["attachments"]:
            for item in sorted(context["attachments"], key=lambda value: value.get("score", 0), reverse=True):
                marker = " [primary]" if item.get("primary") else ""
                lines.append("- {0}: {1} score={2}{3}".format(item["name"], item["kind"], item.get("score", 0), marker))
                if item.get("notes"):
                    lines.append("  notes: {0}".format(item["notes"]))
        else:
            lines.append("- No attachments were provided.")

        specialized_sections = list(self._build_specialized_note_sections(context))
        if specialized_sections:
            lines.extend([""])
            lines.extend(specialized_sections)

        lines.extend(["", "## Findings"])
        if state.findings:
            for item in state.findings:
                lines.append("- [{0}] {1}: {2}".format(item.source, item.summary, item.evidence))
        else:
            lines.append("- No findings yet.")

        lines.extend(["", "## Candidate Flags"])
        if state.candidate_flags:
            for item in state.candidate_flags:
                lines.append("- {0} ({1:.2f})".format(item.value, item.confidence))
        else:
            lines.append("- No candidate flags yet.")

        lines.extend(["", "## Recommended Path"])
        lines.append("- {0}".format(context.get("recommended_path") or "manual-followup"))
        if context.get("recommended_tools"):
            lines.append("- tools: {0}".format(", ".join(context["recommended_tools"])))
        if context.get("recommended_mcp"):
            lines.append("- mcp: {0}".format(", ".join(context["recommended_mcp"])))
        if context.get("selected_remote_host"):
            lines.append("- remote: {0}".format(context["selected_remote_host"]))

        lines.extend(["", "## Next Actions"])
        if context.get("next_actions"):
            for item in context["next_actions"]:
                lines.append("- {0}".format(item))
        else:
            lines.append("- No next action recorded.")

        self.file_tool.write_text(workspace / "notes.md", "\n".join(lines).strip() + "\n")

    def _write_solution_stub(self, challenge, workspace, context):
        lines = [
            "#!/usr/bin/env python3",
            "# -*- coding: utf-8 -*-",
            '"""',
            "Triage-driven placeholder script.",
            "Read triage_board.json and notes.md before continuing.",
            '"""',
            "",
            "def main():",
            "    print('category =', {0!r})".format(challenge.category),
            "    print('recommended_path =', {0!r})".format(context.get("recommended_path", "")),
        ]
        if context.get("recommended_tools"):
            lines.append("    print('recommended_tools =', {0!r})".format(context["recommended_tools"]))
        if context.get("selected_remote_host"):
            lines.append("    print('selected_remote_host =', {0!r})".format(context["selected_remote_host"]))
        extra_lines = list(self._build_specialized_solution_lines(challenge, context))
        if extra_lines:
            lines.extend([""])
            lines.extend(extra_lines)
        lines.extend(["", "if __name__ == '__main__':", "    main()"])
        self.file_tool.write_text(workspace / "solution.py", "\n".join(lines) + "\n")

    def _build_specialized_note_sections(self, context):
        specialized = dict(context.get("specialized") or {})
        if not specialized:
            return []

        lines = ["## Specialized Analysis"]
        summary = str(specialized.get("summary") or "").strip()
        if summary:
            lines.append("- Summary: {0}".format(summary))
        subtype = str(specialized.get("subtype") or "").strip()
        if subtype:
            lines.append("- Subtype: {0}".format(subtype))
        if specialized.get("artifact_path"):
            lines.append("- Artifact: {0}".format(specialized.get("artifact_path")))
        if specialized.get("best_path"):
            lines.append("- Best Path: {0}".format(specialized.get("best_path")))
        used_tools = list(specialized.get("used_tools", []) or context.get("used_tools", []))
        used_mcp = list(specialized.get("used_mcp", []) or context.get("used_mcp", []))
        capability_plan = dict(context.get("capability_plan") or {})
        if used_tools:
            lines.append("- Used Tools: {0}".format(", ".join(used_tools[:8])))
        if used_mcp:
            lines.append("- Used MCP: {0}".format(", ".join(used_mcp[:6])))
        if capability_plan:
            lines.append(
                "- Capability Plan: lanes={0}; sidecars={1}".format(
                    "+".join(list(capability_plan.get("selected_lanes", []))) or "?",
                    ", ".join(list(capability_plan.get("recommended_sidecars", []))[:5]) or "none",
                )
            )
        for key in ["entities", "decoded_candidates", "iocs", "indicators", "subpaths"]:
            values = specialized.get(key)
            if isinstance(values, list) and values:
                lines.append("- {0}:".format(key))
                for item in values[:8]:
                    lines.append("  - {0}".format(item))
        return lines

    def _build_specialized_solution_lines(self, challenge, context):
        specialized = dict(context.get("specialized") or {})
        lines = []
        if specialized.get("artifact_path"):
            lines.append("    print('specialized_artifact =', {0!r})".format(specialized.get("artifact_path")))
        if specialized.get("subtype"):
            lines.append("    print('specialized_subtype =', {0!r})".format(specialized.get("subtype")))
        return lines

    def _scan_text(self, text, source, memory):
        for flag in self.verifier.discover_from_text(text or "")[:10]:
            memory.add_candidate_flag(flag, source=source, confidence=0.55, reproducible=True)
        lowered = (text or "").lower()
        for keyword in ["flag", "password", "token", "jwt", "secret", "admin", "upload", "deserialize", "xxe", "rsa", "pcap", "dns", "c2"]:
            if keyword in lowered:
                memory.add_finding(source, "Sensitive keyword hit", keyword, 0.46)

    def _select_remote_host(self, challenge, category):
        if not self.remote_tool:
            return {}
        decision = dict((challenge.metadata or {}).get("remote_selection") or {})
        if decision:
            return decision
        return self.remote_tool.recommend_host(
            category=category,
            target=challenge.target or "",
            preferred=(challenge.metadata or {}).get("use_remote_host"),
        )

    def _dedupe(self, values):
        items = []
        for value in values:
            if value and value not in items:
                items.append(value)
        return items
