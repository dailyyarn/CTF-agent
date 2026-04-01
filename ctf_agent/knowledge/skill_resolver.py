import re
from pathlib import Path
from typing import Dict, List, Optional

from ctf_agent.knowledge.skillpacks import (
    SKILLPACKS,
    get_skillpack,
    normalize_category,
    supported_categories,
)


class SkillResolver(object):
    """Resolve category, skillpack, runtime policy, and recommendations."""

    def resolve(self, task_text="", target="", attachments=None, explicit_category=None, speed_mode="standard"):
        attachments = [Path(item) for item in list(attachments or [])]
        normalized_speed = str(speed_mode or "standard").strip().lower() or "standard"
        explicit = normalize_category(explicit_category)
        auto_scores = {category: 0 for category in supported_categories()}
        auto_evidence = {category: [] for category in supported_categories()}
        text = " ".join(
            [
                str(task_text or ""),
                str(target or ""),
                " ".join(item.name for item in attachments),
            ]
        ).lower()

        def score(category, points, reason):
            auto_scores[category] += int(points)
            auto_evidence[category].append(str(reason))

        if target:
            lowered_target = str(target).lower()
            if re.match(r"^[a-z]+://", lowered_target):
                score("web", 45, "target looks like a URL")
                score("osint", 8, "target includes a web URL")
            elif re.match(r"^[a-z0-9_.-]+:\d{1,5}$", lowered_target):
                score("web", 28, "target looks like host:port for a web service")
                score("pwn", 20, "target looks like host:port and may be a remote binary service")

        for category, pack in SKILLPACKS.items():
            for keyword in pack.get("keywords", []):
                if keyword and keyword.lower() in text:
                    score(category, 9, "keyword:{0}".format(keyword))

        for attachment in attachments:
            suffix = attachment.suffix.lower()
            name = attachment.name.lower()
            if suffix in {".pcap", ".pcapng", ".raw", ".img", ".dd", ".mem", ".vmem"}:
                score("forensics", 32, "forensics-oriented attachment suffix:{0}".format(suffix))
            if suffix in {".sage", ".pem", ".pub", ".enc"}:
                score("crypto", 28, "crypto-oriented attachment suffix:{0}".format(suffix))
            if suffix in {".exe", ".dll", ".ps1", ".vbs"}:
                score("malware", 14, "malware-oriented attachment suffix:{0}".format(suffix))
            if suffix in {".exe", ".dll", ".elf", ".so", ".bin", ".apk", ".ipa", ".jar", ".class"}:
                score("re", 20, "reverse-oriented attachment suffix:{0}".format(suffix))
                score("reverse", 20, "reverse-oriented attachment suffix:{0}".format(suffix))
            if suffix in {".elf", ".so", ".bin"}:
                score("pwn", 14, "binary service style suffix:{0}".format(suffix))
            if suffix in {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"}:
                score("forensics", 10, "image attachment")
                score("osint", 8, "media attachment")
                score("misc", 6, "misc image-style attachment")
            if suffix in {".zip", ".7z", ".rar", ".tar", ".gz", ".tgz"}:
                score("misc", 10, "archive attachment")
                score("forensics", 6, "archive may hide forensic material")
            if suffix in {".php", ".html", ".htm", ".js", ".ts", ".jsp", ".aspx"}:
                score("web", 18, "web-oriented attachment suffix:{0}".format(suffix))
            if "jwt" in name or "auth" in name:
                score("web", 10, "web/auth filename hint")
            if "pcap" in name or "traffic" in name:
                score("forensics", 18, "traffic filename hint")
            if "rsa" in name or "cipher" in name:
                score("crypto", 14, "crypto filename hint")
            if "social" in name or "dns" in name or "geo" in name:
                score("osint", 12, "osint filename hint")
            if "payload" in name or "shell" in name:
                score("pwn", 8, "payload filename hint")

        auto_category = max(auto_scores, key=lambda item: auto_scores[item]) if auto_scores else "misc"
        auto_score = int(auto_scores.get(auto_category, 0))
        if auto_score <= 0:
            auto_category = "misc"
            auto_score = 1
            auto_evidence["misc"].append("fallback:misc")

        selected_category = explicit or auto_category
        selected_pack = get_skillpack(selected_category, speed_mode=normalized_speed)
        selected_evidence = list(auto_evidence.get(auto_category if explicit else selected_category, []))
        if explicit:
            selected_evidence = ["explicit:{0}".format(explicit)] + list(auto_evidence.get(auto_category, []))

        confidence = min(0.99, round(max(0.2, auto_score / 80.0), 2))
        allowed_tools = list(selected_pack.get("allowed_tools", []))
        denied_tools = list(selected_pack.get("denied_tools", []))
        retrieval_enabled = "search_knowledge" in allowed_tools and "search_knowledge" not in denied_tools
        retrieval_reason = "search_knowledge allowed by runtime tool policy"
        if normalized_speed == "fastest":
            retrieval_enabled = False
            retrieval_reason = "fastest mode skipped knowledge retrieval"
        elif "search_knowledge" in denied_tools:
            retrieval_enabled = False
            retrieval_reason = "search_knowledge denied by runtime tool policy"
        elif allowed_tools and "search_knowledge" not in allowed_tools:
            retrieval_enabled = False
            retrieval_reason = "search_knowledge missing from allowed_tools"

        resolution = {
            "category": {
                "selected_skill_category": selected_category,
                "auto_category": auto_category,
                "explicit_category": explicit or "",
                "category_confidence": confidence,
                "category_evidence": selected_evidence[:8],
                "category_consistent": not explicit or explicit == auto_category,
                "solver": selected_pack.get("solver", "triage"),
            },
            "skillpack": {
                "category": selected_pack.get("category", selected_category),
                "label": selected_pack.get("label", ""),
                "solver": selected_pack.get("solver", "triage"),
                "execution_mode": selected_pack.get("execution_mode", "inline"),
                "knowledge_pack": dict(selected_pack.get("knowledge_pack", {})),
            },
            "knowledge": {
                "pack_name": selected_pack.get("label", ""),
                "knowledge_topics": list(selected_pack.get("knowledge_topics", [])),
                "top_tactics": list(selected_pack.get("top_tactics", [])),
                "reference_docs": list(selected_pack.get("reference_docs", [])),
            },
            "runtime": {
                "speed_mode": normalized_speed,
                "allowed_tools": allowed_tools,
                "denied_tools": denied_tools,
                "default_budget": dict(selected_pack.get("default_budget", {})),
                "initial_prompt_template": str(selected_pack.get("initial_prompt_template", "")),
                "followup_prompt_template": str(selected_pack.get("followup_prompt_template", "")),
                "retrieval_enabled": bool(retrieval_enabled),
                "retrieval_reason": retrieval_reason,
            },
            "recommendations": {
                "recommended_tools": list(selected_pack.get("recommended_tools", [])),
                "recommended_mcp": list(selected_pack.get("preferred_mcp", selected_pack.get("recommended_mcp", []))),
                "preferred_remote_templates": list(
                    selected_pack.get("preferred_remote_templates", selected_pack.get("recommended_remote_templates", []))
                ),
            },
        }
        resolution["summary"] = self._build_summary(resolution)
        return resolution

    @staticmethod
    def to_legacy_selection(resolution):
        resolution = dict(resolution or {})
        category = dict(resolution.get("category") or {})
        skillpack = dict(resolution.get("skillpack") or {})
        knowledge = dict(resolution.get("knowledge") or {})
        runtime = dict(resolution.get("runtime") or {})
        recommendations = dict(resolution.get("recommendations") or {})
        confidence = float(category.get("category_confidence", 0.0) or 0.0)
        return {
            "selected_skill_category": category.get("selected_skill_category", ""),
            "auto_category": category.get("auto_category", ""),
            "explicit_category": category.get("explicit_category", ""),
            "category_confidence": confidence,
            "confidence": confidence,
            "category_evidence": list(category.get("category_evidence", [])),
            "category_consistent": bool(category.get("category_consistent", False)),
            "knowledge_pack": dict(skillpack.get("knowledge_pack", {})),
            "pack_name": knowledge.get("pack_name", skillpack.get("label", "")),
            "solver": category.get("solver", skillpack.get("solver", "triage")),
            "knowledge_topics": list(knowledge.get("knowledge_topics", [])),
            "top_tactics": list(knowledge.get("top_tactics", [])),
            "reference_docs": list(knowledge.get("reference_docs", [])),
            "recommended_tools": list(recommendations.get("recommended_tools", [])),
            "recommended_mcp": list(recommendations.get("recommended_mcp", [])),
            "recommended_remote_templates": list(recommendations.get("preferred_remote_templates", [])),
            "execution_mode": skillpack.get("execution_mode", "inline"),
            "allowed_tools": list(runtime.get("allowed_tools", [])),
            "denied_tools": list(runtime.get("denied_tools", [])),
            "default_budget": dict(runtime.get("default_budget", {})),
        }

    def _build_summary(self, resolution):
        category = dict(resolution.get("category") or {})
        knowledge = dict(resolution.get("knowledge") or {})
        runtime = dict(resolution.get("runtime") or {})
        recommendations = dict(resolution.get("recommendations") or {})
        summary_parts = [
            "selected={0}".format(category.get("selected_skill_category", "misc") or "misc"),
            "auto={0}".format(category.get("auto_category", "misc") or "misc"),
            "speed={0}".format(runtime.get("speed_mode", "standard") or "standard"),
            "retrieval={0}".format("enabled" if runtime.get("retrieval_enabled") else "disabled"),
        ]
        if knowledge.get("pack_name"):
            summary_parts.append("playbook={0}".format(knowledge.get("pack_name", "")))
        recommended_tools = list(recommendations.get("recommended_tools", []))
        if recommended_tools:
            summary_parts.append("tools={0}".format(",".join(recommended_tools[:4])))
        return " | ".join(summary_parts)
