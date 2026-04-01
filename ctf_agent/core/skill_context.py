from pathlib import Path

from ctf_agent.knowledge import SkillResolver


_SKILL_RESOLVER = SkillResolver()


def normalize_speed_mode(value, default="standard"):
    return str(value or default or "standard").strip().lower() or "standard"


def build_task_text(payload=None, category="", task_text=""):
    payload = dict(payload or {})
    if str(task_text or "").strip():
        return str(task_text).strip()
    parts = [
        str(payload.get("task") or ""),
        str(payload.get("task_body") or ""),
        str(payload.get("title") or ""),
        str(payload.get("description") or ""),
        str(payload.get("hint") or ""),
        str(category or ""),
    ]
    return "\n".join([item for item in parts if item]).strip()


def _normalize_attachment_inputs(values):
    normalized = []
    for item in list(values or []):
        if isinstance(item, dict):
            candidate = item.get("path") or item.get("uri") or item.get("name") or ""
        else:
            candidate = item
        text = str(candidate or "").strip()
        if text:
            normalized.append(text)
    return normalized


def resolve_skill_context(payload=None, metadata=None, category="", target="", attachments=None, speed_mode=None, task_text=""):
    payload = dict(payload or {})
    metadata = dict(metadata or payload.get("metadata") or {})
    autopilot = dict(payload.get("autopilot_plan") or metadata.get("autopilot_plan") or {})
    runtime_speed = normalize_speed_mode(
        speed_mode
        or payload.get("speed_mode")
        or metadata.get("speed_mode")
        or autopilot.get("speed_mode")
        or ((payload.get("skill_resolution") or {}).get("runtime") or {}).get("speed_mode")
        or ((metadata.get("skill_resolution") or {}).get("runtime") or {}).get("speed_mode")
    )

    runtime_category = str(category or payload.get("category") or metadata.get("category") or "").strip().lower()
    runtime_target = str(target or payload.get("target") or payload.get("url") or metadata.get("target") or "").strip()
    runtime_attachments = _normalize_attachment_inputs(attachments or payload.get("attachments") or metadata.get("attachments") or [])
    runtime_task_text = build_task_text(payload=payload, category=runtime_category, task_text=task_text)

    skill_resolution = dict(payload.get("skill_resolution") or metadata.get("skill_resolution") or autopilot.get("skill_resolution") or {})
    cached_speed = normalize_speed_mode(((skill_resolution.get("runtime") or {}).get("speed_mode") or ""))
    if not skill_resolution or cached_speed != runtime_speed:
        skill_resolution = _SKILL_RESOLVER.resolve(
            task_text=runtime_task_text,
            target=runtime_target,
            attachments=[Path(item) for item in runtime_attachments],
            explicit_category=runtime_category,
            speed_mode=runtime_speed,
        )

    category_info = dict(skill_resolution.get("category") or {})
    skillpack = dict(skill_resolution.get("skillpack") or {})
    knowledge_info = dict(skill_resolution.get("knowledge") or {})
    runtime_info = dict(skill_resolution.get("runtime") or {})
    recommendations = dict(skill_resolution.get("recommendations") or {})
    legacy_selection = dict(payload.get("knowledge_selection") or metadata.get("knowledge_selection") or _SKILL_RESOLVER.to_legacy_selection(skill_resolution))
    autopilot_knowledge = dict(autopilot.get("knowledge") or {})

    knowledge = {
        "selected_skill_category": autopilot_knowledge.get(
            "selected_skill_category",
            legacy_selection.get("selected_skill_category", category_info.get("selected_skill_category", runtime_category)),
        ),
        "pack_name": autopilot_knowledge.get(
            "pack_name",
            legacy_selection.get("pack_name", knowledge_info.get("pack_name", skillpack.get("label", ""))),
        ),
        "knowledge_pack": dict(
            autopilot_knowledge.get(
                "knowledge_pack",
                legacy_selection.get("knowledge_pack", skillpack.get("knowledge_pack", {})),
            )
        ),
        "knowledge_topics": list(
            autopilot_knowledge.get(
                "knowledge_topics",
                legacy_selection.get("knowledge_topics", knowledge_info.get("knowledge_topics", [])),
            )
        ),
        "top_tactics": list(
            autopilot_knowledge.get(
                "top_tactics",
                legacy_selection.get("top_tactics", knowledge_info.get("top_tactics", [])),
            )
        ),
        "reference_docs": list(
            autopilot_knowledge.get(
                "reference_docs",
                legacy_selection.get("reference_docs", knowledge_info.get("reference_docs", [])),
            )
        ),
        "tactics_consumed": list(
            autopilot_knowledge.get(
                "tactics_consumed",
                legacy_selection.get("top_tactics", knowledge_info.get("top_tactics", [])),
            )
        )[:3],
        "category_confidence": autopilot_knowledge.get(
            "category_confidence",
            legacy_selection.get("category_confidence", category_info.get("category_confidence", 0.0)),
        ),
        "category_evidence": list(
            autopilot_knowledge.get(
                "category_evidence",
                legacy_selection.get("category_evidence", category_info.get("category_evidence", [])),
            )
        ),
        "explicit_category": autopilot_knowledge.get(
            "explicit_category",
            legacy_selection.get("explicit_category", category_info.get("explicit_category", "")),
        ),
        "auto_category": autopilot_knowledge.get(
            "auto_category",
            legacy_selection.get("auto_category", category_info.get("auto_category", "")),
        ),
        "category_consistent": bool(
            autopilot_knowledge.get(
                "category_consistent",
                legacy_selection.get("category_consistent", category_info.get("category_consistent", False)),
            )
        ),
        "speed_mode": runtime_speed,
        "retrieval_enabled": bool(runtime_info.get("retrieval_enabled", True)),
        "retrieval_reason": str(runtime_info.get("retrieval_reason", "")),
        "resolution_summary": str(skill_resolution.get("summary", "")),
    }

    merged_autopilot = dict(autopilot)
    merged_autopilot_knowledge = dict(autopilot_knowledge)
    for key, value in knowledge.items():
        current = merged_autopilot_knowledge.get(key)
        if current in (None, "", [], {}):
            if isinstance(value, dict):
                merged_autopilot_knowledge[key] = dict(value)
            elif isinstance(value, list):
                merged_autopilot_knowledge[key] = list(value)
            else:
                merged_autopilot_knowledge[key] = value
    merged_autopilot["knowledge"] = merged_autopilot_knowledge
    merged_autopilot.setdefault("skill_resolution", dict(skill_resolution))
    merged_autopilot.setdefault("selected_skill_category", knowledge["selected_skill_category"])
    merged_autopilot.setdefault("category_confidence", knowledge["category_confidence"])
    merged_autopilot.setdefault("category_evidence", list(knowledge["category_evidence"]))
    merged_autopilot.setdefault("top_tactics", list(knowledge["top_tactics"]))
    merged_autopilot.setdefault("reference_docs", list(knowledge["reference_docs"]))
    merged_autopilot.setdefault("speed_mode", runtime_speed)

    return {
        "speed_mode": runtime_speed,
        "skill_resolution": dict(skill_resolution),
        "legacy_selection": legacy_selection,
        "category": category_info,
        "skillpack": skillpack,
        "knowledge": knowledge,
        "runtime": runtime_info,
        "recommendations": {
            "recommended_tools": list(recommendations.get("recommended_tools", [])),
            "recommended_mcp": list(recommendations.get("recommended_mcp", [])),
            "preferred_remote_templates": list(recommendations.get("preferred_remote_templates", [])),
        },
        "autopilot": merged_autopilot,
    }
