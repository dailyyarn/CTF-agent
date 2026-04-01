import json
from pathlib import Path

from ctf_agent.core.skill_context import resolve_skill_context
from ctf_agent.core.solved_export import build_flag_first_text, load_workspace_export_summary
from ctf_agent.core.workspace import (
    load_recent_mcp_calls,
    load_workspace_approval_status,
    load_workspace_mcp_status,
    load_workspace_plugin_status,
)


def build_triage_board(challenge, state, workspace, solver_name, context=None, run_meta=None):
    workspace = Path(workspace)
    context = dict(context or {})
    run_meta = dict(run_meta or {})
    attachments = list(context.get("attachments", []))
    findings = [_finding_to_dict(item) for item in list(getattr(state, "findings", []))]
    candidate_flags = [_flag_to_dict(item) for item in list(getattr(state, "candidate_flags", []))]
    exploit_plans = [_plan_to_dict(item) for item in list(getattr(state, "exploit_plans", []))]
    action_timeline = [_action_to_dict(item) for item in list(getattr(state, "tried_actions", []))]
    subagents = [_subagent_to_dict(item) for item in list(getattr(state, "subagents", []))]
    recent_actions = _recent_actions(action_timeline)
    mcp_status = load_workspace_mcp_status(workspace)
    approval_status = load_workspace_approval_status(workspace)
    plugin_status = load_workspace_plugin_status(workspace)
    recent_mcp = load_recent_mcp_calls(workspace, limit=5)
    recent_activity = _recent_activity(recent_actions, recent_mcp)
    remote_subagents = _remote_subagents_from_subagents(subagents)

    next_actions = list(context.get("next_actions", []))
    if not next_actions:
        if exploit_plans:
            next_actions.append("优先沿当前最高置信 exploit plan 继续推进。")
        elif findings:
            next_actions.append("先根据已有关键线索收缩方向，再决定调用哪个 solver 或工具。")
        else:
            next_actions.append("先完成附件或目标的基础分诊。")

    blockers = list(context.get("blockers", []))
    if getattr(state, "blocked_reason", None):
        blockers.append(state.blocked_reason)

    metadata = dict(challenge.metadata or {})
    attachment_inputs = _attachment_paths(attachments) or [str(item) for item in list(getattr(challenge, "attachments", []) or [])]
    skill_context = resolve_skill_context(
        payload={
            "category": challenge.category,
            "target": challenge.target or "",
            "attachments": attachment_inputs,
            "title": challenge.title,
            "description": challenge.description,
            "task": (metadata.get("input_summary") or {}).get("task", ""),
            "task_body": (metadata.get("input_summary") or {}).get("task_body", ""),
            "hint": metadata.get("hint", ""),
            "speed_mode": metadata.get("speed_mode") or dict(context.get("autopilot") or {}).get("speed_mode"),
            "autopilot_plan": context.get("autopilot") or metadata.get("autopilot_plan") or {},
            "knowledge_selection": metadata.get("knowledge_selection") or {},
            "skill_resolution": metadata.get("skill_resolution") or {},
        },
        metadata=metadata,
        category=challenge.category,
        target=challenge.target or "",
        attachments=attachment_inputs,
    )
    autopilot = dict(skill_context.get("autopilot") or {})
    for key, value in dict(context.get("autopilot") or {}).items():
        if key == "knowledge":
            continue
        autopilot[key] = value
    capability_plan = dict(autopilot.get("capability_plan") or {})
    capability_plan.update(dict(context.get("capability_plan") or {}))
    knowledge = dict(skill_context.get("knowledge") or {})
    knowledge.update(dict(autopilot.get("knowledge") or {}))
    knowledge.update(dict(context.get("knowledge") or {}))
    autopilot["knowledge"] = dict(knowledge)
    recommendations = dict(skill_context.get("recommendations") or {})
    specialized = dict(context.get("specialized") or {})

    board = {
        "run": {
            "meta": {
                "run_id": run_meta.get("run_id", ""),
                "status": run_meta.get("status", ""),
                "solver": solver_name,
                "workspace": str(workspace),
                "title": challenge.title,
                "category": challenge.category,
                "flag": candidate_flags[0]["value"] if candidate_flags else "",
            }
        },
        "input_summary": {
            "source": challenge.metadata.get("source", ""),
            "title": challenge.title,
            "description": challenge.description,
            "max_rounds": challenge.metadata.get("max_rounds"),
            "use_browser_mcp": challenge.metadata.get("use_browser_mcp"),
            "use_remote_host": challenge.metadata.get("use_remote_host"),
            "autopilot_summary": autopilot.get("summary", ""),
            "task": (challenge.metadata.get("input_summary") or {}).get("task", ""),
            "task_body": (challenge.metadata.get("input_summary") or {}).get("task_body", ""),
            "template_detected": (challenge.metadata.get("task_template") or {}).get("detected", False),
            "template_fields": list((challenge.metadata.get("task_template") or {}).get("field_names", [])),
            "template_protocol": dict((challenge.metadata.get("task_template") or {}).get("protocol", {})),
        },
        "target_summary": {
            "target": challenge.target or "",
            "recommended_path": context.get("recommended_path", ""),
            "normalized_target": context.get("normalized_target", challenge.target or ""),
        },
        "knowledge": {
            "selected_skill_category": knowledge.get("selected_skill_category", ""),
            "pack_name": knowledge.get("pack_name", ""),
            "knowledge_pack": dict(knowledge.get("knowledge_pack", {})),
            "knowledge_topics": list(knowledge.get("knowledge_topics", [])),
            "top_tactics": list(knowledge.get("top_tactics", [])),
            "reference_docs": list(knowledge.get("reference_docs", [])),
            "tactics_consumed": list(knowledge.get("tactics_consumed", [])),
            "category_confidence": knowledge.get("category_confidence", 0.0),
            "category_evidence": list(knowledge.get("category_evidence", [])),
            "explicit_category": knowledge.get("explicit_category", ""),
            "auto_category": knowledge.get("auto_category", ""),
            "category_consistent": bool(knowledge.get("category_consistent", False)),
        },
        "specialized": {
            "subtype": specialized.get("subtype", ""),
            "summary": specialized.get("summary", ""),
            "artifact_path": specialized.get("artifact_path", ""),
            "analysis_artifact_name": specialized.get("analysis_artifact_name", ""),
            "seed_entities": list(specialized.get("seed_entities", [])),
            "pcap_reports": list(specialized.get("pcap_reports", [])),
            "entities": list(specialized.get("entities", [])),
            "pivot_entities": list(specialized.get("pivot_entities", [])),
            "entity_graph": list(specialized.get("entity_graph", [])) if isinstance(specialized.get("entity_graph", []), list) else dict(specialized.get("entity_graph", {})),
            "fetch_reports": list(specialized.get("fetch_reports", [])),
            "browser_reports": list(specialized.get("browser_reports", [])),
            "decoded_candidates": list(specialized.get("decoded_candidates", [])),
            "attempts": list(specialized.get("attempts", [])),
            "successful_decodes": list(specialized.get("successful_decodes", [])),
            "subsolver_reports": list(specialized.get("subsolver_reports", [])),
            "extracted_artifacts": list(specialized.get("extracted_artifacts", [])),
            "recovered_objects": list(specialized.get("recovered_objects", [])),
            "iocs": list(specialized.get("iocs", [])),
            "indicators": list(specialized.get("indicators", [])),
            "subpaths": list(specialized.get("subpaths", [])),
            "blocked_tokens": list(specialized.get("blocked_tokens", [])),
            "viable_payloads": list(specialized.get("viable_payloads", [])),
            "payload_rationale": list(specialized.get("payload_rationale", [])),
            "dns_reports": list(specialized.get("dns_reports", [])),
            "rf_reports": list(specialized.get("rf_reports", [])),
            "channel_preview": dict(specialized.get("channel_preview", {})),
            "attacks_attempted": list(specialized.get("attacks_attempted", [])),
            "successful_attacks": list(specialized.get("successful_attacks", [])),
            "config_blobs": list(specialized.get("config_blobs", [])),
            "stages": list(specialized.get("stages", [])),
            "seed_count": specialized.get("seed_count", 0),
            "entity_count": specialized.get("entity_count", 0),
            "pivot_count": specialized.get("pivot_count", 0),
            "budget_used": specialized.get("budget_used", 0),
            "best_path": specialized.get("best_path", ""),
            "artifact_count": specialized.get("artifact_count", 0) or (1 if specialized.get("artifact_path") else 0) + len(list(specialized.get("extracted_artifacts", []))[:8]),
            "extracted_artifact_count": specialized.get("extracted_artifact_count", 0) or len(list(specialized.get("extracted_artifacts", []))[:8]),
            "candidate_flag_count": specialized.get("candidate_flag_count", 0) or len(candidate_flags),
            "indicator_count": specialized.get("indicator_count", 0) or len(list(specialized.get("indicators", []))[:8]),
            "attempt_count": specialized.get("attempt_count", 0),
            "successful_decode_count": specialized.get("successful_decode_count", 0),
            "payload_count": specialized.get("payload_count", 0),
            "attack_count": specialized.get("attack_count", 0),
            "success_count": specialized.get("success_count", 0),
            "stage_count": specialized.get("stage_count", 0),
            "ioc_count": specialized.get("ioc_count", 0),
            "recovered_object_count": specialized.get("recovered_object_count", 0),
            "http_body_artifact_count": specialized.get("http_body_artifact_count", 0),
            "protocol_hints": list(specialized.get("protocol_hints", [])),
        },
        "binary": {
            "subtype": (context.get("binary") or {}).get("subtype", ""),
            "summary": (context.get("binary") or {}).get("summary", ""),
            "protections": dict((context.get("binary") or {}).get("protections", {})),
            "candidate_inputs": list((context.get("binary") or {}).get("candidate_inputs", [])),
            "candidate_input_count": int((context.get("binary") or {}).get("candidate_input_count", 0) or 0),
            "exploit_plan_count": int((context.get("binary") or {}).get("exploit_plan_count", 0) or 0),
            "interesting_symbols": list((context.get("binary") or {}).get("interesting_symbols", [])),
            "best_path": (context.get("binary") or {}).get("best_path", ""),
            "mcp_used": bool((context.get("binary") or {}).get("mcp_used", False)),
            "remote_used": bool((context.get("binary") or {}).get("remote_used", False)),
            "analysis_strategy": dict((context.get("binary") or {}).get("analysis_strategy", {})),
            "selected_debugger": dict((context.get("binary") or {}).get("selected_debugger", {})),
            "selected_analyzer": dict((context.get("binary") or {}).get("selected_analyzer", {})),
            "recommended_remote_templates": list((context.get("binary") or {}).get("recommended_remote_templates", [])),
            "pwn_capabilities": dict((context.get("binary") or {}).get("pwn_capabilities", {})),
            "pwn_parity": dict((context.get("binary") or {}).get("pwn_parity", {})),
            "pwn_env_doctor": dict((context.get("binary") or {}).get("pwn_env_doctor", {})),
            "pwn_wave2_reports": list((context.get("binary") or {}).get("pwn_wave2_reports", [])),
            "build_profile": (context.get("binary") or {}).get("build_profile", ""),
            "build_capabilities": dict((context.get("binary") or {}).get("build_capabilities", {})),
            "build_missing": list((context.get("binary") or {}).get("build_missing", [])),
            "build_recommended": list((context.get("binary") or {}).get("build_recommended", [])),
            "suggested_build_template": (context.get("binary") or {}).get("suggested_build_template", ""),
            "source_build": dict((context.get("binary") or {}).get("source_build", {})),
            "build_reports": list((context.get("binary") or {}).get("build_reports", [])),
            "debug_trace": dict((context.get("binary") or {}).get("debug_trace", {})),
            "pwn_family": (context.get("binary") or {}).get("pwn_family", ""),
            "pwn_family_confidence": float((context.get("binary") or {}).get("pwn_family_confidence", 0.0) or 0.0),
            "pwn_family_evidence": list((context.get("binary") or {}).get("pwn_family_evidence", [])),
            "pwn_family_candidates": list((context.get("binary") or {}).get("pwn_family_candidates", [])),
            "pwn_stage_status": dict((context.get("binary") or {}).get("pwn_stage_status", {})),
            "exploit_stub_generated": bool((context.get("binary") or {}).get("exploit_stub_generated", False)),
            "stage2_generated": bool((context.get("binary") or {}).get("stage2_generated", False)),
            "pwn_hard_reports": list((context.get("binary") or {}).get("pwn_hard_reports", [])),
            "hard_blockers": list((context.get("binary") or {}).get("hard_blockers", [])),
            "leak_artifacts": list((context.get("binary") or {}).get("leak_artifacts", [])),
            "resolved_libc_context": dict((context.get("binary") or {}).get("resolved_libc_context", {})),
            "stage1_payload": dict((context.get("binary") or {}).get("stage1_payload", {})),
            "stage2_payload": dict((context.get("binary") or {}).get("stage2_payload", {})),
            "exploit_transcript": dict((context.get("binary") or {}).get("exploit_transcript", {})),
        },
        "attachments": attachments,
        "findings": findings,
        "candidate_flags": candidate_flags,
        "exploit_plans": exploit_plans,
        "action_timeline": action_timeline,
        "subagents": subagents,
        "recent_actions": recent_actions,
        "recent_mcp_calls": recent_mcp,
        "recent_activity": recent_activity,
        "mcp_status": mcp_status,
        "approval_status": approval_status,
        "plugin_status": plugin_status,
        "remote_subagents": remote_subagents,
        "resource_enabled_servers": list(mcp_status.get("resource_enabled_servers", [])),
        "next_actions": next_actions,
        "blockers": blockers,
        "tool_usage": {
            "configured": list(context.get("configured_tools", [])),
            "used": list(context.get("used_tools", [])),
            "recommended_tools": list(context.get("recommended_tools", []) or recommendations.get("recommended_tools", [])),
            "capability_digest": dict(context.get("toolkit_capabilities", {})),
            "tool_health": dict((context.get("toolkit_capabilities", {}) or {}).get("tool_health", {})),
        },
        "capability_plan": {
            "category": capability_plan.get("category", challenge.category),
            "subtype": capability_plan.get("subtype", specialized.get("subtype", "")),
            "selected_lanes": list(capability_plan.get("selected_lanes", [])),
            "recommended_tools": list(capability_plan.get("recommended_tools", [])),
            "recommended_libraries": list(capability_plan.get("recommended_libraries", [])),
            "recommended_sidecars": list(capability_plan.get("recommended_sidecars", [])),
            "recommended_tool_reasons": list(capability_plan.get("recommended_tool_reasons", [])),
            "recommended_library_reasons": list(capability_plan.get("recommended_library_reasons", [])),
            "recommended_sidecar_reasons": list(capability_plan.get("recommended_sidecar_reasons", [])),
            "fast_lane_tools": list(capability_plan.get("fast_lane_tools", [])),
            "bounded_heavy_lane_tools": list(capability_plan.get("bounded_heavy_lane_tools", [])),
            "sidecar_lane_tools": list(capability_plan.get("sidecar_lane_tools", [])),
            "triggers": list(capability_plan.get("triggers", [])),
            "recommended_tool_health": list(capability_plan.get("recommended_tool_health", [])),
            "tool_health": dict(capability_plan.get("tool_health", {})),
        },
        "mcp_usage": {
            "available_servers": list(context.get("available_mcp_servers", [])),
            "digest": list(context.get("mcp_digest", [])),
            "recommended_mcp": list(context.get("recommended_mcp", []) or recommendations.get("recommended_mcp", [])),
            "used": list(context.get("used_mcp", [])),
        },
        "remote_usage": {
            "available_hosts": list(context.get("available_remote_hosts", [])),
            "selected_host": context.get("selected_remote_host", ""),
            "selection_mode": context.get("remote_selection_mode", ""),
            "selection_reason": context.get("remote_selection_reason", ""),
            "selection_candidates": list(context.get("remote_selection_candidates", [])),
            "reports": list(context.get("remote_reports", [])),
            "placeholder": context.get("remote_placeholder", ""),
        },
        "browser_usage": {
            "requested": bool((context.get("browser_usage") or {}).get("requested", False)),
            "enabled": bool((context.get("browser_usage") or {}).get("enabled", False)),
            "used": bool((context.get("browser_usage") or {}).get("used", False)),
            "server": (context.get("browser_usage") or {}).get("server", ""),
            "tool": (context.get("browser_usage") or {}).get("tool", ""),
            "fallback_reason": (context.get("browser_usage") or {}).get("fallback_reason", ""),
            "auth_state": (context.get("browser_usage") or {}).get("auth_state", "unknown"),
            "auth_evidence": list((context.get("browser_usage") or {}).get("auth_evidence", [])),
            "route_candidates": list((context.get("browser_usage") or {}).get("route_candidates", [])),
            "param_candidates": list((context.get("browser_usage") or {}).get("param_candidates", [])),
            "upload_candidates": list((context.get("browser_usage") or {}).get("upload_candidates", [])),
            "executable_candidates": list((context.get("browser_usage") or {}).get("executable_candidates", [])),
            "login_forms": (context.get("browser_usage") or {}).get("login_forms", 0),
            "upload_forms": (context.get("browser_usage") or {}).get("upload_forms", 0),
            "best_http_plan": (context.get("browser_usage") or {}).get("best_http_plan", ""),
            "best_browser_plan": (context.get("browser_usage") or {}).get("best_browser_plan", ""),
            "reports": list((context.get("browser_usage") or {}).get("reports", [])),
        },
        "oob_usage": {
            "enabled": bool((context.get("oob_usage") or {}).get("enabled", False)),
            "can_poll": bool((context.get("oob_usage") or {}).get("can_poll", False)),
            "configured_mode": (context.get("oob_usage") or {}).get("configured_mode", ""),
            "callback_url": (context.get("oob_usage") or {}).get("callback_url", ""),
            "token": (context.get("oob_usage") or {}).get("token", ""),
            "matched": bool((context.get("oob_usage") or {}).get("matched", False)),
            "hit_count": int((context.get("oob_usage") or {}).get("hit_count", 0) or 0),
            "best_oob_plan": (context.get("oob_usage") or {}).get("best_oob_plan", ""),
            "last_poll_url": (context.get("oob_usage") or {}).get("last_poll_url", ""),
            "last_poll_status": (context.get("oob_usage") or {}).get("last_poll_status"),
            "reports": list((context.get("oob_usage") or {}).get("reports", [])),
        },
        "autopilot": autopilot,
        "artifacts": {
            "notes_path": str(workspace / "notes.md"),
            "state_path": str(workspace / "state.json"),
            "runs_path": str(workspace / "runs.jsonl"),
            "solution_path": str(workspace / "solution.py"),
            "protocol_summary_path": str(workspace / "task_protocol_summary.json"),
            "mcp_status_path": str(workspace / "mcp_status.json"),
            "mcp_log_path": str(workspace / "logs" / "mcp_call_log.jsonl"),
            "approval_status_path": str(workspace / "approval_status.json"),
            "approval_requests_path": str(workspace / "approvals" / "requests.jsonl"),
            "approval_grants_path": str(workspace / "approvals" / "grants.json"),
            "plugin_status_path": str(workspace / "plugin_status.json"),
            "artifact_count": len(list((workspace / "artifacts").glob("*"))) if (workspace / "artifacts").exists() else 0,
            "subagents_root": str(workspace / "subagents"),
        },
    }
    return board


def list_artifacts(workspace):
    workspace = Path(workspace)
    artifacts = []
    artifacts_dir = workspace / "artifacts"
    if not artifacts_dir.exists():
        return artifacts
    for item in sorted(path for path in artifacts_dir.rglob("*") if path.is_file()):
        artifacts.append(
            {
                "name": item.name,
                "path": str(item),
                "relative_path": str(item.relative_to(workspace)),
                "size": item.stat().st_size,
            }
        )
    return artifacts


def load_workspace_board(workspace, run_meta=None):
    workspace = Path(workspace)
    board_path = workspace / "triage_board.json"
    if board_path.exists():
        board = json.loads(board_path.read_text(encoding="utf-8-sig"))
    else:
        metadata = _read_json_if_exists(workspace / "metadata.json")
        state = _read_json_if_exists(workspace / "state.json")
        metadata_blob = dict(metadata.get("metadata", {}))
        skill_context = resolve_skill_context(
            payload={
                "category": metadata.get("category", ""),
                "target": metadata.get("target", ""),
                "attachments": list(metadata.get("attachments", [])),
                "title": metadata.get("title", workspace.name),
                "description": metadata.get("description", ""),
                "task": (metadata_blob.get("input_summary") or {}).get("task", ""),
                "task_body": (metadata_blob.get("input_summary") or {}).get("task_body", ""),
                "hint": metadata_blob.get("hint", ""),
                "speed_mode": metadata_blob.get("speed_mode") or dict(metadata_blob.get("autopilot_plan", {})).get("speed_mode"),
                "autopilot_plan": metadata_blob.get("autopilot_plan") or {},
                "knowledge_selection": metadata_blob.get("knowledge_selection") or {},
                "skill_resolution": metadata_blob.get("skill_resolution") or {},
            },
            metadata=metadata_blob,
            category=metadata.get("category", ""),
            target=metadata.get("target", ""),
            attachments=list(metadata.get("attachments", [])),
        )
        autopilot = dict(skill_context.get("autopilot") or {})
        knowledge = dict(skill_context.get("knowledge") or {})
        recommendations = dict(skill_context.get("recommendations") or {})
        board = {
            "run": {"meta": dict(run_meta or {})},
            "input_summary": {
                "source": metadata_blob.get("source", ""),
                "title": metadata.get("title", workspace.name),
                "description": metadata.get("description", ""),
                "max_rounds": metadata_blob.get("max_rounds"),
                "use_browser_mcp": metadata_blob.get("use_browser_mcp"),
                "use_remote_host": metadata_blob.get("use_remote_host"),
                "autopilot_summary": autopilot.get("summary", ""),
                "task": metadata_blob.get("input_summary", {}).get("task", ""),
                "task_body": metadata_blob.get("input_summary", {}).get("task_body", ""),
                "template_detected": metadata_blob.get("task_template", {}).get("detected", False),
                "template_fields": list(metadata_blob.get("task_template", {}).get("field_names", [])),
                "template_protocol": dict(metadata_blob.get("task_template", {}).get("protocol", {})),
            },
            "target_summary": {
                "target": metadata.get("target", ""),
                "recommended_path": "",
                "normalized_target": metadata.get("target", ""),
            },
            "knowledge": {
                "selected_skill_category": knowledge.get("selected_skill_category", metadata.get("category", "")),
                "pack_name": knowledge.get("pack_name", ""),
                "knowledge_pack": dict(knowledge.get("knowledge_pack", {})),
                "knowledge_topics": list(knowledge.get("knowledge_topics", [])),
                "top_tactics": list(knowledge.get("top_tactics", [])),
                "reference_docs": list(knowledge.get("reference_docs", [])),
                "tactics_consumed": list(knowledge.get("tactics_consumed", [])),
                "category_confidence": knowledge.get("category_confidence", 0.0),
                "category_evidence": list(knowledge.get("category_evidence", [])),
                "explicit_category": knowledge.get("explicit_category", ""),
                "auto_category": knowledge.get("auto_category", ""),
                "category_consistent": bool(knowledge.get("category_consistent", False)),
            },
            "specialized": {
                "subtype": "",
                "summary": "",
                "artifact_path": "",
                "analysis_artifact_name": "",
                "seed_entities": [],
                "entities": [],
                "pivot_entities": [],
                "entity_graph": [],
                "fetch_reports": [],
                "browser_reports": [],
                "decoded_candidates": [],
                "attempts": [],
                "successful_decodes": [],
                "subsolver_reports": [],
                "extracted_artifacts": [],
                "recovered_objects": [],
                "iocs": [],
                "indicators": [],
                "subpaths": [],
                "blocked_tokens": [],
                "viable_payloads": [],
                "payload_rationale": [],
                "dns_reports": [],
                "rf_reports": [],
                "channel_preview": {},
                "pcap_reports": [],
                "attacks_attempted": [],
                "successful_attacks": [],
                "config_blobs": [],
                "stages": [],
                "seed_count": 0,
                "entity_count": 0,
                "pivot_count": 0,
                "budget_used": 0,
                "best_path": "",
                "artifact_count": 0,
                "extracted_artifact_count": 0,
                "candidate_flag_count": 0,
                "indicator_count": 0,
                "attempt_count": 0,
                "successful_decode_count": 0,
                "payload_count": 0,
                "attack_count": 0,
                "success_count": 0,
                "stage_count": 0,
                "ioc_count": 0,
                "recovered_object_count": 0,
                "http_body_artifact_count": 0,
                "protocol_hints": [],
            },
            "binary": {
                "subtype": "",
                "summary": "",
                "protections": {},
                "candidate_inputs": [],
                "candidate_input_count": 0,
                "exploit_plan_count": 0,
                "interesting_symbols": [],
                "best_path": "",
                "mcp_used": False,
                "remote_used": False,
                "analysis_strategy": {},
                "selected_debugger": {},
                "selected_analyzer": {},
                "recommended_remote_templates": [],
                "build_profile": "",
                "build_capabilities": {},
                "build_missing": [],
                "build_recommended": [],
                "suggested_build_template": "",
                "source_build": {},
                "build_reports": [],
                "debug_trace": {},
            },
            "attachments": [{"name": Path(item).name, "path": item} for item in metadata.get("attachments", [])],
            "findings": list(state.get("findings", [])),
            "candidate_flags": list(state.get("candidate_flags", [])),
            "exploit_plans": list(state.get("exploit_plans", [])),
            "action_timeline": list(state.get("tried_actions", [])),
            "subagents": list(state.get("subagents", [])),
            "next_actions": [],
            "blockers": [state.get("blocked_reason")] if state.get("blocked_reason") else [],
            "tool_usage": {
                "configured": [],
                "used": [],
                "recommended_tools": list(recommendations.get("recommended_tools", [])),
                "capability_digest": {},
                "tool_health": {},
            },
            "capability_plan": {
                "category": metadata.get("category", ""),
                "subtype": "",
                "selected_lanes": list(autopilot.get("capability_plan", {}).get("selected_lanes", [])),
                "recommended_tools": list(autopilot.get("capability_plan", {}).get("recommended_tools", [])),
                "recommended_libraries": list(autopilot.get("capability_plan", {}).get("recommended_libraries", [])),
                "recommended_sidecars": list(autopilot.get("capability_plan", {}).get("recommended_sidecars", [])),
                "recommended_tool_reasons": list(autopilot.get("capability_plan", {}).get("recommended_tool_reasons", [])),
                "recommended_library_reasons": list(autopilot.get("capability_plan", {}).get("recommended_library_reasons", [])),
                "recommended_sidecar_reasons": list(autopilot.get("capability_plan", {}).get("recommended_sidecar_reasons", [])),
                "fast_lane_tools": list(autopilot.get("capability_plan", {}).get("fast_lane_tools", [])),
                "bounded_heavy_lane_tools": list(autopilot.get("capability_plan", {}).get("bounded_heavy_lane_tools", [])),
                "sidecar_lane_tools": list(autopilot.get("capability_plan", {}).get("sidecar_lane_tools", [])),
                "triggers": list(autopilot.get("capability_plan", {}).get("triggers", [])),
                "recommended_tool_health": list(autopilot.get("capability_plan", {}).get("recommended_tool_health", [])),
                "tool_health": dict(autopilot.get("capability_plan", {}).get("tool_health", {})),
            },
            "mcp_usage": {
                "available_servers": [],
                "digest": [],
                "recommended_mcp": list(recommendations.get("recommended_mcp", [])),
                "used": [],
            },
            "remote_usage": {"available_hosts": [], "selected_host": "", "selection_mode": "", "selection_reason": "", "selection_candidates": [], "reports": [], "placeholder": ""},
            "browser_usage": {"requested": False, "enabled": False, "used": False, "server": "", "tool": "", "fallback_reason": "", "auth_state": "unknown", "auth_evidence": [], "route_candidates": [], "param_candidates": [], "upload_candidates": [], "executable_candidates": [], "login_forms": 0, "upload_forms": 0, "best_http_plan": "", "best_browser_plan": "", "reports": []},
            "oob_usage": {"enabled": False, "can_poll": False, "configured_mode": "", "callback_url": "", "token": "", "matched": False, "hit_count": 0, "best_oob_plan": "", "last_poll_url": "", "last_poll_status": None, "reports": []},
            "autopilot": autopilot,
        }
    board.setdefault("artifacts", {})
    board["artifacts"].setdefault("protocol_summary_path", str(workspace / "task_protocol_summary.json"))
    board["artifacts"].setdefault("mcp_status_path", str(workspace / "mcp_status.json"))
    board["artifacts"].setdefault("mcp_log_path", str(workspace / "logs" / "mcp_call_log.jsonl"))
    board["artifacts"].setdefault("approval_status_path", str(workspace / "approval_status.json"))
    board["artifacts"].setdefault("approval_requests_path", str(workspace / "approvals" / "requests.jsonl"))
    board["artifacts"].setdefault("approval_grants_path", str(workspace / "approvals" / "grants.json"))
    board["artifacts"].setdefault("plugin_status_path", str(workspace / "plugin_status.json"))
    board["artifacts"].setdefault("subagents_root", str(workspace / "subagents"))
    board["artifacts"]["items"] = list_artifacts(workspace)
    board["mcp_status"] = load_workspace_mcp_status(workspace)
    board["approval_status"] = load_workspace_approval_status(workspace)
    board["plugin_status"] = load_workspace_plugin_status(workspace)
    board["recent_mcp_calls"] = load_recent_mcp_calls(workspace, limit=5)
    board["resource_enabled_servers"] = list((board.get("mcp_status") or {}).get("resource_enabled_servers", []))
    board["recent_actions"] = _recent_actions(board.get("action_timeline", []))
    board["recent_activity"] = _recent_activity(board.get("recent_actions", []), board.get("recent_mcp_calls", []))
    board["remote_subagents"] = _remote_subagents_from_subagents(board.get("subagents", []))
    board["run"].setdefault("meta", {})
    if run_meta:
        board["run"]["meta"].update({key: value for key, value in run_meta.items() if value is not None})
    board["run"]["meta"].setdefault("workspace", str(workspace))
    board["run"]["meta"].setdefault("title", board_value(board, "input_summary.title", workspace.name))
    board["run"]["meta"].setdefault(
        "category",
        board_value(board, "knowledge.selected_skill_category", board_value(board, "target_summary.category", "")),
    )
    return board


def scan_workspace_history(workspace_root, active_runs=None, limit=100):
    workspace_root = Path(workspace_root)
    active_runs = dict(active_runs or {})
    items = []
    for metadata_path in sorted(workspace_root.rglob("metadata.json"), key=lambda item: item.stat().st_mtime, reverse=True):
        workspace = metadata_path.parent
        metadata = _read_json_if_exists(metadata_path)
        state = _read_json_if_exists(workspace / "state.json")
        matching_run = None
        for run_id, run in active_runs.items():
            if str(workspace) == run.get("workspace"):
                matching_run = run
                break
        board_path = workspace / "triage_board.json"
        board = _read_json_if_exists(board_path) if board_path.exists() else {}
        status = ""
        if matching_run:
            status = matching_run.get("status", "")
        elif board_path.exists():
            status = board.get("run", {}).get("meta", {}).get("status", "")
        run_id = matching_run.get("run_id", "") if matching_run else board.get("run", {}).get("meta", {}).get("run_id", "")
        solved_from_state = bool(state.get("candidate_flags")) if state else False
        derived_status = status or ("solved" if solved_from_state else "unresolved" if state else "")
        items.append(
            {
                "run_id": run_id,
                "workspace": str(workspace),
                "title": metadata.get("title", workspace.name),
                "category": metadata.get("category", ""),
                "target": metadata.get("target", ""),
                "status": derived_status,
                "solver": matching_run.get("result", {}).get("solver", "") if matching_run else board.get("run", {}).get("meta", {}).get("solver", ""),
                "updated_at": metadata_path.stat().st_mtime,
                "board_path": str(board_path) if board_path.exists() else "",
            }
        )
    items = sorted(items, key=lambda item: item["updated_at"], reverse=True)
    return items[:limit]


def load_protocol_summary(workspace):
    workspace = Path(workspace)
    path = workspace / "task_protocol_summary.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return {}


def build_board_summary(workspace, run_meta=None, findings_limit=5):
    workspace = Path(workspace)
    board = load_workspace_board(workspace, run_meta=run_meta)
    protocol = load_protocol_summary(workspace)
    findings_limit = max(1, int(findings_limit or 5))

    run_id = board_value(board, "run.meta.run_id", "") or (run_meta or {}).get("run_id", "")
    status = board_value(board, "run.meta.status", "") or board_value(protocol, "execution.status", "") or (run_meta or {}).get("status", "")
    solver = board_value(board, "run.meta.solver", "") or board_value(protocol, "execution.solver", "")
    category = board_value(board, "run.meta.category", "") or board_value(protocol, "summary.category", "")
    title = board_value(board, "input_summary.title", "") or board_value(board, "run.meta.title", "") or (run_meta or {}).get("challenge_title", "") or workspace.name
    target = board_value(board, "target_summary.target", "") or board_value(protocol, "request.target", "")
    export_summary = load_workspace_export_summary(workspace)
    flag = board_value(protocol, "execution.flag", "")
    if not flag:
        flag = str(export_summary.get("flag") or "")
    if not flag:
        candidate_flags = board.get("candidate_flags", []) if isinstance(board.get("candidate_flags"), list) else []
        if candidate_flags:
            flag = str((candidate_flags[0] or {}).get("value") or "")
    if flag and status in {"", "unresolved"}:
        status = "solved"

    findings = board.get("findings", []) if isinstance(board.get("findings"), list) else []
    candidate_flags = board.get("candidate_flags", []) if isinstance(board.get("candidate_flags"), list) else []
    exploit_plans = board.get("exploit_plans", []) if isinstance(board.get("exploit_plans"), list) else []
    next_actions = board.get("next_actions", []) if isinstance(board.get("next_actions"), list) else []
    blockers = board.get("blockers", []) if isinstance(board.get("blockers"), list) else []
    subagents = board.get("subagents", []) if isinstance(board.get("subagents"), list) else []
    recent_actions = board.get("recent_actions", []) if isinstance(board.get("recent_actions"), list) else []
    recent_mcp_calls = board.get("recent_mcp_calls", []) if isinstance(board.get("recent_mcp_calls"), list) else []
    mcp_status = dict(board.get("mcp_status") or {})
    approval_status = dict(board.get("approval_status") or {})
    plugin_status = dict(board.get("plugin_status") or {})
    resource_enabled_servers = list(board.get("resource_enabled_servers", []) or mcp_status.get("resource_enabled_servers", []))
    recent_activity = _recent_activity(recent_actions, recent_mcp_calls)
    remote_subagents = list(board.get("remote_subagents", []) or _remote_subagents_from_subagents(subagents))
    recommended_tools = board_value(board, "tool_usage.recommended_tools", [])
    recommended_mcp = board_value(board, "mcp_usage.recommended_mcp", [])
    selected_remote_host = board_value(board, "remote_usage.selected_host", "")
    recommended_path = board_value(board, "target_summary.recommended_path", "")
    autopilot_summary = board_value(board, "input_summary.autopilot_summary", "")
    dispatch_mode = board_value(protocol, "routing.dispatch_mode", "")
    dispatch_reason = board_value(protocol, "routing.dispatch_reason", "")
    headline = board_value(protocol, "summary.headline", "") or _build_summary_headline(status, flag)

    knowledge = dict(board.get("knowledge") or {})
    specialized = dict(board.get("specialized") or {})
    binary = dict(board.get("binary") or {})
    capability_plan = dict(board.get("capability_plan") or board_value(board, "autopilot.capability_plan", {}) or {})
    findings_digest = []
    for item in findings[:findings_limit]:
        findings_digest.append(
            {
                "source": str(item.get("source", "")),
                "summary": str(item.get("summary", "")),
                "confidence": item.get("confidence", 0.0),
            }
        )

    payload = {
        "run_id": run_id,
        "workspace": str(workspace),
        "title": title,
        "category": category,
        "status": status,
        "solver": solver,
        "target": target,
        "headline": headline,
        "flag_found": bool(flag),
        "flag": flag,
        "wp_exported": bool(export_summary.get("wp_exported", False)),
        "wp_package_path": str(export_summary.get("wp_package_path") or ""),
        "wp_root": str(export_summary.get("wp_root") or ""),
        "wp_warning": str(export_summary.get("wp_warning") or ""),
        "flag_first_text": str(export_summary.get("flag_first_text") or build_flag_first_text(flag)),
        "recommended_path": recommended_path,
        "selected_remote_host": selected_remote_host,
        "autopilot_summary": autopilot_summary,
        "dispatch_mode": dispatch_mode,
        "dispatch_reason": dispatch_reason,
        "pwn_family": str(binary.get("pwn_family", "") or ""),
        "pwn_family_confidence": float(binary.get("pwn_family_confidence", 0.0) or 0.0),
        "pwn_stage_status": dict(binary.get("pwn_stage_status", {})),
        "build_profile": str(binary.get("build_profile", "") or dict(binary.get("pwn_parity", {})).get("build_profile", "")),
        "build_missing": list(binary.get("build_missing", []) or dict(binary.get("pwn_parity", {})).get("build_missing", [])),
        "debug_trace": dict(binary.get("debug_trace", {})),
        "exploit_stub_generated": bool(binary.get("exploit_stub_generated", False)),
        "stage2_generated": bool(binary.get("stage2_generated", False)),
        "recommended_tools": list(recommended_tools[:8]) if isinstance(recommended_tools, list) else [],
        "recommended_mcp": list(recommended_mcp[:8]) if isinstance(recommended_mcp, list) else [],
        "next_actions": next_actions[:5],
        "blockers": blockers[:5],
        "autopilot": dict(board.get("autopilot") or {}),
        "capability_plan": capability_plan,
        "counts": {
            "findings": len(findings),
            "candidate_flags": len(candidate_flags),
            "exploit_plans": len(exploit_plans),
            "artifacts": len(board_value(board, "artifacts.items", [])) if isinstance(board_value(board, "artifacts.items", []), list) else 0,
            "subagents": len(subagents),
            "remote_subagents": len(remote_subagents),
            "pending_approvals": len(list(approval_status.get("pending_requests", []) or [])),
        },
        "subagents": subagents[:8],
        "remote_subagents": remote_subagents[:8],
        "recent_actions": recent_actions[:5],
        "recent_mcp_calls": recent_mcp_calls[:5],
        "recent_activity": recent_activity[:5],
        "mcp_status": mcp_status,
        "approval_status": approval_status,
        "plugin_status": plugin_status,
        "resource_enabled_servers": resource_enabled_servers[:8],
        "findings_digest": findings_digest,
        "artifacts": {
            "board_path": str(workspace / "triage_board.json"),
            "protocol_summary_path": str(workspace / "task_protocol_summary.json"),
            "mcp_status_path": str(workspace / "mcp_status.json"),
            "mcp_log_path": str(workspace / "logs" / "mcp_call_log.jsonl"),
            "approval_status_path": str(workspace / "approval_status.json"),
            "approval_requests_path": str(workspace / "approvals" / "requests.jsonl"),
            "approval_grants_path": str(workspace / "approvals" / "grants.json"),
            "plugin_status_path": str(workspace / "plugin_status.json"),
            "notes_path": str(workspace / "notes.md"),
            "solution_path": str(workspace / "solution.py"),
            "subagents_root": str(workspace / "subagents"),
        },
        "knowledge": {
            "selected_skill_category": knowledge.get("selected_skill_category", ""),
            "pack_name": knowledge.get("pack_name", ""),
            "top_tactics": list(knowledge.get("top_tactics", []))[:5],
            "reference_docs": list(knowledge.get("reference_docs", []))[:5],
            "tactics_consumed": list(knowledge.get("tactics_consumed", []))[:5],
            "category_confidence": knowledge.get("category_confidence", 0.0),
        },
        "tool_usage": {
            "configured": list(board_value(board, "tool_usage.configured", []))[:12],
            "used": list(board_value(board, "tool_usage.used", []))[:12],
            "recommended_tools": list(board_value(board, "tool_usage.recommended_tools", []))[:12],
            "capability_digest": dict(board_value(board, "tool_usage.capability_digest", {})),
            "tool_health": dict(board_value(board, "tool_usage.tool_health", {})),
        },
        "mcp_usage": {
            "available_servers": list(board_value(board, "mcp_usage.available_servers", []))[:12],
            "recommended_mcp": list(board_value(board, "mcp_usage.recommended_mcp", []))[:12],
            "used": list(board_value(board, "mcp_usage.used", []))[:12],
        },
        "remote_usage": {
            "available_hosts": list(board_value(board, "remote_usage.available_hosts", []))[:12],
            "selected_host": str(board_value(board, "remote_usage.selected_host", "") or ""),
            "selection_mode": str(board_value(board, "remote_usage.selection_mode", "") or ""),
            "reports": list(board_value(board, "remote_usage.reports", []))[:6],
        },
        "specialized": {
            "subtype": specialized.get("subtype", ""),
            "summary": specialized.get("summary", ""),
            "artifact_path": specialized.get("artifact_path", ""),
            "analysis_artifact_name": specialized.get("analysis_artifact_name", ""),
            "seed_entities": list(specialized.get("seed_entities", []))[:8],
            "pcap_reports": list(specialized.get("pcap_reports", []))[:5],
            "entities": list(specialized.get("entities", []))[:8],
            "pivot_entities": list(specialized.get("pivot_entities", []))[:8],
            "entity_graph": specialized.get("entity_graph", []),
            "fetch_reports": list(specialized.get("fetch_reports", []))[:5],
            "browser_reports": list(specialized.get("browser_reports", []))[:3],
            "decoded_candidates": list(specialized.get("decoded_candidates", []))[:5],
            "attempts": list(specialized.get("attempts", []))[:8],
            "successful_decodes": list(specialized.get("successful_decodes", []))[:5],
            "subsolver_reports": list(specialized.get("subsolver_reports", []))[:5],
            "extracted_artifacts": list(specialized.get("extracted_artifacts", []))[:8],
            "recovered_objects": list(specialized.get("recovered_objects", []))[:8],
            "iocs": list(specialized.get("iocs", []))[:8],
            "indicators": list(specialized.get("indicators", []))[:8],
            "blocked_tokens": list(specialized.get("blocked_tokens", []))[:8],
            "viable_payloads": list(specialized.get("viable_payloads", []))[:6],
            "payload_rationale": list(specialized.get("payload_rationale", []))[:6],
            "dns_reports": list(specialized.get("dns_reports", []))[:5],
            "rf_reports": list(specialized.get("rf_reports", []))[:5],
            "channel_preview": dict(specialized.get("channel_preview", {})),
            "attacks_attempted": list(specialized.get("attacks_attempted", []))[:8],
            "successful_attacks": list(specialized.get("successful_attacks", []))[:8],
            "config_blobs": list(specialized.get("config_blobs", []))[:8],
            "stages": list(specialized.get("stages", []))[:8],
            "seed_count": specialized.get("seed_count", 0),
            "entity_count": specialized.get("entity_count", 0),
            "pivot_count": specialized.get("pivot_count", 0),
            "budget_used": specialized.get("budget_used", 0),
            "best_path": specialized.get("best_path", ""),
            "artifact_count": specialized.get("artifact_count", 0),
            "extracted_artifact_count": specialized.get("extracted_artifact_count", 0),
            "candidate_flag_count": specialized.get("candidate_flag_count", 0),
            "indicator_count": specialized.get("indicator_count", 0),
            "attempt_count": specialized.get("attempt_count", 0),
            "successful_decode_count": specialized.get("successful_decode_count", 0),
            "payload_count": specialized.get("payload_count", 0),
            "attack_count": specialized.get("attack_count", 0),
            "success_count": specialized.get("success_count", 0),
            "stage_count": specialized.get("stage_count", 0),
            "ioc_count": specialized.get("ioc_count", 0),
            "recovered_object_count": specialized.get("recovered_object_count", 0),
            "http_body_artifact_count": specialized.get("http_body_artifact_count", 0),
            "protocol_hints": list(specialized.get("protocol_hints", []))[:8],
        },
        "binary": {
            "subtype": binary.get("subtype", ""),
            "summary": binary.get("summary", ""),
            "protections": dict(binary.get("protections", {})),
            "candidate_input_count": int(binary.get("candidate_input_count", 0) or 0),
            "exploit_plan_count": int(binary.get("exploit_plan_count", 0) or 0),
            "interesting_symbols": list(binary.get("interesting_symbols", []))[:8],
            "best_path": binary.get("best_path", ""),
            "mcp_used": bool(binary.get("mcp_used", False)),
            "remote_used": bool(binary.get("remote_used", False)),
            "analysis_strategy": dict(binary.get("analysis_strategy", {})),
            "selected_debugger": dict(binary.get("selected_debugger", {})),
            "selected_analyzer": dict(binary.get("selected_analyzer", {})),
            "recommended_remote_templates": list(binary.get("recommended_remote_templates", []))[:8],
            "pwn_capabilities": dict(binary.get("pwn_capabilities", {})),
            "pwn_env_doctor": dict(binary.get("pwn_env_doctor", {})),
            "pwn_wave2_reports": list(binary.get("pwn_wave2_reports", []))[:8],
            "build_profile": str(binary.get("build_profile", "") or ""),
            "build_capabilities": dict(binary.get("build_capabilities", {})),
            "build_missing": list(binary.get("build_missing", [])),
            "build_recommended": list(binary.get("build_recommended", [])),
            "suggested_build_template": str(binary.get("suggested_build_template", "") or ""),
            "source_build": dict(binary.get("source_build", {})),
            "build_reports": list(binary.get("build_reports", []))[:8],
            "debug_trace": dict(binary.get("debug_trace", {})),
            "pwn_family": str(binary.get("pwn_family", "") or ""),
            "pwn_family_confidence": float(binary.get("pwn_family_confidence", 0.0) or 0.0),
            "pwn_family_evidence": list(binary.get("pwn_family_evidence", []))[:8],
            "pwn_family_candidates": list(binary.get("pwn_family_candidates", []))[:6],
            "pwn_stage_status": dict(binary.get("pwn_stage_status", {})),
            "exploit_stub_generated": bool(binary.get("exploit_stub_generated", False)),
            "stage2_generated": bool(binary.get("stage2_generated", False)),
            "pwn_hard_reports": list(binary.get("pwn_hard_reports", []))[:8],
            "hard_blockers": list(binary.get("hard_blockers", []))[:6],
            "leak_artifacts": list(binary.get("leak_artifacts", []))[:4],
            "resolved_libc_context": dict(binary.get("resolved_libc_context", {})),
            "stage1_payload": dict(binary.get("stage1_payload", {})),
            "stage2_payload": dict(binary.get("stage2_payload", {})),
            "exploit_transcript": dict(binary.get("exploit_transcript", {})),
        },
        "browser_enabled": bool(board_value(board, "browser_usage.enabled", False)),
        "browser_used": bool(board_value(board, "browser_usage.used", False)),
        "browser_auth_state": board_value(board, "browser_usage.auth_state", ""),
        "browser_route_count": len(board_value(board, "browser_usage.route_candidates", [])) if isinstance(board_value(board, "browser_usage.route_candidates", []), list) else 0,
        "browser_upload_count": len(board_value(board, "browser_usage.upload_candidates", [])) if isinstance(board_value(board, "browser_usage.upload_candidates", []), list) else 0,
        "browser_fallback_reason": board_value(board, "browser_usage.fallback_reason", ""),
        "best_http_plan": board_value(board, "browser_usage.best_http_plan", ""),
        "best_browser_plan": board_value(board, "browser_usage.best_browser_plan", ""),
        "oob_enabled": bool(board_value(board, "oob_usage.enabled", False)),
        "oob_can_poll": bool(board_value(board, "oob_usage.can_poll", False)),
        "oob_matched": bool(board_value(board, "oob_usage.matched", False)),
        "oob_hit_count": int(board_value(board, "oob_usage.hit_count", 0) or 0),
        "best_oob_plan": board_value(board, "oob_usage.best_oob_plan", ""),
    }
    payload["text"] = format_board_summary(payload)
    return payload


def format_board_summary(summary):
    summary = dict(summary or {})
    lines = []
    flag_first_text = str(summary.get("flag_first_text", "") or "").strip()
    if flag_first_text:
        lines.extend(flag_first_text.splitlines())
    lines.extend(
        [
            "headline: {0}".format(summary.get("headline", "")),
            "status: {0}".format(summary.get("status", "")),
            "category: {0}".format(summary.get("category", "")),
            "solver: {0}".format(summary.get("solver", "")),
            "title: {0}".format(summary.get("title", "")),
        ]
    )
    if summary.get("target"):
        lines.append("target: {0}".format(summary.get("target", "")))
    knowledge = dict(summary.get("knowledge") or {})
    binary = dict(summary.get("binary") or {})
    tool_usage = dict(summary.get("tool_usage") or {})
    if knowledge.get("selected_skill_category") or knowledge.get("pack_name"):
        lines.append(
            "knowledge: category={0}, pack={1}, confidence={2}".format(
                knowledge.get("selected_skill_category", "") or "?",
                knowledge.get("pack_name", "") or "?",
                knowledge.get("category_confidence", 0.0),
            )
        )
        if knowledge.get("top_tactics"):
            lines.append("top_tactics:")
            for item in list(knowledge.get("top_tactics", []))[:5]:
                lines.append("- {0}".format(item))
    capability_digest = dict(tool_usage.get("capability_digest") or {})
    if capability_digest:
        layers = dict(capability_digest.get("layers") or {})
        categories = dict(capability_digest.get("categories") or {})
        lines.append(
            "toolkit: fast={0}, heavy={1}, sidecar={2}".format(
                len(list(layers.get("fast_lane", []))),
                len(list(layers.get("bounded_heavy_lane", []))),
                len(list(layers.get("sidecar_lane", []))),
            )
        )
        if categories.get("binary_tools") or categories.get("crypto_runtime") or categories.get("stego_tools"):
            lines.append(
                "toolkit_categories: binary={0}, crypto={1}, stego={2}, forensics={3}, sidecars={4}".format(
                    ",".join(list(categories.get("binary_tools", []))[:5]) or "?",
                    ",".join(list(categories.get("crypto_runtime", []))[:5]) or "?",
                    ",".join(list(categories.get("stego_tools", []))[:5]) or "?",
                    ",".join(list(categories.get("forensics_tools", []))[:5]) or "?",
                    ",".join(list(categories.get("sidecar_tools", []))[:5]) or "?",
                )
            )
    autopilot = dict(summary.get("autopilot") or {})
    capability_plan = dict(summary.get("capability_plan") or autopilot.get("capability_plan") or {})
    if capability_plan:
        lines.append(
            "capability_plan: category={0}, subtype={1}, selected={2}, sidecars={3}".format(
                capability_plan.get("category", "") or "?",
                capability_plan.get("subtype", "") or "?",
                "+".join(list(capability_plan.get("selected_lanes", []))) or "?",
                ",".join(list(capability_plan.get("recommended_sidecars", []))[:5]) or "?",
            )
        )
        fast_tools = ",".join(list(capability_plan.get("recommended_tools", []))[:5]) or "?"
        heavy_tools = ",".join(list(capability_plan.get("recommended_libraries", []))[:5]) or "?"
        trigger_text = ",".join(list(capability_plan.get("triggers", []))[:5]) or "?"
        lines.append(
            "capability_digest: fast={0}, heavy={1}, triggers={2}".format(
                fast_tools,
                heavy_tools,
                trigger_text,
            )
        )
        tool_reasons = [
            "{0}={1}".format(item.get("name", ""), item.get("reason", ""))
            for item in list(capability_plan.get("recommended_tool_reasons", []))[:3]
            if item.get("name")
        ]
        library_reasons = [
            "{0}={1}".format(item.get("name", ""), item.get("reason", ""))
            for item in list(capability_plan.get("recommended_library_reasons", []))[:2]
            if item.get("name")
        ]
        sidecar_reasons = [
            "{0}={1}".format(item.get("name", ""), item.get("reason", ""))
            for item in list(capability_plan.get("recommended_sidecar_reasons", []))[:2]
            if item.get("name")
        ]
        reason_parts = []
        if tool_reasons:
            reason_parts.append("tools: {0}".format(" | ".join(tool_reasons)))
        if library_reasons:
            reason_parts.append("libs: {0}".format(" | ".join(library_reasons)))
        if sidecar_reasons:
            reason_parts.append("sidecars: {0}".format(" | ".join(sidecar_reasons)))
        if reason_parts:
            lines.append("capability_reasons: {0}".format(" || ".join(reason_parts)))
        unhealthy = [
            "{0}=unhealthy".format(item.get("name", ""))
            for item in list(capability_plan.get("recommended_tool_health", []))
            if item.get("name") and item.get("healthy") is False
        ]
        if unhealthy:
            lines.append("capability_health: {0}".format(", ".join(unhealthy[:4])))
    used_tools = list(tool_usage.get("used", []))
    recommended_tools = list(tool_usage.get("recommended_tools", []))
    mcp_usage = dict(summary.get("mcp_usage") or {})
    used_mcp = list(mcp_usage.get("used", []))
    recommended_mcp = list(mcp_usage.get("recommended_mcp", []))
    mcp_status = dict(summary.get("mcp_status") or {})
    approval_status = dict(summary.get("approval_status") or {})
    plugin_status = dict(summary.get("plugin_status") or {})
    remote_usage = dict(summary.get("remote_usage") or {})
    remote_subagents = list(summary.get("remote_subagents") or [])
    selected_remote = str(remote_usage.get("selected_host", "") or "")
    remote_reports = list(remote_usage.get("reports", []))
    if used_tools or recommended_tools:
        lines.append(
            "tool_usage: used={0}, recommended={1}".format(
                ",".join(used_tools[:5]) or "?",
                ",".join(recommended_tools[:5]) or "?",
            )
        )
    tool_health = dict(tool_usage.get("tool_health") or {})
    health_parts = []
    for name in ["sage", "yafu"]:
        status = tool_health.get(name)
        if isinstance(status, dict) and status.get("available"):
            health_parts.append("{0}={1}".format(name, "ok" if status.get("healthy") else "bad"))
    if health_parts:
        lines.append("tool_health: {0}".format(", ".join(health_parts)))
    if used_mcp or recommended_mcp:
        lines.append(
            "mcp_usage: used={0}, recommended={1}".format(
                ",".join(used_mcp[:5]) or "?",
                ",".join(recommended_mcp[:5]) or "?",
            )
        )
    if mcp_status:
        counts = dict(mcp_status.get("counts") or {})
        lines.append(
            "mcp_status: available={0}, connected={1}, failed={2}, disabled={3}, resources={4}".format(
                len(list(mcp_status.get("available_servers", []))),
                counts.get("connected", 0),
                counts.get("failed", 0),
                counts.get("disabled", 0),
                ",".join(list(mcp_status.get("resource_enabled_servers", []))[:5]) or "none",
            )
        )
        failed_servers = list(mcp_status.get("failed_servers", []))
        if failed_servers:
            lines.append(
                "mcp_failed: {0}".format(
                    ", ".join("{0}={1}".format(item.get("name", ""), item.get("last_error", "")) for item in failed_servers[:3])
                )
            )
        fallback_reasons = list(mcp_status.get("fallback_reasons", []))
        if fallback_reasons:
            lines.append(
                "mcp_fallbacks: {0}".format(
                    " | ".join("{0}={1}".format(item.get("server", ""), item.get("reason", "")) for item in fallback_reasons[:3])
                )
            )
    if approval_status:
        counts = dict(approval_status.get("counts") or {})
        lines.append(
            "approval_status: pending={0}, approved={1}, denied={2}".format(
                len(list(approval_status.get("pending_requests", []) or [])),
                counts.get("approved", 0),
                counts.get("denied", 0),
            )
        )
    if plugin_status:
        counts = dict(plugin_status.get("counts") or {})
        lines.append(
            "plugin_status: total={0}, enabled={1}, invalid={2}".format(
                counts.get("total", 0),
                counts.get("enabled", 0),
                counts.get("invalid", 0),
            )
        )
    if selected_remote or remote_reports:
        lines.append(
            "remote_usage: selected={0}, reports={1}".format(
                selected_remote or "none",
                len(remote_reports),
            )
        )
    if remote_subagents:
        lines.append("remote_subagents:")
        for item in remote_subagents[:5]:
            usage = dict(item.get("usage") or {})
            remote_status_item = dict(item.get("remote_status") or {})
            lines.append(
                "- {0} [{1}/{2}] host={3} remote_state={4} steps={5} tools={6}".format(
                    item.get("id", ""),
                    item.get("status", ""),
                    item.get("stop_reason", ""),
                    remote_status_item.get("remote_host", "") or "?",
                    remote_status_item.get("status", "") or "?",
                    int(usage.get("steps", 0) or 0),
                    int(usage.get("tool_calls", 0) or 0),
                )
            )
    specialized = dict(summary.get("specialized") or {})
    if specialized.get("subtype") or specialized.get("summary"):
        lines.append(
            "specialized: subtype={0}, summary={1}".format(
                specialized.get("subtype", "") or "?",
                specialized.get("summary", "") or "?",
            )
        )
        if specialized.get("best_path"):
            lines.append("specialized_best_path: {0}".format(specialized.get("best_path", "")))
        lines.append(
            "specialized_digest: artifacts={0}, extracted={1}, flags={2}, indicators={3}, best_path={4}".format(
                specialized.get("artifact_count", 0),
                specialized.get("extracted_artifact_count", 0),
                specialized.get("candidate_flag_count", 0),
                specialized.get("indicator_count", 0),
                specialized.get("best_path", "") or "?",
            )
        )
        if specialized.get("entity_count") or specialized.get("pivot_count") or specialized.get("budget_used"):
            lines.append(
                "specialized_osint: seed_count={0}, entity_count={1}, pivot_count={2}, budget_used={3}, best_path={4}".format(
                    specialized.get("seed_count", 0),
                    specialized.get("entity_count", 0),
                    specialized.get("pivot_count", 0),
                    specialized.get("budget_used", 0),
                    specialized.get("best_path", "") or "?",
                )
            )
        if specialized.get("attempt_count") or specialized.get("successful_decode_count") or specialized.get("payload_count"):
            lines.append(
                "specialized_misc: attempts={0}, successful_decodes={1}, payload_or_artifacts={2}, best_path={3}".format(
                    specialized.get("attempt_count", 0),
                    specialized.get("successful_decode_count", 0),
                    specialized.get("payload_count", 0),
                    specialized.get("best_path", "") or "?",
                )
            )
        if specialized.get("stage_count") or specialized.get("ioc_count"):
            lines.append(
                "specialized_malware: stage_count={0}, ioc_count={1}, best_path={2}".format(
                    specialized.get("stage_count", 0),
                    specialized.get("ioc_count", 0),
                    specialized.get("best_path", "") or "?",
                )
            )
        if specialized.get("attack_count") or specialized.get("success_count"):
            lines.append(
                "specialized_crypto: attack_count={0}, success_count={1}, best_path={2}".format(
                    specialized.get("attack_count", 0),
                    specialized.get("success_count", 0),
                    specialized.get("best_path", "") or "?",
                )
            )
        if specialized.get("subtype") == "network" or specialized.get("pcap_reports") or specialized.get("http_body_artifact_count"):
            lines.append(
                "specialized_pcap: objects={0}, http_body_artifacts={1}, protocol_hints={2}, best_path={3}".format(
                    specialized.get("recovered_object_count", 0),
                    specialized.get("http_body_artifact_count", 0),
                    ",".join(list(specialized.get("protocol_hints", []))[:5]) or "?",
                    specialized.get("best_path", "") or "?",
                )
            )
        if specialized.get("recovered_object_count") or specialized.get("protocol_hints"):
            lines.append(
                "specialized_forensics: recovered_objects={0}, protocol_or_object_hints={1}, best_path={2}".format(
                    specialized.get("recovered_object_count", 0),
                    ",".join(list(specialized.get("protocol_hints", []))[:5]) or "?",
                    specialized.get("best_path", "") or "?",
                )
            )
        for key in ["seed_entities", "entities", "pivot_entities", "decoded_candidates", "iocs", "indicators", "blocked_tokens", "viable_payloads", "extracted_artifacts"]:
            values = list(specialized.get(key, []))
            if values:
                lines.append("{0}:".format(key))
                for item in values[:5]:
                    lines.append("- {0}".format(item))
    if binary.get("subtype") or binary.get("summary"):
        lines.append(
            "binary: subtype={0}, summary={1}".format(
                binary.get("subtype", "") or "?",
                binary.get("summary", "") or "?",
            )
        )
        if binary.get("best_path"):
            lines.append("binary_best_path: {0}".format(binary.get("best_path", "")))
        lines.append(
            "binary_digest: candidate_inputs={0}, exploit_plans={1}, mcp_used={2}, remote_used={3}".format(
                binary.get("candidate_input_count", 0),
                binary.get("exploit_plan_count", 0),
                "yes" if binary.get("mcp_used") else "no",
                "yes" if binary.get("remote_used") else "no",
            )
        )
        selected_debugger = dict(binary.get("selected_debugger") or {})
        if selected_debugger:
            lines.append(
                "binary_debugger: name={0}, bits={1}, reason={2}".format(
                    selected_debugger.get("debugger_name", "") or "?",
                    selected_debugger.get("bits", "") or "?",
                    selected_debugger.get("reason", "") or "?",
                )
            )
        selected_analyzer = dict(binary.get("selected_analyzer") or {})
        if selected_analyzer:
            lines.append(
                "binary_analyzer: name={0}, mode={1}, lane={2}, reason={3}".format(
                    selected_analyzer.get("analyzer_name", "") or "?",
                    selected_analyzer.get("analyzer_mode", "") or "?",
                    selected_analyzer.get("lane", "") or "?",
                    selected_analyzer.get("reason", "") or "?",
                )
            )
        analysis_strategy = dict(binary.get("analysis_strategy") or {})
        if analysis_strategy:
            lines.append(
                "binary_analysis_strategy: order={0}, skipped={1}, fallback={2}, score={3}".format(
                    "+".join(list(analysis_strategy.get("order", []))) or "?",
                    ",".join(list(analysis_strategy.get("skipped", []))) or "none",
                    "yes" if analysis_strategy.get("fallback_used") else "no",
                    analysis_strategy.get("signal_score", 0),
                )
            )
        protections = dict(binary.get("protections") or {})
        if protections:
            lines.append(
                "binary_protections: {0}".format(
                    ", ".join("{0}={1}".format(key, protections.get(key)) for key in sorted(protections.keys()))
                )
            )
        pwn_capabilities = dict(binary.get("pwn_capabilities") or {})
        if pwn_capabilities:
            pwn_parity = dict(binary.get("pwn_parity") or {})
            lines.append(
                "binary_pwn_caps: profile={0}, missing={1}, templates={2}".format(
                    pwn_parity.get("profile", pwn_capabilities.get("parity_profile", "?")) or "?",
                    ",".join(list(pwn_capabilities.get("missing", []))[:6]) or "none",
                    ",".join(list(pwn_capabilities.get("recommended_templates", []))[:6]) or "?",
                )
            )
            if pwn_parity:
                lines.append(
                    "binary_pwn_parity: core_missing={0}, advanced_missing={1}, debugger_missing={2}, bootstrap={3}, template={4}".format(
                        ",".join(list(pwn_parity.get("core_missing", []))[:6]) or "none",
                        ",".join(list(pwn_parity.get("advanced_missing", []))[:6]) or "none",
                        ",".join(list(pwn_parity.get("debugger_missing", []))[:6]) or "none",
                        "yes" if pwn_parity.get("bootstrap_recommended") else "no",
                        pwn_parity.get("suggested_template", "") or "?",
                    )
                )
        if binary.get("pwn_family"):
            lines.append(
                "binary_pwn_family: family={0}, confidence={1}, exploit_stub={2}, stage2={3}".format(
                    binary.get("pwn_family", "") or "?",
                    binary.get("pwn_family_confidence", 0.0),
                    "yes" if binary.get("exploit_stub_generated") else "no",
                    "yes" if binary.get("stage2_generated") else "no",
                )
            )
            stage = dict(binary.get("pwn_stage_status") or {})
            if stage:
                lines.append(
                    "binary_pwn_stage: status={0}, source_lane={1}, summary={2}".format(
                        stage.get("status", "") or "?",
                        stage.get("source_lane", "") or "?",
                        stage.get("summary", "") or "?",
                    )
                )
            evidence = list(binary.get("pwn_family_evidence", []))
            if evidence:
                lines.append(
                    "binary_pwn_evidence: {0}".format(
                        ", ".join(
                            "{0}:{1}".format(str(item.get("source") or "?"), str(item.get("value") or "?"))
                            for item in evidence[:4]
                        )
                    )
                )
        pwn_wave2_reports = list(binary.get("pwn_wave2_reports") or [])
        if pwn_wave2_reports:
            lines.append(
                "binary_pwn_wave2: {0}".format(
                    ", ".join(
                        "{0}={1}".format(item.get("template_kind", ""), item.get("status", ""))
                        for item in pwn_wave2_reports[:5]
                    )
                )
            )
        pwn_hard_reports = list(binary.get("pwn_hard_reports") or [])
        if pwn_hard_reports:
            lines.append(
                "binary_pwn_wave4: {0}".format(
                    ", ".join(
                        "{0}={1}".format(item.get("lane", "") or item.get("template_kind", ""), item.get("status", ""))
                        for item in pwn_hard_reports[:5]
                    )
                )
            )
        if binary.get("interesting_symbols"):
            lines.append("binary_symbols:")
            for item in list(binary.get("interesting_symbols", []))[:5]:
                lines.append("- {0}".format(item))
    if summary.get("selected_remote_host"):
        lines.append("selected_remote_host: {0}".format(summary.get("selected_remote_host", "")))
    lines.append(
        "browser: enabled={0}, used={1}, auth_state={2}, routes={3}, uploads={4}".format(
            "yes" if summary.get("browser_enabled") else "no",
            "yes" if summary.get("browser_used") else "no",
            summary.get("browser_auth_state", "") or "unknown",
            summary.get("browser_route_count", 0),
            summary.get("browser_upload_count", 0),
        )
    )
    lines.append(
        "oob: enabled={0}, can_poll={1}, matched={2}, hits={3}".format(
            "yes" if summary.get("oob_enabled") else "no",
            "yes" if summary.get("oob_can_poll") else "no",
            "yes" if summary.get("oob_matched") else "no",
            summary.get("oob_hit_count", 0),
        )
    )
    if summary.get("browser_fallback_reason"):
        lines.append("browser_fallback_reason: {0}".format(summary.get("browser_fallback_reason", "")))
    if summary.get("best_http_plan"):
        lines.append("best_http_plan: {0}".format(summary.get("best_http_plan", "")))
    if summary.get("best_browser_plan"):
        lines.append("best_browser_plan: {0}".format(summary.get("best_browser_plan", "")))
    if summary.get("best_oob_plan"):
        lines.append("best_oob_plan: {0}".format(summary.get("best_oob_plan", "")))
    if summary.get("recommended_path"):
        lines.append("recommended_path: {0}".format(summary.get("recommended_path", "")))
    if summary.get("dispatch_mode"):
        lines.append("dispatch_mode: {0}".format(summary.get("dispatch_mode", "")))
    if summary.get("dispatch_reason"):
        lines.append("dispatch_reason: {0}".format(summary.get("dispatch_reason", "")))
    if summary.get("wp_exported"):
        lines.append("wp_exported: yes")
    if summary.get("wp_root"):
        lines.append("wp_root: {0}".format(summary.get("wp_root", "")))
    if summary.get("wp_warning"):
        lines.append("wp_warning: {0}".format(summary.get("wp_warning", "")))
    if summary.get("flag_found") and not flag_first_text:
        lines.append("flag: {0}".format(summary.get("flag", "")))
    counts = dict(summary.get("counts") or {})
    lines.append(
        "counts: findings={0}, candidate_flags={1}, exploit_plans={2}, artifacts={3}".format(
            counts.get("findings", 0),
            counts.get("candidate_flags", 0),
            counts.get("exploit_plans", 0),
            counts.get("artifacts", 0),
        )
    )
    next_actions = list(summary.get("next_actions") or [])
    if next_actions:
        lines.append("next_actions:")
        for item in next_actions[:5]:
            lines.append("- {0}".format(item))
    blockers = list(summary.get("blockers") or [])
    if blockers:
        lines.append("blockers:")
        for item in blockers[:5]:
            lines.append("- {0}".format(item))
    subagents = list(summary.get("subagents") or [])
    if subagents:
        lines.append("subagents:")
        for item in subagents[:5]:
            usage = dict(item.get("usage") or {})
            sub_summary = dict(item.get("summary") or {})
            lines.append(
                "- {0} [{1}/{2}] steps={3} tools={4} tokens={5} {6}".format(
                    item.get("id", ""),
                    item.get("status", ""),
                    item.get("stop_reason", "completed"),
                    int(usage.get("steps", 0) or 0),
                    int(usage.get("tool_calls", 0) or 0),
                    int(usage.get("tokens_used", 0) or 0),
                    sub_summary.get("what_was_found", "")[:120] or sub_summary.get("what_to_do_next", "")[:120],
                )
            )
    findings_digest = list(summary.get("findings_digest") or [])
    if findings_digest:
        lines.append("findings_digest:")
        for item in findings_digest[:5]:
            lines.append("- [{0}] {1}".format(item.get("source", "") or "?", item.get("summary", "")))
    recent_activity = list(summary.get("recent_activity") or [])
    if recent_activity:
        lines.append("recent_activity:")
        for item in recent_activity[:5]:
            if item.get("kind") == "mcp":
                lines.append("- [mcp] {0}/{1}: {2}".format(item.get("server", ""), item.get("tool", ""), item.get("summary", "")))
            else:
                lines.append("- [action] {0}/{1}: {2}".format(item.get("phase", ""), item.get("action", ""), item.get("summary", "")))
    return "\n".join(lines)


def _recent_actions(action_timeline, limit=5):
    payload = []
    for item in list(action_timeline or [])[-max(1, int(limit or 5)) :]:
        payload.append(
            {
                "kind": "action",
                "phase": item.get("phase", ""),
                "action": item.get("action", ""),
                "status": item.get("status", ""),
                "summary": item.get("summary", ""),
                "artifact": item.get("artifact", ""),
            }
        )
    return payload


def _recent_activity(recent_actions, recent_mcp_calls, limit=5):
    limit = max(1, int(limit or 5))
    actions = list(recent_actions or [])[-max(1, limit // 2 or 1) :]
    mcp_calls = []
    for item in list(recent_mcp_calls or [])[-max(1, limit - len(actions)) :]:
        record = dict(item or {})
        record["kind"] = "mcp"
        mcp_calls.append(record)
    return (actions + mcp_calls)[-limit:]


def _build_summary_headline(status, flag):
    if flag:
        return "flag found"
    if status in {"running", "queued"}:
        return "run is still active"
    if status == "unresolved":
        return "no flag yet, continue with next_actions"
    if status == "failed":
        return "run failed, inspect blockers and logs"
    if status == "cancelled":
        return "run cancelled"
    return "board summary ready"


def _read_json_if_exists(path):
    path = Path(path)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return {}


def _attachment_paths(attachments):
    paths = []
    for item in list(attachments or []):
        if isinstance(item, dict):
            candidate = item.get("path") or item.get("name") or ""
        else:
            candidate = item
        text = str(candidate or "").strip()
        if text:
            paths.append(text)
    return paths


def _finding_to_dict(item):
    return {
        "source": item.source,
        "summary": item.summary,
        "evidence": item.evidence,
        "confidence": item.confidence,
    }


def _flag_to_dict(item):
    return {
        "value": item.value,
        "source": item.source,
        "confidence": item.confidence,
        "reproducible": item.reproducible,
    }


def _plan_to_dict(item):
    return {
        "title": item.title,
        "method": item.method,
        "url": item.url,
        "data": dict(item.data),
        "headers": dict(item.headers),
        "notes": item.notes,
        "confidence": item.confidence,
    }


def _action_to_dict(item):
    return {
        "phase": item.phase,
        "action": item.action,
        "status": item.status,
        "summary": item.summary,
        "artifact": item.artifact,
    }


def _subagent_to_dict(item):
    if isinstance(item, dict):
        spec = dict(item.get("spec") or {})
        summary = dict(item.get("summary") or {})
        usage = dict(item.get("usage") or {})
        remote_status = dict(item.get("remote_status") or {})
        sync_manifest = dict(item.get("sync_manifest") or {})
        return {
            "id": item.get("id", ""),
            "status": item.get("status", ""),
            "stop_reason": item.get("stop_reason", "completed"),
            "usage": usage,
            "started_at": item.get("started_at"),
            "finished_at": item.get("finished_at"),
            "spec": spec,
            "summary": summary,
            "remote_status": remote_status,
            "approval_request_id": item.get("approval_request_id", ""),
            "sync_manifest": sync_manifest,
            "error": item.get("error"),
            "artifact_paths": list(item.get("artifact_paths", []) or []),
        }
    spec = getattr(item, "spec", None)
    summary = dict(getattr(item, "summary", {}) or {})
    return {
        "id": getattr(item, "id", ""),
        "status": getattr(item, "status", ""),
        "stop_reason": getattr(item, "stop_reason", "completed"),
        "usage": dict(getattr(item, "usage", {}) or {}),
        "started_at": getattr(item, "started_at", None),
        "finished_at": getattr(item, "finished_at", None),
        "spec": spec.to_dict() if hasattr(spec, "to_dict") else dict(spec or {}),
        "summary": summary,
        "remote_status": dict(getattr(item, "remote_status", {}) or {}),
        "approval_request_id": getattr(item, "approval_request_id", ""),
        "sync_manifest": dict(getattr(item, "sync_manifest", {}) or {}),
        "error": getattr(item, "error", None),
        "artifact_paths": list(getattr(item, "artifact_paths", []) or []),
    }


def _remote_subagents_from_subagents(subagents):
    payload = []
    for item in list(subagents or []):
        record = _subagent_to_dict(item)
        spec = dict(record.get("spec") or {})
        remote_status = dict(record.get("remote_status") or {})
        if spec.get("execution_mode") != "remote" and not remote_status:
            continue
        payload.append(
            {
                "id": record.get("id", ""),
                "status": record.get("status", ""),
                "stop_reason": record.get("stop_reason", ""),
                "usage": dict(record.get("usage") or {}),
                "summary": dict(record.get("summary") or {}),
                "approval_request_id": record.get("approval_request_id", ""),
                "remote_status": remote_status,
                "sync_manifest": dict(record.get("sync_manifest") or {}),
                "artifact_paths": list(record.get("artifact_paths", []) or []),
            }
        )
    return payload


def board_value(board, dotted_key, default=None):
    current = board
    for part in str(dotted_key or "").split("."):
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current
