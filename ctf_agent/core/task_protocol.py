import json
from pathlib import Path

from ctf_agent.core.board import load_workspace_board
from ctf_agent.core.skill_context import resolve_skill_context
from ctf_agent.core.solved_export import build_flag_first_text, load_workspace_export_summary


TASK_PROTOCOL_NAME = "ctf-task-feed"
TASK_PROTOCOL_VERSION = "2026-03-23"
TASK_PROTOCOL_SUMMARY_FILENAME = "task_protocol_summary.json"


def _resolve_protocol_skill_context(resolved):
    resolved = dict(resolved or {})
    return resolve_skill_context(
        payload=resolved,
        metadata=dict(resolved.get("metadata") or {}),
        category=resolved.get("category", ""),
        target=resolved.get("target") or resolved.get("url") or "",
        attachments=list(resolved.get("attachments", []) or []),
        speed_mode=resolved.get("speed_mode"),
        task_text=str(resolved.get("task") or resolved.get("description") or ""),
    )


def _knowledge_brief(knowledge, tactic_limit=5):
    knowledge = dict(knowledge or {})
    return {
        "selected_skill_category": knowledge.get("selected_skill_category", ""),
        "pack_name": knowledge.get("pack_name", ""),
        "top_tactics": list(knowledge.get("top_tactics", []))[: max(1, int(tactic_limit or 5))],
        "reference_docs": list(knowledge.get("reference_docs", []))[: max(1, int(tactic_limit or 5))],
        "tactics_consumed": list(knowledge.get("tactics_consumed", []))[: max(1, int(tactic_limit or 5))],
    }


def build_sync_envelope(task, resolved, result):
    workspace = str((result or {}).get("workspace") or "")
    skill_context = _resolve_protocol_skill_context(resolved)
    board = load_board(workspace)
    payload = {
        "protocol": protocol_header(),
        "mode": "sync",
        "request": build_request_view(task, resolved, skill_context=skill_context),
        "routing": build_routing_view(resolved, result=result, board=board, skill_context=skill_context),
        "execution": build_execution_view(result=result, workspace=workspace),
        "validation": build_validation_view(resolved),
        "polling": {
            "supported": False,
            "status_tool": "get_ctf_task_status",
            "artifact_tool": "read_ctf_run_artifact",
        },
        "artifacts": build_artifact_paths(workspace),
        "summary": summarize_payload(resolved, result=result, board=board, skill_context=skill_context),
        "board": summarize_board(board),
    }
    persist_protocol_summary(workspace, payload)
    return payload


def build_async_start_envelope(task, resolved, run):
    workspace = str((run or {}).get("workspace") or "")
    skill_context = _resolve_protocol_skill_context(resolved)
    board = load_board(workspace)
    payload = {
        "protocol": protocol_header(),
        "mode": "async",
        "request": build_request_view(task, resolved, skill_context=skill_context),
        "routing": build_routing_view(resolved, run=run, board=board, skill_context=skill_context),
        "execution": build_execution_view(run=run, workspace=workspace),
        "validation": build_validation_view(resolved),
        "polling": {
            "supported": True,
            "run_id": (run or {}).get("run_id", ""),
            "status_tool": "get_ctf_task_status",
            "artifact_tool": "read_ctf_run_artifact",
        },
        "artifacts": build_artifact_paths(workspace),
        "summary": summarize_payload(resolved, run=run, board=board, skill_context=skill_context),
        "board": summarize_board(board),
    }
    persist_protocol_summary(workspace, payload)
    return payload


def build_status_envelope(run_payload):
    run_payload = dict(run_payload or {})
    workspace = str(run_payload.get("workspace") or "")
    board = load_board(workspace)
    resolved = dict(run_payload.get("request") or {})
    skill_context = _resolve_protocol_skill_context(resolved)
    status = run_payload.get("status", "")
    payload = {
        "protocol": protocol_header(),
        "mode": "status",
        "request": build_request_view(resolved.get("task") or resolved.get("description") or "", resolved, skill_context=skill_context),
        "routing": build_routing_view(resolved, run=run_payload, board=board, skill_context=skill_context),
        "execution": build_execution_view(run=run_payload, workspace=workspace),
        "validation": build_validation_view(resolved),
        "polling": {
            "supported": True,
            "run_id": run_payload.get("run_id", ""),
            "status_tool": "get_ctf_task_status",
            "artifact_tool": "read_ctf_run_artifact",
            "is_terminal": status in {"solved", "unresolved", "failed", "cancelled"},
        },
        "artifacts": build_artifact_paths(workspace),
        "summary": summarize_payload(resolved, run=run_payload, board=board, skill_context=skill_context),
        "board": summarize_board(board),
    }
    persist_protocol_summary(workspace, payload)
    return payload


def build_needs_input_envelope(task, resolved, validation, mode="sync"):
    resolved = dict(resolved or {})
    validation = dict(validation or {})
    skill_context = _resolve_protocol_skill_context(resolved)
    knowledge = _knowledge_brief(skill_context.get("knowledge"))
    speed_mode = str(skill_context.get("speed_mode") or resolved.get("speed_mode") or board_value(resolved, "autopilot_plan.speed_mode", "standard") or "standard")
    return {
        "protocol": protocol_header(),
        "mode": mode,
        "request": build_request_view(task, resolved, skill_context=skill_context),
        "routing": build_routing_view(resolved, skill_context=skill_context),
        "execution": {
            "status": "needs_input",
            "solver": "",
            "workspace": "",
            "run_id": "",
            "flag": "",
            "wp_exported": False,
            "wp_package_path": "",
            "wp_root": "",
            "wp_warning": "",
            "flag_first_text": "",
            "error": "",
        },
        "validation": validation,
        "polling": {
            "supported": False,
            "status_tool": "get_ctf_task_status",
            "artifact_tool": "read_ctf_run_artifact",
        },
        "artifacts": build_artifact_paths(""),
        "summary": {
            "headline": "输入不足，先补齐 target 或 attachments 再发起解题。",
            "status": "needs_input",
            "category": resolved.get("category", ""),
            "speed_mode": speed_mode,
            "solver": "",
            "flag_found": False,
            "flag": "",
            "wp_exported": False,
            "wp_package_path": "",
            "wp_root": "",
            "wp_warning": "",
            "flag_first_text": "",
            "template_detected": bool((resolved.get("task_template") or {}).get("detected")),
            "recommended_tools": [],
            "recommended_mcp": [],
            "next_actions": list(validation.get("next_actions", [])),
            "blockers": list(validation.get("errors", [])),
            "knowledge": knowledge,
        },
        "board": {
            "present": False,
            "run_status": "needs_input",
            "solver": "",
            "speed_mode": speed_mode,
            "wp_exported": False,
            "wp_package_path": "",
            "wp_root": "",
            "wp_warning": "",
            "flag_first_text": "",
            "recommended_path": "",
            "selected_remote_host": "",
            "next_actions": list(validation.get("next_actions", [])),
            "knowledge": knowledge,
        },
    }


def protocol_header():
    return {"name": TASK_PROTOCOL_NAME, "version": TASK_PROTOCOL_VERSION}


def build_request_view(task, resolved, skill_context=None):
    resolved = dict(resolved or {})
    attachments = list(resolved.get("attachments", []) or [])
    task_template = dict(resolved.get("task_template") or {})
    background_policy = dict(resolved.get("background_policy") or {})
    skill_context = skill_context or _resolve_protocol_skill_context(resolved)
    speed_mode = str(skill_context.get("speed_mode") or resolved.get("speed_mode") or board_value(resolved, "autopilot_plan.speed_mode", "standard") or "standard")
    return {
        "task": str(task or resolved.get("task") or resolved.get("description") or ""),
        "category": resolved.get("category") or (_knowledge_brief(skill_context.get("knowledge")).get("selected_skill_category", "")),
        "target": resolved.get("target") or resolved.get("url") or "",
        "attachments": attachments,
        "attachment_count": len(attachments),
        "title": resolved.get("title", ""),
        "challenge_id": resolved.get("challenge_id", ""),
        "template_detected": bool(task_template.get("detected")),
        "template_fields": list(task_template.get("field_names", [])),
        "template_protocol": dict(task_template.get("protocol") or {}),
        "background_requested": background_policy.get("requested_mode", ""),
        "speed_mode": speed_mode,
    }


def build_validation_view(resolved, errors=None, warnings=None):
    generated = validate_resolved_request(resolved)
    if errors is not None:
        generated["errors"] = list(errors or [])
    if warnings is not None:
        generated["warnings"] = list(warnings or [])
    generated["ok"] = not bool(generated.get("errors"))
    return generated


def build_routing_view(resolved, result=None, run=None, board=None, skill_context=None):
    resolved = dict(resolved or {})
    result = dict(result or {})
    run = dict(run or {})
    board = dict(board or {})
    skill_context = skill_context or _resolve_protocol_skill_context(resolved)
    autopilot = dict(skill_context.get("autopilot") or resolved.get("autopilot_plan") or {})
    knowledge = dict(skill_context.get("knowledge") or autopilot.get("knowledge") or {})
    background_policy = dict(resolved.get("background_policy") or run.get("request", {}).get("background_policy") or {})
    speed_mode = str(skill_context.get("speed_mode") or resolved.get("speed_mode") or autopilot.get("speed_mode") or "standard")
    return {
        "solver": result.get("solver") or board_value(board, "run.meta.solver", ""),
        "category": resolved.get("category") or run.get("category", "") or knowledge.get("selected_skill_category", ""),
        "autopilot_summary": autopilot.get("summary", ""),
        "execution_profile": autopilot.get("execution_profile", ""),
        "speed_mode": speed_mode,
        "speed_profile": dict(resolved.get("speed_profile") or autopilot.get("speed_profile") or {}),
        "recommended_path": board_value(board, "target_summary.recommended_path", ""),
        "selected_remote_host": board_value(board, "remote_usage.selected_host", autopilot.get("selected_remote_host", "")),
        "dispatch_mode": background_policy.get("effective_mode", "sync"),
        "dispatch_reason": background_policy.get("reason", ""),
        "dispatch_signals": list(background_policy.get("signals", [])),
        "selected_skill_category": knowledge.get("selected_skill_category", autopilot.get("selected_skill_category", "")),
        "category_confidence": knowledge.get("category_confidence", autopilot.get("category_confidence", 0.0)),
        "category_evidence": list(knowledge.get("category_evidence", autopilot.get("category_evidence", []))),
        "knowledge_pack": dict(knowledge.get("knowledge_pack", {})),
        "pack_name": knowledge.get("pack_name", ""),
        "top_tactics": list(knowledge.get("top_tactics", autopilot.get("top_tactics", [])))[:5],
        "reference_docs": list(knowledge.get("reference_docs", autopilot.get("reference_docs", [])))[:5],
    }


def build_execution_view(result=None, run=None, workspace=""):
    result = dict(result or {})
    run = dict(run or {})
    resolved_workspace = workspace or result.get("workspace") or run.get("workspace", "")
    export_summary = _resolve_export_summary(resolved_workspace, result=result, run=run)
    flag = result.get("flag") or ((run.get("result") or {}).get("flag", ""))
    return {
        "status": result.get("status") or run.get("status", ""),
        "solver": result.get("solver") or run.get("category", ""),
        "workspace": resolved_workspace,
        "run_id": run.get("run_id", ""),
        "flag": flag,
        "error": result.get("error") or run.get("error", ""),
        "wp_exported": bool(export_summary.get("wp_exported", False)),
        "wp_package_path": str(export_summary.get("wp_package_path") or ""),
        "wp_root": str(export_summary.get("wp_root") or ""),
        "wp_warning": str(export_summary.get("wp_warning") or ""),
        "flag_first_text": str(export_summary.get("flag_first_text") or build_flag_first_text(flag)),
    }


def build_artifact_paths(workspace):
    export_summary = load_workspace_export_summary(workspace) if workspace else {}
    if not workspace:
        return {
            "workspace": "",
            "board_path": "",
            "notes_path": "",
            "solution_path": "",
            "state_path": "",
            "runs_path": "",
            "subagents_root": "",
            "protocol_summary_path": "",
            "mcp_status_path": "",
            "mcp_log_path": "",
            "approval_status_path": "",
            "approval_requests_path": "",
            "approval_grants_path": "",
            "plugin_status_path": "",
            "wp_export_path": "",
            "wp_package_path": "",
            "wp_root": "",
        }
    root = Path(workspace)
    return {
        "workspace": str(root),
        "board_path": str(root / "triage_board.json"),
        "notes_path": str(root / "notes.md"),
        "solution_path": str(root / "solution.py"),
        "state_path": str(root / "state.json"),
        "runs_path": str(root / "runs.jsonl"),
        "subagents_root": str(root / "subagents"),
        "protocol_summary_path": str(root / TASK_PROTOCOL_SUMMARY_FILENAME),
        "mcp_status_path": str(root / "mcp_status.json"),
        "mcp_log_path": str(root / "logs" / "mcp_call_log.jsonl"),
        "approval_status_path": str(root / "approval_status.json"),
        "approval_requests_path": str(root / "approvals" / "requests.jsonl"),
        "approval_grants_path": str(root / "approvals" / "grants.json"),
        "plugin_status_path": str(root / "plugin_status.json"),
        "wp_export_path": str(root / "wp_export.json"),
        "wp_package_path": str(export_summary.get("wp_package_path") or ""),
        "wp_root": str(export_summary.get("wp_root") or ""),
    }


def summarize_payload(resolved, result=None, run=None, board=None, skill_context=None):
    resolved = dict(resolved or {})
    result = dict(result or {})
    run = dict(run or {})
    board = dict(board or {})
    skill_context = skill_context or _resolve_protocol_skill_context(resolved)
    status = result.get("status") or run.get("status", "")
    flag = result.get("flag") or ((run.get("result") or {}).get("flag", ""))
    category = resolved.get("category") or run.get("category", "") or dict(skill_context.get("knowledge") or {}).get("selected_skill_category", "")
    solver = result.get("solver") or board_value(board, "run.meta.solver", "")
    recommended_tools = board_value(board, "tool_usage.recommended_tools", [])
    recommended_mcp = board_value(board, "mcp_usage.recommended_mcp", [])
    next_actions = board.get("next_actions", []) if isinstance(board.get("next_actions"), list) else []
    blockers = board.get("blockers", []) if isinstance(board.get("blockers"), list) else []
    subagents = board.get("subagents", []) if isinstance(board.get("subagents"), list) else []
    mcp_status = dict(board.get("mcp_status") or {})
    approval_status = dict(board.get("approval_status") or {})
    plugin_status = dict(board.get("plugin_status") or {})
    remote_subagents = list(board.get("remote_subagents", []) or [])
    recent_mcp_calls = list(board.get("recent_mcp_calls", []) or [])
    resource_enabled_servers = list(board.get("resource_enabled_servers", []) or mcp_status.get("resource_enabled_servers", []))
    recent_actions = list(board.get("recent_actions", []) or [])
    background_policy = dict(resolved.get("background_policy") or run.get("request", {}).get("background_policy") or {})
    knowledge = dict(board.get("knowledge") or skill_context.get("knowledge") or board_value(resolved, "autopilot_plan.knowledge", {}))
    pwn_parity = dict(board_value(board, "binary.pwn_parity", {}))
    pwn_family = str(board_value(board, "binary.pwn_family", "") or "")
    pwn_stage_status = dict(board_value(board, "binary.pwn_stage_status", {}))
    build_profile = str(board_value(board, "binary.build_profile", "") or pwn_parity.get("build_profile", ""))
    build_missing = list(board_value(board, "binary.build_missing", []) or pwn_parity.get("build_missing", []))
    debug_trace = dict(board_value(board, "binary.debug_trace", {}))
    speed_mode = str(skill_context.get("speed_mode") or resolved.get("speed_mode") or board_value(resolved, "autopilot_plan.speed_mode", "standard") or "standard")
    workspace = str(result.get("workspace") or run.get("workspace") or "")
    export_summary = _resolve_export_summary(workspace, result=result, run=run)

    if flag:
        headline = "已获得 flag，优先复核复现链路。"
    elif status in {"running", "queued"}:
        headline = "任务正在运行，继续轮询状态并读取答题板。"
    elif status == "unresolved":
        headline = "当前未拿到 flag，优先按答题板里的 next_actions 继续推进。"
    elif status == "failed":
        headline = "任务执行失败，先看 error 和答题板 blockers。"
    else:
        headline = "任务已启动，优先看答题板中的 routing 和 next_actions。"

    return {
        "headline": headline,
        "status": status,
        "category": category,
        "solver": solver,
        "speed_mode": speed_mode,
        "flag_found": bool(flag),
        "flag": flag,
        "wp_exported": bool(export_summary.get("wp_exported", False)),
        "wp_package_path": str(export_summary.get("wp_package_path") or ""),
        "wp_root": str(export_summary.get("wp_root") or ""),
        "wp_warning": str(export_summary.get("wp_warning") or ""),
        "flag_first_text": str(export_summary.get("flag_first_text") or build_flag_first_text(flag)),
        "template_detected": bool((resolved.get("task_template") or {}).get("detected")),
        "dispatch_mode": background_policy.get("effective_mode", "sync"),
        "dispatch_reason": background_policy.get("reason", ""),
        "recommended_tools": recommended_tools,
        "recommended_mcp": recommended_mcp,
        "next_actions": next_actions[:5],
        "blockers": blockers[:5],
        "subagents": subagents[:6],
        "remote_subagents": remote_subagents[:6],
        "mcp_status": mcp_status,
        "approval_status": approval_status,
        "plugin_status": plugin_status,
        "recent_mcp_calls": recent_mcp_calls[:5],
        "resource_enabled_servers": resource_enabled_servers[:8],
        "recent_activity": _recent_activity(recent_actions, recent_mcp_calls),
        "pwn_parity": pwn_parity,
        "pwn_family": pwn_family,
        "pwn_family_confidence": float(board_value(board, "binary.pwn_family_confidence", 0.0) or 0.0),
        "pwn_stage_status": pwn_stage_status,
        "build_profile": build_profile,
        "build_missing": build_missing,
        "debug_trace": debug_trace,
        "exploit_stub_generated": bool(board_value(board, "binary.exploit_stub_generated", False)),
        "stage2_generated": bool(board_value(board, "binary.stage2_generated", False)),
        "knowledge": _knowledge_brief(knowledge),
    }


def summarize_board(board):
    board = dict(board or {})
    knowledge = dict(board.get("knowledge") or {})
    speed_mode = str(board_value(board, "autopilot.speed_mode", knowledge.get("speed_mode", "standard")) or "standard")
    export_summary = dict(board.get("solved_export") or {})
    flag = str(board_value(board, "run.meta.flag", "") or "")
    pwn_parity = dict(board_value(board, "binary.pwn_parity", {}))
    pwn_family = str(board_value(board, "binary.pwn_family", "") or "")
    pwn_stage_status = dict(board_value(board, "binary.pwn_stage_status", {}))
    build_profile = str(board_value(board, "binary.build_profile", "") or pwn_parity.get("build_profile", ""))
    build_missing = list(board_value(board, "binary.build_missing", []) or pwn_parity.get("build_missing", []))
    debug_trace = dict(board_value(board, "binary.debug_trace", {}))
    mcp_status = dict(board.get("mcp_status") or {})
    approval_status = dict(board.get("approval_status") or {})
    plugin_status = dict(board.get("plugin_status") or {})
    return {
        "present": bool(board),
        "run_status": board_value(board, "run.meta.status", ""),
        "solver": board_value(board, "run.meta.solver", ""),
        "speed_mode": speed_mode,
        "wp_exported": bool(export_summary.get("wp_exported", False)),
        "wp_package_path": str(export_summary.get("wp_package_path") or ""),
        "wp_root": str(export_summary.get("wp_root") or ""),
        "wp_warning": str(export_summary.get("wp_warning") or ""),
        "flag_first_text": str(export_summary.get("flag_first_text") or build_flag_first_text(flag)),
        "recommended_path": board_value(board, "target_summary.recommended_path", ""),
        "selected_remote_host": board_value(board, "remote_usage.selected_host", ""),
        "next_actions": board.get("next_actions", [])[:5] if isinstance(board.get("next_actions"), list) else [],
        "blockers": board.get("blockers", [])[:5] if isinstance(board.get("blockers"), list) else [],
        "subagents": board.get("subagents", [])[:6] if isinstance(board.get("subagents"), list) else [],
        "remote_subagents": board.get("remote_subagents", [])[:6] if isinstance(board.get("remote_subagents"), list) else [],
        "mcp_status": mcp_status,
        "approval_status": approval_status,
        "plugin_status": plugin_status,
        "recent_mcp_calls": list(board.get("recent_mcp_calls", []) or [])[:5],
        "resource_enabled_servers": list(board.get("resource_enabled_servers", []) or mcp_status.get("resource_enabled_servers", []))[:8],
        "recent_activity": _recent_activity(board.get("recent_actions", []), board.get("recent_mcp_calls", [])),
        "pwn_parity": pwn_parity,
        "pwn_family": pwn_family,
        "pwn_family_confidence": float(board_value(board, "binary.pwn_family_confidence", 0.0) or 0.0),
        "pwn_stage_status": pwn_stage_status,
        "build_profile": build_profile,
        "build_missing": build_missing,
        "debug_trace": debug_trace,
        "exploit_stub_generated": bool(board_value(board, "binary.exploit_stub_generated", False)),
        "stage2_generated": bool(board_value(board, "binary.stage2_generated", False)),
        "knowledge": _knowledge_brief(knowledge),
    }


def load_board(workspace):
    if not workspace:
        return {}
    return load_workspace_board(workspace)


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


def validate_resolved_request(resolved):
    resolved = dict(resolved or {})
    category = str(resolved.get("category") or "").strip().lower()
    target = str(resolved.get("target") or resolved.get("url") or "").strip()
    attachments = list(resolved.get("attachments", []) or [])
    errors = []
    warnings = []
    next_actions = []

    if not target and not attachments:
        errors.append("缺少 target 或 attachments，当前任务没有可执行对象。")
        next_actions.append("补充目标 URL、host:port 或至少一个附件路径。")

    if category in {"re", "reverse", "pwn", "crypto", "forensics", "malware"} and not attachments:
        warnings.append("当前题型通常至少需要一个本地附件；如果这是远程题，可忽略。")

    if category == "web" and not target:
        warnings.append("当前是 web 题型，但没有目标 URL；如果是纯源码审计题，可忽略。")

    if not next_actions:
        next_actions.append("输入已满足最小执行条件，可以直接启动 solve 流程。")

    return {
        "ok": not bool(errors),
        "errors": errors,
        "warnings": warnings,
        "next_actions": next_actions,
    }


def persist_protocol_summary(workspace, envelope):
    if not workspace:
        return
    try:
        root = Path(workspace)
        root.mkdir(parents=True, exist_ok=True)
        (root / TASK_PROTOCOL_SUMMARY_FILENAME).write_text(
            json.dumps(envelope, ensure_ascii=False, indent=2),
            encoding="utf-8-sig",
        )
    except Exception:
        return


def persist_run_status_summary(run_payload):
    try:
        build_status_envelope(run_payload or {})
    except Exception:
        return


def board_value(board, dotted_key, default=None):
    current = board
    for part in str(dotted_key or "").split("."):
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current


def _resolve_export_summary(workspace, result=None, run=None):
    result = dict(result or {})
    run = dict(run or {})
    run_result = dict(run.get("result") or {})
    merged = dict(load_workspace_export_summary(workspace) if workspace else {})
    for source in [run_result, result]:
        for key in ["wp_exported", "wp_package_path", "wp_root", "wp_warning", "flag_first_text", "wp_summary_path", "package_name"]:
            if source.get(key) not in [None, ""]:
                merged[key] = source.get(key)
    flag = str(result.get("flag") or run_result.get("flag") or "")
    merged["flag_first_text"] = str(
        merged.get("flag_first_text")
        or build_flag_first_text(flag, merged.get("wp_package_path", ""), merged.get("wp_warning", ""))
    )
    return merged
