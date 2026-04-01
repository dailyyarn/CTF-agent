import json
from pathlib import Path

from ctf_agent.core.models import ActionRecord, CandidateFlag, ChallengeState, ExploitPlan, Finding, SubAgentRecord
from ctf_agent.core.workspace import load_workspace_approval_status


def _read_json(path):
    path = Path(path)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return None


def _write_json(path, payload):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str), encoding="utf-8-sig")
    return str(path)


def solver_session_path(workspace):
    return Path(workspace) / "agent_session.json"


def solver_context_path(workspace):
    return Path(workspace) / "solver_context.json"


def save_solver_context(workspace, payload):
    return _write_json(solver_context_path(workspace), dict(payload or {}))


def load_solver_context(workspace, context_path=None):
    target = Path(context_path) if context_path else solver_context_path(workspace)
    return dict(_read_json(target) or {})


def save_solver_session(
    workspace,
    challenge,
    state,
    solver="",
    checkpoint="",
    solver_context_path_value="",
    pending_approval=None,
    pending_action=None,
):
    payload = {
        "version": 1,
        "session_kind": "solver",
        "solver": str(solver or ""),
        "checkpoint": str(checkpoint or ""),
        "solver_context_path": str(solver_context_path_value or ""),
        "workspace": str(workspace),
        "challenge": challenge.to_dict() if hasattr(challenge, "to_dict") else {},
        "state": state.to_dict() if hasattr(state, "to_dict") else dict(state or {}),
        "pending_approval": dict(pending_approval or {}),
        "pending_action": dict(pending_action or {}),
    }
    return _write_json(solver_session_path(workspace), payload)


def load_solver_session(workspace):
    payload = _read_json(solver_session_path(workspace))
    if not isinstance(payload, dict):
        return None
    if str(payload.get("session_kind", "") or "") != "solver":
        return None
    return payload


def approval_status_for_session(workspace, session=None):
    session = dict(session or {})
    pending = dict(session.get("pending_approval") or {})
    request_id = str(pending.get("request_id", "") or "")
    if not request_id:
        return "missing"
    approval_status = load_workspace_approval_status(workspace)
    for item in list(approval_status.get("pending_requests", []) or []) + list(approval_status.get("recent_requests", []) or []):
        if str(item.get("id", "") or "") == request_id:
            return str(item.get("status", "") or "pending")
    return "missing"


def clear_solver_session(workspace):
    for path in [solver_session_path(workspace), solver_context_path(workspace)]:
        target = Path(path)
        if target.exists():
            try:
                target.unlink()
            except Exception:
                pass


def restore_solver_state(payload):
    payload = dict(payload or {})
    state = ChallengeState(phase=str(payload.get("phase", "init") or "init"))
    state.hypotheses = list(payload.get("hypotheses", []))
    state.blocked_reason = payload.get("blocked_reason")
    for item in list(payload.get("findings", []) or []):
        state.findings.append(Finding(**item))
    for item in list(payload.get("candidate_flags", []) or []):
        state.candidate_flags.append(CandidateFlag(**item))
    for item in list(payload.get("tried_actions", []) or []):
        state.tried_actions.append(ActionRecord(**item))
    for item in list(payload.get("exploit_plans", []) or []):
        state.exploit_plans.append(ExploitPlan(**{k: v for k, v in dict(item).items() if k not in {"data", "headers"}}))
    for item in list(payload.get("subagents", []) or []):
        state.subagents.append(SubAgentRecord.from_dict(item))
    return state
