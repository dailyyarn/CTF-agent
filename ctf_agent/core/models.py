from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class Challenge:
    contest_id: str
    challenge_id: str
    title: str
    category: str
    description: str
    attachments: List[Path] = field(default_factory=list)
    target: Optional[str] = None
    flag_format: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "contest_id": self.contest_id,
            "challenge_id": self.challenge_id,
            "title": self.title,
            "category": self.category,
            "description": self.description,
            "attachments": [str(path) for path in self.attachments],
            "target": self.target,
            "flag_format": self.flag_format,
            "metadata": _json_safe(self.metadata),
        }


@dataclass
class Finding:
    source: str
    summary: str
    evidence: str
    confidence: float = 0.5


@dataclass
class CandidateFlag:
    value: str
    source: str
    confidence: float
    reproducible: bool = False


@dataclass
class ExploitPlan:
    title: str
    method: str
    url: str
    data: Dict[str, Any] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    notes: str = ""
    confidence: float = 0.5


@dataclass
class ActionRecord:
    phase: str
    action: str
    status: str
    summary: str
    artifact: Optional[str] = None


@dataclass
class SubAgentSpec:
    id: str
    purpose: str
    prompt: str
    allowed_tools: List[str] = field(default_factory=list)
    execution_mode: str = "local"
    transport: str = "local"
    remote_host: str = ""
    sync_policy: str = "summary_only"
    poll_interval_sec: int = 5
    mirror_artifacts: bool = True
    max_steps: int = 6
    max_tool_calls: int = 4
    max_tokens: int = 2000000
    timeout_sec: int = 90
    workspace_dir: Optional[str] = None
    parent_run_id: Optional[str] = None
    category_hint: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["allowed_tools"] = list(self.allowed_tools)
        return payload

    @classmethod
    def from_dict(cls, payload: Optional[Dict[str, Any]] = None) -> "SubAgentSpec":
        payload = dict(payload or {})
        return cls(
            id=str(payload.get("id", "")),
            purpose=str(payload.get("purpose", "")),
            prompt=str(payload.get("prompt", "")),
            allowed_tools=[str(item) for item in list(payload.get("allowed_tools", [])) if str(item or "").strip()],
            execution_mode=str(payload.get("execution_mode", "local") or "local"),
            transport=str(payload.get("transport", "local") or "local"),
            remote_host=str(payload.get("remote_host", "") or ""),
            sync_policy=str(payload.get("sync_policy", "summary_only") or "summary_only"),
            poll_interval_sec=int(payload.get("poll_interval_sec", 5) or 5),
            mirror_artifacts=bool(payload.get("mirror_artifacts", True)),
            max_steps=int(payload.get("max_steps", 6) or 6),
            max_tool_calls=int(payload.get("max_tool_calls", 4) or 4),
            max_tokens=int(payload.get("max_tokens", 2000000) or 2000000),
            timeout_sec=int(payload.get("timeout_sec", 90) or 90),
            workspace_dir=payload.get("workspace_dir"),
            parent_run_id=payload.get("parent_run_id"),
            category_hint=payload.get("category_hint"),
        )


@dataclass
class SubAgentRecord:
    id: str
    status: str
    started_at: float
    finished_at: Optional[float]
    spec: SubAgentSpec
    summary: Dict[str, Any] = field(default_factory=dict)
    stop_reason: str = "completed"
    usage: Dict[str, Any] = field(default_factory=dict)
    remote_status: Dict[str, Any] = field(default_factory=dict)
    approval_request_id: str = ""
    sync_manifest: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    artifact_paths: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "spec": self.spec.to_dict(),
            "summary": _json_safe(self.summary),
            "stop_reason": self.stop_reason,
            "usage": _json_safe(self.usage),
            "remote_status": _json_safe(self.remote_status),
            "approval_request_id": self.approval_request_id,
            "sync_manifest": _json_safe(self.sync_manifest),
            "error": self.error,
            "artifact_paths": [_json_safe(item) for item in self.artifact_paths],
        }

    @classmethod
    def from_dict(cls, payload: Optional[Dict[str, Any]] = None) -> "SubAgentRecord":
        payload = dict(payload or {})
        return cls(
            id=str(payload.get("id", "")),
            status=str(payload.get("status", "")),
            started_at=float(payload.get("started_at", 0.0) or 0.0),
            finished_at=float(payload["finished_at"]) if payload.get("finished_at") is not None else None,
            spec=SubAgentSpec.from_dict(payload.get("spec", {})),
            summary=dict(payload.get("summary") or {}),
            stop_reason=str(payload.get("stop_reason", "completed") or "completed"),
            usage=dict(payload.get("usage") or {}),
            remote_status=dict(payload.get("remote_status") or {}),
            approval_request_id=str(payload.get("approval_request_id", "") or ""),
            sync_manifest=dict(payload.get("sync_manifest") or {}),
            error=payload.get("error"),
            artifact_paths=[str(item) for item in list(payload.get("artifact_paths", []))],
        )


@dataclass
class ChallengeState:
    phase: str = "init"
    hypotheses: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    tried_actions: List[ActionRecord] = field(default_factory=list)
    candidate_flags: List[CandidateFlag] = field(default_factory=list)
    exploit_plans: List[ExploitPlan] = field(default_factory=list)
    blocked_reason: Optional[str] = None
    subagents: List[SubAgentRecord] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "phase": self.phase,
            "hypotheses": list(self.hypotheses),
            "findings": [asdict(item) for item in self.findings],
            "tried_actions": [asdict(item) for item in self.tried_actions],
            "candidate_flags": [asdict(item) for item in self.candidate_flags],
            "exploit_plans": [asdict(item) for item in self.exploit_plans],
            "blocked_reason": self.blocked_reason,
            "subagents": [item.to_dict() for item in self.subagents],
        }


def _json_safe(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item) for item in value]
    return repr(value)
