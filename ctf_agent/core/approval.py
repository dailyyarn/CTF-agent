import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


APPROVAL_STATUS_PENDING = "pending"
APPROVAL_STATUS_APPROVED = "approved"
APPROVAL_STATUS_DENIED = "denied"
APPROVAL_STATUS_EXPIRED = "expired"
APPROVAL_STATUS_CANCELLED = "cancelled"
APPROVAL_STATUS_CONSUMED = "consumed"
APPROVAL_TERMINAL_STATUSES = {
    APPROVAL_STATUS_APPROVED,
    APPROVAL_STATUS_DENIED,
    APPROVAL_STATUS_EXPIRED,
    APPROVAL_STATUS_CANCELLED,
    APPROVAL_STATUS_CONSUMED,
}
APPROVAL_SCOPE_ONCE = "once"
APPROVAL_SCOPE_RUN = "run"
APPROVAL_SCOPE_WORKSPACE_SESSION = "workspace_session"


def _now_ts():
    return float(time.time())


@dataclass
class PolicyDecision:
    decision: str
    operation: str
    reason: str
    category: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    request_id: str = ""
    fingerprint: str = ""
    scope: str = ""
    grant_id: str = ""

    def to_dict(self):
        return {
            "decision": self.decision,
            "operation": self.operation,
            "reason": self.reason,
            "category": self.category,
            "details": dict(self.details or {}),
            "request_id": self.request_id,
            "fingerprint": self.fingerprint,
            "scope": self.scope,
            "grant_id": self.grant_id,
        }


@dataclass
class ApprovalRequest:
    id: str
    created_at: float
    updated_at: float
    status: str
    operation: str
    category: str
    fingerprint: str
    subject: str = ""
    reason: str = ""
    workspace: str = ""
    run_id: str = ""
    default_scope: str = APPROVAL_SCOPE_ONCE
    ttl_sec: int = 1800
    auto_resume: bool = True
    details: Dict[str, Any] = field(default_factory=dict)
    pending_action: Dict[str, Any] = field(default_factory=dict)
    response: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, payload=None):
        payload = dict(payload or {})
        return cls(
            id=str(payload.get("id", "")),
            created_at=float(payload.get("created_at", 0.0) or 0.0),
            updated_at=float(payload.get("updated_at", 0.0) or 0.0),
            status=str(payload.get("status", APPROVAL_STATUS_PENDING) or APPROVAL_STATUS_PENDING),
            operation=str(payload.get("operation", "") or ""),
            category=str(payload.get("category", "") or ""),
            fingerprint=str(payload.get("fingerprint", "") or ""),
            subject=str(payload.get("subject", "") or ""),
            reason=str(payload.get("reason", "") or ""),
            workspace=str(payload.get("workspace", "") or ""),
            run_id=str(payload.get("run_id", "") or ""),
            default_scope=str(payload.get("default_scope", APPROVAL_SCOPE_ONCE) or APPROVAL_SCOPE_ONCE),
            ttl_sec=int(payload.get("ttl_sec", 1800) or 1800),
            auto_resume=bool(payload.get("auto_resume", True)),
            details=dict(payload.get("details") or {}),
            pending_action=dict(payload.get("pending_action") or {}),
            response=dict(payload.get("response") or {}),
        )


@dataclass
class ApprovalGrant:
    id: str
    request_id: str
    created_at: float
    updated_at: float
    status: str
    scope: str
    operation: str
    category: str
    fingerprint: str
    workspace: str = ""
    run_id: str = ""
    expires_at: Optional[float] = None
    use_count: int = 0
    max_uses: int = 0
    reason: str = ""

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, payload=None):
        payload = dict(payload or {})
        expires_at = payload.get("expires_at")
        return cls(
            id=str(payload.get("id", "")),
            request_id=str(payload.get("request_id", "") or ""),
            created_at=float(payload.get("created_at", 0.0) or 0.0),
            updated_at=float(payload.get("updated_at", 0.0) or 0.0),
            status=str(payload.get("status", APPROVAL_STATUS_APPROVED) or APPROVAL_STATUS_APPROVED),
            scope=str(payload.get("scope", APPROVAL_SCOPE_ONCE) or APPROVAL_SCOPE_ONCE),
            operation=str(payload.get("operation", "") or ""),
            category=str(payload.get("category", "") or ""),
            fingerprint=str(payload.get("fingerprint", "") or ""),
            workspace=str(payload.get("workspace", "") or ""),
            run_id=str(payload.get("run_id", "") or ""),
            expires_at=float(expires_at) if expires_at not in [None, ""] else None,
            use_count=int(payload.get("use_count", 0) or 0),
            max_uses=int(payload.get("max_uses", 0) or 0),
            reason=str(payload.get("reason", "") or ""),
        )


class ApprovalManager(object):
    def __init__(self, workspace_manager=None, workspace=None, approval_policy=None, run_id=""):
        self.workspace_manager = workspace_manager
        self.workspace = str(workspace or "")
        self.run_id = str(run_id or "")
        self.approval_policy = dict(approval_policy or {})

    def configure(self, workspace=None, run_id=None, approval_policy=None):
        if workspace is not None:
            self.workspace = str(workspace or "")
        if run_id is not None:
            self.run_id = str(run_id or "")
        if approval_policy is not None:
            self.approval_policy = dict(approval_policy or {})
        return self

    def enabled(self):
        return bool(self.approval_policy.get("enabled", True))

    def default_scope(self):
        return str(self.approval_policy.get("default_scope", APPROVAL_SCOPE_WORKSPACE_SESSION) or APPROVAL_SCOPE_WORKSPACE_SESSION)

    def session_ttl_sec(self):
        return int(self.approval_policy.get("session_ttl_sec", 1800) or 1800)

    def auto_resume(self):
        return bool(self.approval_policy.get("auto_resume", True))

    def ask_categories(self):
        categories = list(self.approval_policy.get("ask_categories", []) or [])
        if categories:
            return {str(item).strip() for item in categories if str(item).strip()}
        return {"shell_mutation", "shell_network", "remote_subagent"}

    def _workspace_path(self, workspace=None):
        value = str(workspace or self.workspace or "").strip()
        return Path(value) if value else None

    def _approvals_root(self, workspace=None):
        root = self._workspace_path(workspace)
        if not root:
            return None
        return root / "approvals"

    def _requests_path(self, workspace=None):
        root = self._approvals_root(workspace)
        return root / "requests.jsonl" if root else None

    def _grants_path(self, workspace=None):
        root = self._approvals_root(workspace)
        return root / "grants.json" if root else None

    def _status_path(self, workspace=None):
        root = self._workspace_path(workspace)
        return root / "approval_status.json" if root else None

    def _append_jsonl(self, path, payload):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8-sig") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False) + "\n")

    def _write_json(self, path, payload):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8-sig")

    def _load_requests(self, workspace=None):
        path = self._requests_path(workspace)
        if not path or not path.exists():
            return []
        latest = {}
        try:
            with path.open("r", encoding="utf-8-sig") as handle:
                for raw in handle:
                    text = raw.strip()
                    if not text:
                        continue
                    try:
                        request = ApprovalRequest.from_dict(json.loads(text))
                    except Exception:
                        continue
                    latest[request.id] = request
        except Exception:
            return []
        return sorted(latest.values(), key=lambda item: (item.created_at, item.id))

    def _load_grants(self, workspace=None):
        path = self._grants_path(workspace)
        if not path or not path.exists():
            return []
        try:
            payload = json.loads(path.read_text(encoding="utf-8-sig"))
        except Exception:
            return []
        return [ApprovalGrant.from_dict(item) for item in list(payload or [])]

    def _save_grants(self, grants, workspace=None):
        path = self._grants_path(workspace)
        if not path:
            return
        self._write_json(path, [item.to_dict() for item in list(grants or [])])

    def _persist_status(self, workspace=None):
        workspace = workspace or self.workspace
        if not workspace:
            return {}
        requests = self._load_requests(workspace)
        grants = self._load_grants(workspace)
        now = _now_ts()
        counts = {
            APPROVAL_STATUS_PENDING: 0,
            APPROVAL_STATUS_APPROVED: 0,
            APPROVAL_STATUS_DENIED: 0,
            APPROVAL_STATUS_EXPIRED: 0,
            APPROVAL_STATUS_CANCELLED: 0,
            APPROVAL_STATUS_CONSUMED: 0,
        }
        recent_requests = []
        pending_requests = []
        expired_grants = 0
        active_grants = []
        for request in requests:
            counts[request.status] = counts.get(request.status, 0) + 1
            request_payload = request.to_dict()
            recent_requests.append(request_payload)
            if request.status == APPROVAL_STATUS_PENDING:
                pending_requests.append(request_payload)
        for grant in grants:
            if grant.expires_at and grant.expires_at <= now and grant.status == APPROVAL_STATUS_APPROVED:
                grant.status = APPROVAL_STATUS_EXPIRED
                expired_grants += 1
            if grant.status == APPROVAL_STATUS_APPROVED:
                active_grants.append(grant.to_dict())
        if expired_grants:
            self._save_grants(grants, workspace=workspace)
        payload = {
            "updated_at": now,
            "workspace": str(workspace),
            "run_id": str(self.run_id or ""),
            "enabled": self.enabled(),
            "counts": counts,
            "pending_requests": pending_requests[:10],
            "recent_requests": recent_requests[-10:],
            "active_grants": active_grants[:10],
        }
        path = self._status_path(workspace)
        if path:
            self._write_json(path, payload)
        return payload

    def get_status(self, workspace=None, run_id=None):
        workspace = workspace or self.workspace
        status_path = self._status_path(workspace)
        if status_path and status_path.exists():
            try:
                payload = json.loads(status_path.read_text(encoding="utf-8-sig"))
            except Exception:
                payload = {}
        else:
            payload = self._persist_status(workspace=workspace)
        if run_id:
            filtered_pending = [
                item for item in list(payload.get("pending_requests", []) or [])
                if str(item.get("run_id", "") or "") == str(run_id or "")
            ]
            filtered_recent = [
                item for item in list(payload.get("recent_requests", []) or [])
                if str(item.get("run_id", "") or "") == str(run_id or "")
            ]
            payload["pending_requests"] = filtered_pending
            payload["recent_requests"] = filtered_recent
        payload.setdefault("counts", {})
        payload.setdefault("pending_requests", [])
        payload.setdefault("recent_requests", [])
        payload.setdefault("active_grants", [])
        payload.setdefault("enabled", self.enabled())
        return payload

    def list_requests(self, workspace=None, run_id=None, status=None):
        requests = self._load_requests(workspace=workspace)
        filtered = []
        run_id = str(run_id or "").strip()
        status = str(status or "").strip().lower()
        for item in requests:
            if run_id and str(item.run_id or "") != run_id:
                continue
            if status and str(item.status or "").lower() != status:
                continue
            filtered.append(item.to_dict())
        return filtered

    def get_request(self, request_id, workspace=None):
        for item in self._load_requests(workspace=workspace):
            if item.id == request_id:
                return item
        return None

    def _find_pending_duplicate(self, operation, fingerprint, workspace="", run_id=""):
        for item in reversed(self._load_requests(workspace=workspace)):
            if item.status != APPROVAL_STATUS_PENDING:
                continue
            if item.operation != operation or item.fingerprint != fingerprint:
                continue
            if workspace and item.workspace != str(workspace):
                continue
            if run_id and item.run_id not in {"", str(run_id)}:
                continue
            return item
        return None

    def create_request(
        self,
        operation,
        category,
        fingerprint,
        subject="",
        reason="",
        details=None,
        pending_action=None,
        workspace=None,
        run_id=None,
        default_scope=None,
        ttl_sec=None,
        auto_resume=None,
    ):
        workspace = str(workspace or self.workspace or "")
        run_id = str(run_id or self.run_id or "")
        duplicate = self._find_pending_duplicate(operation, fingerprint, workspace=workspace, run_id=run_id)
        if duplicate:
            return duplicate
        now = _now_ts()
        request = ApprovalRequest(
            id="apr-{0}".format(uuid.uuid4().hex[:12]),
            created_at=now,
            updated_at=now,
            status=APPROVAL_STATUS_PENDING,
            operation=str(operation or ""),
            category=str(category or ""),
            fingerprint=str(fingerprint or ""),
            subject=str(subject or ""),
            reason=str(reason or ""),
            workspace=workspace,
            run_id=run_id,
            default_scope=str(default_scope or self.default_scope()),
            ttl_sec=int(ttl_sec or self.session_ttl_sec()),
            auto_resume=self.auto_resume() if auto_resume is None else bool(auto_resume),
            details=dict(details or {}),
            pending_action=dict(pending_action or {}),
        )
        path = self._requests_path(workspace=workspace)
        if path:
            self._append_jsonl(path, request.to_dict())
        self._persist_status(workspace=workspace)
        return request

    def _grant_matches(self, grant, operation, fingerprint, workspace="", run_id=""):
        if grant.status != APPROVAL_STATUS_APPROVED:
            return False
        now = _now_ts()
        if grant.expires_at and grant.expires_at <= now:
            return False
        if grant.operation != str(operation or ""):
            return False
        if grant.fingerprint != str(fingerprint or ""):
            return False
        if grant.scope == APPROVAL_SCOPE_RUN and run_id and grant.run_id not in {"", str(run_id)}:
            return False
        if grant.scope == APPROVAL_SCOPE_WORKSPACE_SESSION and workspace and grant.workspace not in {"", str(workspace)}:
            return False
        if grant.scope == APPROVAL_SCOPE_ONCE and grant.max_uses and grant.use_count >= grant.max_uses:
            return False
        return True

    def get_active_grant(self, operation, fingerprint, workspace=None, run_id=None):
        workspace = str(workspace or self.workspace or "")
        run_id = str(run_id or self.run_id or "")
        grants = self._load_grants(workspace=workspace)
        changed = False
        for grant in grants:
            if grant.expires_at and grant.expires_at <= _now_ts() and grant.status == APPROVAL_STATUS_APPROVED:
                grant.status = APPROVAL_STATUS_EXPIRED
                grant.updated_at = _now_ts()
                changed = True
                continue
            if self._grant_matches(grant, operation, fingerprint, workspace=workspace, run_id=run_id):
                if changed:
                    self._save_grants(grants, workspace=workspace)
                    self._persist_status(workspace=workspace)
                return grant
        if changed:
            self._save_grants(grants, workspace=workspace)
            self._persist_status(workspace=workspace)
        return None

    def consume_grant(self, grant_id, workspace=None):
        workspace = str(workspace or self.workspace or "")
        grants = self._load_grants(workspace=workspace)
        changed = False
        for grant in grants:
            if grant.id != grant_id:
                continue
            if grant.status != APPROVAL_STATUS_APPROVED:
                break
            grant.use_count += 1
            grant.updated_at = _now_ts()
            if grant.scope == APPROVAL_SCOPE_ONCE and grant.max_uses and grant.use_count >= grant.max_uses:
                grant.status = APPROVAL_STATUS_CONSUMED
            changed = True
            break
        if changed:
            self._save_grants(grants, workspace=workspace)
            self._persist_status(workspace=workspace)
        return changed

    def respond(self, request_id, decision, scope=None, ttl_sec=None, reason="", workspace=None, auto_resume=None):
        workspace = str(workspace or self.workspace or "")
        request = self.get_request(request_id, workspace=workspace)
        if not request:
            return {"status": "missing", "request_id": request_id}
        lowered = str(decision or "").strip().lower()
        if lowered not in {"approve", "approved", "deny", "denied"}:
            return {"status": "invalid", "request_id": request_id, "message": "decision must be approve or deny"}
        now = _now_ts()
        request.status = APPROVAL_STATUS_APPROVED if lowered.startswith("approve") else APPROVAL_STATUS_DENIED
        request.updated_at = now
        request.response = {
            "decision": request.status,
            "reason": str(reason or ""),
            "scope": str(scope or request.default_scope or self.default_scope()),
            "ttl_sec": int(ttl_sec or request.ttl_sec or self.session_ttl_sec()),
            "auto_resume": request.auto_resume if auto_resume is None else bool(auto_resume),
            "responded_at": now,
        }
        path = self._requests_path(workspace=workspace)
        if path:
            self._append_jsonl(path, request.to_dict())
        grants = self._load_grants(workspace=workspace)
        grant_payload = None
        if request.status == APPROVAL_STATUS_APPROVED:
            scope_value = str(scope or request.default_scope or self.default_scope())
            ttl_value = int(ttl_sec or request.ttl_sec or self.session_ttl_sec())
            expires_at = None
            max_uses = 0
            if scope_value == APPROVAL_SCOPE_ONCE:
                max_uses = 1
            elif scope_value == APPROVAL_SCOPE_WORKSPACE_SESSION:
                expires_at = now + max(1, ttl_value)
            grant = ApprovalGrant(
                id="agr-{0}".format(uuid.uuid4().hex[:12]),
                request_id=request.id,
                created_at=now,
                updated_at=now,
                status=APPROVAL_STATUS_APPROVED,
                scope=scope_value,
                operation=request.operation,
                category=request.category,
                fingerprint=request.fingerprint,
                workspace=request.workspace,
                run_id=request.run_id,
                expires_at=expires_at,
                max_uses=max_uses,
                reason=str(reason or ""),
            )
            grants.append(grant)
            grant_payload = grant.to_dict()
        self._save_grants(grants, workspace=workspace)
        status_payload = self._persist_status(workspace=workspace)
        return {
            "status": request.status,
            "request": request.to_dict(),
            "grant": grant_payload,
            "approval_status": status_payload,
        }

