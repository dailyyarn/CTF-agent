import json
import threading
import traceback
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


def utc_now():
    return datetime.now(timezone.utc).isoformat()


@dataclass
class RunRecord:
    run_id: str
    created_at: str
    updated_at: str
    status: str = "queued"
    category: str = "web"
    workspace: str = ""
    challenge_title: str = ""
    request: Dict[str, Any] = field(default_factory=dict)
    result: Dict[str, Any] = field(default_factory=dict)
    error: str = ""
    traceback_text: str = ""
    cancel_requested: bool = False

    def to_dict(self):
        return {
            "run_id": self.run_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "status": self.status,
            "category": self.category,
            "workspace": self.workspace,
            "challenge_title": self.challenge_title,
            "request": self.request,
            "result": self.result,
            "error": self.error,
            "traceback_text": self.traceback_text,
            "cancel_requested": self.cancel_requested,
        }


class RunManager(object):
    def __init__(self, storage_root=None):
        self._runs: Dict[str, RunRecord] = {}
        self._threads: Dict[str, threading.Thread] = {}
        self._cancel_events: Dict[str, threading.Event] = {}
        self._lock = threading.Lock()
        self._storage_root: Optional[Path] = None
        self.set_storage_root(storage_root)

    def set_storage_root(self, storage_root):
        if not storage_root:
            return
        path = Path(storage_root).resolve()
        runs_dir = path / "_runs"
        runs_dir.mkdir(parents=True, exist_ok=True)
        self._storage_root = path

    def start(self, category, request_payload, runner):
        run_id = "run-{0}".format(uuid.uuid4().hex[:12])
        now = utc_now()
        record = RunRecord(
            run_id=run_id,
            created_at=now,
            updated_at=now,
            category=category,
            challenge_title=request_payload.get("title") or request_payload.get("challenge_id") or category,
            request=dict(request_payload or {}),
        )
        cancel_event = threading.Event()

        def worker():
            self._set_status(run_id, "running")
            try:
                result = runner(run_id, cancel_event)
                if cancel_event.is_set():
                    self._set_status(run_id, "cancelled")
                else:
                    self._set_result(run_id, result or {})
                    self._set_status(run_id, (result or {}).get("status", "completed"))
            except Exception as exc:
                self._set_error(run_id, str(exc), traceback.format_exc())
                self._set_status(run_id, "failed")

        thread = threading.Thread(target=worker, name=run_id, daemon=True)
        with self._lock:
            self._runs[run_id] = record
            self._threads[run_id] = thread
            self._cancel_events[run_id] = cancel_event
            self._persist_record(record)
        thread.start()
        return record.to_dict()

    def list_runs(self):
        with self._lock:
            payload = {item.run_id: item.to_dict() for item in self._runs.values()}
        for item in self._load_persisted_runs():
            payload.setdefault(item["run_id"], item)
        return sorted(payload.values(), key=lambda item: item.get("updated_at", ""), reverse=True)

    def get(self, run_id):
        with self._lock:
            record = self._runs.get(run_id)
            if record:
                return record.to_dict()
        return self._load_persisted_record(run_id)

    def cancel(self, run_id):
        with self._lock:
            event = self._cancel_events.get(run_id)
            record = self._runs.get(run_id)
            if not event or not record:
                return {"status": "missing", "run_id": run_id}
            event.set()
            record.cancel_requested = True
            record.updated_at = utc_now()
            self._persist_record(record)
        return {"status": "cancel_requested", "run_id": run_id}

    def set_status(self, run_id, status):
        self._set_status(run_id, status)
        return self.get(run_id)

    def set_result(self, run_id, result):
        self._set_result(run_id, result or {})
        return self.get(run_id)

    def set_error(self, run_id, error, trace_text=""):
        self._set_error(run_id, error, trace_text)
        return self.get(run_id)

    def resume(self, run_id, runner):
        with self._lock:
            record = self._runs.get(run_id)
            if record is None:
                persisted = self._load_persisted_record(run_id)
                if not persisted:
                    return {"status": "missing", "run_id": run_id}
                record = RunRecord(
                    run_id=str(persisted.get("run_id", run_id)),
                    created_at=str(persisted.get("created_at", utc_now())),
                    updated_at=str(persisted.get("updated_at", utc_now())),
                    status=str(persisted.get("status", "queued") or "queued"),
                    category=str(persisted.get("category", "web") or "web"),
                    workspace=str(persisted.get("workspace", "") or ""),
                    challenge_title=str(persisted.get("challenge_title", "") or ""),
                    request=dict(persisted.get("request") or {}),
                    result=dict(persisted.get("result") or {}),
                    error=str(persisted.get("error", "") or ""),
                    traceback_text=str(persisted.get("traceback_text", "") or ""),
                    cancel_requested=bool(persisted.get("cancel_requested", False)),
                )
                self._runs[run_id] = record
            existing = self._threads.get(run_id)
            if existing and existing.is_alive():
                return {"status": "running", "run_id": run_id}
            cancel_event = threading.Event()
            record.cancel_requested = False
            record.updated_at = utc_now()
            record.status = "queued"
            self._persist_record(record)

            def worker():
                self._set_status(run_id, "running")
                try:
                    result = runner(run_id, cancel_event)
                    if cancel_event.is_set():
                        self._set_status(run_id, "cancelled")
                    else:
                        self._set_result(run_id, result or {})
                        self._set_status(run_id, (result or {}).get("status", "completed"))
                except Exception as exc:
                    self._set_error(run_id, str(exc), traceback.format_exc())
                    self._set_status(run_id, "failed")

            thread = threading.Thread(target=worker, name="{0}-resume".format(run_id), daemon=True)
            self._threads[run_id] = thread
            self._cancel_events[run_id] = cancel_event
            snapshot = record.to_dict()
        self._persist_protocol_summary(snapshot)
        thread.start()
        return self.get(run_id)

    def get_cancel_event(self, run_id):
        with self._lock:
            return self._cancel_events.get(run_id)

    def read_artifact(self, run_id, relative_path, limit_bytes=200000):
        payload = self.get(run_id)
        if not payload:
            return {"status": "missing", "run_id": run_id}
        workspace = Path(payload.get("workspace")) if payload.get("workspace") else None
        if not workspace:
            return {"status": "missing_workspace", "run_id": run_id}

        artifact_path = (workspace / relative_path).resolve()
        if workspace.resolve() not in artifact_path.parents and artifact_path != workspace.resolve():
            return {"status": "forbidden", "run_id": run_id, "path": str(artifact_path)}
        if not artifact_path.exists():
            return {"status": "missing", "run_id": run_id, "path": str(artifact_path)}

        content = artifact_path.read_bytes()[:limit_bytes]
        try:
            text = content.decode("utf-8-sig", errors="replace")
        except Exception:
            text = ""
        return {
            "status": "ok",
            "run_id": run_id,
            "path": str(artifact_path),
            "text": text,
            "size": artifact_path.stat().st_size,
        }

    def _set_status(self, run_id, status):
        with self._lock:
            record = self._runs.get(run_id)
            if not record:
                return
            record.status = status
            record.updated_at = utc_now()
            self._persist_record(record)
            snapshot = record.to_dict()
        self._persist_protocol_summary(snapshot)

    def _set_result(self, run_id, result):
        with self._lock:
            record = self._runs.get(run_id)
            if not record:
                return
            record.result = dict(result or {})
            record.workspace = result.get("workspace", record.workspace)
            record.updated_at = utc_now()
            self._persist_record(record)
            snapshot = record.to_dict()
        self._persist_protocol_summary(snapshot)

    def _set_error(self, run_id, error, trace_text):
        with self._lock:
            record = self._runs.get(run_id)
            if not record:
                return
            record.error = error
            record.traceback_text = trace_text
            record.updated_at = utc_now()
            self._persist_record(record)
            snapshot = record.to_dict()
        self._persist_protocol_summary(snapshot)

    def _persist_record(self, record):
        if not self._storage_root:
            return
        target = self._storage_root / "_runs" / "{0}.json".format(record.run_id)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(record.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8-sig")

    def _load_persisted_runs(self):
        if not self._storage_root:
            return []
        runs_dir = self._storage_root / "_runs"
        if not runs_dir.exists():
            return []
        payload = []
        for item in sorted(runs_dir.glob("*.json")):
            try:
                payload.append(json.loads(item.read_text(encoding="utf-8-sig")))
            except Exception:
                continue
        return payload

    def _load_persisted_record(self, run_id):
        if not self._storage_root:
            return None
        path = self._storage_root / "_runs" / "{0}.json".format(run_id)
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8-sig"))
        except Exception:
            return None

    def _persist_protocol_summary(self, payload):
        if not payload or not payload.get("workspace"):
            return
        try:
            from ctf_agent.core.task_protocol import persist_run_status_summary

            persist_run_status_summary(payload)
        except Exception:
            return
