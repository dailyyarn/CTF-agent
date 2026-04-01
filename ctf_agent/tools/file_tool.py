import json
from pathlib import Path


class FileTool(object):
    def __init__(self, policy=None, workspace=None):
        self.policy = policy
        self.workspace = str(workspace) if workspace else ""

    def configure_policy(self, policy=None, workspace=None):
        if policy is not None:
            self.policy = policy
        if workspace is not None:
            self.workspace = str(workspace)
        return self

    def _resolve_path(self, path):
        value = Path(path)
        if not value.is_absolute() and self.workspace:
            value = Path(self.workspace) / value
        try:
            return value.resolve()
        except Exception:
            return value.absolute()

    def exists(self, path):
        return self._resolve_path(path).exists()

    def read_text(self, path, limit_bytes=None, limit=None):
        path = self._resolve_path(path)
        requested = limit if limit is not None else limit_bytes
        if self.policy:
            requested = self.policy.validate_file_read(path, requested)
        with path.open("rb") as handle:
            content = handle.read(requested) if requested else handle.read()
        return content.decode("utf-8-sig", errors="replace")

    def read_bytes(self, path, limit_bytes=None, limit=None):
        path = self._resolve_path(path)
        requested = limit if limit is not None else limit_bytes
        if self.policy:
            requested = self.policy.validate_file_read(path, requested)
        with path.open("rb") as handle:
            return handle.read(requested) if requested else handle.read()

    def _evaluate_write(self, path, pending_action=None):
        path = self._resolve_path(path)
        if not self.policy:
            return path, {"status": "ok", "path": str(path)}
        decision = self.policy.evaluate_file_write(path, pending_action=pending_action)
        if getattr(decision, "decision", "") == "deny":
            return path, {
                "status": "blocked",
                "path": str(path),
                "message": getattr(decision, "reason", "file write blocked"),
                "error": decision.to_dict() if hasattr(decision, "to_dict") else {"reason": getattr(decision, "reason", "")},
            }
        if getattr(decision, "decision", "") == "ask":
            return path, {
                "status": "needs_approval",
                "path": str(path),
                "message": getattr(decision, "reason", "approval required for file write"),
                "request_id": getattr(decision, "request_id", ""),
                "approval": decision.to_dict() if hasattr(decision, "to_dict") else {},
                "error": decision.to_dict() if hasattr(decision, "to_dict") else {"reason": getattr(decision, "reason", "")},
            }
        return path, {"status": "ok", "path": str(path)}

    def write_text_safe(self, path, content, pending_action=None):
        path, gate = self._evaluate_write(path, pending_action=pending_action)
        if gate.get("status") != "ok":
            return gate
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8-sig") as handle:
            handle.write(content)
        return {"status": "ok", "path": str(path), "bytes_written": len(str(content or "").encode("utf-8"))}

    def write_json_safe(self, path, payload, pending_action=None):
        path, gate = self._evaluate_write(path, pending_action=pending_action)
        if gate.get("status") != "ok":
            return gate
        serialized = json.dumps(payload, ensure_ascii=False, indent=2)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8-sig") as handle:
            handle.write(serialized)
        return {"status": "ok", "path": str(path), "bytes_written": len(serialized.encode("utf-8"))}

    def write_bytes_safe(self, path, payload, pending_action=None):
        path, gate = self._evaluate_write(path, pending_action=pending_action)
        if gate.get("status") != "ok":
            return gate
        raw = bytes(payload or b"")
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("wb") as handle:
            handle.write(raw)
        return {"status": "ok", "path": str(path), "bytes_written": len(raw)}

    def write_text(self, path, content):
        result = self.write_text_safe(path, content)
        if result.get("status") == "blocked":
            raise PermissionError(result.get("message", "file write blocked"))
        if result.get("status") == "needs_approval":
            raise PermissionError("approval required for file write: {0}".format(result.get("request_id", "")))

    def write_json(self, path, payload):
        result = self.write_json_safe(path, payload)
        if result.get("status") == "blocked":
            raise PermissionError(result.get("message", "file write blocked"))
        if result.get("status") == "needs_approval":
            raise PermissionError("approval required for file write: {0}".format(result.get("request_id", "")))

    def write_bytes(self, path, payload):
        result = self.write_bytes_safe(path, payload)
        if result.get("status") == "blocked":
            raise PermissionError(result.get("message", "file write blocked"))
        if result.get("status") == "needs_approval":
            raise PermissionError("approval required for file write: {0}".format(result.get("request_id", "")))

    def read_json(self, path):
        path = self._resolve_path(path)
        if self.policy:
            self.policy.validate_file_read(path)
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
