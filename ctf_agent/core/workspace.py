import json
import re
from pathlib import Path


class WorkspaceManager(object):
    def __init__(self, base_dir):
        self.base_dir = Path(base_dir)

    def prepare(self, challenge):
        contest_dir = self.base_dir / self._slugify(challenge.contest_id or "contest")
        challenge_dir = contest_dir / self._slugify(
            "{0}-{1}".format(challenge.challenge_id, challenge.title)
        )

        for path in [
            challenge_dir,
            challenge_dir / "attachments",
            challenge_dir / "artifacts",
            challenge_dir / "logs",
        ]:
            path.mkdir(parents=True, exist_ok=True)

        self.write_json(challenge_dir / "metadata.json", challenge.to_dict())
        self.write_text(
            challenge_dir / "target.txt",
            (challenge.target or "").strip() + "\n",
        )
        self.write_text(
            challenge_dir / "notes.md",
            self.default_notes(challenge),
        )
        return challenge_dir

    def default_notes(self, challenge):
        return (
            "# Challenge Notes\n\n"
            "## Metadata\n"
            "- Title: {0}\n"
            "- Category: {1}\n"
            "- Target: {2}\n\n"
            "## Recon\n"
            "- Pending\n\n"
            "## Hypotheses\n"
            "- Pending\n\n"
            "## Tried Actions\n"
            "- Pending\n\n"
            "## Findings\n"
            "- Pending\n\n"
            "## Candidate Flags\n"
            "- Pending\n\n"
            "## Final Exploit\n"
            "- Pending\n"
        ).format(challenge.title, challenge.category, challenge.target or "N/A")

    def write_json(self, path, payload):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8-sig") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)

    def write_text(self, path, content):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8-sig") as handle:
            handle.write(content)

    def append_jsonl(self, path, payload):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(payload, ensure_ascii=False)
        with path.open("a", encoding="utf-8-sig") as handle:
            handle.write(line + "\n")

    def save_state(self, workspace, state):
        self.write_json(Path(workspace) / "state.json", state.to_dict())

    def save_board(self, workspace, board):
        self.write_json(Path(workspace) / "triage_board.json", board)

    def write_action_log(self, workspace, state):
        path = Path(workspace) / "runs.jsonl"
        lines = []
        for item in state.tried_actions:
            lines.append(
                json.dumps(
                    {
                        "phase": item.phase,
                        "action": item.action,
                        "status": item.status,
                        "summary": item.summary,
                        "artifact": item.artifact,
                    },
                    ensure_ascii=False,
                )
            )
        self.write_text(path, "\n".join(lines) + ("\n" if lines else ""))

    def subagents_root(self, workspace):
        return Path(workspace) / "subagents"

    def subagent_dir(self, workspace, subagent_id):
        root = self.subagents_root(workspace) / self.slugify(subagent_id)
        root.mkdir(parents=True, exist_ok=True)
        (root / "artifacts").mkdir(parents=True, exist_ok=True)
        return root

    def subagent_artifacts_dir(self, workspace, subagent_id):
        path = self.subagent_dir(workspace, subagent_id) / "artifacts"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def save_subagent_transcript(self, workspace, subagent_id, messages):
        path = self.subagent_dir(workspace, subagent_id) / "transcript.jsonl"
        lines = []
        for item in list(messages or []):
            lines.append(json.dumps(item, ensure_ascii=False, default=str))
        self.write_text(path, "\n".join(lines) + ("\n" if lines else ""))
        return path

    def save_subagent_summary(self, workspace, subagent_id, payload):
        path = self.subagent_dir(workspace, subagent_id) / "summary.json"
        self.write_json(path, payload)
        return path

    def save_subagent_remote_status(self, workspace, subagent_id, payload):
        path = self.subagent_dir(workspace, subagent_id) / "remote_status.json"
        self.write_json(path, payload)
        return path

    def save_subagent_sync_manifest(self, workspace, subagent_id, payload):
        path = self.subagent_dir(workspace, subagent_id) / "sync_manifest.json"
        self.write_json(path, payload)
        return path

    def save_mcp_artifact(self, workspace, server_name, tool_name, payload, suffix="json"):
        safe_server = self.slugify(server_name or "server")
        safe_tool = self.slugify(tool_name or "tool")
        target = Path(workspace) / "artifacts" / "mcp" / "{0}-{1}.{2}".format(safe_server, safe_tool, suffix)
        if suffix.lower() == "txt":
            self.write_text(target, str(payload or ""))
        else:
            self.write_json(target, payload)
        return target

    def append_mcp_call_log(self, workspace, payload):
        path = Path(workspace) / "logs" / "mcp_call_log.jsonl"
        self.append_jsonl(path, payload)
        return path

    def save_mcp_status(self, workspace, payload):
        path = Path(workspace) / "mcp_status.json"
        self.write_json(path, payload)
        return path

    def save_approval_status(self, workspace, payload):
        path = Path(workspace) / "approval_status.json"
        self.write_json(path, payload)
        return path

    def save_plugin_status(self, workspace, payload):
        path = Path(workspace) / "plugin_status.json"
        self.write_json(path, payload)
        return path

    def load_mcp_status(self, workspace):
        return load_workspace_mcp_status(workspace)

    def load_recent_mcp_calls(self, workspace, limit=5):
        return load_recent_mcp_calls(workspace, limit=limit)

    def load_approval_status(self, workspace):
        return load_workspace_approval_status(workspace)

    def load_plugin_status(self, workspace):
        return load_workspace_plugin_status(workspace)

    @staticmethod
    def slugify(value):
        value = value or "item"
        value = re.sub(r"[^a-zA-Z0-9._-]+", "-", value.strip())
        value = value.strip("-")
        return value or "item"

    def _slugify(self, value):
        return self.slugify(value)


def read_json_if_exists(path):
    path = Path(path)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return {}


def read_jsonl_tail(path, limit=5):
    path = Path(path)
    if not path.exists():
        return []
    lines = []
    try:
        with path.open("r", encoding="utf-8-sig") as handle:
            for raw in handle:
                text = raw.strip()
                if not text:
                    continue
                try:
                    lines.append(json.loads(text))
                except Exception:
                    continue
    except Exception:
        return []
    if limit is None:
        return lines
    return lines[-max(0, int(limit or 0)) :]


def load_workspace_mcp_status(workspace):
    workspace = Path(workspace)
    payload = read_json_if_exists(workspace / "mcp_status.json")
    payload.setdefault("available_servers", [])
    payload.setdefault("connected_servers", [])
    payload.setdefault("resource_enabled_servers", [])
    payload.setdefault("failed_servers", [])
    payload.setdefault("fallback_reasons", [])
    payload.setdefault(
        "counts",
        {
            "pending": 0,
            "connected": 0,
            "failed": 0,
            "disabled": 0,
        },
    )
    payload.setdefault("servers", [])
    return payload


def load_workspace_approval_status(workspace):
    workspace = Path(workspace)
    payload = read_json_if_exists(workspace / "approval_status.json")
    payload.setdefault("enabled", False)
    payload.setdefault("counts", {})
    payload.setdefault("pending_requests", [])
    payload.setdefault("recent_requests", [])
    payload.setdefault("active_grants", [])
    return payload


def load_workspace_plugin_status(workspace):
    workspace = Path(workspace)
    payload = read_json_if_exists(workspace / "plugin_status.json")
    payload.setdefault("loaded", False)
    payload.setdefault("counts", {})
    payload.setdefault("plugins", [])
    payload.setdefault("tool_names", [])
    payload.setdefault("remote_template_names", [])
    payload.setdefault("knowledge_roots", [])
    return payload


def load_recent_mcp_calls(workspace, limit=5):
    workspace = Path(workspace)
    records = read_jsonl_tail(workspace / "logs" / "mcp_call_log.jsonl", limit=limit)
    normalized = []
    for item in records:
        normalized.append(
            {
                "ts": item.get("ts"),
                "ok": bool(item.get("ok")),
                "status": item.get("status", ""),
                "server": item.get("server", ""),
                "tool": item.get("tool", ""),
                "resource_uri": item.get("resource_uri", ""),
                "summary": item.get("summary", ""),
                "saved_to": item.get("saved_to", ""),
                "elapsed_ms": int(item.get("elapsed_ms", 0) or 0),
                "error": item.get("error", {}),
            }
        )
    return normalized
