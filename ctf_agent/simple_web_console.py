import cgi
import json
import shutil
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlparse

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ctf_agent.core.board import load_workspace_board, scan_workspace_history
from ctf_agent.core.intake import IntakeService
from ctf_agent.core.runtime import RUN_MANAGER, build_service, close_service, run_payload
from ctf_agent.core.task_template import build_task_template_payload

TEMPLATE_ROOT = Path(__file__).resolve().parent / "web_templates"


def _create_state(config_path=None, workspace_root=None):
    bootstrap = build_service(config_path=config_path, workspace_root=workspace_root)
    try:
        project_root = bootstrap["project_root"]
        workspace_dir = bootstrap["workspace_dir"]
        config = bootstrap["config"]
    finally:
        close_service(bootstrap)

    templates = Environment(
        loader=FileSystemLoader(str(TEMPLATE_ROOT)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    templates.filters["urlencode"] = lambda value: quote(str(value or ""))
    return {
        "project_root": project_root,
        "workspace_dir": workspace_dir,
        "config_path": str(Path(config_path).expanduser().absolute()) if config_path else None,
        "config": config,
        "templates": templates,
        "task_template": build_task_template_payload(),
    }


def _build_runtime(state, timeout=8.0, max_js_assets=8):
    return build_service(
        config_path=state["config_path"],
        workspace_root=state["workspace_dir"],
        timeout=timeout,
        max_js_assets=max_js_assets,
    )


def _build_history(state):
    active_runs = {item["run_id"]: item for item in RUN_MANAGER.list_runs() if item.get("run_id")}
    history = scan_workspace_history(state["workspace_dir"], active_runs=active_runs, limit=100)
    seen = {item.get("run_id") for item in history if item.get("run_id")}
    for item in RUN_MANAGER.list_runs():
        run_id = item.get("run_id")
        if run_id in seen:
            continue
        history.insert(
            0,
            {
                "run_id": run_id,
                "workspace": item.get("workspace", ""),
                "title": item.get("challenge_title", run_id),
                "category": item.get("category", ""),
                "target": item.get("request", {}).get("url", ""),
                "status": item.get("status", ""),
                "solver": item.get("result", {}).get("solver", ""),
                "updated_at": item.get("updated_at", ""),
                "board_path": "",
            },
        )
    return history[:100]


def _format_history_item(item):
    payload = dict(item)
    updated_at = payload.get("updated_at")
    if isinstance(updated_at, (int, float)):
        payload["updated_at_display"] = datetime.fromtimestamp(updated_at).strftime("%Y-%m-%d %H:%M:%S")
    else:
        payload["updated_at_display"] = str(updated_at or "")
    return payload


def _normalize_payload(state, raw_payload):
    runtime = _build_runtime(
        state,
        timeout=float(raw_payload.get("timeout", 8.0) or 8.0),
        max_js_assets=int(raw_payload.get("max_js_assets", 8) or 8),
    )
    try:
        intake = IntakeService(runtime["config"], runtime["workspace_dir"])
        if raw_payload.get("task"):
            return intake.normalize_brief(raw_payload)
        return intake.normalize(raw_payload)
    finally:
        close_service(runtime)


def _parse_form_payload(handler, state):
    content_type = handler.headers.get("Content-Type", "")
    form = cgi.FieldStorage(
        fp=handler.rfile,
        headers=handler.headers,
        environ={
            "REQUEST_METHOD": "POST",
            "CONTENT_TYPE": content_type,
            "CONTENT_LENGTH": handler.headers.get("Content-Length", "0"),
        },
        keep_blank_values=True,
    )

    def first_value(name, default=""):
        value = form.getvalue(name)
        if isinstance(value, list):
            return str(value[0] or default)
        return str(value or default)

    payload = {
        "category": first_value("category", "web"),
        "task": first_value("task", "").strip(),
        "target": first_value("target", "").strip(),
        "title": first_value("title", "").strip(),
        "description": first_value("description", "").strip(),
        "hint": first_value("hint", "").strip(),
        "flag_format": first_value("flag_format", "").strip(),
        "workspace_root": str(state["workspace_dir"]),
        "config_path": state["config_path"],
        "max_rounds": first_value("max_rounds", "") or None,
        "use_remote_host": first_value("use_remote_host", "").strip(),
        "timeout": 8.0,
        "max_js_assets": 8,
    }
    browser_choice = first_value("use_browser_mcp", "").strip().lower()
    if browser_choice in {"true", "1", "on", "yes"}:
        payload["use_browser_mcp"] = True
    elif browser_choice in {"false", "0", "off", "no"}:
        payload["use_browser_mcp"] = False

    runtime = _build_runtime(state)
    try:
        intake = IntakeService(runtime["config"], runtime["workspace_dir"])
        upload_dir = intake.create_incoming_dir(prefix=payload["category"] or "web")
        saved = []
        attachments_field = form["attachments"] if "attachments" in form else []
        if not isinstance(attachments_field, list):
            attachments_field = [attachments_field]
        for item in attachments_field:
            if not getattr(item, "filename", ""):
                continue
            destination = upload_dir / Path(item.filename).name
            with destination.open("wb") as handle:
                shutil.copyfileobj(item.file, handle)
            saved.append(str(destination))
        payload["attachments"] = saved
        return payload
    finally:
        close_service(runtime)


def _collect_payload(handler, state):
    content_type = (handler.headers.get("Content-Type") or "").lower()
    if "application/json" in content_type:
        length = int(handler.headers.get("Content-Length", "0") or "0")
        body = handler.rfile.read(length) if length else b"{}"
        payload = json.loads(body.decode("utf-8-sig"))
        payload.setdefault("workspace_root", str(state["workspace_dir"]))
        return payload
    return _parse_form_payload(handler, state)


def serve_simple_console(host="127.0.0.1", port=8765, config_path=None, workspace_root=None):
    state = _create_state(config_path=config_path, workspace_root=workspace_root)

    class Handler(BaseHTTPRequestHandler):
        server_version = "CTFAgentFallback/0.1"

        def log_message(self, format, *args):
            return

        def _send_json(self, payload, status=200):
            body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _send_html(self, html, status=200):
            body = html.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _not_found(self, detail="not found"):
            self._send_json({"detail": detail}, status=404)

        def _render(self, template_name, context):
            template = state["templates"].get_template(template_name)
            return template.render(**context)

        def do_GET(self):
            parsed = urlparse(self.path)
            parts = [item for item in parsed.path.split("/") if item]

            if parsed.path == "/":
                html = self._render(
                    "index.html",
                    {
                        "recent_runs": [_format_history_item(item) for item in _build_history(state)],
                        "remote_hosts": sorted(state["config"].remote_hosts.keys()),
                        "workspace_root": str(state["workspace_dir"]),
                        "task_template": state["task_template"]["markdown"],
                    },
                )
                return self._send_html(html)

            if len(parts) == 2 and parts[0] == "runs":
                run_id = parts[1]
                record = RUN_MANAGER.get(run_id)
                if not record:
                    return self._not_found("run not found")
                workspace = record.get("workspace")
                if not workspace:
                    return self._not_found("workspace not ready")
                board = load_workspace_board(Path(workspace), run_meta=record)
                html = self._render(
                    "run.html",
                    {
                        "run": record,
                        "board": board,
                        "artifacts": board.get("artifacts", {}).get("items", []),
                    },
                )
                return self._send_html(html)

            if parsed.path == "/api/runs":
                return self._send_json(
                    {
                        "items": [_format_history_item(item) for item in _build_history(state)],
                        "workspace_root": str(state["workspace_dir"]),
                    }
                )

            if parsed.path == "/api/task-template":
                return self._send_json(state["task_template"])

            if len(parts) == 3 and parts[0] == "api" and parts[1] == "runs":
                run_id = parts[2]
                payload = RUN_MANAGER.get(run_id)
                if not payload:
                    return self._not_found("run not found")
                return self._send_json(payload)

            if len(parts) == 4 and parts[0] == "api" and parts[1] == "runs" and parts[3] == "board":
                run_id = parts[2]
                payload = RUN_MANAGER.get(run_id)
                if not payload:
                    return self._not_found("run not found")
                workspace = payload.get("workspace")
                if not workspace:
                    return self._not_found("workspace not ready")
                return self._send_json(load_workspace_board(Path(workspace), run_meta=payload))

            if len(parts) == 4 and parts[0] == "api" and parts[1] == "runs" and parts[3] == "artifact":
                run_id = parts[2]
                query = parse_qs(parsed.query)
                relative_path = (query.get("path") or [""])[0]
                limit_bytes = int((query.get("limit_bytes") or ["200000"])[0])
                payload = RUN_MANAGER.read_artifact(run_id, relative_path, limit_bytes=limit_bytes)
                status = payload.get("status")
                if status != "ok":
                    return self._send_json(payload, status=404 if status.startswith("missing") else 403)
                return self._send_json(payload)

            return self._not_found()

        def do_POST(self):
            parsed = urlparse(self.path)
            parts = [item for item in parsed.path.split("/") if item]

            if parsed.path == "/api/intake":
                raw_payload = _collect_payload(self, state)
                resolved = _normalize_payload(state, raw_payload)
                category = (resolved.get("category") or "web").strip().lower()

                def runner(run_id, cancel_event):
                    runtime = _build_runtime(
                        state,
                        timeout=float(resolved.get("timeout", 8.0)),
                        max_js_assets=int(resolved.get("max_js_assets", 8)),
                    )
                    try:
                        return run_payload(runtime, resolved, run_id=run_id, cancel_event=cancel_event, source="web-fallback")
                    finally:
                        close_service(runtime)

                run = RUN_MANAGER.start(category, dict(resolved), runner)
                return self._send_json(
                    {
                        "ok": True,
                        "resolved": resolved,
                        "run": run,
                        "redirect_url": "/runs/{0}".format(run["run_id"]),
                    }
                )

            if len(parts) == 4 and parts[0] == "api" and parts[1] == "runs" and parts[3] == "cancel":
                return self._send_json(RUN_MANAGER.cancel(parts[2]))

            return self._not_found()

    httpd = ThreadingHTTPServer((host, int(port)), Handler)
    print(
        "CTF Agent fallback web console listening on http://{0}:{1} using workspace_root={2}".format(
            host, port, state["workspace_dir"]
        )
    )
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()
