from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from ctf_agent.core.board import load_workspace_board, scan_workspace_history
from ctf_agent.core.intake import IntakeService
from ctf_agent.core.runtime import RUN_MANAGER, build_service, close_service, run_payload
from ctf_agent.core.task_template import build_task_template_payload

TEMPLATE_ROOT = Path(__file__).resolve().parent / "web_templates"


def create_app(config_path=None, workspace_root=None):
    bootstrap = build_service(config_path=config_path, workspace_root=workspace_root)
    try:
        project_root = bootstrap["project_root"]
        workspace_dir = bootstrap["workspace_dir"]
        config = bootstrap["config"]
    finally:
        close_service(bootstrap)

    app = FastAPI(title="CTF Agent Console")
    templates = Jinja2Templates(directory=str(TEMPLATE_ROOT))

    app.state.project_root = project_root
    app.state.workspace_dir = workspace_dir
    app.state.config_path = str(Path(config_path).resolve()) if config_path else None
    app.state.config = config
    app.state.templates = templates
    app.state.task_template = build_task_template_payload()

    def build_runtime(timeout=8.0, max_js_assets=8):
        return build_service(
            config_path=app.state.config_path,
            workspace_root=app.state.workspace_dir,
            timeout=timeout,
            max_js_assets=max_js_assets,
        )

    def build_history():
        active_runs = {item["run_id"]: item for item in RUN_MANAGER.list_runs() if item.get("run_id")}
        history = scan_workspace_history(app.state.workspace_dir, active_runs=active_runs, limit=100)
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

    def format_history_item(item):
        payload = dict(item)
        updated_at = payload.get("updated_at")
        if isinstance(updated_at, (int, float)):
            payload["updated_at_display"] = datetime.fromtimestamp(updated_at).strftime("%Y-%m-%d %H:%M:%S")
        else:
            payload["updated_at_display"] = str(updated_at or "")
        return payload

    def normalize_payload(raw_payload):
        runtime = build_runtime(
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

    async def collect_payload(request: Request):
        content_type = (request.headers.get("content-type") or "").lower()
        if "application/json" in content_type:
            payload = dict(await request.json())
            payload.setdefault("workspace_root", str(app.state.workspace_dir))
            return payload

        form = await request.form()
        payload = {
            "category": str(form.get("category") or "web"),
            "task": str(form.get("task") or "").strip(),
            "target": str(form.get("target") or "").strip(),
            "title": str(form.get("title") or "").strip(),
            "description": str(form.get("description") or "").strip(),
            "hint": str(form.get("hint") or "").strip(),
            "flag_format": str(form.get("flag_format") or "").strip(),
            "workspace_root": str(app.state.workspace_dir),
            "config_path": app.state.config_path,
            "max_rounds": form.get("max_rounds") or None,
            "use_remote_host": str(form.get("use_remote_host") or "").strip(),
            "timeout": 8.0,
            "max_js_assets": 8,
        }
        browser_choice = str(form.get("use_browser_mcp") or "").strip().lower()
        if browser_choice in {"true", "1", "on", "yes"}:
            payload["use_browser_mcp"] = True
        elif browser_choice in {"false", "0", "off", "no"}:
            payload["use_browser_mcp"] = False

        runtime = build_runtime()
        try:
            intake = IntakeService(runtime["config"], runtime["workspace_dir"])
            upload_dir = intake.create_incoming_dir(prefix=payload["category"])
            saved = []
            for item in form.getlist("attachments"):
                if not getattr(item, "filename", ""):
                    continue
                destination = upload_dir / Path(item.filename).name
                with destination.open("wb") as handle:
                    handle.write(await item.read())
                saved.append(str(destination))
            payload["attachments"] = saved
            return payload
        finally:
            close_service(runtime)

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        context = {
            "request": request,
            "recent_runs": [format_history_item(item) for item in build_history()],
            "remote_hosts": sorted(app.state.config.remote_hosts.keys()),
            "workspace_root": str(app.state.workspace_dir),
            "task_template": app.state.task_template["markdown"],
        }
        return templates.TemplateResponse("index.html", context)

    @app.get("/runs/{run_id}", response_class=HTMLResponse)
    async def run_board_page(request: Request, run_id: str):
        record = RUN_MANAGER.get(run_id)
        if not record:
            raise HTTPException(status_code=404, detail="run not found")
        workspace = record.get("workspace")
        if not workspace:
            raise HTTPException(status_code=404, detail="workspace not ready")
        board = load_workspace_board(Path(workspace), run_meta=record)
        context = {
            "request": request,
            "run": record,
            "board": board,
            "artifacts": board.get("artifacts", {}).get("items", []),
        }
        return templates.TemplateResponse("run.html", context)

    @app.post("/api/intake")
    async def intake_api(request: Request):
        raw_payload = await collect_payload(request)
        resolved = normalize_payload(raw_payload)
        category = (resolved.get("category") or "web").strip().lower()

        def runner(run_id, cancel_event):
            runtime = build_runtime(
                timeout=float(resolved.get("timeout", 8.0)),
                max_js_assets=int(resolved.get("max_js_assets", 8)),
            )
            try:
                return run_payload(runtime, resolved, run_id=run_id, cancel_event=cancel_event, source="web")
            finally:
                close_service(runtime)

        run = RUN_MANAGER.start(category, dict(resolved), runner)
        return JSONResponse(
            {
                "ok": True,
                "resolved": resolved,
                "run": run,
                "redirect_url": "/runs/{0}".format(run["run_id"]),
            }
        )

    @app.get("/api/runs")
    async def runs_api():
        return JSONResponse(
            {
                "items": [format_history_item(item) for item in build_history()],
                "workspace_root": str(app.state.workspace_dir),
            }
        )

    @app.get("/api/task-template")
    async def task_template_api():
        return JSONResponse(app.state.task_template)

    @app.get("/api/runs/{run_id}")
    async def run_api(run_id: str):
        payload = RUN_MANAGER.get(run_id)
        if not payload:
            raise HTTPException(status_code=404, detail="run not found")
        return JSONResponse(payload)

    @app.get("/api/runs/{run_id}/board")
    async def board_api(run_id: str):
        payload = RUN_MANAGER.get(run_id)
        if not payload:
            raise HTTPException(status_code=404, detail="run not found")
        workspace = payload.get("workspace")
        if not workspace:
            raise HTTPException(status_code=404, detail="workspace not ready")
        return JSONResponse(load_workspace_board(Path(workspace), run_meta=payload))

    @app.get("/api/runs/{run_id}/artifact")
    async def artifact_api(run_id: str, path: str, limit_bytes: int = 200000):
        payload = RUN_MANAGER.read_artifact(run_id, path, limit_bytes=limit_bytes)
        status = payload.get("status")
        if status not in {"ok", "missing", "missing_workspace", "forbidden"}:
            return JSONResponse(payload)
        if status != "ok":
            raise HTTPException(status_code=404 if status.startswith("missing") else 403, detail=status)
        return JSONResponse(payload)

    @app.post("/api/runs/{run_id}/cancel")
    async def cancel_api(run_id: str):
        return JSONResponse(RUN_MANAGER.cancel(run_id))

    return app
