import json
import shutil
import tarfile
import threading
import time
import traceback
from pathlib import Path


TERMINAL_STATUSES = {"completed", "failed", "timed_out", "budget_exhausted", "cancelled"}


def _write_json(path, payload):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8-sig")


def _write_text(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(content or ""), encoding="utf-8-sig")


def _read_json(path):
    path = Path(path)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return {}


def _status_from_reason(loop, reason):
    if hasattr(loop, "_subagent_status_from_reason"):
        return loop._subagent_status_from_reason(reason)
    if reason in {"max_steps", "max_tool_calls", "max_tokens"}:
        return "budget_exhausted"
    if reason == "timeout":
        return "timed_out"
    if reason == "error":
        return "failed"
    return "completed"


def _build_policy(payload, workspace_root):
    from ctf_agent.core.execution_policy import ExecutionPolicy

    payload = dict(payload or {})
    return ExecutionPolicy(
        allowed_roots=[str(item) for item in list(payload.get("allowed_roots", []) or [])] + [str(workspace_root)],
        denied_roots=[str(item) for item in list(payload.get("denied_roots", []) or [])],
        max_file_read_bytes=int(payload.get("max_file_read_bytes", 1024 * 1024) or 1024 * 1024),
        max_shell_timeout_sec=int(payload.get("max_shell_timeout_sec", 20) or 20),
        allow_workspace_writes_only=True,
        allow_remote=False,
        allowed_remote_hosts=[],
        allow_public_web_targets_only=bool(payload.get("allow_public_web_targets_only", True)),
        allow_background_remote=False,
        allow_mcp_servers=[],
        workspace_root=str(workspace_root),
        mode="subagent",
        approval_policy={"enabled": False},
        approval_manager=None,
        run_id=str(payload.get("run_id", "") or ""),
    )


def _build_plugin_registry(bundle_root):
    from ctf_agent.core.plugin_registry import PluginRegistry

    plugin_root = Path(bundle_root) / "plugins_snapshot"
    if not plugin_root.exists():
        return None
    registry = PluginRegistry(bundled_root=None, plugin_roots=[plugin_root])
    registry.discover()
    return registry


def _build_knowledge_retriever(bundle_root, plugin_registry=None):
    from ctf_agent.core.knowledge_retriever import KnowledgeRetriever

    embedded_root = Path(bundle_root) / "ctf_agent" / "knowledge" / "embedded_ctf_skills"
    skill_roots = [str(embedded_root)] if embedded_root.exists() else []
    if plugin_registry:
        skill_roots = plugin_registry.merged_knowledge_roots(skill_roots)
    retriever = KnowledgeRetriever(skills_root=skill_roots, wiki_root=None)
    retriever.load()
    return retriever if retriever.is_loaded() else None


def _build_llm_client(payload):
    from ctf_agent.core.llm import LLMClient

    payload = dict(payload or {})
    client = LLMClient(
        api_key=payload.get("api_key"),
        base_url=payload.get("base_url"),
        model=payload.get("model"),
        temperature=payload.get("temperature"),
        max_tokens=payload.get("max_tokens"),
        timeout=payload.get("timeout"),
    )
    return client if client.is_configured() else None


def _map_allowed_tools(requested, available):
    mapping = {
        "run_remote_command": "shell",
        "run_remote_python": "run_python",
        "http_request": "http_request",
        "scan_for_flags": "scan_for_flags",
        "search_knowledge": "search_knowledge",
        "read_file": "read_file",
        "run_python": "run_python",
        "shell": "shell",
    }
    allowed = []
    available = set(available or [])
    for item in list(requested or []):
        resolved = mapping.get(str(item or "").strip(), str(item or "").strip())
        if resolved in available and resolved not in allowed:
            allowed.append(resolved)
    return allowed


def _copy_tree(src_root, dst_root):
    src_root = Path(src_root)
    dst_root = Path(dst_root)
    if not src_root.exists():
        return []
    copied = []
    for item in sorted(path for path in src_root.rglob("*") if path.is_file()):
        relative = item.relative_to(src_root)
        target = dst_root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(str(item), str(target))
        copied.append(str(target))
    return copied


def _heartbeat_writer(output_dir, shared_state, poll_interval_sec):
    output_dir = Path(output_dir)
    while not shared_state.get("done"):
        payload = {
            "status": str(shared_state.get("status", "running") or "running"),
            "phase": str(shared_state.get("phase", "heartbeat") or "heartbeat"),
            "updated_at": time.time(),
            "workspace": str(shared_state.get("workspace", "") or ""),
            "job_id": str(shared_state.get("job_id", "") or ""),
            "stop_reason": str(shared_state.get("stop_reason", "") or ""),
            "usage": dict(shared_state.get("usage") or {}),
        }
        _write_json(output_dir / "heartbeat.json", payload)
        _write_json(
            output_dir / "state.json",
            {
                "status": payload["status"],
                "updated_at": payload["updated_at"],
                "workspace": payload["workspace"],
                "job_id": payload["job_id"],
                "stop_reason": payload["stop_reason"],
                "usage": payload["usage"],
            },
        )
        time.sleep(max(1.0, float(poll_interval_sec or 2)))


def execute_remote_subagent(workspace_root):
    from ctf_agent.core.agent_loop import AgentLoop, SYSTEM_PROMPT
    from ctf_agent.core.code_executor import CodeExecutor
    from ctf_agent.core.memory import StateMemory
    from ctf_agent.core.models import Challenge, ChallengeState, SubAgentSpec
    from ctf_agent.core.workspace import WorkspaceManager
    from ctf_agent.tools.file_tool import FileTool
    from ctf_agent.tools.http_tool import HttpTool
    from ctf_agent.tools.shell_tool import ShellTool

    workspace_root = Path(workspace_root).resolve()
    input_dir = workspace_root / "input"
    output_dir = workspace_root / "output"
    output_artifacts = output_dir / "artifacts"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_artifacts.mkdir(parents=True, exist_ok=True)

    spec = SubAgentSpec.from_dict(_read_json(input_dir / "spec.json"))
    challenge_payload = dict(_read_json(input_dir / "challenge.json") or {})
    llm_payload = dict(_read_json(input_dir / "llm.json") or {})
    policy_payload = dict(_read_json(input_dir / "policy.json") or {})
    bundle_root = workspace_root / "bundle"
    attachment_paths = [Path(item) for item in list(challenge_payload.get("attachments", []) or [])]
    challenge = Challenge(
        contest_id=str(challenge_payload.get("contest_id", "") or ""),
        challenge_id=str(challenge_payload.get("challenge_id", "") or ""),
        title=str(challenge_payload.get("title", "") or ""),
        category=str(challenge_payload.get("category", "") or ""),
        description=str(challenge_payload.get("description", "") or ""),
        attachments=attachment_paths,
        target=challenge_payload.get("target"),
        flag_format=challenge_payload.get("flag_format"),
        metadata=dict(challenge_payload.get("metadata") or {}),
    )
    challenge.metadata.setdefault("skill_resolution", {})

    policy = _build_policy(policy_payload, workspace_root)
    plugin_registry = _build_plugin_registry(bundle_root)
    knowledge = _build_knowledge_retriever(bundle_root, plugin_registry=plugin_registry)
    llm = _build_llm_client(llm_payload)
    if llm is None:
        error_payload = {
            "id": spec.id,
            "status": "failed",
            "stop_reason": "error",
            "usage": {"steps": 0, "tool_calls": 0, "tokens_used": 0, "elapsed_ms": 0},
            "summary": {
                "what_was_tried": spec.prompt[:300],
                "what_was_found": "",
                "what_to_do_next": "remote runner is missing LLM credentials",
                "summary_text": "remote runner is missing LLM credentials",
            },
            "artifact_paths": [],
        }
        _write_json(output_dir / "summary.json", error_payload)
        _write_json(output_dir / "state.json", {"status": "failed", "updated_at": time.time(), "workspace": str(workspace_root)})
        _write_json(output_dir / "heartbeat.json", {"status": "failed", "updated_at": time.time(), "workspace": str(workspace_root)})
        return error_payload

    file_tool = FileTool().configure_policy(policy, workspace=str(workspace_root))
    shell_tool = ShellTool().configure_policy(policy, workspace=str(workspace_root))
    http_tool = HttpTool(timeout=min(20.0, max(6.0, float(spec.timeout_sec or 90))))
    code_executor = CodeExecutor(python_bin=llm_payload.get("python_bin"), default_timeout=min(int(spec.timeout_sec or 90), 45), policy=policy)
    loop = AgentLoop(
        llm=llm,
        file_tool=file_tool,
        shell_tool=shell_tool,
        http_tool=http_tool,
        code_executor=code_executor,
        knowledge_retriever=knowledge,
        workspace_manager=WorkspaceManager(workspace_root),
        execution_policy=policy,
        allow_subagents=False,
        is_subagent=True,
        plugin_registry=plugin_registry,
        approval_manager=None,
        max_steps=max(1, int(spec.max_steps or 1)),
        max_tokens_budget=max(1, int(spec.max_tokens or 1)),
    )
    loop._configure_runtime(challenge, workspace_root, background=False)
    active_tools = loop._select_active_tools(challenge, "standard", {})
    requested_tools = _map_allowed_tools(spec.allowed_tools, active_tools.names)
    active_tools = active_tools.only_names(requested_tools or active_tools.names).without_names(
        ["plan_parallel", "run_remote_command", "run_remote_python", "browse_url", "decompile_function", "local_tool"]
    )
    loop._active_tools = active_tools
    knowledge_ctx = loop._retrieve_initial_knowledge(challenge, speed_mode="standard", speed_profile={})
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT.format(tool_list=active_tools.describe(), knowledge=knowledge_ctx)},
        {
            "role": "user",
            "content": loop._format_challenge(challenge, workspace_root)
            + "\n\n## Remote Subagent Mission\nPurpose: {0}\nPrompt: {1}\nExecution host: local-remote-runner".format(
                spec.purpose,
                spec.prompt,
            ),
        },
    ]

    state = ChallengeState(phase="subagent")
    memory = StateMemory(state)
    memory.record_action("subagent", "init", "ok", spec.purpose[:200])
    shared_state = {
        "status": "running",
        "phase": "running",
        "workspace": str(workspace_root),
        "usage": {"steps": 0, "tool_calls": 0, "tokens_used": 0, "elapsed_ms": 0},
        "done": False,
    }
    heartbeat = threading.Thread(
        target=_heartbeat_writer,
        args=(output_dir, shared_state, int(spec.poll_interval_sec or 2)),
        daemon=True,
    )
    heartbeat.start()
    started_at = time.time()
    try:
        state = loop._run_loop(
            challenge,
            workspace_root,
            state,
            memory,
            messages,
            start_step=0,
            active_tools=active_tools,
            speed_mode="standard",
            speed_profile={"tool_call_budget": int(spec.max_tool_calls or 0)},
            runtime_limits={
                "max_steps": int(spec.max_steps or 0),
                "max_tool_calls": int(spec.max_tool_calls or 0),
                "max_tokens": int(spec.max_tokens or 0),
                "timeout_sec": int(spec.timeout_sec or 0),
                "token_baseline": loop._current_total_tokens(),
            },
        )
        loop._write_notes(workspace_root, state, challenge=challenge, speed_mode="standard")
        loop._write_board(challenge, workspace_root, state, speed_mode="standard")
        transcript_path = output_dir / "transcript.jsonl"
        _write_text(transcript_path, "\n".join(json.dumps(item, ensure_ascii=False, default=str) for item in messages) + "\n")
        summary = loop._build_subagent_summary(state)
        usage = dict(getattr(loop, "_last_runtime_usage", {}) or {})
        stop_reason = str(getattr(loop, "_last_stop_reason", "completed") or "completed")
        status = _status_from_reason(loop, stop_reason)
        _copy_tree(workspace_root / "artifacts", output_artifacts)
        tar_path = output_dir / "artifacts.tar.gz"
        with tarfile.open(tar_path, "w:gz") as handle:
            if output_artifacts.exists():
                for item in sorted(path for path in output_artifacts.rglob("*") if path.is_file()):
                    handle.add(str(item), arcname=str(item.relative_to(output_artifacts)))
        artifact_paths = [str(path) for path in sorted(path for path in output_artifacts.rglob("*") if path.is_file())]
        artifact_paths.extend([str(transcript_path), str(tar_path)])
        summary_payload = {
            "id": spec.id,
            "status": status,
            "stop_reason": stop_reason,
            "usage": usage,
            "summary": summary,
            "artifact_paths": artifact_paths,
            "remote_status": {
                "status": status,
                "remote_workspace": str(workspace_root),
            },
        }
        _write_json(output_dir / "summary.json", summary_payload)
        shared_state["status"] = status
        shared_state["phase"] = status
        shared_state["stop_reason"] = stop_reason
        shared_state["usage"] = usage
        return summary_payload
    except Exception as exc:
        failure = {
            "id": spec.id,
            "status": "failed",
            "stop_reason": "error",
            "usage": {
                "steps": 0,
                "tool_calls": 0,
                "tokens_used": 0,
                "elapsed_ms": int((time.time() - started_at) * 1000),
            },
            "summary": {
                "what_was_tried": spec.prompt[:300],
                "what_was_found": "",
                "what_to_do_next": str(exc),
                "summary_text": str(exc),
            },
            "artifact_paths": [],
            "error": traceback.format_exc(),
        }
        _write_json(output_dir / "summary.json", failure)
        shared_state["status"] = "failed"
        shared_state["phase"] = "failed"
        shared_state["stop_reason"] = "error"
        return failure
    finally:
        shared_state["done"] = True
        _write_json(
            output_dir / "state.json",
            {
                "status": str(shared_state.get("status", "failed") or "failed"),
                "updated_at": time.time(),
                "workspace": str(workspace_root),
                "stop_reason": str(shared_state.get("stop_reason", "") or ""),
                "usage": dict(shared_state.get("usage") or {}),
            },
        )
        _write_json(
            output_dir / "heartbeat.json",
            {
                "status": str(shared_state.get("status", "failed") or "failed"),
                "phase": str(shared_state.get("phase", "failed") or "failed"),
                "updated_at": time.time(),
                "workspace": str(workspace_root),
                "stop_reason": str(shared_state.get("stop_reason", "") or ""),
                "usage": dict(shared_state.get("usage") or {}),
            },
        )

