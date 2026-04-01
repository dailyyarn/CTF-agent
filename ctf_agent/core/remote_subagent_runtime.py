import json
import shutil
import tarfile
import time
from pathlib import Path

from ctf_agent.core.models import SubAgentRecord
from ctf_agent.core.remote_subagent_runner import TERMINAL_STATUSES


def _read_json(path):
    path = Path(path)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return {}


def _quote(value):
    return '"{0}"'.format(str(value).replace('"', '\\"'))


def _parse_runner_payload(result):
    payload = dict(result or {})
    stdout = str(payload.get("stdout", "") or "")
    for line in reversed(stdout.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except Exception:
            continue
        if isinstance(parsed, dict):
            return parsed
    parsed_payload = payload.get("payload")
    return dict(parsed_payload or {}) if isinstance(parsed_payload, dict) else {}


def _approval_result(loop, workspace, spec, payload):
    approval_payload = dict(payload or {})
    request_id = str(
        approval_payload.get("request_id", "")
        or dict(approval_payload.get("approval") or {}).get("request_id", "")
        or ""
    )
    loop.workspace_manager.save_subagent_remote_status(
        workspace,
        spec.id,
        {
            "status": "queued",
            "message": str(approval_payload.get("message", "approval required") or "approval required"),
            "request_id": request_id,
            "subagent_spec": spec.to_dict(),
            "remote_host": str(spec.remote_host or ""),
            "remote_workspace": "",
            "execution_mode": "remote",
        },
    )
    return None, {
        "tool": "subagent:{0}".format(spec.id),
        "purpose": spec.purpose,
        "status": "needs_approval",
        "request_id": request_id,
        "approval": dict(approval_payload.get("approval") or {}),
        "subagent_spec": spec.to_dict(),
        "summary": {
            "what_was_tried": spec.prompt[:300],
            "what_was_found": "",
            "what_to_do_next": str(approval_payload.get("message", "approve the remote subagent request") or ""),
            "summary_text": str(approval_payload.get("message", "approval required") or "approval required"),
        },
        "artifact_paths": [],
        "result": "[status=needs_approval] {0}".format(
            str(approval_payload.get("message", "approval required") or "approval required")
        ),
        "elapsed_ms": 0,
    }


def _failed_record(loop, started_at, workspace, spec, message, stop_reason="error", remote_status=None, sync_manifest=None, artifact_paths=None):
    summary = {
        "what_was_tried": spec.prompt[:300],
        "what_was_found": "",
        "what_to_do_next": str(message or ""),
        "summary_text": "tried: {0}\nfound: (none)\nnext: {1}".format(spec.prompt[:300], str(message or "")),
    }
    usage = {
        "steps": 0,
        "tool_calls": 0,
        "tokens_used": 0,
        "elapsed_ms": int((time.time() - started_at) * 1000),
    }
    record = SubAgentRecord(
        id=spec.id,
        status=loop._subagent_status_from_reason(stop_reason),
        started_at=started_at,
        finished_at=time.time(),
        spec=spec,
        summary=summary,
        stop_reason=stop_reason,
        usage=usage,
        remote_status=dict(remote_status or {}),
        sync_manifest=dict(sync_manifest or {}),
        error=str(message or ""),
        artifact_paths=list(artifact_paths or []),
    )
    loop.workspace_manager.save_subagent_summary(workspace, spec.id, record.to_dict())
    if remote_status:
        loop.workspace_manager.save_subagent_remote_status(workspace, spec.id, dict(remote_status or {}))
    if sync_manifest:
        loop.workspace_manager.save_subagent_sync_manifest(workspace, spec.id, dict(sync_manifest or {}))
    return record, {
        "tool": "subagent:{0}".format(spec.id),
        "purpose": spec.purpose,
        "status": record.status,
        "stop_reason": record.stop_reason,
        "usage": dict(record.usage),
        "summary": dict(record.summary),
        "artifact_paths": list(record.artifact_paths),
        "result": loop._format_subagent_result(record),
        "elapsed_ms": int(record.usage.get("elapsed_ms", 0) or 0),
    }


def _runner_phase(remote_tool, host_name, python_bin, runner_path, remote_root, phase, timeout=30):
    result = remote_tool.run_command(
        host_name,
        "{0} {1} {2} {3}".format(_quote(python_bin), _quote(runner_path), _quote(remote_root), phase),
        timeout=timeout,
    )
    return result, _parse_runner_payload(result)


def _upload(sync_manifest, remote_tool, host_name, local_path, remote_path, kind, timeout=30):
    upload_result = remote_tool.upload(host_name, str(local_path), remote_path=remote_path, timeout=timeout)
    if dict(upload_result or {}).get("status") == "ok":
        sync_manifest["uploads"].append(
            {
                "local_path": str(local_path),
                "remote_path": str(upload_result.get("remote_path", remote_path)),
                "kind": kind,
            }
        )
    return upload_result


def _upload_text(sync_manifest, remote_tool, host_name, content, remote_path, kind, timeout=20):
    upload_result = remote_tool.upload_text(host_name, content, remote_path=remote_path, timeout=timeout)
    if dict(upload_result or {}).get("status") == "ok":
        sync_manifest["uploads"].append(
            {
                "local_path": "",
                "remote_path": str(upload_result.get("remote_path", remote_path)),
                "kind": kind,
            }
        )
    return upload_result


def _download(sync_manifest, remote_tool, host_name, remote_path, local_path, kind, timeout=30, optional=False):
    result = remote_tool.download(host_name, remote_path, str(local_path), timeout=timeout)
    if dict(result or {}).get("status") == "ok":
        sync_manifest["downloads"].append(
            {
                "remote_path": remote_path,
                "local_path": str(local_path),
                "kind": kind,
            }
        )
    elif not optional:
        return result
    return result


def _build_policy_payload(loop, sub_workspace, selected_host):
    remote_policy = loop.execution_policy.for_remote_subagent(sub_workspace, selected_host) if loop.execution_policy else None
    return {
        "denied_roots": list(getattr(remote_policy, "denied_roots", []) or []),
        "max_file_read_bytes": int(getattr(remote_policy, "max_file_read_bytes", 1024 * 1024) or 1024 * 1024),
        "max_shell_timeout_sec": int(getattr(remote_policy, "max_shell_timeout_sec", 20) or 20),
        "allow_public_web_targets_only": bool(getattr(remote_policy, "allow_public_web_targets_only", True)),
        "allow_mcp_servers": list(getattr(remote_policy, "allow_mcp_servers", []) or []),
        "run_id": str(getattr(remote_policy, "run_id", "") or ""),
    }


def run_remote_subagent(loop, challenge, workspace, spec):
    started_at = time.time()
    workspace = Path(workspace)
    sub_workspace = Path(spec.workspace_dir or loop.workspace_manager.subagent_dir(workspace, spec.id))
    sub_workspace.mkdir(parents=True, exist_ok=True)
    local_input_dir = sub_workspace / "input"
    local_input_dir.mkdir(parents=True, exist_ok=True)

    if not loop.remote_tool:
        return _failed_record(loop, started_at, workspace, spec, "remote_tool is not configured for remote subagent execution")

    selected_host = loop._select_remote_subagent_host(challenge, spec)
    if not selected_host:
        return _failed_record(loop, started_at, workspace, spec, "no remote host is available for remote subagent execution")

    spec.remote_host = selected_host
    if loop.execution_policy:
        decision = loop.execution_policy.evaluate_remote_subagent(
            selected_host,
            category=str(getattr(challenge, "category", "") or ""),
            target=str(getattr(challenge, "target", "") or ""),
            background=True,
            pending_action={
                "kind": "remote_subagent",
                "subagent_id": spec.id,
                "purpose": spec.purpose,
                "remote_host": selected_host,
                "workspace": str(sub_workspace),
            },
        )
        if getattr(decision, "decision", "") == "deny":
            return _failed_record(
                loop,
                started_at,
                workspace,
                spec,
                getattr(decision, "reason", "remote subagent blocked"),
                remote_status={
                    "status": "failed",
                    "remote_host": selected_host,
                    "remote_workspace": "",
                    "message": getattr(decision, "reason", "remote subagent blocked"),
                },
            )
        if getattr(decision, "decision", "") == "ask":
            return _approval_result(
                loop,
                workspace,
                spec,
                {
                    "status": "needs_approval",
                    "message": getattr(decision, "reason", "approval required for remote subagent"),
                    "request_id": getattr(decision, "request_id", ""),
                    "approval": decision.to_dict() if hasattr(decision, "to_dict") else {},
                },
            )

    loop._update_remote_status(
        workspace,
        spec.id,
        {
            "status": "queued",
            "remote_host": selected_host,
            "remote_workspace": "",
            "execution_mode": "remote",
            "poll_interval_sec": int(spec.poll_interval_sec or 5),
        },
    )
    bundle_path, runner_name = loop._create_remote_bundle(sub_workspace)
    sync_manifest = {
        "remote_host": selected_host,
        "uploads": [],
        "downloads": [],
        "remote_workspace": "",
        "mirror_artifacts": bool(spec.mirror_artifacts),
    }

    try:
        remote_setup = loop.remote_tool.ensure_workspace(selected_host, run_id=spec.id, timeout=30)
    except Exception as exc:
        remote_setup = {"status": "error", "message": str(exc)}
    if dict(remote_setup or {}).get("status") == "needs_approval":
        return _approval_result(loop, workspace, spec, remote_setup)
    if dict(remote_setup or {}).get("status") != "ok":
        return _failed_record(
            loop,
            started_at,
            workspace,
            spec,
            "failed to ensure remote workspace: {0}".format(dict(remote_setup or {}).get("message", remote_setup)),
            remote_status={
                "status": "failed",
                "remote_host": selected_host,
                "remote_workspace": str(dict(remote_setup or {}).get("workspace_root", "") or ""),
                "message": str(dict(remote_setup or {}).get("message", remote_setup)),
            },
        )

    remote_workspace = str(remote_setup.get("workspace_root", "") or "")
    remote_input_dir = str(remote_setup.get("input_dir", "") or (remote_workspace.rstrip("/") + "/input"))
    remote_output_dir = remote_workspace.rstrip("/") + "/output"
    sync_manifest["remote_workspace"] = remote_workspace
    spec.workspace_dir = str(sub_workspace)
    spec.transport = "ssh"
    loop._update_remote_status(
        workspace,
        spec.id,
        {
            "status": "staging",
            "remote_host": selected_host,
            "remote_workspace": remote_workspace,
            "execution_mode": "remote",
            "poll_interval_sec": int(spec.poll_interval_sec or 5),
        },
    )

    remote_attachment_paths = []
    for item in list(getattr(challenge, "attachments", []) or []):
        attachment_path = Path(item)
        remote_attachment_path = remote_input_dir + "/attachments/" + attachment_path.name
        upload_result = _upload(sync_manifest, loop.remote_tool, selected_host, attachment_path, remote_attachment_path, "attachment", timeout=30)
        if dict(upload_result or {}).get("status") == "needs_approval":
            return _approval_result(loop, workspace, spec, upload_result)
        if dict(upload_result or {}).get("status") != "ok":
            return _failed_record(
                loop,
                started_at,
                workspace,
                spec,
                "failed to upload attachment {0}: {1}".format(
                    attachment_path.name,
                    dict(upload_result or {}).get("message", upload_result),
                ),
                remote_status={
                    "status": "failed",
                    "remote_host": selected_host,
                    "remote_workspace": remote_workspace,
                    "message": str(dict(upload_result or {}).get("message", upload_result)),
                },
                sync_manifest=sync_manifest,
                artifact_paths=[str(bundle_path)],
            )
        remote_attachment_paths.append(str(upload_result.get("remote_path", remote_attachment_path)))

    challenge_payload = challenge.to_dict() if hasattr(challenge, "to_dict") else {}
    challenge_payload["attachments"] = list(remote_attachment_paths)
    challenge_metadata = dict(challenge_payload.get("metadata") or {})
    challenge_metadata["remote_subagent"] = {
        "remote_host": selected_host,
        "remote_workspace": remote_workspace,
        "remote_input_dir": remote_input_dir,
        "remote_output_dir": remote_output_dir,
        "attachments": list(remote_attachment_paths),
    }
    challenge_payload["metadata"] = challenge_metadata

    plugin_snapshot = loop.plugin_registry.describe() if loop.plugin_registry else {"loaded": False, "counts": {}, "plugins": []}
    local_spec_path = local_input_dir / "spec.json"
    local_policy_path = local_input_dir / "policy.json"
    local_challenge_path = local_input_dir / "challenge.json"
    local_plugin_path = local_input_dir / "plugin_snapshot.json"
    local_llm_path = local_input_dir / "llm.json"
    loop.workspace_manager.write_json(local_spec_path, dict(spec.to_dict()))
    loop.workspace_manager.write_json(local_policy_path, _build_policy_payload(loop, sub_workspace, selected_host))
    loop.workspace_manager.write_json(local_challenge_path, challenge_payload)
    loop.workspace_manager.write_json(local_plugin_path, plugin_snapshot)
    loop.workspace_manager.write_json(local_llm_path, loop._remote_llm_payload())

    staged_uploads = [
        (bundle_path, remote_input_dir + "/" + bundle_path.name, "remote_subagent_bundle.zip"),
        (local_spec_path, remote_input_dir + "/spec.json", "spec.json"),
        (local_policy_path, remote_input_dir + "/policy.json", "policy.json"),
        (local_challenge_path, remote_input_dir + "/challenge.json", "challenge.json"),
        (local_plugin_path, remote_input_dir + "/plugin_snapshot.json", "plugin_snapshot.json"),
        (local_llm_path, remote_input_dir + "/llm.json", "llm.json"),
    ]
    for local_path, remote_path, kind in staged_uploads:
        upload_result = _upload(sync_manifest, loop.remote_tool, selected_host, local_path, remote_path, kind, timeout=30)
        if dict(upload_result or {}).get("status") == "needs_approval":
            return _approval_result(loop, workspace, spec, upload_result)
        if dict(upload_result or {}).get("status") != "ok":
            return _failed_record(
                loop,
                started_at,
                workspace,
                spec,
                "failed to upload {0}: {1}".format(Path(local_path).name, dict(upload_result or {}).get("message", upload_result)),
                remote_status={
                    "status": "failed",
                    "remote_host": selected_host,
                    "remote_workspace": remote_workspace,
                    "message": str(dict(upload_result or {}).get("message", upload_result)),
                },
                sync_manifest=sync_manifest,
                artifact_paths=[str(bundle_path)],
            )

    runner_remote_path = remote_input_dir + "/" + runner_name
    runner_upload = _upload_text(
        sync_manifest,
        loop.remote_tool,
        selected_host,
        loop._remote_runner_script(),
        runner_remote_path,
        "remote_subagent_runner.py",
        timeout=20,
    )
    if dict(runner_upload or {}).get("status") == "needs_approval":
        return _approval_result(loop, workspace, spec, runner_upload)
    if dict(runner_upload or {}).get("status") != "ok":
        return _failed_record(
            loop,
            started_at,
            workspace,
            spec,
            "failed to upload remote runner: {0}".format(dict(runner_upload or {}).get("message", runner_upload)),
            remote_status={
                "status": "failed",
                "remote_host": selected_host,
                "remote_workspace": remote_workspace,
                "message": str(dict(runner_upload or {}).get("message", runner_upload)),
            },
            sync_manifest=sync_manifest,
            artifact_paths=[str(bundle_path)],
        )

    host_python = str((loop.remote_tool.hosts.get(selected_host, {}) or {}).get("python_bin", "python3") or "python3")
    runner_init, init_payload = _runner_phase(
        loop.remote_tool,
        selected_host,
        host_python,
        runner_remote_path,
        remote_workspace,
        "init",
        timeout=30,
    )
    if dict(runner_init or {}).get("status") == "needs_approval":
        return _approval_result(loop, workspace, spec, runner_init)
    if dict(runner_init or {}).get("status") != "ok":
        return _failed_record(
            loop,
            started_at,
            workspace,
            spec,
            "failed to initialize remote runner: {0}".format(dict(runner_init or {}).get("message", runner_init)),
            remote_status={
                "status": "failed",
                "remote_host": selected_host,
                "remote_workspace": remote_workspace,
                "message": str(dict(runner_init or {}).get("message", runner_init)),
            },
            sync_manifest=sync_manifest,
            artifact_paths=[str(bundle_path)],
        )

    runner_start, start_payload = _runner_phase(
        loop.remote_tool,
        selected_host,
        host_python,
        runner_remote_path,
        remote_workspace,
        "start",
        timeout=30,
    )
    if dict(runner_start or {}).get("status") == "needs_approval":
        return _approval_result(loop, workspace, spec, runner_start)
    if dict(runner_start or {}).get("status") != "ok":
        return _failed_record(
            loop,
            started_at,
            workspace,
            spec,
            "failed to start remote runner: {0}".format(dict(runner_start or {}).get("message", runner_start)),
            remote_status={
                "status": "failed",
                "remote_host": selected_host,
                "remote_workspace": remote_workspace,
                "message": str(dict(runner_start or {}).get("message", runner_start)),
            },
            sync_manifest=sync_manifest,
            artifact_paths=[str(bundle_path)],
        )

    job_id = str(start_payload.get("job_id", "") or "")
    remote_status = loop._update_remote_status(
        workspace,
        spec.id,
        {
            "status": "running",
            "remote_host": selected_host,
            "remote_workspace": remote_workspace,
            "execution_mode": "remote",
            "poll_interval_sec": int(spec.poll_interval_sec or 5),
            "job_id": job_id,
            "runner_init": init_payload,
        },
    )

    heartbeat_path = sub_workspace / "remote_heartbeat.json"
    state_path = sub_workspace / "remote_state.json"
    remote_summary_path = remote_output_dir + "/summary.json"
    remote_transcript_path = remote_output_dir + "/transcript.jsonl"
    remote_tar_path = remote_output_dir + "/artifacts.tar.gz"
    local_remote_summary_path = sub_workspace / "remote_summary.json"
    local_remote_transcript_path = sub_workspace / "remote_transcript.jsonl"
    local_remote_tar_path = sub_workspace / "remote_artifacts.tar.gz"
    poll_interval = max(1.0, float(spec.poll_interval_sec or 5))
    deadline = time.time() + max(float(spec.timeout_sec or 90), poll_interval * 2.0) + 15.0
    timed_out = False
    last_status_payload = dict(start_payload or {})

    while True:
        if time.time() > deadline:
            timed_out = True
            cancel_result, cancel_payload = _runner_phase(
                loop.remote_tool,
                selected_host,
                host_python,
                runner_remote_path,
                remote_workspace,
                "cancel",
                timeout=20,
            )
            if dict(cancel_result or {}).get("status") == "needs_approval":
                return _approval_result(loop, workspace, spec, cancel_result)
            if cancel_payload:
                last_status_payload = cancel_payload
            break

        status_result, status_payload = _runner_phase(
            loop.remote_tool,
            selected_host,
            host_python,
            runner_remote_path,
            remote_workspace,
            "status",
            timeout=20,
        )
        if dict(status_result or {}).get("status") == "needs_approval":
            return _approval_result(loop, workspace, spec, status_result)
        if dict(status_result or {}).get("status") != "ok":
            return _failed_record(
                loop,
                started_at,
                workspace,
                spec,
                "failed to query remote runner status: {0}".format(dict(status_result or {}).get("message", status_result)),
                remote_status={
                    "status": "failed",
                    "remote_host": selected_host,
                    "remote_workspace": remote_workspace,
                    "job_id": job_id,
                    "message": str(dict(status_result or {}).get("message", status_result)),
                },
                sync_manifest=sync_manifest,
                artifact_paths=[str(bundle_path)],
            )
        last_status_payload = dict(status_payload or {})
        if str(last_status_payload.get("job_id", "") or "").strip():
            job_id = str(last_status_payload.get("job_id", "") or "")
        _download(sync_manifest, loop.remote_tool, selected_host, remote_output_dir + "/heartbeat.json", heartbeat_path, "heartbeat", timeout=20, optional=True)
        _download(sync_manifest, loop.remote_tool, selected_host, remote_output_dir + "/state.json", state_path, "state", timeout=20, optional=True)
        heartbeat_payload = _read_json(heartbeat_path)
        state_payload = _read_json(state_path)
        remote_status = loop._update_remote_status(
            workspace,
            spec.id,
            {
                "status": str(
                    state_payload.get("status")
                    or heartbeat_payload.get("status")
                    or last_status_payload.get("state")
                    or "running"
                ),
                "remote_host": selected_host,
                "remote_workspace": remote_workspace,
                "execution_mode": "remote",
                "poll_interval_sec": int(spec.poll_interval_sec or 5),
                "job_id": job_id,
                "stop_reason": str(
                    state_payload.get("stop_reason")
                    or heartbeat_payload.get("stop_reason")
                    or remote_status.get("stop_reason", "")
                ),
                "usage": dict(state_payload.get("usage") or heartbeat_payload.get("usage") or {}),
                "summary_ready": bool(last_status_payload.get("summary_ready")),
            },
        )
        status_name = str(last_status_payload.get("state", "") or "")
        if (
            bool(last_status_payload.get("summary_ready"))
            or status_name in TERMINAL_STATUSES
            or str(heartbeat_payload.get("status", "") or "") in TERMINAL_STATUSES
            or str(state_payload.get("status", "") or "") in TERMINAL_STATUSES
            or status_name == "finished"
        ):
            break
        time.sleep(poll_interval)

    loop._update_remote_status(
        workspace,
        spec.id,
        {
            "status": "syncing",
            "remote_host": selected_host,
            "remote_workspace": remote_workspace,
            "execution_mode": "remote",
            "poll_interval_sec": int(spec.poll_interval_sec or 5),
            "job_id": job_id,
        },
    )

    _download(sync_manifest, loop.remote_tool, selected_host, remote_summary_path, local_remote_summary_path, "summary", timeout=30, optional=True)
    _download(sync_manifest, loop.remote_tool, selected_host, remote_transcript_path, local_remote_transcript_path, "transcript", timeout=30, optional=True)
    _download(sync_manifest, loop.remote_tool, selected_host, remote_tar_path, local_remote_tar_path, "artifacts", timeout=45, optional=True)

    remote_summary = _read_json(local_remote_summary_path)
    if timed_out and not remote_summary:
        remote_summary = {
            "id": spec.id,
            "status": "timed_out",
            "stop_reason": "timeout",
            "usage": dict(remote_status.get("usage") or {}),
            "summary": {
                "what_was_tried": spec.prompt[:300],
                "what_was_found": "",
                "what_to_do_next": "remote subagent timed out before summary was available",
                "summary_text": "remote subagent timed out before summary was available",
            },
            "artifact_paths": [],
        }
    if not remote_summary:
        return _failed_record(
            loop,
            started_at,
            workspace,
            spec,
            "remote runner finished without summary.json",
            remote_status={
                "status": "timed_out" if timed_out else "failed",
                "remote_host": selected_host,
                "remote_workspace": remote_workspace,
                "job_id": job_id,
                "message": "missing remote summary",
            },
            sync_manifest=sync_manifest,
            artifact_paths=[str(bundle_path)],
        )

    stop_reason = str(remote_summary.get("stop_reason", "") or ("timeout" if timed_out else "completed"))
    status = str(remote_summary.get("status", "") or loop._subagent_status_from_reason(stop_reason))
    usage = dict(remote_summary.get("usage") or {})
    summary = dict(remote_summary.get("summary") or {})
    final_remote_status = loop._update_remote_status(
        workspace,
        spec.id,
        {
            "status": status,
            "remote_host": selected_host,
            "remote_workspace": remote_workspace,
            "execution_mode": "remote",
            "poll_interval_sec": int(spec.poll_interval_sec or 5),
            "job_id": job_id,
            "stop_reason": stop_reason,
            "usage": usage,
            "summary_ready": True,
        },
    )

    transcript_path = sub_workspace / "transcript.jsonl"
    if local_remote_transcript_path.exists():
        shutil.copyfile(str(local_remote_transcript_path), str(transcript_path))
    local_artifact_paths = [str(path) for path in sorted((sub_workspace / "artifacts").rglob("*")) if path.is_file()]
    if local_remote_tar_path.exists() and spec.mirror_artifacts:
        extracted_remote_artifacts = sub_workspace / "artifacts" / "remote_mirror"
        extracted_remote_artifacts.mkdir(parents=True, exist_ok=True)
        try:
            with tarfile.open(local_remote_tar_path, "r:gz") as handle:
                handle.extractall(extracted_remote_artifacts)
            local_artifact_paths = [str(path) for path in sorted((sub_workspace / "artifacts").rglob("*")) if path.is_file()]
        except Exception:
            pass

    artifact_paths = list(local_artifact_paths)
    for candidate in [transcript_path, local_remote_summary_path, local_remote_transcript_path, local_remote_tar_path]:
        if Path(candidate).exists():
            artifact_paths.append(str(candidate))

    record = SubAgentRecord(
        id=spec.id,
        status=status,
        started_at=started_at,
        finished_at=time.time(),
        spec=spec,
        summary=summary,
        stop_reason=stop_reason,
        usage=usage,
        remote_status=final_remote_status,
        sync_manifest=sync_manifest,
        error=str(remote_summary.get("error", "") or "") or None,
        artifact_paths=artifact_paths,
    )
    record_payload = record.to_dict()
    record_payload["summary_text"] = summary.get("summary_text", "")
    if transcript_path.exists():
        record_payload["transcript_path"] = str(transcript_path)
    loop.workspace_manager.save_subagent_summary(workspace, spec.id, record_payload)
    loop.workspace_manager.save_subagent_sync_manifest(workspace, spec.id, sync_manifest)
    return record, {
        "tool": "subagent:{0}".format(spec.id),
        "purpose": spec.purpose,
        "status": record.status,
        "stop_reason": record.stop_reason,
        "usage": dict(record.usage),
        "summary": dict(record.summary),
        "artifact_paths": list(record.artifact_paths),
        "remote_status": dict(record.remote_status),
        "sync_manifest": dict(record.sync_manifest),
        "result": loop._format_subagent_result(record),
        "elapsed_ms": int(record.usage.get("elapsed_ms", 0) or 0),
    }
