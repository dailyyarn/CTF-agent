import json
import os
import re
from datetime import datetime
from pathlib import Path

from ctf_agent.core.board import build_board_summary
from ctf_agent.core.intake import IntakeService
from ctf_agent.core.runtime import close_service, run_payload
from ctf_agent.knowledge import normalize_category, supported_categories


CATEGORY_SET = set(supported_categories())
CASE_META_FILENAMES = ("case.json", "challenge.json", "task.json")
TEXT_HINT_FILENAMES = ("task.txt", "description.txt", "hint.txt", "README.md", "readme.md")
DEFAULT_LIVE_PWN_ENV_SWITCH = "CTF_AGENT_ENABLE_PWN_LIVE_SMOKE"


def run_regression_suite(
    service,
    *,
    manifest_path=None,
    cases_root=None,
    report_dir=None,
    category_filters=None,
    limit=None,
    findings_limit=5,
):
    workspace_root = Path(service["workspace_dir"]).expanduser().absolute()
    intake = IntakeService(service["config"], workspace_root)
    cases = load_regression_cases(
        manifest_path=manifest_path,
        cases_root=cases_root,
        category_filters=category_filters,
        limit=limit,
    )
    if not cases:
        raise ValueError("No regression cases found.")

    resolved_report_dir = _resolve_report_dir(
        report_dir=report_dir,
        workspace_root=workspace_root,
    )
    started_at = datetime.now()
    results = []
    by_category = {}

    for index, case in enumerate(cases, start=1):
        prepared = _prepare_case_payload(case, intake)
        expected_flag = str(case.get("expected_flag") or "").strip()
        record = {
            "index": index,
            "title": prepared.get("title", ""),
            "category": prepared.get("category", ""),
            "challenge_id": prepared.get("challenge_id", ""),
            "target": prepared.get("url") or prepared.get("target") or "",
            "attachments": list(prepared.get("attachments", [])),
            "expected_flag": expected_flag,
            "status": "failed",
            "flag": "",
            "workspace": "",
            "solver": "",
            "matched_expected_flag": False,
            "board_summary": {},
            "pwn_family": "",
            "pwn_family_confidence": 0.0,
            "pwn_stage_status": {},
            "build_profile": "",
            "build_missing": [],
            "debug_trace": {},
            "exploit_stub_generated": False,
            "stage2_generated": False,
            "error": "",
        }
        try:
            result = run_payload(service, prepared, source="cli-regress")
            record["status"] = str(result.get("status") or "")
            record["flag"] = str(result.get("flag") or "")
            record["workspace"] = str(result.get("workspace") or "")
            record["solver"] = str(result.get("solver") or "")
            if record["workspace"]:
                board_summary = build_board_summary(
                    record["workspace"],
                    findings_limit=int(findings_limit),
                )
                record["board_summary"] = board_summary
                binary_summary = dict(board_summary.get("binary") or {})
                record["pwn_family"] = str(binary_summary.get("pwn_family") or board_summary.get("pwn_family") or "")
                record["pwn_family_confidence"] = float(binary_summary.get("pwn_family_confidence", board_summary.get("pwn_family_confidence", 0.0)) or 0.0)
                record["pwn_stage_status"] = dict(binary_summary.get("pwn_stage_status") or board_summary.get("pwn_stage_status") or {})
                record["build_profile"] = str(binary_summary.get("build_profile") or board_summary.get("build_profile") or "")
                record["build_missing"] = list(binary_summary.get("build_missing") or board_summary.get("build_missing") or [])
                record["debug_trace"] = dict(binary_summary.get("debug_trace") or board_summary.get("debug_trace") or {})
                record["exploit_stub_generated"] = bool(binary_summary.get("exploit_stub_generated", board_summary.get("exploit_stub_generated", False)))
                record["stage2_generated"] = bool(binary_summary.get("stage2_generated", board_summary.get("stage2_generated", False)))
            if expected_flag:
                record["matched_expected_flag"] = bool(record["flag"] and record["flag"] == expected_flag)
        except Exception as exc:
            record["status"] = "failed"
            record["error"] = str(exc)
        results.append(record)
        _accumulate_category(by_category, record)

    payload = build_regression_summary(
        cases=results,
        by_category=by_category,
        report_dir=resolved_report_dir,
        started_at=started_at,
        source={
            "manifest_path": str(manifest_path) if manifest_path else "",
            "cases_root": str(cases_root) if cases_root else "",
        },
    )
    _write_regression_report(resolved_report_dir, payload)
    return payload


def load_regression_cases(*, manifest_path=None, cases_root=None, category_filters=None, limit=None):
    manifest = Path(manifest_path).expanduser().absolute() if manifest_path else None
    root = Path(cases_root).expanduser().absolute() if cases_root else None
    filters = {normalize_category(item or "") for item in list(category_filters or []) if normalize_category(item or "")}

    cases = []
    if manifest:
        cases.extend(_load_manifest_cases(manifest))
    if root:
        cases.extend(_discover_cases(root))

    if filters:
        cases = [item for item in cases if normalize_category(item.get("category") or "") in filters]
    if limit is not None:
        cases = cases[: int(limit)]
    return cases


def build_regression_summary(*, cases, by_category, report_dir, started_at, source):
    solved = sum(1 for item in cases if item.get("status") == "solved")
    unresolved = sum(1 for item in cases if item.get("status") == "unresolved")
    failed = sum(1 for item in cases if item.get("status") == "failed")
    matched = sum(1 for item in cases if item.get("matched_expected_flag"))
    expected = sum(1 for item in cases if item.get("expected_flag"))
    status = "ok" if failed == 0 else "warn"
    if not cases:
        status = "empty"
    categorized = _finalize_category_stats(by_category)
    review = _build_review_groups(cases)
    return {
        "status": status,
        "started_at": started_at.isoformat(),
        "finished_at": datetime.now().isoformat(),
        "source": dict(source or {}),
        "report_dir": str(report_dir),
        "case_count": len(cases),
        "solved_count": solved,
        "unresolved_count": unresolved,
        "failed_count": failed,
        "expected_flag_count": expected,
        "expected_flag_match_count": matched,
        "solve_rate": round((solved / len(cases)) if cases else 0.0, 4),
        "expected_flag_match_rate": round((matched / expected) if expected else 0.0, 4),
        "by_category": categorized,
        "review": review,
        "cases": cases,
    }


def render_regression_markdown(payload):
    payload = dict(payload or {})
    lines = [
        "# Regression Report",
        "",
        "- Status: {0}".format(payload.get("status", "")),
        "- Started: {0}".format(payload.get("started_at", "")),
        "- Finished: {0}".format(payload.get("finished_at", "")),
        "- Report Dir: {0}".format(payload.get("report_dir", "")),
        "- Cases: {0}".format(payload.get("case_count", 0)),
        "- Solved: {0}".format(payload.get("solved_count", 0)),
        "- Unresolved: {0}".format(payload.get("unresolved_count", 0)),
        "- Failed: {0}".format(payload.get("failed_count", 0)),
        "- Expected Flag Matches: {0}/{1}".format(
            payload.get("expected_flag_match_count", 0),
            payload.get("expected_flag_count", 0),
        ),
        "",
        "## By Category",
        "",
    ]
    by_category = dict(payload.get("by_category") or {})
    for category in sorted(by_category):
        stats = dict(by_category.get(category) or {})
        lines.append(
            "- `{0}`: total={1}, solved={2}, unresolved={3}, failed={4}, matched={5}/{6}, solve_rate={7:.2%}, match_rate={8:.2%}".format(
                category,
                stats.get("total", 0),
                stats.get("solved", 0),
                stats.get("unresolved", 0),
                stats.get("failed", 0),
                stats.get("matched_expected_flag", 0),
                stats.get("expected_flag_count", 0),
                stats.get("solve_rate", 0.0),
                stats.get("expected_flag_match_rate", 0.0),
            )
        )
    review = dict(payload.get("review") or {})
    lines.extend(["", "## Needs Review", ""])
    if not any(review.values()):
        lines.append("- None")
    else:
        for label, items in (
            ("failed", list(review.get("failed") or [])),
            ("unresolved", list(review.get("unresolved") or [])),
            ("mismatched_flags", list(review.get("mismatched_flags") or [])),
        ):
            if not items:
                continue
            lines.append("- `{0}`".format(label))
            for item in items:
                lines.append(
                    "  - `{0}` `{1}` workspace={2}".format(
                        item.get("category", ""),
                        item.get("title", ""),
                        item.get("workspace", ""),
                    )
                )
    lines.extend(["", "## Cases", ""])
    for case in list(payload.get("cases") or []):
        headline = "- [{status}] `{category}` `{title}`".format(
            status=case.get("status", ""),
            category=case.get("category", ""),
            title=case.get("title", ""),
        )
        lines.append(headline)
        lines.append("  - Workspace: {0}".format(case.get("workspace", "")))
        if case.get("flag"):
            lines.append("  - Flag: {0}".format(case.get("flag", "")))
        if case.get("expected_flag"):
            lines.append(
                "  - Expected: {0} ({1})".format(
                    case.get("expected_flag", ""),
                    "match" if case.get("matched_expected_flag") else "mismatch",
                )
            )
        summary = dict(case.get("board_summary") or {})
        if summary:
            lines.append("  - Best Path: {0}".format(summary.get("specialized_best_path", "") or summary.get("recommended_path", "")))
            lines.append("  - Solver: {0}".format(summary.get("solver", "")))
            if summary.get("headline"):
                lines.append("  - Headline: {0}".format(summary.get("headline", "")))
            if case.get("pwn_family"):
                lines.append(
                    "  - Pwn: family={0}, confidence={1}, stage={2}, build={3}, stub={4}, stage2={5}".format(
                        case.get("pwn_family", ""),
                        case.get("pwn_family_confidence", 0.0),
                        dict(case.get("pwn_stage_status") or {}).get("status", ""),
                        case.get("build_profile", ""),
                        "yes" if case.get("exploit_stub_generated") else "no",
                        "yes" if case.get("stage2_generated") else "no",
                    )
                )
                if case.get("build_missing"):
                    lines.append("  - Build Missing: {0}".format(", ".join(list(case.get("build_missing") or []))))
            used_tools = list(dict(summary.get("tool_usage") or {}).get("used", []))
            used_mcp = list(dict(summary.get("mcp_usage") or {}).get("used", []))
            selected_remote = str(dict(summary.get("remote_usage") or {}).get("selected_host", "") or "")
            if used_tools:
                lines.append("  - Used Tools: {0}".format(", ".join(used_tools[:8])))
            if used_mcp:
                lines.append("  - Used MCP: {0}".format(", ".join(used_mcp[:6])))
            if selected_remote:
                lines.append("  - Used Remote: {0}".format(selected_remote))
        if case.get("error"):
            lines.append("  - Error: {0}".format(case.get("error", "")))
    lines.append("")
    return "\n".join(lines)


def scaffold_regression_corpus(destination):
    destination = Path(destination).expanduser().absolute()
    destination.mkdir(parents=True, exist_ok=True)
    for category in sorted(CATEGORY_SET):
        category_dir = destination / category
        category_dir.mkdir(parents=True, exist_ok=True)
        template_dir = category_dir / "case-template"
        template_dir.mkdir(parents=True, exist_ok=True)
        (template_dir / "case.json").write_text(
            json.dumps(
                {
                    "title": "{0}-sample".format(category),
                    "category": category,
                    "attachment": "F:/path/to/attachment",
                    "target": "http://target-or-empty",
                    "description": "Optional description",
                    "hint": "Optional hint",
                    "expected_flag": "",
                    "flag_format": r"flag\{[^{}\n]+\}",
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8-sig",
        )
        (template_dir / "README.md").write_text(
            "\n".join(
                [
                    "# Case Template",
                    "",
                    "- Put one challenge per folder.",
                    "- Edit `case.json`.",
                    "- Either set `attachment` / `attachments`, or `target`, or both.",
                    "- `expected_flag` is optional but recommended for regression scoring.",
                    "",
                ]
            ),
            encoding="utf-8-sig",
        )
    (destination / "README.md").write_text(
        "\n".join(
            [
                "# Regression Corpus",
                "",
                "Layout:",
                "- <root>/<category>/<case-name>/case.json",
                "",
                "Supported categories:",
                "- {0}".format(", ".join(sorted(CATEGORY_SET))),
                "",
                "Run:",
                "- python F:/codex/ctf-agent/app.py regress --cases-root {0} --workspace-root F:/ctf-agent-output --config F:/codex/ctf-agent/local_config.json --json".format(
                    str(destination).replace("\\", "/")
                ),
                "",
            ]
        ),
        encoding="utf-8-sig",
    )
    return {
        "status": "ok",
        "destination": str(destination),
        "categories": sorted(CATEGORY_SET),
    }


def run_pwn_live_smoke(
    service,
    *,
    hosts=None,
    report_dir=None,
    timeout=25.0,
    bootstrap=False,
    env_switch=DEFAULT_LIVE_PWN_ENV_SWITCH,
):
    workspace_root = Path(service["workspace_dir"]).expanduser().absolute()
    remote_tool = service["remote_tool"]
    available_hosts = list(remote_tool.list_hosts())
    host_configs = dict(getattr(remote_tool, "hosts", {}) or {})
    config = service.get("config")
    if config is not None:
        host_configs.update(dict(getattr(config, "remote_hosts", {}) or {}))
    selected_hosts = _resolve_live_pwn_hosts(
        available_hosts,
        host_configs=host_configs,
        hosts=hosts,
        env_switch=env_switch,
    )
    if not selected_hosts:
        return {
            "status": "skipped",
            "message": "no configured pwn-capable remote hosts selected; pass hosts explicitly or set {0}=1".format(env_switch),
            "env_switch": env_switch,
            "available_hosts": available_hosts,
            "selected_hosts": [],
            "report_dir": "",
            "bootstrap": bool(bootstrap),
            "hosts": [],
        }

    resolved_report_dir = _resolve_report_dir(report_dir=report_dir, workspace_root=workspace_root)
    results = []
    statuses = []
    for host_name in selected_hosts:
        item = {
            "host": host_name,
            "status": "ok",
            "probe_before": {},
            "runtime_before": {},
            "bootstrap": {},
            "probe_after": {},
            "runtime_after": {},
            "message": "",
        }
        probe_before = remote_tool.probe(host_name, timeout=float(timeout))
        item["probe_before"] = probe_before
        item["runtime_before"] = _summarize_probe_runtime(probe_before)
        if probe_before.get("status") != "ok":
            item["status"] = "error"
            item["message"] = probe_before.get("message", "remote probe failed")
            statuses.append(item["status"])
            results.append(item)
            continue

        if bootstrap:
            bootstrap_kind = str(
                dict(probe_before.get("pwn_capabilities") or {}).get("suggested_template")
                or dict(probe_before.get("pwn_capabilities") or {}).get("suggested_build_template")
                or "pwn-ubuntu-bootstrap"
            )
            bootstrap_result = remote_tool.run_template(
                host_name,
                bootstrap_kind,
                timeout=max(float(timeout), 1200.0),
            )
            bootstrap_payload = _extract_template_execute_payload(bootstrap_result)
            item["bootstrap"] = {
                "result": bootstrap_result,
                "payload": bootstrap_payload,
            }

        probe_after = remote_tool.probe(host_name, timeout=float(timeout))
        item["probe_after"] = probe_after
        item["runtime_after"] = _summarize_probe_runtime(probe_after)
        final_runtime = dict(item["runtime_after"] or item["runtime_before"])
        profile = str(final_runtime.get("parity_profile") or "weak")
        if probe_after.get("status") != "ok":
            item["status"] = "error"
            item["message"] = probe_after.get("message", "post-smoke probe failed")
        elif profile == "ready":
            item["status"] = "ok"
            item["message"] = "pwn parity ready"
        else:
            item["status"] = "warn"
            item["message"] = "pwn parity is {0}".format(profile)
        statuses.append(item["status"])
        results.append(item)

    payload = {
        "status": _merge_live_smoke_status(statuses),
        "message": "",
        "env_switch": env_switch,
        "available_hosts": available_hosts,
        "selected_hosts": selected_hosts,
        "bootstrap": bool(bootstrap),
        "report_dir": str(resolved_report_dir),
        "hosts": results,
        "started_at": datetime.now().isoformat(),
    }
    payload["message"] = _build_live_smoke_message(payload)
    _write_live_smoke_report(resolved_report_dir, payload)
    return payload


def _prepare_case_payload(case, intake):
    raw = dict(case or {})
    if raw.get("task"):
        normalized = intake.normalize_brief(raw)
    else:
        normalized = intake.normalize(raw)
    return normalized


def _resolve_report_dir(*, report_dir, workspace_root):
    if report_dir:
        path = Path(report_dir).expanduser()
        if not path.is_absolute():
            path = Path.cwd() / path
    else:
        regression_root = workspace_root / "_regression"
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")[:-3]
        path = regression_root / stamp
        if path.exists():
            counter = 2
            while True:
                candidate = regression_root / "{0}-{1:02d}".format(stamp, counter)
                if not candidate.exists():
                    path = candidate
                    break
                counter += 1
    path.mkdir(parents=True, exist_ok=True)
    return path.absolute()


def _write_regression_report(report_dir, payload):
    report_dir = Path(report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "regression_report.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8-sig",
    )
    (report_dir / "regression_report.md").write_text(
        render_regression_markdown(payload),
        encoding="utf-8-sig",
    )


def _write_live_smoke_report(report_dir, payload):
    report_dir = Path(report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "pwn_live_smoke.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8-sig",
    )
    (report_dir / "pwn_live_smoke.md").write_text(
        render_pwn_live_smoke_markdown(payload),
        encoding="utf-8-sig",
    )


def render_pwn_live_smoke_markdown(payload):
    payload = dict(payload or {})
    lines = [
        "# Pwn Live Smoke",
        "",
        "- Status: {0}".format(payload.get("status", "")),
        "- Report Dir: {0}".format(payload.get("report_dir", "")),
        "- Bootstrap: {0}".format("yes" if payload.get("bootstrap") else "no"),
        "- Selected Hosts: {0}".format(", ".join(list(payload.get("selected_hosts", []))) or "none"),
        "- Message: {0}".format(payload.get("message", "")),
        "",
        "## Hosts",
        "",
    ]
    for item in list(payload.get("hosts") or []):
        runtime_before = dict(item.get("runtime_before") or {})
        runtime_after = dict(item.get("runtime_after") or {})
        lines.append("- `{0}` status={1}".format(item.get("host", ""), item.get("status", "")))
        lines.append("  - before: parity={0} build={1}".format(runtime_before.get("parity_profile", "unknown"), runtime_before.get("build_profile", "unknown")))
        lines.append("  - after: parity={0} build={1}".format(runtime_after.get("parity_profile", "unknown"), runtime_after.get("build_profile", "unknown")))
        if runtime_after:
            lines.append(
                "  - missing: core=[{0}] advanced=[{1}] debugger=[{2}] build=[{3}]".format(
                    ",".join(list(runtime_after.get("core_missing", []))) or "none",
                    ",".join(list(runtime_after.get("advanced_missing", []))) or "none",
                    ",".join(list(runtime_after.get("debugger_missing", []))) or "none",
                    ",".join(list(runtime_after.get("build_missing", []))) or "none",
                )
            )
        if item.get("message"):
            lines.append("  - message: {0}".format(item.get("message", "")))
    lines.append("")
    return "\n".join(lines)


def _resolve_live_pwn_hosts(available_hosts, *, host_configs=None, hosts=None, env_switch=DEFAULT_LIVE_PWN_ENV_SWITCH):
    requested = [str(item).strip() for item in list(hosts or []) if str(item).strip()]
    if requested:
        return requested
    if _truthy_env(os.environ.get(env_switch, "")):
        selected = []
        for item in list(available_hosts or []):
            config = dict((host_configs or {}).get(item) or {})
            preferred_for = {
                str(entry).strip().lower()
                for entry in list(config.get("preferred_for", []) or [])
                if str(entry).strip()
            }
            if preferred_for.intersection({"pwn", "re", "reverse", "binary"}):
                selected.append(item)
                continue
            hint_text = " ".join(
                [
                    str(item or ""),
                    str(config.get("username", "") or ""),
                    str(config.get("notes", "") or ""),
                ]
            ).lower()
            if any(token in hint_text for token in ("pwn", "re", "reverse", "binary", "linux", "ubuntu", "debian", "kali", "centos", "rocky", "alma")):
                selected.append(item)
        return selected
    return []


def _truthy_env(value):
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _extract_template_execute_payload(result):
    result = dict(result or {})
    execute = dict(result.get("execute") or {})
    stdout = str(execute.get("stdout", "") or "").strip()
    if not stdout:
        return {}
    try:
        return json.loads(stdout)
    except Exception:
        return {"raw_stdout": stdout[:12000]}


def _summarize_probe_runtime(probe):
    probe = dict(probe or {})
    caps = dict(probe.get("pwn_capabilities") or {})
    return {
        "parity_profile": str(caps.get("parity_profile") or ""),
        "build_profile": str(caps.get("build_profile") or ""),
        "core_missing": list(caps.get("core_missing", [])),
        "advanced_missing": list(caps.get("advanced_missing", [])),
        "debugger_missing": list(caps.get("debugger_missing", [])),
        "build_missing": list(caps.get("build_missing", [])),
        "bootstrap_recommended": bool(caps.get("bootstrap_recommended")),
        "suggested_template": str(caps.get("suggested_template") or ""),
        "suggested_build_template": str(caps.get("suggested_build_template") or ""),
    }


def _merge_live_smoke_status(statuses):
    statuses = [str(item or "").strip().lower() for item in list(statuses or []) if str(item or "").strip()]
    if not statuses:
        return "skipped"
    if "error" in statuses:
        return "error"
    if "warn" in statuses:
        return "warn"
    if "ok" in statuses:
        return "ok"
    return statuses[0]


def _build_live_smoke_message(payload):
    payload = dict(payload or {})
    host_items = list(payload.get("hosts") or [])
    ready_hosts = [item.get("host", "") for item in host_items if str(dict(item.get("runtime_after") or item.get("runtime_before") or {}).get("parity_profile") or "") == "ready"]
    if ready_hosts:
        return "ready hosts: {0}".format(", ".join(ready_hosts))
    if payload.get("selected_hosts"):
        return "selected hosts still need parity work"
    return payload.get("message", "")


def _load_manifest_cases(path):
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if isinstance(data, list):
        raw_cases = data
    else:
        raw_cases = list(data.get("cases") or data.get("items") or [])
    cases = []
    for index, item in enumerate(raw_cases, start=1):
        cases.append(_normalize_case_entry(item, base_dir=Path(path).parent, default_title="case-{0:03d}".format(index)))
    return cases


def _discover_cases(root):
    root = Path(root)
    cases = []
    category_dirs = [item for item in sorted(root.iterdir()) if item.is_dir() and normalize_category(item.name) in CATEGORY_SET]
    if not category_dirs:
        return cases
    for category_dir in category_dirs:
        category = normalize_category(category_dir.name)
        children = sorted(category_dir.iterdir())
        for child in children:
            if child.is_dir():
                entry = _discover_case_dir(child, category)
                if entry:
                    cases.append(entry)
            elif child.is_file():
                cases.append(
                    _normalize_case_entry(
                        {
                            "category": category,
                            "title": child.stem,
                            "attachment": str(child),
                            "challenge_id": _slugify(child.stem),
                        },
                        base_dir=child.parent,
                        default_title=child.stem,
                    )
                )
    return cases


def _discover_case_dir(case_dir, category):
    metadata = {}
    for filename in CASE_META_FILENAMES:
        candidate = case_dir / filename
        if candidate.exists():
            metadata = json.loads(candidate.read_text(encoding="utf-8-sig"))
            break
    text_hint = ""
    for filename in TEXT_HINT_FILENAMES:
        candidate = case_dir / filename
        if candidate.exists():
            text_hint = candidate.read_text(encoding="utf-8-sig")
            break
    attachments = []
    for item in sorted(case_dir.rglob("*")):
        if not item.is_file():
            continue
        if item.name in CASE_META_FILENAMES or item.name in TEXT_HINT_FILENAMES:
            continue
        attachments.append(str(item))
    if metadata.get("attachment"):
        attachments.append(str(metadata.get("attachment")))
    attachments.extend(list(metadata.get("attachments") or []))
    entry = {
        "category": category,
        "title": metadata.get("title") or case_dir.name,
        "challenge_id": metadata.get("challenge_id") or _slugify(case_dir.name),
        "target": metadata.get("target") or metadata.get("url") or "",
        "description": metadata.get("description") or text_hint or "",
        "hint": metadata.get("hint") or text_hint or "",
        "attachments": attachments,
        "flag_format": metadata.get("flag_format"),
        "expected_flag": metadata.get("expected_flag") or metadata.get("flag"),
    }
    if metadata.get("task"):
        entry["task"] = metadata.get("task")
    return _normalize_case_entry(entry, base_dir=case_dir, default_title=case_dir.name)


def _normalize_case_entry(item, *, base_dir, default_title):
    raw = dict(item or {})
    category = normalize_category(raw.get("category") or "")
    title = str(raw.get("title") or default_title or "case").strip()
    attachments = []
    if raw.get("attachment"):
        attachments.append(raw.get("attachment"))
    attachments.extend(list(raw.get("attachments") or []))
    resolved_attachments = []
    for attachment in attachments:
        path = Path(str(attachment)).expanduser()
        if not path.is_absolute():
            path = Path(base_dir) / path
        resolved_attachments.append(str(path.resolve()))
    target = raw.get("target") or raw.get("url") or ""
    if target:
        target_path = Path(str(target)).expanduser()
        if not str(target).startswith(("http://", "https://")) and not str(target).startswith(("tcp://", "udp://")):
            if not target_path.is_absolute():
                target_path = Path(base_dir) / target_path
            if target_path.exists():
                target = str(target_path.resolve())
    payload = {
        "category": category or "misc",
        "title": title,
        "challenge_id": raw.get("challenge_id") or _slugify(title),
        "contest_id": raw.get("contest_id") or "manual",
        "target": target,
        "url": raw.get("url") or (target if str(target).startswith(("http://", "https://")) else ""),
        "description": raw.get("description") or "",
        "hint": raw.get("hint") or "",
        "attachments": resolved_attachments,
        "flag_format": raw.get("flag_format") or r"flag\{[^{}\n]+\}",
        "expected_flag": raw.get("expected_flag") or raw.get("flag") or "",
    }
    if raw.get("task"):
        payload["task"] = raw.get("task")
    return payload


def _accumulate_category(by_category, record):
    category = record.get("category") or "unknown"
    bucket = by_category.setdefault(
        category,
        {
            "total": 0,
            "solved": 0,
            "unresolved": 0,
            "failed": 0,
            "expected_flag_count": 0,
            "matched_expected_flag": 0,
        },
    )
    bucket["total"] += 1
    status = record.get("status")
    if status in {"solved", "unresolved", "failed"}:
        bucket[status] += 1
    if record.get("expected_flag"):
        bucket["expected_flag_count"] += 1
    if record.get("matched_expected_flag"):
        bucket["matched_expected_flag"] += 1


def _finalize_category_stats(by_category):
    finalized = {}
    for category, raw in dict(by_category or {}).items():
        bucket = dict(raw or {})
        total = int(bucket.get("total", 0) or 0)
        expected = int(bucket.get("expected_flag_count", 0) or 0)
        bucket["solve_rate"] = round((bucket.get("solved", 0) / total) if total else 0.0, 4)
        bucket["expected_flag_match_rate"] = round((bucket.get("matched_expected_flag", 0) / expected) if expected else 0.0, 4)
        finalized[category] = bucket
    return finalized


def _build_review_groups(cases):
    groups = {
        "failed": [],
        "unresolved": [],
        "mismatched_flags": [],
    }
    for item in list(cases or []):
        if item.get("status") == "failed":
            groups["failed"].append(_review_case(item))
        elif item.get("status") == "unresolved":
            groups["unresolved"].append(_review_case(item))
        elif item.get("expected_flag") and not item.get("matched_expected_flag"):
            groups["mismatched_flags"].append(_review_case(item))
    return groups


def _review_case(item):
    summary = dict(item.get("board_summary") or {})
    return {
        "title": item.get("title", ""),
        "category": item.get("category", ""),
        "workspace": item.get("workspace", ""),
        "status": item.get("status", ""),
        "flag": item.get("flag", ""),
        "expected_flag": item.get("expected_flag", ""),
        "best_path": summary.get("specialized_best_path", ""),
        "used_tools": list(dict(summary.get("tool_usage") or {}).get("used", []))[:8],
        "used_mcp": list(dict(summary.get("mcp_usage") or {}).get("used", []))[:6],
        "used_remote": str(dict(summary.get("remote_usage") or {}).get("selected_host", "") or ""),
    }


def _slugify(value):
    value = str(value or "case")
    value = re.sub(r"[^a-zA-Z0-9._-]+", "-", value.strip())
    value = value.strip("-")
    return value or "case"
