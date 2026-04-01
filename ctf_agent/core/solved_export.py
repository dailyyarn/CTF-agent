import json
import shutil
from datetime import datetime
from pathlib import Path

from ctf_agent.core.workspace import WorkspaceManager


EXPORT_SUMMARY_FILENAME = "wp_export.json"
DEFAULT_EXPORT_POLICY = {
    "enabled": True,
    "root": "./agent-wp",
    "duplicate_policy": "increment",
    "emit_flag_first": True,
    "copy_artifacts": True,
}


def normalize_export_policy(policy=None):
    merged = dict(DEFAULT_EXPORT_POLICY)
    merged.update(dict(policy or {}))
    merged["enabled"] = bool(merged.get("enabled", True))
    merged["emit_flag_first"] = bool(merged.get("emit_flag_first", True))
    merged["copy_artifacts"] = bool(merged.get("copy_artifacts", True))
    merged["root"] = str(merged.get("root") or DEFAULT_EXPORT_POLICY["root"]).strip() or DEFAULT_EXPORT_POLICY["root"]
    duplicate_policy = str(merged.get("duplicate_policy") or "increment").strip().lower()
    if duplicate_policy not in {"increment", "overwrite", "timestamp"}:
        duplicate_policy = "increment"
    merged["duplicate_policy"] = duplicate_policy
    return merged


def build_flag_first_text(flag, wp_package_path="", wp_warning=""):
    flag = str(flag or "").strip()
    if not flag:
        return ""
    lines = ["flag: {0}".format(flag)]
    package_path = str(wp_package_path or "").strip()
    if package_path:
        lines.append("wp_package_path: {0}".format(package_path))
    warning = str(wp_warning or "").strip()
    if warning:
        lines.append("wp_warning: {0}".format(warning))
    return "\n".join(lines)


def load_workspace_export_summary(workspace):
    workspace_path = Path(workspace) if workspace else None
    if not workspace_path:
        return {}
    summary_path = workspace_path / EXPORT_SUMMARY_FILENAME
    if summary_path.exists():
        try:
            return json.loads(summary_path.read_text(encoding="utf-8-sig"))
        except Exception:
            return {}
    board_path = workspace_path / "triage_board.json"
    if not board_path.exists():
        return {}
    try:
        board = json.loads(board_path.read_text(encoding="utf-8-sig"))
    except Exception:
        return {}
    return dict(board.get("solved_export") or {})


def export_solved_workspace(challenge, result, policy=None):
    normalized_policy = normalize_export_policy(policy)
    summary = _base_summary(result=result, policy=normalized_policy)
    if not normalized_policy.get("enabled", True):
        summary["wp_warning"] = "export policy is disabled"
        summary["flag_first_text"] = build_flag_first_text(summary["flag"], "", summary["wp_warning"])
        return summary
    if str(result.get("status") or "") != "solved" or not str(result.get("flag") or "").strip():
        return summary

    workspace_text = str(result.get("workspace") or "").strip()
    if not workspace_text:
        summary["wp_warning"] = "workspace is missing"
        summary["flag_first_text"] = build_flag_first_text(summary["flag"], "", summary["wp_warning"])
        return summary
    workspace = Path(workspace_text).expanduser()
    summary["workspace"] = str(workspace)

    try:
        package_root = Path(normalized_policy["root"]).expanduser().absolute()
        package_root.mkdir(parents=True, exist_ok=True)
        summary["wp_root"] = str(package_root)

        package_dir = _allocate_package_dir(
            package_root=package_root,
            base_name=_build_package_name(challenge),
            duplicate_policy=normalized_policy.get("duplicate_policy", "increment"),
        )
        package_dir.mkdir(parents=True, exist_ok=True)

        board = _read_json(workspace / "triage_board.json")
        state = _read_json(workspace / "state.json")
        notes_path = _pick_first_existing(workspace / "notes.md", workspace / "agent_loop_notes.md")
        notes_text = _read_text(notes_path)
        solution_path = _pick_first_existing(workspace / "solution.py", workspace / "artifacts" / "solution_generated.py")

        flag_value = str(result.get("flag") or "").strip()
        (package_dir / "flag.txt").write_text(flag_value + "\n", encoding="utf-8-sig")

        wp_text = _render_wp_markdown(challenge, result, board, state, notes_text)
        poc_text = _render_poc_markdown(challenge, result, board, state, notes_text)
        (package_dir / "wp.md").write_text(wp_text, encoding="utf-8-sig")
        (package_dir / "poc.md").write_text(poc_text, encoding="utf-8-sig")

        code_dir = package_dir / "code"
        code_dir.mkdir(parents=True, exist_ok=True)
        copied_files = _copy_code_artifacts(
            workspace=workspace,
            code_dir=code_dir,
            solution_path=solution_path,
            copy_artifacts=normalized_policy.get("copy_artifacts", True),
        )

        meta_payload = {
            "generated_at": datetime.now().isoformat(),
            "title": getattr(challenge, "title", "") or "",
            "category": getattr(challenge, "category", "") or "",
            "challenge_id": getattr(challenge, "challenge_id", "") or "",
            "contest_id": getattr(challenge, "contest_id", "") or "",
            "target": getattr(challenge, "target", "") or "",
            "workspace": str(workspace),
            "solver": str(result.get("solver") or ""),
            "status": str(result.get("status") or ""),
            "flag": flag_value,
            "notes_path": str(notes_path) if notes_path else "",
            "solution_path": str(solution_path) if solution_path else "",
            "copied_files": copied_files,
        }
        (package_dir / "meta.json").write_text(
            json.dumps(meta_payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8-sig",
        )

        summary.update(
            {
                "status": "ok",
                "wp_exported": True,
                "wp_package_path": str(package_dir),
                "package_name": package_dir.name,
                "wp_summary_path": str(workspace / EXPORT_SUMMARY_FILENAME),
                "copied_files": copied_files,
            }
        )
    except Exception as exc:
        summary["status"] = "error"
        summary["wp_warning"] = str(exc)

    summary["flag_first_text"] = build_flag_first_text(
        summary.get("flag", ""),
        summary.get("wp_package_path", ""),
        summary.get("wp_warning", ""),
    )
    _persist_workspace_export_summary(summary)
    return summary


def _base_summary(result, policy):
    return {
        "status": "",
        "wp_exported": False,
        "wp_package_path": "",
        "wp_root": str(policy.get("root") or ""),
        "wp_warning": "",
        "wp_summary_path": "",
        "flag": str((result or {}).get("flag") or ""),
        "flag_first_text": "",
        "duplicate_policy": str(policy.get("duplicate_policy") or "increment"),
        "workspace": str((result or {}).get("workspace") or ""),
        "package_name": "",
        "copied_files": [],
    }


def _build_package_name(challenge):
    category = getattr(challenge, "category", "") or "ctf"
    title = getattr(challenge, "title", "") or getattr(challenge, "challenge_id", "") or "challenge"
    return WorkspaceManager.slugify("{0}_{1}_wp".format(category, title))


def _allocate_package_dir(package_root, base_name, duplicate_policy):
    package_root = Path(package_root)
    base_dir = package_root / (base_name or "ctf_wp")
    if duplicate_policy == "overwrite":
        if base_dir.exists():
            shutil.rmtree(base_dir)
        return base_dir
    if duplicate_policy == "timestamp":
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return package_root / "{0}_{1}".format(base_name, stamp)
    if not base_dir.exists():
        return base_dir
    index = 2
    while True:
        candidate = package_root / "{0}_{1}".format(base_name, index)
        if not candidate.exists():
            return candidate
        index += 1


def _persist_workspace_export_summary(summary):
    workspace = Path(summary.get("workspace") or "") if summary.get("workspace") else None
    if not workspace:
        return
    summary_path = workspace / EXPORT_SUMMARY_FILENAME
    try:
        summary_path.write_text(
            json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8-sig",
        )
    except Exception:
        return
    board_path = workspace / "triage_board.json"
    if not board_path.exists():
        return
    try:
        board = json.loads(board_path.read_text(encoding="utf-8-sig"))
    except Exception:
        return
    board["solved_export"] = {
        "wp_exported": bool(summary.get("wp_exported", False)),
        "wp_package_path": str(summary.get("wp_package_path") or ""),
        "wp_root": str(summary.get("wp_root") or ""),
        "wp_warning": str(summary.get("wp_warning") or ""),
        "flag_first_text": str(summary.get("flag_first_text") or ""),
        "wp_summary_path": str(summary.get("wp_summary_path") or ""),
        "package_name": str(summary.get("package_name") or ""),
    }
    artifacts = dict(board.get("artifacts") or {})
    artifacts["wp_export_path"] = str(summary_path)
    artifacts["wp_package_path"] = str(summary.get("wp_package_path") or "")
    artifacts["wp_root"] = str(summary.get("wp_root") or "")
    board["artifacts"] = artifacts
    try:
        board_path.write_text(json.dumps(board, ensure_ascii=False, indent=2) + "\n", encoding="utf-8-sig")
    except Exception:
        return


def _render_wp_markdown(challenge, result, board, state, notes_text):
    lines = [
        "# WP",
        "",
        "## 基本信息",
        "- 题目: {0}".format(getattr(challenge, "title", "") or "-"),
        "- 方向: {0}".format(getattr(challenge, "category", "") or "-"),
        "- 状态: {0}".format(str(result.get("status") or "") or "-"),
        "- Flag: {0}".format(str(result.get("flag") or "") or "-"),
        "- Solver: {0}".format(str(result.get("solver") or "") or "-"),
        "- Target: {0}".format(getattr(challenge, "target", "") or "-"),
        "",
        "## 解题结论",
        "- 最终先以工作区中的可复现链路为准。",
        "- 建议优先复跑 `code/` 目录中的脚本或工作区 `solution.py` 对应链路。",
    ]
    best_path = str(((board.get("binary") or {}).get("best_path")) or board.get("recommended_path") or "")
    if best_path:
        lines.append("- Best Path: {0}".format(best_path))
    protections = dict((board.get("binary") or {}).get("protections") or {})
    if protections:
        lines.extend(["", "## 保护与环境"])
        for key in sorted(protections.keys()):
            lines.append("- {0}: {1}".format(key, protections.get(key)))
    exploit_plans = list((board.get("exploit_plans") or state.get("exploit_plans") or []))
    if exploit_plans:
        lines.extend(["", "## 关键利用路径"])
        for item in exploit_plans[:5]:
            if isinstance(item, dict):
                title = str(item.get("title") or item.get("method") or "").strip()
                method = str(item.get("method") or "").strip()
                if title:
                    lines.append("- {0}{1}".format(title, " ({0})".format(method) if method else ""))
    recommended_templates = list((board.get("binary") or {}).get("recommended_remote_templates") or [])
    if recommended_templates:
        lines.extend(["", "## Remote Templates"])
        for item in recommended_templates[:8]:
            lines.append("- {0}".format(item))
    if notes_text.strip():
        lines.extend(["", "## 工作区原始笔记摘录", notes_text.strip()[:6000]])
    return "\n".join(lines).strip() + "\n"


def _render_poc_markdown(challenge, result, board, state, notes_text):
    lines = [
        "# PoC",
        "",
        "## 输出顺序",
        "1. 先在对话中返回 flag。",
        "2. 再引用本目录下的 `wp.md`、`poc.md`、`code/`。",
        "",
        "## 最短复现",
        "- 工作区: {0}".format(str(result.get("workspace") or "") or "-"),
        "- Solver: {0}".format(str(result.get("solver") or "") or "-"),
        "- Flag: {0}".format(str(result.get("flag") or "") or "-"),
    ]
    target = getattr(challenge, "target", "") or ""
    if target:
        lines.append("- Target: {0}".format(target))
    best_path = str(((board.get("binary") or {}).get("best_path")) or board.get("recommended_path") or "")
    if best_path:
        lines.append("- Best Path: {0}".format(best_path))
    candidate_flags = list(state.get("candidate_flags") or [])
    if candidate_flags:
        lines.extend(["", "## 结果确认"])
        for item in candidate_flags[:3]:
            if isinstance(item, dict):
                lines.append(
                    "- {0} | source={1} | reproducible={2}".format(
                        str(item.get("value") or ""),
                        str(item.get("source") or ""),
                        bool(item.get("reproducible", False)),
                    )
                )
    pwn_capabilities = dict((board.get("binary") or {}).get("pwn_capabilities") or {})
    if pwn_capabilities:
        lines.extend(["", "## Pwn 环境提示"])
        for key in ["gdbserver", "qemu_user", "one_gadget", "pwninit", "libc_patch_tooling"]:
            if key in pwn_capabilities:
                lines.append("- {0}: {1}".format(key, "yes" if pwn_capabilities.get(key) else "no"))
        missing = list(pwn_capabilities.get("missing") or [])
        if missing:
            lines.append("- missing: {0}".format(", ".join(missing)))
    lines.extend(
        [
            "",
            "## 建议执行",
            "- 优先查看 `code/solution.py`。",
            "- 如果存在额外脚本，再查看 `code/` 内的 pwntools / runner / probe 文件。",
            "- 若需原始分析上下文，回到工作区 `notes.md`、`triage_board.json`、`state.json`。",
        ]
    )
    if notes_text.strip():
        lines.extend(["", "## 备注", notes_text.strip()[:3000]])
    return "\n".join(lines).strip() + "\n"


def _copy_code_artifacts(workspace, code_dir, solution_path=None, copy_artifacts=True):
    copied = []
    candidates = []
    if solution_path and Path(solution_path).exists():
        candidates.append(Path(solution_path))
    candidates.extend(
        [
            workspace / "solution.py",
            workspace / "artifacts" / "solution_generated.py",
        ]
    )
    seen = set()
    for candidate in candidates:
        candidate = Path(candidate)
        if not candidate.exists():
            continue
        marker = str(candidate.resolve()).lower()
        if marker in seen:
            continue
        seen.add(marker)
        target = code_dir / candidate.name
        shutil.copy2(candidate, target)
        copied.append(str(target))
    if not copy_artifacts:
        return copied

    artifact_dir = workspace / "artifacts"
    if not artifact_dir.exists():
        return copied
    patterns = ("*.py", "*.sh", "*.ps1", "*.cmd")
    for pattern in patterns:
        for candidate in sorted(artifact_dir.glob(pattern)):
            marker = str(candidate.resolve()).lower()
            if marker in seen:
                continue
            seen.add(marker)
            target = code_dir / candidate.name
            shutil.copy2(candidate, target)
            copied.append(str(target))
    return copied


def _read_json(path):
    path = Path(path)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return {}


def _read_text(path):
    if not path:
        return ""
    path = Path(path)
    if not path.exists():
        return ""
    try:
        return path.read_text(encoding="utf-8-sig", errors="replace")
    except Exception:
        return ""


def _pick_first_existing(*paths):
    for path in paths:
        candidate = Path(path)
        if candidate.exists():
            return candidate
    return None
