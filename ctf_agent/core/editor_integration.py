import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from ctf_agent.core.config import load_agent_config


AGENT_PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SERVER_NAME = "ctf-agent"
MANAGED_START = "<!-- ctf-agent:start -->"
MANAGED_END = "<!-- ctf-agent:end -->"


def _normalize_cli_path(value: Optional[str] = None, default: Optional[Path] = None) -> Path:
    raw = Path(value) if value is not None else Path(default) if default is not None else Path.cwd()
    raw = raw.expanduser()
    if not raw.is_absolute():
        raw = Path.cwd() / raw
    return raw.absolute()


def build_editor_context(
    project_root: Optional[str] = None,
    config_path: Optional[str] = None,
    workspace_root: Optional[str] = None,
    server_name: Optional[str] = None,
) -> Dict[str, Any]:
    target_project_root = _normalize_cli_path(project_root, Path.cwd())
    resolved_config = _normalize_cli_path(config_path, AGENT_PROJECT_ROOT / "local_config.json")
    config = load_agent_config(resolved_config)
    resolved_workspace = _normalize_cli_path(workspace_root, Path(config.workspace_root))
    resolved_server_name = server_name or config.editor_policy.get("server_name") or DEFAULT_SERVER_NAME
    return {
        "agent_root": AGENT_PROJECT_ROOT,
        "project_root": target_project_root,
        "config_path": resolved_config,
        "workspace_root": resolved_workspace,
        "server_name": resolved_server_name,
        "config": config,
    }


def build_mcp_stdio_args(context: Dict[str, Any]) -> List[str]:
    return [
        "--stdio",
        "--config",
        str(context["config_path"]),
        "--workspace-root",
        str(context["workspace_root"]),
    ]


def build_mcp_stdio_entry(context: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "command": "ctf-agent-mcp",
        "args": build_mcp_stdio_args(context),
    }


def build_codex_add_command(context: Dict[str, Any]) -> List[str]:
    return [
        "codex",
        "mcp",
        "add",
        str(context["server_name"]),
        "--",
        "ctf-agent-mcp",
        *build_mcp_stdio_args(context),
    ]


def build_codex_remove_command(context: Dict[str, Any]) -> List[str]:
    return ["codex", "mcp", "remove", str(context["server_name"])]


def format_shell_command(command: List[str]) -> str:
    return subprocess.list2cmdline([str(item) for item in command])


def export_editor_assets(
    editor: str,
    project_root: Optional[str] = None,
    output_dir: Optional[str] = None,
    config_path: Optional[str] = None,
    workspace_root: Optional[str] = None,
    server_name: Optional[str] = None,
) -> Dict[str, Any]:
    context = build_editor_context(
        project_root=project_root,
        config_path=config_path,
        workspace_root=workspace_root,
        server_name=server_name,
    )
    resolved_output_dir = _normalize_cli_path(output_dir, context["project_root"] / "editor_exports")
    resolved_output_dir.mkdir(parents=True, exist_ok=True)

    result = {
        "editor": editor,
        "output_dir": str(resolved_output_dir),
        "files": [],
        "commands": [],
    }

    if editor in {"codex", "all"}:
        codex_script = resolved_output_dir / "codex_mcp_add_{0}.ps1".format(context["server_name"])
        codex_script.write_text(
            "$ErrorActionPreference = 'Stop'\n{0}\n".format(format_shell_command(build_codex_add_command(context))),
            encoding="utf-8",
        )
        result["files"].append(str(codex_script))
        result["commands"].append(format_shell_command(build_codex_add_command(context)))

    if editor in {"cursor", "all"}:
        cursor_config = resolved_output_dir / "cursor_mcp.json"
        cursor_config.write_text(
            json.dumps({"mcpServers": {context["server_name"]: build_mcp_stdio_entry(context)}}, ensure_ascii=False, indent=2)
            + "\n",
            encoding="utf-8",
        )
        result["files"].append(str(cursor_config))

        cursor_rule = resolved_output_dir / "cursor_rule_ctf-agent.mdc"
        cursor_rule.write_text(build_cursor_rule(context), encoding="utf-8")
        result["files"].append(str(cursor_rule))

    if editor in {"windsurf", "all"}:
        windsurf_config = resolved_output_dir / "windsurf_mcp_config.json"
        windsurf_config.write_text(
            json.dumps({"mcpServers": {context["server_name"]: build_mcp_stdio_entry(context)}}, ensure_ascii=False, indent=2)
            + "\n",
            encoding="utf-8",
        )
        result["files"].append(str(windsurf_config))

        windsurf_rule = resolved_output_dir / "windsurf_rule_ctf-agent.md"
        windsurf_rule.write_text(build_windsurf_rule(context), encoding="utf-8")
        result["files"].append(str(windsurf_rule))

    agents_file = resolved_output_dir / "AGENTS.md"
    agents_file.write_text(build_agents_markdown(context), encoding="utf-8")
    result["files"].append(str(agents_file))
    return result


def install_editor_integration(
    editor: str,
    project_root: Optional[str] = None,
    config_path: Optional[str] = None,
    workspace_root: Optional[str] = None,
    server_name: Optional[str] = None,
    force: bool = False,
) -> Dict[str, Any]:
    context = build_editor_context(
        project_root=project_root,
        config_path=config_path,
        workspace_root=workspace_root,
        server_name=server_name,
    )
    result = {
        "editor": editor,
        "project_root": str(context["project_root"]),
        "server_name": context["server_name"],
        "written_files": [],
        "executed_commands": [],
        "warnings": [],
    }

    if editor in {"cursor", "all"}:
        cursor_dir = context["project_root"] / ".cursor"
        cursor_rules_dir = cursor_dir / "rules"
        cursor_rules_dir.mkdir(parents=True, exist_ok=True)
        cursor_config_path = cursor_dir / "mcp.json"
        _merge_mcp_config(cursor_config_path, context["server_name"], build_mcp_stdio_entry(context))
        result["written_files"].append(str(cursor_config_path))
        cursor_rule_path = cursor_rules_dir / "ctf-agent.mdc"
        cursor_rule_path.write_text(build_cursor_rule(context), encoding="utf-8")
        result["written_files"].append(str(cursor_rule_path))

    if editor in {"windsurf", "all"}:
        windsurf_config_path = Path.home() / ".codeium" / "windsurf" / "mcp_config.json"
        windsurf_config_path.parent.mkdir(parents=True, exist_ok=True)
        _merge_mcp_config(windsurf_config_path, context["server_name"], build_mcp_stdio_entry(context))
        result["written_files"].append(str(windsurf_config_path))

        windsurf_rules_dir = context["project_root"] / ".windsurf" / "rules"
        windsurf_rules_dir.mkdir(parents=True, exist_ok=True)
        windsurf_rule_path = windsurf_rules_dir / "ctf-agent.md"
        windsurf_rule_path.write_text(build_windsurf_rule(context), encoding="utf-8")
        result["written_files"].append(str(windsurf_rule_path))

    if editor in {"codex", "all"}:
        existing = _run_codex_subprocess(["mcp", "get", str(context["server_name"]), "--json"])
        if existing.returncode == 0 and force:
            remove_command = _build_codex_exec_command(build_codex_remove_command(context))
            _run_codex_subprocess(["mcp", "remove", str(context["server_name"])])
            result["executed_commands"].append(format_shell_command(remove_command))
        if existing.returncode != 0 or force:
            add_command = _build_codex_exec_command(build_codex_add_command(context))
            completed = _run_codex_subprocess(add_command[1:])
            result["executed_commands"].append(format_shell_command(add_command))
            if completed.returncode != 0:
                result["warnings"].append((completed.stderr or completed.stdout or "codex mcp add failed").strip())
        else:
            result["warnings"].append("Codex MCP server already exists; use --force to replace it.")

    agents_path = context["project_root"] / "AGENTS.md"
    _upsert_managed_block(agents_path, build_agents_block(context))
    result["written_files"].append(str(agents_path))
    return result


def build_agents_markdown(context: Dict[str, Any]) -> str:
    return "# Workspace Instructions\n\n{0}\n".format(build_agents_block(context))


def build_agents_block(context: Dict[str, Any]) -> str:
    editor_policy = dict(context["config"].editor_policy or {})
    auto_tool = editor_policy.get("auto_tool", "run_ctf_session")
    entry_tool = editor_policy.get("recommended_entry_tool", "submit_ctf_task")
    background_tool = editor_policy.get("recommended_background_tool", "start_ctf_task")
    status_tool = editor_policy.get("status_tool", "get_ctf_task_status")
    artifact_tool = editor_policy.get("artifact_tool", "read_ctf_run_artifact")
    cancel_tool = editor_policy.get("cancel_tool", "cancel_ctf_run")
    template_tool = editor_policy.get("template_tool", "get_ctf_task_template")
    board_summary_tool = editor_policy.get("board_summary_tool", "get_ctf_board_summary")
    continue_tool = editor_policy.get("continue_tool", "continue_ctf_session")
    language = context["config"].language or "zh-CN"
    return """{start}
## CTF Agent Hub

- This workspace is for authorized CTF tasks. Route work through the local MCP hub `{server}`.
- Default to `{auto_tool}` for one-shot execution. Let that tool choose sync vs background automatically unless you need to override the policy.
- The agent now includes an embedded `ctf-skills-main` knowledge pack and will auto-select a playbook from the declared or inferred category.
- If the user says `fastest`, `最快`, `搏一把`, or `speedrun`, switch to the fastest profile: skip preview detours, avoid knowledge retrieval, keep the answer compact, and prefer the shortest runnable lane.
- In fastest mode for `pwn`, prefer the configured remote helper first and keep the lane compact.
- If a challenge is solved, output the `flag` first in chat, then the `wp_package_path`, then a short conclusion.
- Solved runs auto-export a package under `./agent-wp/<category>_<title>_wp` by default with `flag.txt`, `wp.md`, `poc.md`, and `code/`.
- Prefer this short chat format before calling `{auto_tool}`:
  ```text
  Type: web|misc|pwn|re|reverse|crypto|forensics|osint|malware
  Target:
  Files:
  - F:/path/to/attachment
  Hint:
  ```
- If you need stepwise control, first fetch the canonical task template with `{template_tool}`, then submit through `{entry_tool}`.
- If the user input is noisy, incomplete, or mixed with long free text, call `preview_ctf_task` first and then pass the normalized `quick_markdown` into `{auto_tool}`. Skip that preview round-trip when fastest mode is explicitly requested.
- For explicit stepwise long-running tasks, use `{background_tool}`.
- After `{auto_tool}` or `{background_tool}` returns a `run_id`, prefer `{continue_tool}` for follow-up polling because it combines task status and board summary into one response.
- Use `{status_tool}` only when you specifically need the raw protocol envelope instead of the chat-friendly continuation view.
- Reuse `triage_board.json`, `notes.md`, `solution.py`, and `artifacts/*` before opening a new branch.
- When a chat-friendly progress snapshot is needed, call `{board_summary_tool}` instead of manually stitching multiple artifacts.
- If `{entry_tool}` or `{background_tool}` returns `execution.status=needs_input`, stop and request the missing target or attachments listed in `validation.errors` / `summary.next_actions`.
- Only call `{cancel_tool}` when the run is clearly stuck or the user explicitly asks to stop it.
- Keep the final answer in Chinese unless the user explicitly asks for another language. Current default language: `{language}`.
- Do not expose nested IDA / Ghidra / browser MCP servers directly to the editor. Those capabilities stay behind `ctf-agent-mcp`.
- MCP startup parameters:
  - config: `{config_path}`
  - workspace_root: `{workspace_root}`
{end}
""".format(
        start=MANAGED_START,
        end=MANAGED_END,
        server=context["server_name"],
        auto_tool=auto_tool,
        entry_tool=entry_tool,
        background_tool=background_tool,
        status_tool=status_tool,
        continue_tool=continue_tool,
        artifact_tool=artifact_tool,
        cancel_tool=cancel_tool,
        template_tool=template_tool,
        board_summary_tool=board_summary_tool,
        language=language,
        config_path=context["config_path"],
        workspace_root=context["workspace_root"],
    )


def build_cursor_rule(context: Dict[str, Any]) -> str:
    editor_policy = dict(context["config"].editor_policy or {})
    auto_tool = editor_policy.get("auto_tool", "run_ctf_session")
    entry_tool = editor_policy.get("recommended_entry_tool", "submit_ctf_task")
    background_tool = editor_policy.get("recommended_background_tool", "start_ctf_task")
    template_tool = editor_policy.get("template_tool", "get_ctf_task_template")
    board_summary_tool = editor_policy.get("board_summary_tool", "get_ctf_board_summary")
    continue_tool = editor_policy.get("continue_tool", "continue_ctf_session")
    return """---
description: Use the local ctf-agent MCP hub for authorized CTF tasks in this workspace.
alwaysApply: true
---

- Default to `{auto_tool}` for authorized CTF tasks. Let that tool choose sync vs background automatically unless you need to override the policy.
- The local agent embeds `ctf-skills-main` and auto-selects the matching playbook before execution.
- If the prompt contains `fastest`, `最快`, `搏一把`, or `speedrun`, use the fastest profile: skip knowledge detours, minimize tool calls, and keep the answer short.
- In fastest `pwn` runs, stay remote-first and prefer the configured remote helper / remote templates before local-only debugging.
- If a challenge is solved, return the `flag` on the first line, then the `wp_package_path`, then the short answer.
- Solved runs auto-export a package under `./agent-wp/<category>_<title>_wp` by default with `flag.txt`, `wp.md`, `poc.md`, and `code/`.
- Before calling `{auto_tool}`, normalize the user input into this short format:
  ```text
  Type: web|misc|pwn|re|reverse|crypto|forensics|osint|malware
  Target:
  Files:
  - F:/path/to/attachment
  Hint:
  ```
- If you need stepwise control, first structure the task text with the template from `{template_tool}`, then call `{entry_tool}`.
- If the input is noisy or ambiguous, call `preview_ctf_task` first and then use its `suggested_task.quick_markdown`. Skip that preview hop when fastest mode is explicitly requested.
- If the protocol response returns `execution.status=needs_input`, stop and request the missing target or attachments instead of guessing.
- If the task is long-running, use `{background_tool}`.
- After `{auto_tool}` or `{background_tool}` returns a `run_id`, prefer `{continue_tool}` for follow-up polling because it combines status and board summary into one response.
- If you need a concise board view for the chat window, call `{board_summary_tool}`.
- Reuse `triage_board.json`, `notes.md`, `solution.py`, and `artifacts/*` before trying another path.
- Keep output in Chinese unless the user explicitly requests another language.
    """.format(
        auto_tool=auto_tool,
        entry_tool=entry_tool,
        background_tool=background_tool,
        template_tool=template_tool,
        board_summary_tool=board_summary_tool,
        continue_tool=continue_tool,
    )


def build_windsurf_rule(context: Dict[str, Any]) -> str:
    editor_policy = dict(context["config"].editor_policy or {})
    auto_tool = editor_policy.get("auto_tool", "run_ctf_session")
    entry_tool = editor_policy.get("recommended_entry_tool", "submit_ctf_task")
    background_tool = editor_policy.get("recommended_background_tool", "start_ctf_task")
    template_tool = editor_policy.get("template_tool", "get_ctf_task_template")
    board_summary_tool = editor_policy.get("board_summary_tool", "get_ctf_board_summary")
    continue_tool = editor_policy.get("continue_tool", "continue_ctf_session")
    return """---
trigger: always_on
---

- Default to `{auto_tool}` for authorized CTF tasks. Let that tool choose sync vs background automatically unless you need to override the policy.
- The local agent embeds `ctf-skills-main` and auto-selects the matching playbook before execution.
- Before calling `{auto_tool}`, normalize the user input into this short format:
  ```text
  Type: web|misc|pwn|re|reverse|crypto|forensics|osint|malware
  Target:
  Files:
  - F:/path/to/attachment
  Hint:
  ```
- If you need stepwise control, first structure the task text with `{template_tool}`, then route work through `{entry_tool}`.
- If the input is noisy or ambiguous, call `preview_ctf_task` first and then use its `suggested_task.quick_markdown`.
- If the protocol response returns `execution.status=needs_input`, stop and ask for the missing target or attachments.
- For long-running work, use `{background_tool}`.
- After `{auto_tool}` or `{background_tool}` returns a `run_id`, prefer `{continue_tool}` for follow-up polling because it combines status and board summary into one response.
- If you need a compact board snapshot for the conversation, call `{board_summary_tool}`.
- Read `triage_board.json`, `notes.md`, `solution.py`, and `artifacts/*` before branching into a new exploit path.
- Keep the final answer in Chinese unless the user explicitly requests another language.
    """.format(
        auto_tool=auto_tool,
        entry_tool=entry_tool,
        background_tool=background_tool,
        template_tool=template_tool,
        board_summary_tool=board_summary_tool,
        continue_tool=continue_tool,
    )


def _merge_mcp_config(path: Path, server_name: str, server_entry: Dict[str, Any]) -> None:
    payload: Dict[str, Any] = {}
    if path.exists():
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            payload = {}
    payload.setdefault("mcpServers", {})
    payload["mcpServers"][server_name] = server_entry
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _upsert_managed_block(path: Path, block: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = path.read_text(encoding="utf-8") if path.exists() else ""
    normalized_block = block.strip() + "\n"
    if MANAGED_START in existing and MANAGED_END in existing:
        start = existing.index(MANAGED_START)
        end = existing.index(MANAGED_END) + len(MANAGED_END)
        updated = existing[:start].rstrip() + "\n\n" + normalized_block + existing[end:]
    else:
        updated = existing.rstrip()
        if updated:
            updated += "\n\n"
        updated += normalized_block
    path.write_text(updated.rstrip() + "\n", encoding="utf-8")


def _build_codex_exec_command(command: List[str]) -> List[str]:
    executable = _find_codex_executable()
    return [executable, *list(command[1:])]


def _run_codex_subprocess(arguments: List[str]) -> subprocess.CompletedProcess:
    executable = _find_codex_executable()
    return subprocess.run(
        [executable, *list(arguments)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )


def _find_codex_executable() -> str:
    for name in ["codex.cmd", "codex.exe", "codex"]:
        path = shutil.which(name)
        if path:
            return path
    raise FileNotFoundError("codex executable not found on PATH")
