"""ReAct Agent Loop with tool enhancement, multi-turn, and parallel subtasks.

Implements:
- Phase 2: Observe -> Think -> Act loop with tool calling
- Phase 5: Periodic self-reflection and strategy adjustment
- Feature 6: Extended tool set (remote, decompile, browse, extract, diff)
- Feature 7: Multi-turn pause/resume with user hints
- Feature 8: Parallel subtask planning and execution
"""

import json
import logging
import os
import re
import shutil
import sys
import tarfile
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from ctf_agent.core.board import build_triage_board
from ctf_agent.core.execution_policy import ExecutionPolicy
from ctf_agent.core.memory import StateMemory
from ctf_agent.core.models import ChallengeState, SubAgentRecord, SubAgentSpec
from ctf_agent.core.workspace import WorkspaceManager
from ctf_agent.knowledge import SkillResolver

logger = logging.getLogger(__name__)

_DEFAULT_MAX_STEPS = 25
_DEFAULT_MAX_TOKENS = 120000
_REFLECTION_INTERVAL = 5
_MIN_STEPS_BEFORE_REFLECTION = 3
_TOOL_OUTPUT_CAP = 12000
_KNOWLEDGE_CAP = 3000
_PARALLEL_WORKERS = 4
_SUBTASK_TIMEOUT = 60
_DEFAULT_SUBAGENT_MAX_TOKENS = 2000000

SYSTEM_PROMPT = """\
你是一个专业的 CTF 解题 AI Agent。你的目标是分析题目、使用工具、编写并运行代码，最终找到 flag。

## 工作原则
1. 先观察、再推理、再行动（Observe -> Think -> Act）。
2. 每次行动后仔细检查结果，决定下一步。
3. 如果一条路走不通，主动反思原因并换方向。
4. 优先复用已有工具和知识。
5. 需要计算、解码、爆破时直接编写 Python 脚本并运行。
6. 找到 flag 后在回复中写 [FLAG]flag值[/FLAG]。
7. 如果题目有多个附件或多条线索，可调用 plan_parallel 拆分成子任务并行处理。

## 可用工具
{tool_list}

## 相关知识
{knowledge}
"""

REFLECTION_PROMPT = """\
回顾当前 CTF 解题进度并给出下一步建议。

## 状态
阶段: {phase}  |  已执行步骤: {n_actions}  |  候选 flag 数: {n_flags}

## 已尝试
{tried}

## 假设
{hypotheses}

## 线索
{findings}

请用 3-5 句话总结：哪些尝试有效、哪些无效、下一步最有希望的方向。"""

PARALLEL_PLAN_PROMPT = """\
你是一个 CTF 子任务规划器。给定题目信息和当前状态，把剩余工作拆成 2-4 个可以并行执行的子任务。

每个子任务必须包含：
- tool: 要调用的工具名
- args: 工具参数（JSON 对象）
- purpose: 这个子任务要解决什么

以 JSON 数组返回，例如:
[
  {"tool": "shell", "args": {"command": "strings file.bin"}, "purpose": "提取可打印字符串"},
  {"tool": "run_python", "args": {"code": "import base64; ..."}, "purpose": "尝试 base64 解码"}
]

## 当前题目
{challenge}

## 当前已知线索
{findings}

## 可用工具
{tools}
"""

FASTEST_APPENDIX = """\

## Fastest Mode
- Use the minimum viable tool path and avoid detours.
- Do not call knowledge-retrieval tools unless the user explicitly overrides this mode.
- Prefer one larger runnable script over many tiny experiments.
- Keep explanations short and focus on result, exploit direction, or blocker.
- For pwn tasks, stay remote-first and prefer remote Python / remote templates before local-only work.
"""

FLAG_TAG_RE = re.compile(r"\[FLAG\]\s*(.+?)\s*\[/FLAG\]", re.S)


# =====================================================================
# Tool Registry
# =====================================================================

class ToolRegistry:
    """Registry of callable tools exposed to the LLM."""

    def __init__(self):
        self._tools = {}  # type: Dict[str, Dict[str, Any]]
        self._last_result = None

    def register(self, name, func, description, parameters):
        self._tools[name] = {
            "func": func,
            "description": description,
            "parameters": parameters,
        }

    def get(self, name):
        return self._tools.get(name)

    def execute(self, name, arguments):
        tool = self._tools.get(name)
        if not tool:
            return "[ERROR] Unknown tool: {0}".format(name)
        try:
            result = tool["func"](arguments)
            self._last_result = result
            if not isinstance(result, str):
                result = json.dumps(result, ensure_ascii=False, indent=2)
            return result[:_TOOL_OUTPUT_CAP]
        except Exception as exc:
            logger.warning("Tool %s failed: %s", name, exc, exc_info=True)
            self._last_result = {"status": "error", "message": str(exc), "tool": name}
            return "[ERROR] {0}: {1}".format(name, exc)

    def to_openai_tools(self):
        return [
            {
                "type": "function",
                "function": {
                    "name": name,
                    "description": info["description"],
                    "parameters": info["parameters"],
                },
            }
            for name, info in self._tools.items()
        ]

    def describe(self):
        return "\n".join(
            "- **{0}**: {1}".format(n, i["description"])
            for n, i in self._tools.items()
        )

    def without_names(self, names):
        filtered = ToolRegistry()
        denied = {str(item).strip() for item in list(names or []) if str(item).strip()}
        for name, info in self._tools.items():
            if name in denied:
                continue
            filtered.register(name, info["func"], info["description"], info["parameters"])
        return filtered

    def only_names(self, names):
        filtered = ToolRegistry()
        allowed = {str(item).strip() for item in list(names or []) if str(item).strip()}
        if not allowed:
            return filtered
        for name, info in self._tools.items():
            if name not in allowed:
                continue
            filtered.register(name, info["func"], info["description"], info["parameters"])
        return filtered

    @property
    def names(self):
        return list(self._tools.keys())


# =====================================================================
# Tool Builders (Feature 6: extended tool set)
# =====================================================================

def build_default_tools(
    code_executor=None,
    knowledge_retriever=None,
    verifier=None,
    file_tool=None,
    shell_tool=None,
    toolkit_tool=None,
    http_tool=None,
    remote_tool=None,
    mcp_registry=None,
    oob_tool=None,
    workspace=None,
    plugin_registry=None,
):
    """Create a ToolRegistry with the full CTF tool set (original 7 + 5 new)."""
    reg = ToolRegistry()

    # --- Original 7 tools ---

    if code_executor:
        def _run_python(args):
            code = args.get("code", "")
            desc = args.get("description", "")
            res = code_executor.execute(code, workspace=workspace, description=desc)
            return res.output

        reg.register("run_python", _run_python,
            "Execute a Python script and return stdout/stderr. "
            "Use for decoding, crypto, data processing, exploit scripting.",
            {
                "type": "object",
                "properties": {
                    "code": {"type": "string", "description": "Python source code"},
                    "description": {"type": "string", "description": "Brief description"},
                },
                "required": ["code"],
            })

    if knowledge_retriever and knowledge_retriever.is_loaded():
        def _search_knowledge(args):
            q = args.get("query", "")
            source = args.get("source", None)
            cat = args.get("category", None)
            results = knowledge_retriever.query(q, top_k=4, category_hint=cat, source_filter=source)
            if not results:
                return "No relevant knowledge found."
            parts = []
            for r in results:
                label = "playbook" if r["source_type"] == "skills" else "writeup"
                parts.append("[{0}] {1}\nSource: {2}\n\n{3}".format(
                    label, r.get("heading", ""), r["source_file"], r["text"][:600]))
            return "\n---\n".join(parts)

        reg.register("search_knowledge", _search_knowledge,
            "Search CTF knowledge base (playbooks + wiki writeups) for techniques and prior experience.",
            {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query"},
                    "source": {"type": "string", "enum": ["skills", "wiki"]},
                    "category": {"type": "string", "description": "Category hint"},
                },
                "required": ["query"],
            })

    if file_tool:
        def _read_file(args):
            path = args.get("path", "")
            try:
                data = file_tool.read_text(path, limit=8000)
                return data if data else "(empty file)"
            except Exception as exc:
                return "[ERROR] {0}".format(exc)

        reg.register("read_file", _read_file,
            "Read text content of a local file.",
            {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path"},
                },
                "required": ["path"],
            })

    if shell_tool:
        def _shell(args):
            cmd = args.get("command", "")
            timeout = int(args.get("timeout", 15))
            try:
                result = shell_tool.run(cmd, timeout=timeout)
                if isinstance(result, dict) and result.get("status") == "needs_approval":
                    return result
                parts = []
                out = str(result.get("stdout", "") or "")
                err = str(result.get("stderr", "") or "")
                rc = result.get("returncode", -1)
                if out:
                    parts.append(out[:6000])
                if err:
                    parts.append("[stderr] " + err[:2000])
                parts.append("[exit_code={0}]".format(rc))
                return "\n".join(parts)
            except Exception as exc:
                return "[ERROR] {0}".format(exc)

        reg.register("shell", _shell,
            "Run a shell command (strings, file, checksec, binwalk, exiftool, etc.).",
            {
                "type": "object",
                "properties": {
                    "command": {"type": "string"},
                    "timeout": {"type": "integer", "default": 15},
                },
                "required": ["command"],
            })

    if toolkit_tool and toolkit_tool.is_configured():
        def _local_tool(args):
            tool_name = args.get("tool", "")
            tool_args = args.get("args", "")
            input_file = args.get("input_file", "")
            try:
                result = toolkit_tool.run_tool(tool_name, tool_args, input_file=input_file)
                return str(result)[:6000]
            except Exception as exc:
                return "[ERROR] {0}".format(exc)

        reg.register("local_tool", _local_tool,
            "Run a local CTF toolkit tool (strings, checksec, ROPgadget, steghide, etc.).",
            {
                "type": "object",
                "properties": {
                    "tool": {"type": "string", "description": "Tool name"},
                    "args": {"type": "string", "description": "Arguments"},
                    "input_file": {"type": "string"},
                },
                "required": ["tool"],
            })

    if http_tool:
        def _http(args):
            method = args.get("method", "GET").upper()
            url = args.get("url", "")
            data = args.get("data", None)
            headers = args.get("headers", {})
            try:
                resp = http_tool.request(method, url, data=data, headers=headers)
                parts = ["HTTP {0}".format(resp.get("status", "?"))]
                body = resp.get("body", "")
                if body:
                    parts.append(body[:4000])
                return "\n".join(parts)
            except Exception as exc:
                return "[ERROR] {0}".format(exc)

        reg.register("http_request", _http,
            "Make an HTTP request to a target URL.",
            {
                "type": "object",
                "properties": {
                    "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "PATCH"]},
                    "url": {"type": "string"},
                    "data": {"type": "string"},
                    "headers": {"type": "object"},
                },
                "required": ["url"],
            })

    if verifier:
        def _scan(args):
            text = args.get("text", "")
            found = verifier.discover_from_text(text)
            if found:
                return "Found flags: " + ", ".join(found)
            return "No flags found in the provided text."

        reg.register("scan_for_flags", _scan,
            "Scan text for CTF flags (flag{...}, FLAG{...}, ctf{...}).",
            {
                "type": "object",
                "properties": {
                    "text": {"type": "string"},
                },
                "required": ["text"],
            })

    # --- Feature 6: New tools ---

    # 8. run_remote_python — execute Python on a remote Linux host
    if remote_tool:
        def _run_remote_python(args):
            host = args.get("host", "")
            code = args.get("code", "")
            timeout = int(args.get("timeout", 30))
            if not host:
                hosts = remote_tool.list_hosts()
                host = hosts[0] if hosts else ""
            if not host:
                return "[ERROR] No remote host configured"
            try:
                result = remote_tool.run_python(host, code, timeout=timeout)
                if isinstance(result, dict) and result.get("status") == "needs_approval":
                    return result
                return str(result)[:_TOOL_OUTPUT_CAP]
            except Exception as exc:
                return "[ERROR] remote_python: {0}".format(exc)

        reg.register("run_remote_python", _run_remote_python,
            "Execute Python code on a remote Linux helper host via SSH. "
            "Use for pwn exploits (pwntools), Linux-only tools, or when local execution fails.",
            {
                "type": "object",
                "properties": {
                    "code": {"type": "string", "description": "Python code to run on the remote host"},
                    "host": {"type": "string", "description": "Host name (default: auto-select)"},
                    "timeout": {"type": "integer", "default": 30},
                },
                "required": ["code"],
            })

        # 9. run_remote_command
        def _run_remote_cmd(args):
            host = args.get("host", "")
            command = args.get("command", "")
            timeout = int(args.get("timeout", 20))
            if not host:
                hosts = remote_tool.list_hosts()
                host = hosts[0] if hosts else ""
            if not host:
                return "[ERROR] No remote host configured"
            try:
                result = remote_tool.run_command(host, command, timeout=timeout)
                if isinstance(result, dict) and result.get("status") == "needs_approval":
                    return result
                return str(result)[:_TOOL_OUTPUT_CAP]
            except Exception as exc:
                return "[ERROR] remote_command: {0}".format(exc)

        reg.register("run_remote_command", _run_remote_cmd,
            "Run a shell command on a remote Linux host via SSH.",
            {
                "type": "object",
                "properties": {
                    "command": {"type": "string"},
                    "host": {"type": "string"},
                    "timeout": {"type": "integer", "default": 20},
                },
                "required": ["command"],
            })

    # 10. decompile_function — via IDA/Ghidra MCP
    if mcp_registry and mcp_registry.has_servers():
        def _decompile(args):
            binary_path = args.get("binary_path", "")
            function = args.get("function", "main")
            try:
                server = mcp_registry.find_server("ida") or mcp_registry.find_server("ghidra")
                if not server:
                    return "[ERROR] No reverse-engineering MCP server available"
                result = mcp_registry.call_tool_safe(
                    server["name"],
                    "decompile_function",
                    {"binary_path": binary_path, "function_name": function},
                )
                if result.get("status") == "needs_approval":
                    return result
                if result.get("ok"):
                    parts = [str(result.get("result_preview", "") or result.get("summary", ""))]
                    if result.get("saved_to"):
                        parts.append("[full_result] {0}".format(result.get("saved_to")))
                    return "\n".join([item for item in parts if item])[:_TOOL_OUTPUT_CAP]
                return mcp_registry.flatten_tool_result(result.get("error"))[:_TOOL_OUTPUT_CAP]
            except Exception as exc:
                return "[ERROR] decompile: {0}".format(exc)

        reg.register("decompile_function", _decompile,
            "Decompile a function from a binary using IDA Pro or Ghidra MCP. "
            "Use for reverse engineering challenges.",
            {
                "type": "object",
                "properties": {
                    "binary_path": {"type": "string", "description": "Path to binary file"},
                    "function": {"type": "string", "description": "Function name (default: main)"},
                },
                "required": ["binary_path"],
            })

        # 11. browse_url — via browser MCP
        def _browse(args):
            url = args.get("url", "")
            action = args.get("action", "screenshot")
            try:
                server = mcp_registry.find_server("browser")
                if not server:
                    return "[ERROR] No browser MCP server available"
                result = mcp_registry.call_tool_safe(
                    server["name"],
                    "browse" if action == "browse" else "screenshot",
                    {"url": url},
                )
                if result.get("status") == "needs_approval":
                    return result
                if result.get("ok"):
                    parts = [str(result.get("result_preview", "") or result.get("summary", ""))]
                    if result.get("saved_to"):
                        parts.append("[full_result] {0}".format(result.get("saved_to")))
                    return "\n".join([item for item in parts if item])[:_TOOL_OUTPUT_CAP]
                return mcp_registry.flatten_tool_result(result.get("error"))[:_TOOL_OUTPUT_CAP]
            except Exception as exc:
                return "[ERROR] browse: {0}".format(exc)

        reg.register("browse_url", _browse,
            "Visit a URL using a headless browser (for SPAs, JavaScript-rendered pages, login flows).",
            {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "action": {"type": "string", "enum": ["browse", "screenshot"], "default": "browse"},
                },
                "required": ["url"],
            })

    # 12. extract_archive — unpack zip/tar/gz/7z
    def _extract_archive(args):
        archive_path = args.get("path", "")
        output_dir = args.get("output_dir", "")
        if not archive_path:
            return "[ERROR] path is required"
        archive_path = Path(archive_path)
        if not archive_path.exists():
            return "[ERROR] File not found: {0}".format(archive_path)
        if not output_dir:
            output_dir = str(Path(workspace) / "artifacts" / "extracted") if workspace else str(archive_path.parent / "extracted")
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        try:
            extracted = []
            name_lower = str(archive_path).lower()
            if name_lower.endswith(".zip"):
                with zipfile.ZipFile(str(archive_path), "r") as zf:
                    zf.extractall(output_dir)
                    extracted = zf.namelist()
            elif name_lower.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz")):
                with tarfile.open(str(archive_path), "r:*") as tf:
                    tf.extractall(output_dir)
                    extracted = tf.getnames()
            elif name_lower.endswith((".gz",)) and not name_lower.endswith(".tar.gz"):
                import gzip
                out_name = archive_path.stem
                out_path = Path(output_dir) / out_name
                with gzip.open(str(archive_path), "rb") as gz_in:
                    with open(str(out_path), "wb") as f_out:
                        shutil.copyfileobj(gz_in, f_out)
                extracted = [out_name]
            elif shell_tool and name_lower.endswith((".7z", ".rar")):
                result = shell_tool.run(
                    '7z x "{0}" -o"{1}" -y'.format(archive_path, output_dir),
                    timeout=30,
                )
                return "7z exit={0}\n{1}".format(
                    result.get("returncode", -1),
                    str(result.get("stdout", "") or "")[:2000],
                )
            else:
                return "[ERROR] Unsupported archive format: {0}".format(archive_path.suffix)
            listing = "\n".join(extracted[:50])
            if len(extracted) > 50:
                listing += "\n... and {0} more files".format(len(extracted) - 50)
            return "Extracted {0} files to {1}\n{2}".format(len(extracted), output_dir, listing)
        except Exception as exc:
            return "[ERROR] extract: {0}".format(exc)

    reg.register("extract_archive", _extract_archive,
        "Extract a zip/tar/gz/7z/rar archive to a directory. "
        "Returns list of extracted files.",
        {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to archive file"},
                "output_dir": {"type": "string", "description": "Output directory (default: workspace/artifacts/extracted)"},
            },
            "required": ["path"],
        })

    # 13. diff_http — compare two HTTP responses
    if http_tool:
        def _diff_http(args):
            url = args.get("url", "")
            params_a = args.get("params_a", {})
            params_b = args.get("params_b", {})
            method = args.get("method", "GET").upper()
            try:
                resp_a = http_tool.request(method, url, data=json.dumps(params_a) if method != "GET" else None,
                                           headers={"Content-Type": "application/json"} if method != "GET" else {})
                resp_b = http_tool.request(method, url, data=json.dumps(params_b) if method != "GET" else None,
                                           headers={"Content-Type": "application/json"} if method != "GET" else {})
                body_a = resp_a.get("body", "")[:3000]
                body_b = resp_b.get("body", "")[:3000]
                status_a = resp_a.get("status", "?")
                status_b = resp_b.get("status", "?")

                if body_a == body_b:
                    diff_summary = "IDENTICAL responses"
                else:
                    lines_a = set(body_a.splitlines())
                    lines_b = set(body_b.splitlines())
                    only_a = lines_a - lines_b
                    only_b = lines_b - lines_a
                    diff_parts = []
                    if only_a:
                        diff_parts.append("Only in A ({0} lines):\n{1}".format(len(only_a), "\n".join(list(only_a)[:10])))
                    if only_b:
                        diff_parts.append("Only in B ({0} lines):\n{1}".format(len(only_b), "\n".join(list(only_b)[:10])))
                    diff_summary = "\n".join(diff_parts) if diff_parts else "Responses differ but no line-level diff"

                return "A: HTTP {0} ({1} chars) | B: HTTP {2} ({3} chars)\n\n{4}".format(
                    status_a, len(body_a), status_b, len(body_b), diff_summary)
            except Exception as exc:
                return "[ERROR] diff_http: {0}".format(exc)

        reg.register("diff_http", _diff_http,
            "Send two HTTP requests with different parameters to the same URL and compare responses. "
            "Useful for blind injection detection, parameter fuzzing, and boolean-based testing.",
            {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "params_a": {"type": "object", "description": "First request parameters"},
                    "params_b": {"type": "object", "description": "Second request parameters"},
                    "method": {"type": "string", "enum": ["GET", "POST"], "default": "GET"},
                },
                "required": ["url", "params_a", "params_b"],
            })

    # 14. plan_parallel — trigger parallel subtask execution
    if plugin_registry:
        for plugin_tool in list(plugin_registry.plugin_tools() or []):
            tool_name = str(plugin_tool.get("name", "") or "").strip()
            if not tool_name or tool_name in reg.names:
                continue
            tool_kind = str(plugin_tool.get("kind", "") or "").strip().lower()
            description = str(plugin_tool.get("description", "") or "Plugin tool").strip()
            defaults = dict(plugin_tool.get("defaults") or {})

            if tool_kind == "shell_template" and shell_tool:
                def _plugin_shell(args, plugin_tool=plugin_tool, defaults=defaults):
                    payload = dict(defaults or {})
                    payload.update(dict(args or {}))
                    template = str(plugin_tool.get("command_template", "") or "")
                    try:
                        command = template.format(**payload)
                    except Exception as exc:
                        return {"status": "error", "message": str(exc), "plugin_tool": plugin_tool.get("name", "")}
                    result = shell_tool.run(command, timeout=int(payload.get("timeout", 20) or 20))
                    if isinstance(result, dict) and result.get("status") == "needs_approval":
                        return result
                    out = str((result or {}).get("stdout", "") or "")
                    err = str((result or {}).get("stderr", "") or "")
                    parts = [item for item in [out[:4000], "[stderr] " + err[:1200] if err else "", "[exit_code={0}]".format((result or {}).get("returncode", -1))] if item]
                    return "\n".join(parts)

                reg.register(tool_name, _plugin_shell, description, {"type": "object", "properties": {"timeout": {"type": "integer", "default": 20}}})

            elif tool_kind == "mcp_proxy" and mcp_registry:
                def _plugin_mcp(args, plugin_tool=plugin_tool, defaults=defaults):
                    payload = dict(defaults or {})
                    payload.update(dict(args or {}))
                    server_name = str(plugin_tool.get("server", "") or payload.pop("server", "")).strip()
                    proxied_tool = str(plugin_tool.get("tool", "") or payload.pop("tool", "")).strip()
                    result = mcp_registry.call_tool_safe(server_name, proxied_tool, arguments=payload)
                    if result.get("status") == "needs_approval":
                        return result
                    if result.get("ok"):
                        return result.get("result_preview") or result.get("summary") or ""
                    return mcp_registry.flatten_tool_result(result.get("error"))

                reg.register(tool_name, _plugin_mcp, description, {"type": "object", "properties": {}})

            elif tool_kind == "remote_template" and remote_tool:
                def _plugin_remote_template(args, plugin_tool=plugin_tool, defaults=defaults):
                    payload = dict(defaults or {})
                    payload.update(dict(args or {}))
                    host = str(payload.pop("host", "") or plugin_tool.get("host", "") or "").strip()
                    if not host:
                        hosts = remote_tool.list_hosts()
                        host = hosts[0] if hosts else ""
                    if not host:
                        return {"status": "missing", "message": "No remote host configured", "plugin_tool": plugin_tool.get("name", "")}
                    template_kind = str(plugin_tool.get("template_kind", "") or payload.pop("template_kind", "")).strip()
                    result = remote_tool.run_template(host, template_kind, **payload)
                    if isinstance(result, dict) and result.get("status") == "needs_approval":
                        return result
                    return json.dumps(result, ensure_ascii=False)[:_TOOL_OUTPUT_CAP]

                reg.register(tool_name, _plugin_remote_template, description, {"type": "object", "properties": {"host": {"type": "string"}}})

            elif tool_kind == "python_entry" and shell_tool:
                def _plugin_python_entry(args, plugin_tool=plugin_tool, defaults=defaults):
                    payload = dict(defaults or {})
                    payload.update(dict(args or {}))
                    script_path = str(plugin_tool.get("script_path", "") or "")
                    argv = list(payload.get("argv", []) or [])
                    quoted_argv = " ".join(['"{0}"'.format(str(item).replace('"', '\\"')) for item in argv])
                    command = '"{0}" "{1}" {2}'.format(sys.executable, script_path, quoted_argv).strip()
                    result = shell_tool.run(command, timeout=int(payload.get("timeout", 30) or 30))
                    if isinstance(result, dict) and result.get("status") == "needs_approval":
                        return result
                    out = str((result or {}).get("stdout", "") or "")
                    err = str((result or {}).get("stderr", "") or "")
                    return "\n".join([item for item in [out[:4000], "[stderr] " + err[:1200] if err else ""] if item])

                reg.register(tool_name, _plugin_python_entry, description, {"type": "object", "properties": {"argv": {"type": "array", "items": {"type": "string"}}}})

    reg.register("plan_parallel", lambda args: "(handled internally by AgentLoop)",
        "Plan 2-4 subtasks and execute them in parallel. "
        "Use when there are multiple independent directions to explore simultaneously "
        "(e.g. multiple attachments, multiple encoding hypotheses, recon + decode in parallel).",
        {
            "type": "object",
            "properties": {
                "reason": {"type": "string", "description": "Why parallel execution is beneficial here"},
            },
            "required": ["reason"],
        })

    return reg


# =====================================================================
# Serialization helpers (Feature 7: multi-turn)
# =====================================================================

def _serialize_session(
    challenge,
    state,
    messages,
    step,
    workspace,
    pending_approval=None,
    pending_action=None,
    runtime_usage=None,
    stop_reason="",
):
    """Serialize the full agent session to a JSON-safe dict."""
    payload = {
        "version": 1,
        "step": step,
        "workspace": str(workspace),
        "challenge": challenge.to_dict() if hasattr(challenge, "to_dict") else {},
        "state": state.to_dict(),
        "messages": [
            {k: v for k, v in m.items() if k != "tool_calls" or isinstance(v, (list, type(None)))}
            for m in messages
        ],
    }
    if pending_approval:
        payload["pending_approval"] = dict(pending_approval or {})
    if pending_action:
        payload["pending_action"] = dict(pending_action or {})
    if runtime_usage:
        payload["runtime_usage"] = dict(runtime_usage or {})
    if stop_reason:
        payload["stop_reason"] = str(stop_reason or "")
    return payload


def _save_session(workspace, session_data):
    """Persist session to disk for later resume."""
    path = Path(workspace) / "agent_session.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(str(path), "w", encoding="utf-8") as fh:
        json.dump(session_data, fh, ensure_ascii=False, indent=2, default=str)
    return str(path)


def _load_session(workspace):
    """Load a persisted session from disk."""
    path = Path(workspace) / "agent_session.json"
    if not path.exists():
        return None
    with open(str(path), "r", encoding="utf-8") as fh:
        return json.load(fh)


def _restore_state(session_data):
    """Rebuild ChallengeState from serialized data."""
    from ctf_agent.core.models import (
        ActionRecord, CandidateFlag, ChallengeState, ExploitPlan, Finding, SubAgentRecord,
    )
    sd = session_data.get("state", {})
    state = ChallengeState(phase=sd.get("phase", "agent-loop"))
    state.hypotheses = list(sd.get("hypotheses", []))
    state.blocked_reason = sd.get("blocked_reason")
    for item in sd.get("findings", []):
        state.findings.append(Finding(**item))
    for item in sd.get("candidate_flags", []):
        state.candidate_flags.append(CandidateFlag(**item))
    for item in sd.get("tried_actions", []):
        state.tried_actions.append(ActionRecord(**item))
    for item in sd.get("exploit_plans", []):
        state.exploit_plans.append(ExploitPlan(**{k: v for k, v in item.items() if k != "data" and k != "headers"}))
    for item in sd.get("subagents", []):
        state.subagents.append(SubAgentRecord.from_dict(item))
    return state


# =====================================================================
# Agent Loop
# =====================================================================

class AgentLoop:
    """
    ReAct agent loop with multi-turn support and parallel subtasks.

    New capabilities over the base implementation:
    - ``continue_solve()``: resume from a saved session with a user hint
    - ``plan_parallel()``: LLM plans subtasks, tools run in parallel
    - Extended tool set: remote execution, decompilation, browser, archive, HTTP diff
    """

    def __init__(
        self,
        llm,
        tools,
        knowledge_retriever=None,
        code_executor=None,
        verifier=None,
        max_steps=None,
        max_tokens_budget=None,
        language="zh-CN",
        file_tool=None,
        shell_tool=None,
        toolkit_tool=None,
        http_tool=None,
        remote_tool=None,
        mcp_registry=None,
        oob_tool=None,
        workspace_manager=None,
        execution_policy=None,
        allow_subagents=True,
        is_subagent=False,
        skill_resolver=None,
        plugin_registry=None,
        approval_manager=None,
    ):
        self.llm = llm
        self.tools = tools
        self.knowledge = knowledge_retriever
        self.code_executor = code_executor
        self.verifier = verifier
        self.max_steps = max_steps or _DEFAULT_MAX_STEPS
        self.max_tokens_budget = max_tokens_budget or _DEFAULT_MAX_TOKENS
        self.language = language
        self._active_tools = tools
        self.file_tool = file_tool
        self.shell_tool = shell_tool
        self.toolkit_tool = toolkit_tool
        self.http_tool = http_tool
        self.remote_tool = remote_tool
        self.mcp_registry = mcp_registry
        self.oob_tool = oob_tool
        self.workspace_manager = workspace_manager or WorkspaceManager(Path.cwd())
        self.execution_policy = execution_policy
        self.allow_subagents = bool(allow_subagents)
        self.is_subagent = bool(is_subagent)
        self.skill_resolver = skill_resolver or SkillResolver()
        self.plugin_registry = plugin_registry
        self.approval_manager = approval_manager
        self._last_runtime_usage = {
            "steps": 0,
            "tool_calls": 0,
            "tokens_used": 0,
            "elapsed_ms": 0,
        }
        self._last_stop_reason = "completed"
        self._pending_approval = {}
        self._pending_action = {}

    # ------------------------------------------------------------------
    # Main entry: solve from scratch
    # ------------------------------------------------------------------

    def solve(self, challenge, workspace, existing_state=None):
        workspace = Path(workspace)
        self._configure_runtime(challenge, workspace, background=self.is_subagent)
        state = existing_state or ChallengeState(phase="agent-loop")
        memory = StateMemory(state)

        speed_mode, speed_profile = self._resolve_speed_profile(challenge)
        active_tools = self._select_active_tools(challenge, speed_mode, speed_profile)
        self._active_tools = active_tools
        knowledge_ctx = self._retrieve_initial_knowledge(challenge, speed_mode=speed_mode, speed_profile=speed_profile)
        sys_prompt = SYSTEM_PROMPT.format(
            tool_list=active_tools.describe(),
            knowledge=knowledge_ctx,
        )
        if speed_mode == "fastest":
            sys_prompt = sys_prompt + "\n\n" + FASTEST_APPENDIX
        messages = [
            {"role": "system", "content": sys_prompt},
            {"role": "user", "content": self._format_challenge(challenge, workspace)},
        ]
        memory.record_action("agent-loop", "init", "ok",
            "Started with {0} tools, budget {1} tokens".format(
                len(active_tools.names), self.max_tokens_budget))

        state = self._run_loop(
            challenge,
            workspace,
            state,
            memory,
            messages,
            start_step=0,
            active_tools=active_tools,
            speed_mode=speed_mode,
            speed_profile=speed_profile,
        )
        self._write_notes(workspace, state, challenge=challenge, speed_mode=speed_mode)
        self._write_board(challenge, workspace, state, speed_mode=speed_mode)
        return state

    # ------------------------------------------------------------------
    # Feature 7: Multi-turn resume
    # ------------------------------------------------------------------

    def pause(self, challenge, workspace, state, messages, step):
        """Save the full session state so it can be resumed later."""
        session = _serialize_session(challenge, state, messages, step, workspace)
        path = _save_session(workspace, session)
        state.phase = "paused"
        return {"status": "paused", "session_path": path, "step": step}

    def continue_solve(self, workspace, user_hint="", challenge=None):
        """
        Resume a paused session with an optional user hint.

        If the session was previously paused, this restores messages and state
        from disk, injects the user's hint, and continues the loop.
        """
        workspace = Path(workspace)
        session_data = _load_session(workspace)
        if not session_data:
            return ChallengeState(phase="error", blocked_reason="No saved session found in {0}".format(workspace))

        state = _restore_state(session_data)
        memory = StateMemory(state)
        messages = session_data.get("messages", [])
        start_step = session_data.get("step", 0)
        pending_approval = dict(session_data.get("pending_approval") or {})

        if user_hint:
            messages.append({"role": "user", "content": user_hint})
            memory.add_hypothesis("[user-hint] {0}".format(user_hint[:200]))
            memory.record_action("agent-loop", "user-hint", "ok", user_hint[:200])

        state.phase = "agent-loop"

        if challenge is None:
            from ctf_agent.core.models import Challenge
            cd = session_data.get("challenge", {})
            challenge = Challenge(
                contest_id=cd.get("contest_id", ""),
                challenge_id=cd.get("challenge_id", ""),
                title=cd.get("title", ""),
                category=cd.get("category", ""),
                description=cd.get("description", ""),
                attachments=[Path(p) for p in cd.get("attachments", [])],
                target=cd.get("target"),
                flag_format=cd.get("flag_format"),
                metadata=cd.get("metadata", {}),
            )

        self._configure_runtime(challenge, workspace, background=self.is_subagent)
        speed_mode, speed_profile = self._resolve_speed_profile(challenge)
        active_tools = self._select_active_tools(challenge, speed_mode, speed_profile)
        self._active_tools = active_tools
        if pending_approval:
            resumed = self._resume_pending_tool_call(
                workspace,
                challenge,
                state,
                memory,
                messages,
                pending_approval,
                active_tools,
            )
            if not resumed and state.phase == "needs_approval":
                self._write_notes(workspace, state, challenge=challenge, speed_mode=speed_mode)
                self._write_board(challenge, workspace, state, speed_mode=speed_mode)
                self._persist_session(
                    challenge,
                    state,
                    messages,
                    start_step,
                    workspace,
                    pending_approval=pending_approval,
                    pending_action=dict(pending_approval.get("result_payload") or {}),
                    runtime_usage=dict(session_data.get("runtime_usage") or {}),
                    stop_reason=str(session_data.get("stop_reason", "needs_approval") or "needs_approval"),
                )
                return state
        state = self._run_loop(
            challenge,
            workspace,
            state,
            memory,
            messages,
            start_step=start_step,
            active_tools=active_tools,
            speed_mode=speed_mode,
            speed_profile=speed_profile,
        )
        self._write_notes(workspace, state, challenge=challenge, speed_mode=speed_mode)
        self._write_board(challenge, workspace, state, speed_mode=speed_mode)
        return state

    def get_session_info(self, workspace):
        """Return summary of a saved session without resuming it."""
        session_data = _load_session(workspace)
        if not session_data:
            return None
        sd = session_data.get("state", {})
        pending_approval = dict(session_data.get("pending_approval") or {})
        return {
            "step": session_data.get("step", 0),
            "phase": sd.get("phase", "unknown"),
            "n_flags": len(sd.get("candidate_flags", [])),
            "n_actions": len(sd.get("tried_actions", [])),
            "n_hypotheses": len(sd.get("hypotheses", [])),
            "n_messages": len(session_data.get("messages", [])),
            "workspace": session_data.get("workspace", ""),
            "pending_approval": pending_approval,
            "pending_approval_request_id": str(pending_approval.get("request_id", "") or ""),
        }

    # ------------------------------------------------------------------
    # Runtime helpers
    # ------------------------------------------------------------------

    def _configure_runtime(self, challenge, workspace, background=False):
        workspace = Path(workspace)
        if self.is_subagent and self.execution_policy:
            policy = self.execution_policy
        else:
            policy = ExecutionPolicy.build_default(
                workspace=workspace,
                attachments=getattr(challenge, "attachments", []),
                category=getattr(challenge, "category", ""),
                target=getattr(challenge, "target", ""),
                remote_hosts=self.remote_tool.list_hosts() if self.remote_tool else [],
                mcp_servers=[
                    item.get("name")
                    for item in (self.mcp_registry.enabled_servers() if self.mcp_registry else [])
                    if item.get("name")
                ],
                mode="subagent" if self.is_subagent else "main",
                approval_policy=getattr(challenge, "metadata", {}).get("approval_policy", {}) or {},
                approval_manager=self.approval_manager.configure(
                    workspace=str(workspace),
                    run_id=str(getattr(challenge, "metadata", {}).get("run_id", "") or ""),
                ) if self.approval_manager else None,
                run_id=str(getattr(challenge, "metadata", {}).get("run_id", "") or ""),
            )
            if self.plugin_registry:
                policy = policy.apply_overlay(self.plugin_registry.policy_overlay())
        self.execution_policy = policy
        if self.file_tool:
            self.file_tool.configure_policy(policy, workspace=str(workspace))
        if self.shell_tool:
            self.shell_tool.configure_policy(policy, workspace=str(workspace))
        if self.code_executor and hasattr(self.code_executor, "configure_policy"):
            self.code_executor.configure_policy(policy)
        if self.remote_tool:
            self.remote_tool.configure_policy(
                policy,
                category=getattr(challenge, "category", ""),
                target=getattr(challenge, "target", ""),
                background=background,
            )
            if hasattr(self.remote_tool, "configure_plugins"):
                self.remote_tool.configure_plugins(self.plugin_registry)
        if self.mcp_registry and hasattr(self.mcp_registry, "configure_runtime"):
            self.mcp_registry.configure_runtime(workspace=str(workspace), policy=policy)
        built_tools = self._build_tools_for_workspace(workspace)
        if built_tools:
            self.tools = built_tools
            self._active_tools = built_tools
        if self.plugin_registry:
            try:
                self.plugin_registry.persist_workspace_status(workspace)
            except Exception:
                logger.debug("Failed to persist plugin status", exc_info=True)
        return policy

    def _build_tools_for_workspace(self, workspace):
        if not any(
            [
                self.code_executor,
                self.knowledge,
                self.verifier,
                self.file_tool,
                self.shell_tool,
                self.toolkit_tool,
                self.http_tool,
                self.remote_tool,
                self.mcp_registry,
                self.oob_tool,
            ]
        ):
            return self.tools
        return build_default_tools(
            code_executor=self.code_executor,
            knowledge_retriever=self.knowledge,
            verifier=self.verifier,
            file_tool=self.file_tool,
            shell_tool=self.shell_tool,
            toolkit_tool=self.toolkit_tool,
            http_tool=self.http_tool,
            remote_tool=self.remote_tool,
            mcp_registry=self.mcp_registry,
            oob_tool=self.oob_tool,
            workspace=str(workspace),
            plugin_registry=self.plugin_registry,
        )

    def _challenge_task_text(self, challenge):
        return "\n".join(
            [
                str(getattr(challenge, "title", "") or ""),
                str(getattr(challenge, "category", "") or ""),
                str(getattr(challenge, "description", "") or ""),
            ]
        ).strip()

    def _resolve_skill_context(self, challenge, speed_mode="standard"):
        normalized_speed = str(speed_mode or "standard").strip().lower() or "standard"
        metadata = getattr(challenge, "metadata", None)
        cached = dict((metadata or {}).get("skill_resolution") or {})
        cached_speed = str(((cached.get("runtime") or {}).get("speed_mode") or "")).strip().lower()
        if not cached or cached_speed != normalized_speed:
            cached = self.skill_resolver.resolve(
                task_text=self._challenge_task_text(challenge),
                target=getattr(challenge, "target", "") or "",
                attachments=list(getattr(challenge, "attachments", []) or []),
                explicit_category=getattr(challenge, "category", "") or "",
                speed_mode=normalized_speed,
            )
            if isinstance(metadata, dict):
                metadata["skill_resolution"] = dict(cached)
                metadata["knowledge_selection"] = self.skill_resolver.to_legacy_selection(cached)
        return cached

    def _skillpack(self, challenge, speed_mode="standard"):
        resolution = self._resolve_skill_context(challenge, speed_mode=speed_mode)
        category = dict(resolution.get("category") or {})
        skillpack = dict(resolution.get("skillpack") or {})
        knowledge = dict(resolution.get("knowledge") or {})
        runtime = dict(resolution.get("runtime") or {})
        recommendations = dict(resolution.get("recommendations") or {})
        return {
            "category": category.get("selected_skill_category", skillpack.get("category", "")),
            "label": skillpack.get("label", ""),
            "solver": skillpack.get("solver", "triage"),
            "execution_mode": skillpack.get("execution_mode", "inline"),
            "knowledge_pack": dict(skillpack.get("knowledge_pack", {})),
            "knowledge_topics": list(knowledge.get("knowledge_topics", [])),
            "top_tactics": list(knowledge.get("top_tactics", [])),
            "reference_docs": list(knowledge.get("reference_docs", [])),
            "allowed_tools": list(runtime.get("allowed_tools", [])),
            "denied_tools": list(runtime.get("denied_tools", [])),
            "default_budget": dict(runtime.get("default_budget", {})),
            "initial_prompt_template": str(runtime.get("initial_prompt_template", "")),
            "followup_prompt_template": str(runtime.get("followup_prompt_template", "")),
            "recommended_tools": list(recommendations.get("recommended_tools", [])),
            "recommended_mcp": list(recommendations.get("recommended_mcp", [])),
            "preferred_mcp": list(recommendations.get("recommended_mcp", [])),
            "recommended_remote_templates": list(recommendations.get("preferred_remote_templates", [])),
            "preferred_remote_templates": list(recommendations.get("preferred_remote_templates", [])),
            "retrieval_enabled": bool(runtime.get("retrieval_enabled", True)),
            "retrieval_reason": str(runtime.get("retrieval_reason", "")),
        }

    def plan_parallel(self, challenge, state, workspace):
        """
        Ask the LLM to plan subtasks, then execute them as either tool batches
        or restricted subagents.

        Returns a list of ``{tool, result, purpose}`` dicts merged back
        into the conversation.
        """
        findings_text = "\n".join(
            "- [{0}] {1}".format(f.source, f.summary[:100])
            for f in state.findings[-8:]
        ) or "(none yet)"

        prompt = PARALLEL_PLAN_PROMPT.format(
            challenge="{0}: {1}".format(challenge.title or "", (challenge.description or "")[:400]),
            findings=findings_text,
            tools=self._tool_registry().describe(),
        ) + "\n\nReturn JSON. Each item may be either:\n" \
            '- {"mode":"tool","tool":"tool_name","args":{},"purpose":"..."}\n' \
            '- {"mode":"subagent","purpose":"...","prompt":"...","allowed_tools":["read_file","run_python"],"execution_mode":"local|remote","remote_host":"optional","max_steps":6,"max_tool_calls":4,"max_tokens":2000000,"timeout_sec":90,"poll_interval_sec":5,"mirror_artifacts":true}\n' \
            "Use subagent mode only for an independent investigative branch. Do not duplicate the same task across modes."

        try:
            plan = self.llm.structured_output(
                [{"role": "user", "content": prompt}],
                schema_hint='[{"mode":"tool|subagent","tool":"string","args":{},"purpose":"string","prompt":"string","allowed_tools":["string"],"execution_mode":"local|remote","remote_host":"string","max_steps":6,"max_tool_calls":4,"max_tokens":2000000,"timeout_sec":90,"poll_interval_sec":5,"mirror_artifacts":true}]',
                temperature=0.2,
            )
        except Exception as exc:
            logger.warning("Parallel plan failed: %s", exc)
            return []

        if isinstance(plan, dict) and "raw" in plan:
            return []

        tasks = [item for item in (plan if isinstance(plan, list) else []) if isinstance(item, dict)]
        tasks = tasks[:_PARALLEL_WORKERS]
        if len(tasks) < 2 or not self.allow_subagents and not any(item.get("tool") for item in tasks):
            return []

        tool_tasks = []
        subagent_tasks = []
        tool_names = set(self._tool_registry().names)
        for task in tasks:
            mode = str(task.get("mode", "") or "").strip().lower()
            if not mode:
                mode = "tool" if task.get("tool") else "subagent"
            if mode == "tool":
                tool_name = str(task.get("tool", "") or "").strip()
                if tool_name and tool_name in tool_names and tool_name != "plan_parallel":
                    tool_tasks.append(task)
            elif mode == "subagent" and self.allow_subagents:
                subagent_tasks.append(task)

        results = []
        if tool_tasks:
            results.extend(self._execute_parallel(tool_tasks))
        if subagent_tasks:
            results.extend(self._spawn_subagents(challenge, state, workspace, subagent_tasks))
        return results

    def _execute_parallel(self, tasks, tool_registry=None):
        """Run multiple tool calls concurrently using a thread pool."""
        results = []
        registry = tool_registry or self._tool_registry()

        def _run_one(task):
            tool_name = task["tool"]
            args = task.get("args", {})
            purpose = task.get("purpose", "")
            start = time.time()
            output = registry.execute(tool_name, args)
            elapsed = int((time.time() - start) * 1000)
            return {
                "tool": tool_name,
                "purpose": purpose,
                "result": output,
                "elapsed_ms": elapsed,
            }

        with ThreadPoolExecutor(max_workers=_PARALLEL_WORKERS) as pool:
            futures = {pool.submit(_run_one, t): i for i, t in enumerate(tasks)}
            for future in as_completed(futures, timeout=_SUBTASK_TIMEOUT):
                try:
                    results.append(future.result())
                except Exception as exc:
                    idx = futures[future]
                    results.append({
                        "tool": tasks[idx].get("tool", "?"),
                        "purpose": tasks[idx].get("purpose", ""),
                        "result": "[ERROR] {0}".format(exc),
                        "elapsed_ms": 0,
                    })

        return results

    def _spawn_subagents(self, challenge, state, workspace, tasks):
        workspace = Path(workspace)
        results = []
        specs = []
        skillpack = self._skillpack(challenge, speed_mode="standard")
        default_budget = dict(skillpack.get("default_budget", {}))
        for index, task in enumerate(list(tasks or [])):
            purpose = str(task.get("purpose", "") or "parallel-branch-{0}".format(index + 1)).strip()
            subagent_id = self.workspace_manager.slugify("subagent-{0}-{1}".format(index + 1, purpose))[:64]
            sub_workspace = self.workspace_manager.subagent_dir(workspace, subagent_id)
            execution_mode = str(task.get("execution_mode", "local") or "local").strip().lower() or "local"
            if execution_mode not in {"local", "remote"}:
                execution_mode = "local"
            requested_tools = task.get("allowed_tools")
            if execution_mode == "remote" and not requested_tools:
                allowed_tools = []
            else:
                allowed_tools = self._resolve_subagent_tool_names(requested_tools)
            spec = SubAgentSpec(
                id=subagent_id,
                purpose=purpose,
                prompt=str(task.get("prompt") or purpose),
                allowed_tools=allowed_tools,
                execution_mode=execution_mode,
                transport="ssh" if execution_mode == "remote" else "local",
                remote_host=str(task.get("remote_host", "") or ""),
                sync_policy=str(task.get("sync_policy", "summary_only") or "summary_only"),
                poll_interval_sec=self._resolve_budget_value(task, "poll_interval_sec", {"poll_interval_sec": 5}, 5),
                mirror_artifacts=bool(task.get("mirror_artifacts", True)),
                max_steps=self._resolve_budget_value(task, "max_steps", default_budget, 6),
                max_tool_calls=self._resolve_budget_value(task, "max_tool_calls", default_budget, 4),
                max_tokens=self._resolve_budget_value(task, "max_tokens", default_budget, _DEFAULT_SUBAGENT_MAX_TOKENS),
                timeout_sec=self._resolve_budget_value(task, "timeout_sec", default_budget, _SUBTASK_TIMEOUT),
                workspace_dir=str(sub_workspace),
                parent_run_id=str(getattr(challenge, "metadata", {}).get("run_id", "") or workspace.name),
                category_hint=str(task.get("category_hint") or getattr(challenge, "category", "") or ""),
            )
            specs.append(spec)

        with ThreadPoolExecutor(max_workers=min(_PARALLEL_WORKERS, max(1, len(specs)))) as pool:
            futures = {pool.submit(self._run_subagent_spec, challenge, workspace, spec): spec for spec in specs}
            for future in as_completed(futures):
                spec = futures[future]
                try:
                    record, result_entry = future.result()
                except Exception as exc:
                    summary = {"what_was_tried": spec.prompt[:300], "what_was_found": "", "what_to_do_next": ""}
                    record = SubAgentRecord(
                        id=spec.id,
                        status="failed",
                        started_at=time.time(),
                        finished_at=time.time(),
                        spec=spec,
                        summary=summary,
                        stop_reason="error",
                        usage={"steps": 0, "tool_calls": 0, "tokens_used": 0, "elapsed_ms": 0},
                        error=str(exc),
                        artifact_paths=[],
                    )
                    self.workspace_manager.save_subagent_summary(workspace, spec.id, record.to_dict())
                    result_entry = {
                        "tool": "subagent:{0}".format(spec.id),
                        "purpose": spec.purpose,
                        "status": record.status,
                        "stop_reason": record.stop_reason,
                        "usage": dict(record.usage),
                        "summary": dict(record.summary),
                        "artifact_paths": list(record.artifact_paths),
                        "result": "[status={0} reason={1}] [ERROR] {2}".format(record.status, record.stop_reason, exc),
                        "elapsed_ms": 0,
                    }
                if record is not None:
                    state.subagents = [item for item in state.subagents if item.id != record.id]
                    state.subagents.append(record)
                results.append(result_entry)
        return results

    def _run_subagent_spec(self, challenge, workspace, spec):
        if str(getattr(spec, "execution_mode", "local") or "local").strip().lower() == "remote":
            return self._run_remote_subagent_spec(challenge, workspace, spec)
        started_at = time.time()
        sub_workspace = Path(spec.workspace_dir or self.workspace_manager.subagent_dir(workspace, spec.id))
        sub_policy = self.execution_policy.for_subagent(sub_workspace) if self.execution_policy else None
        child_loop = AgentLoop(
            llm=self.llm,
            tools=self._build_tools_for_workspace(sub_workspace),
            knowledge_retriever=self.knowledge,
            code_executor=self.code_executor,
            verifier=self.verifier,
            max_steps=max(1, int(spec.max_steps or 1)),
            max_tokens_budget=max(1, int(spec.max_tokens or _DEFAULT_SUBAGENT_MAX_TOKENS)),
            language=self.language,
            file_tool=self.file_tool,
            shell_tool=self.shell_tool,
            toolkit_tool=self.toolkit_tool,
            http_tool=self.http_tool,
            remote_tool=self.remote_tool,
            mcp_registry=self.mcp_registry,
            oob_tool=self.oob_tool,
            workspace_manager=self.workspace_manager,
            execution_policy=sub_policy,
            allow_subagents=False,
            is_subagent=True,
        )
        child_loop._configure_runtime(challenge, sub_workspace, background=False)
        active_tools = child_loop._select_active_tools(challenge, "standard", {})
        allowed = spec.allowed_tools or self._resolve_subagent_tool_names([])
        active_tools = active_tools.only_names(allowed).without_names(["plan_parallel", "run_remote_command", "run_remote_python"])
        child_loop._active_tools = active_tools
        knowledge_ctx = child_loop._retrieve_initial_knowledge(challenge, speed_mode="standard", speed_profile={})
        messages = [
            {
                "role": "system",
                "content": SYSTEM_PROMPT.format(tool_list=active_tools.describe(), knowledge=knowledge_ctx),
            },
            {
                "role": "user",
                "content": child_loop._format_challenge(challenge, sub_workspace)
                + "\n\n## Subagent Mission\nPurpose: {0}\nPrompt: {1}".format(spec.purpose, spec.prompt),
            },
        ]
        child_state = ChallengeState(phase="subagent")
        child_memory = StateMemory(child_state)
        child_memory.record_action("subagent", "init", "ok", spec.purpose[:200])
        child_state = child_loop._run_loop(
            challenge,
            sub_workspace,
            child_state,
            child_memory,
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
                "token_baseline": child_loop._current_total_tokens(),
            },
        )
        child_loop._write_notes(sub_workspace, child_state, challenge=challenge, speed_mode="standard")
        child_loop._write_board(challenge, sub_workspace, child_state, speed_mode="standard")
        transcript_path = self.workspace_manager.save_subagent_transcript(workspace, spec.id, messages)
        summary = self._build_subagent_summary(child_state)
        artifact_paths = [str(path) for path in sorted((sub_workspace / "artifacts").rglob("*")) if path.is_file()]
        usage = dict(getattr(child_loop, "_last_runtime_usage", {}) or {})
        stop_reason = str(getattr(child_loop, "_last_stop_reason", "completed") or "completed")
        status = self._subagent_status_from_reason(stop_reason)
        record = SubAgentRecord(
            id=spec.id,
            status=status,
            started_at=started_at,
            finished_at=time.time(),
            spec=spec,
            summary=summary,
            stop_reason=stop_reason,
            usage=usage,
            error=child_state.blocked_reason if stop_reason == "error" else None,
            artifact_paths=artifact_paths + [str(transcript_path)],
        )
        summary_payload = record.to_dict()
        summary_payload["transcript_path"] = str(transcript_path)
        summary_payload["summary_text"] = summary.get("summary_text", "")
        self.workspace_manager.save_subagent_summary(workspace, spec.id, summary_payload)
        result_entry = {
            "tool": "subagent:{0}".format(spec.id),
            "purpose": spec.purpose,
            "status": record.status,
            "stop_reason": record.stop_reason,
            "usage": dict(record.usage),
            "summary": dict(record.summary),
            "artifact_paths": list(record.artifact_paths),
            "result": self._format_subagent_result(record),
            "elapsed_ms": int(record.usage.get("elapsed_ms", 0) or 0),
        }
        return record, result_entry

    def _run_remote_subagent_spec(self, challenge, workspace, spec):
        from ctf_agent.core.remote_subagent_runtime import run_remote_subagent

        return run_remote_subagent(self, challenge, workspace, spec)

        started_at = time.time()
        workspace = Path(workspace)
        sub_workspace = Path(spec.workspace_dir or self.workspace_manager.subagent_dir(workspace, spec.id))
        sub_workspace.mkdir(parents=True, exist_ok=True)
        local_input_dir = sub_workspace / "input"
        local_input_dir.mkdir(parents=True, exist_ok=True)
        q = lambda value: '"{0}"'.format(str(value).replace('"', '\\"'))

        def _approval_result(payload):
            approval_payload = dict(payload or {})
            request_id = str(approval_payload.get("request_id", "") or dict(approval_payload.get("approval") or {}).get("request_id", "") or "")
            self.workspace_manager.save_subagent_remote_status(
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

        def _failed_record(message, stop_reason="error", remote_status=None, sync_manifest=None, artifact_paths=None):
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
                status=self._subagent_status_from_reason(stop_reason),
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
            self.workspace_manager.save_subagent_summary(workspace, spec.id, record.to_dict())
            if remote_status:
                self.workspace_manager.save_subagent_remote_status(workspace, spec.id, dict(remote_status or {}))
            if sync_manifest:
                self.workspace_manager.save_subagent_sync_manifest(workspace, spec.id, dict(sync_manifest or {}))
            result_entry = {
                "tool": "subagent:{0}".format(spec.id),
                "purpose": spec.purpose,
                "status": record.status,
                "stop_reason": record.stop_reason,
                "usage": dict(record.usage),
                "summary": dict(record.summary),
                "artifact_paths": list(record.artifact_paths),
                "result": self._format_subagent_result(record),
                "elapsed_ms": int(record.usage.get("elapsed_ms", 0) or 0),
            }
            return record, result_entry

        if not self.remote_tool:
            return _failed_record("remote_tool is not configured for remote subagent execution")

        selected_host = self._select_remote_subagent_host(challenge, spec)
        if not selected_host:
            return _failed_record("no remote host is available for remote subagent execution")

        spec.remote_host = selected_host
        if self.execution_policy:
            decision = self.execution_policy.evaluate_remote_subagent(
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
                    {
                        "status": "needs_approval",
                        "message": getattr(decision, "reason", "approval required for remote subagent"),
                        "request_id": getattr(decision, "request_id", ""),
                        "approval": decision.to_dict() if hasattr(decision, "to_dict") else {},
                    }
                )

        remote_status = self._update_remote_status(
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

        bundle_path, runner_name = self._create_remote_bundle(sub_workspace)
        sync_manifest = {
            "remote_host": selected_host,
            "uploads": [],
            "downloads": [],
            "remote_workspace": "",
            "mirror_artifacts": bool(spec.mirror_artifacts),
        }
        try:
            remote_setup = self.remote_tool.ensure_workspace(selected_host, run_id=spec.id, timeout=30)
        except Exception as exc:
            remote_setup = {"status": "error", "message": str(exc)}
        if dict(remote_setup or {}).get("status") == "needs_approval":
            return _approval_result(remote_setup)
        if dict(remote_setup or {}).get("status") != "ok":
            return _failed_record(
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
        remote_artifact_dir = remote_workspace.rstrip("/") + "/output/artifacts"
        sync_manifest["remote_workspace"] = remote_workspace
        spec.workspace_dir = str(sub_workspace)
        spec.transport = "ssh"

        remote_status = self._update_remote_status(
            workspace,
            spec.id,
            {
                "status": "staging",
                "remote_host": selected_host,
                "remote_workspace": remote_workspace,
                "execution_mode": "remote",
                "poll_interval_sec": int(spec.poll_interval_sec or 5),
            },
            remote_host=selected_host,
            remote_workspace=remote_workspace,
            mirror_remote=True,
        )

        mkdir_result = self.remote_tool.run_command(
            selected_host,
            "mkdir -p {0} {1}".format(q(remote_output_dir), q(remote_artifact_dir)),
            timeout=30,
        )
        if dict(mkdir_result or {}).get("status") == "needs_approval":
            return _approval_result(mkdir_result)
        if dict(mkdir_result or {}).get("status") != "ok":
            return _failed_record(
                "failed to prepare remote output directory: {0}".format(dict(mkdir_result or {}).get("message", mkdir_result)),
                remote_status={
                    "status": "failed",
                    "remote_host": selected_host,
                    "remote_workspace": remote_workspace,
                    "message": str(dict(mkdir_result or {}).get("message", mkdir_result)),
                },
            )

        spec_payload = dict(spec.to_dict())
        policy_payload = {}
        if self.execution_policy:
            policy_payload = {
                "allowed_roots": list(getattr(self.execution_policy, "allowed_roots", []) or []),
                "denied_roots": list(getattr(self.execution_policy, "denied_roots", []) or []),
                "allow_remote": True,
                "allowed_remote_hosts": [selected_host],
                "allow_mcp_servers": list(getattr(self.execution_policy, "allow_mcp_servers", []) or []),
            }
        challenge_payload = challenge.to_dict() if hasattr(challenge, "to_dict") else {}
        plugin_snapshot = self.plugin_registry.describe() if self.plugin_registry else {"loaded": False, "counts": {}, "plugins": []}
        local_spec_path = local_input_dir / "spec.json"
        local_policy_path = local_input_dir / "policy.json"
        local_challenge_path = local_input_dir / "challenge.json"
        local_plugin_path = local_input_dir / "plugin_snapshot.json"
        self.workspace_manager.write_json(local_spec_path, spec_payload)
        self.workspace_manager.write_json(local_policy_path, policy_payload)
        self.workspace_manager.write_json(local_challenge_path, challenge_payload)
        self.workspace_manager.write_json(local_plugin_path, plugin_snapshot)

        staged_uploads = [
            (bundle_path, remote_input_dir + "/" + bundle_path.name),
            (local_spec_path, remote_input_dir + "/spec.json"),
            (local_policy_path, remote_input_dir + "/policy.json"),
            (local_challenge_path, remote_input_dir + "/challenge.json"),
            (local_plugin_path, remote_input_dir + "/plugin_snapshot.json"),
        ]
        for local_path, remote_path in staged_uploads:
            upload_result = self.remote_tool.upload(selected_host, str(local_path), remote_path=remote_path, timeout=30)
            if dict(upload_result or {}).get("status") == "needs_approval":
                return _approval_result(upload_result)
            if dict(upload_result or {}).get("status") != "ok":
                return _failed_record(
                    "failed to upload {0}: {1}".format(Path(local_path).name, dict(upload_result or {}).get("message", upload_result)),
                    remote_status={
                        "status": "failed",
                        "remote_host": selected_host,
                        "remote_workspace": remote_workspace,
                        "message": str(dict(upload_result or {}).get("message", upload_result)),
                    },
                )
            sync_manifest["uploads"].append(
                {
                    "local_path": str(local_path),
                    "remote_path": str(upload_result.get("remote_path", remote_path)),
                    "kind": Path(local_path).name,
                }
            )

        runner_remote_path = remote_input_dir + "/" + runner_name
        runner_upload = self.remote_tool.upload_text(
            selected_host,
            self._remote_runner_script(),
            remote_path=runner_remote_path,
            timeout=20,
        )
        if dict(runner_upload or {}).get("status") == "needs_approval":
            return _approval_result(runner_upload)
        if dict(runner_upload or {}).get("status") != "ok":
            return _failed_record(
                "failed to upload remote runner: {0}".format(dict(runner_upload or {}).get("message", runner_upload)),
                remote_status={
                    "status": "failed",
                    "remote_host": selected_host,
                    "remote_workspace": remote_workspace,
                    "message": str(dict(runner_upload or {}).get("message", runner_upload)),
                },
            )
        sync_manifest["uploads"].append(
            {
                "local_path": str(bundle_path),
                "remote_path": runner_remote_path,
                "kind": "remote_subagent_runner.py",
            }
        )

        remote_attachment_paths = []
        for item in list(getattr(challenge, "attachments", []) or []):
            attachment_path = Path(item)
            remote_attachment_path = remote_input_dir + "/attachments/" + attachment_path.name
            upload_result = self.remote_tool.upload(selected_host, str(attachment_path), remote_path=remote_attachment_path, timeout=30)
            if dict(upload_result or {}).get("status") == "needs_approval":
                return _approval_result(upload_result)
            if dict(upload_result or {}).get("status") != "ok":
                return _failed_record(
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
                )
            remote_attachment_paths.append(str(upload_result.get("remote_path", remote_attachment_path)))
            sync_manifest["uploads"].append(
                {
                    "local_path": str(attachment_path),
                    "remote_path": str(upload_result.get("remote_path", remote_attachment_path)),
                    "kind": "attachment",
                }
            )

        host_python = str((self.remote_tool.hosts.get(selected_host, {}) or {}).get("python_bin", "python3") or "python3")
        runner_init = self.remote_tool.run_command(
            selected_host,
            "{0} {1} {2} init".format(q(host_python), q(runner_remote_path), q(remote_workspace)),
            timeout=30,
        )
        if dict(runner_init or {}).get("status") == "needs_approval":
            return _approval_result(runner_init)
        if dict(runner_init or {}).get("status") != "ok":
            logger.debug("Remote runner init failed for %s: %s", spec.id, runner_init)

        remote_challenge = Challenge(
            contest_id=getattr(challenge, "contest_id", ""),
            challenge_id=getattr(challenge, "challenge_id", ""),
            title=getattr(challenge, "title", ""),
            category=getattr(challenge, "category", ""),
            description=getattr(challenge, "description", ""),
            attachments=[Path(item) for item in remote_attachment_paths],
            target=getattr(challenge, "target", None),
            flag_format=getattr(challenge, "flag_format", None),
            metadata=dict(getattr(challenge, "metadata", {}) or {}),
        )
        remote_challenge.metadata["remote_subagent"] = {
            "remote_host": selected_host,
            "remote_workspace": remote_workspace,
            "remote_input_dir": remote_input_dir,
            "remote_output_dir": remote_output_dir,
            "attachments": list(remote_attachment_paths),
        }

        sub_policy = self.execution_policy.for_remote_subagent(sub_workspace, selected_host) if self.execution_policy else None
        child_loop = AgentLoop(
            llm=self.llm,
            tools=self._build_tools_for_workspace(sub_workspace),
            knowledge_retriever=self.knowledge,
            code_executor=self.code_executor,
            verifier=self.verifier,
            max_steps=max(1, int(spec.max_steps or 1)),
            max_tokens_budget=max(1, int(spec.max_tokens or _DEFAULT_SUBAGENT_MAX_TOKENS)),
            language=self.language,
            file_tool=self.file_tool,
            shell_tool=self.shell_tool,
            toolkit_tool=self.toolkit_tool,
            http_tool=self.http_tool,
            remote_tool=self.remote_tool,
            mcp_registry=self.mcp_registry,
            oob_tool=self.oob_tool,
            workspace_manager=self.workspace_manager,
            execution_policy=sub_policy,
            allow_subagents=False,
            is_subagent=True,
            plugin_registry=self.plugin_registry,
            approval_manager=None,
        )
        child_loop._configure_runtime(remote_challenge, sub_workspace, background=False)
        active_tools = child_loop._select_active_tools(remote_challenge, "standard", {})
        remote_safe_tools = [
            "run_remote_command",
            "run_remote_python",
            "search_knowledge",
            "scan_for_flags",
            "http_request",
            "browse_url",
            "decompile_function",
        ]
        allowed = spec.allowed_tools or [name for name in remote_safe_tools if name in active_tools.names]
        active_tools = active_tools.only_names([name for name in allowed if name in active_tools.names]).without_names(
            ["plan_parallel", "run_python", "shell", "local_tool", "read_file"]
        )
        child_loop._active_tools = active_tools
        knowledge_ctx = child_loop._retrieve_initial_knowledge(remote_challenge, speed_mode="standard", speed_profile={})
        messages = [
            {
                "role": "system",
                "content": SYSTEM_PROMPT.format(tool_list=active_tools.describe(), knowledge=knowledge_ctx),
            },
            {
                "role": "user",
                "content": child_loop._format_challenge(remote_challenge, sub_workspace)
                + "\n\n## Remote Subagent Mission\nPurpose: {0}\nPrompt: {1}\nRemote host: {2}\nRemote workspace: {3}".format(
                    spec.purpose,
                    spec.prompt,
                    selected_host,
                    remote_workspace,
                ),
            },
        ]
        child_state = ChallengeState(phase="subagent")
        child_memory = StateMemory(child_state)
        child_memory.record_action("subagent", "init", "ok", spec.purpose[:200])

        self._update_remote_status(
            workspace,
            spec.id,
            {
                "status": "running",
                "remote_host": selected_host,
                "remote_workspace": remote_workspace,
                "execution_mode": "remote",
                "poll_interval_sec": int(spec.poll_interval_sec or 5),
                "message": "remote subagent is running",
            },
            remote_host=selected_host,
            remote_workspace=remote_workspace,
            mirror_remote=True,
        )

        def _run_child():
            return child_loop._run_loop(
                remote_challenge,
                sub_workspace,
                child_state,
                child_memory,
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
                    "token_baseline": child_loop._current_total_tokens(),
                },
            )

        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(_run_child)
            last_heartbeat = 0.0
            while not future.done():
                now = time.time()
                if now - last_heartbeat >= max(1, int(spec.poll_interval_sec or 5)):
                    self._update_remote_status(
                        workspace,
                        spec.id,
                        {
                            "status": "running",
                            "remote_host": selected_host,
                            "remote_workspace": remote_workspace,
                            "execution_mode": "remote",
                            "poll_interval_sec": int(spec.poll_interval_sec or 5),
                            "updated_at": now,
                        },
                        remote_host=selected_host,
                        remote_workspace=remote_workspace,
                        mirror_remote=True,
                    )
                    last_heartbeat = now
                time.sleep(min(1.0, max(0.25, float(spec.poll_interval_sec or 1) / 2.0)))
            try:
                child_state = future.result()
            except Exception as exc:
                return _failed_record(
                    "remote subagent execution failed: {0}".format(exc),
                    remote_status={
                        "status": "failed",
                        "remote_host": selected_host,
                        "remote_workspace": remote_workspace,
                        "message": str(exc),
                    },
                    sync_manifest=sync_manifest,
                    artifact_paths=[str(bundle_path)],
                )

        child_loop._write_notes(sub_workspace, child_state, challenge=remote_challenge, speed_mode="standard")
        child_loop._write_board(remote_challenge, sub_workspace, child_state, speed_mode="standard")
        transcript_path = self.workspace_manager.save_subagent_transcript(workspace, spec.id, messages)
        summary = self._build_subagent_summary(child_state)
        usage = dict(getattr(child_loop, "_last_runtime_usage", {}) or {})
        stop_reason = str(getattr(child_loop, "_last_stop_reason", "completed") or "completed")
        status = self._subagent_status_from_reason(stop_reason)
        local_artifact_paths = [str(path) for path in sorted((sub_workspace / "artifacts").rglob("*")) if path.is_file()]

        self._update_remote_status(
            workspace,
            spec.id,
            {
                "status": "syncing",
                "remote_host": selected_host,
                "remote_workspace": remote_workspace,
                "execution_mode": "remote",
                "poll_interval_sec": int(spec.poll_interval_sec or 5),
                "stop_reason": stop_reason,
            },
            remote_host=selected_host,
            remote_workspace=remote_workspace,
            mirror_remote=True,
        )

        summary_payload = {
            "id": spec.id,
            "status": status,
            "stop_reason": stop_reason,
            "usage": usage,
            "summary": summary,
            "artifact_paths": local_artifact_paths + [str(transcript_path), str(bundle_path)],
            "remote_status": {
                "status": status,
                "remote_host": selected_host,
                "remote_workspace": remote_workspace,
            },
            "sync_manifest": sync_manifest,
        }
        local_summary_path = self.workspace_manager.save_subagent_summary(workspace, spec.id, summary_payload)
        local_tar_path = sub_workspace / "artifacts.tar.gz"
        if spec.mirror_artifacts:
            with tarfile.open(local_tar_path, "w:gz") as handle:
                artifacts_dir = sub_workspace / "artifacts"
                if artifacts_dir.exists():
                    for item in sorted(path for path in artifacts_dir.rglob("*") if path.is_file()):
                        handle.add(str(item), arcname=str(item.relative_to(artifacts_dir)))

        remote_summary_path = remote_output_dir + "/summary.json"
        remote_transcript_path = remote_output_dir + "/transcript.jsonl"
        remote_tar_path = remote_output_dir + "/artifacts.tar.gz"
        for content, remote_path, kind in [
            (json.dumps(summary_payload, ensure_ascii=False, indent=2), remote_summary_path, "summary"),
            (Path(transcript_path).read_text(encoding="utf-8-sig"), remote_transcript_path, "transcript"),
        ]:
            upload_result = self.remote_tool.upload_text(selected_host, content, remote_path=remote_path, timeout=30)
            if dict(upload_result or {}).get("status") == "ok":
                sync_manifest["uploads"].append({"local_path": "", "remote_path": remote_path, "kind": kind})
        if spec.mirror_artifacts and local_tar_path.exists():
            upload_result = self.remote_tool.upload(selected_host, str(local_tar_path), remote_path=remote_tar_path, timeout=45)
            if dict(upload_result or {}).get("status") == "ok":
                sync_manifest["uploads"].append({"local_path": str(local_tar_path), "remote_path": remote_tar_path, "kind": "artifacts"})

        download_summary_path = sub_workspace / "remote_summary.json"
        download_transcript_path = sub_workspace / "remote_transcript.jsonl"
        download_tar_path = sub_workspace / "remote_artifacts.tar.gz"
        for remote_path, local_path, kind in [
            (remote_summary_path, download_summary_path, "summary"),
            (remote_transcript_path, download_transcript_path, "transcript"),
        ]:
            download_result = self.remote_tool.download(selected_host, remote_path, str(local_path), timeout=30)
            if dict(download_result or {}).get("status") == "ok":
                sync_manifest["downloads"].append({"remote_path": remote_path, "local_path": str(local_path), "kind": kind})
        if spec.mirror_artifacts and local_tar_path.exists():
            download_result = self.remote_tool.download(selected_host, remote_tar_path, str(download_tar_path), timeout=45)
            if dict(download_result or {}).get("status") == "ok":
                sync_manifest["downloads"].append({"remote_path": remote_tar_path, "local_path": str(download_tar_path), "kind": "artifacts"})
                extracted_remote_artifacts = sub_workspace / "artifacts" / "remote_mirror"
                extracted_remote_artifacts.mkdir(parents=True, exist_ok=True)
                try:
                    with tarfile.open(download_tar_path, "r:gz") as handle:
                        handle.extractall(extracted_remote_artifacts)
                except Exception:
                    logger.debug("Failed to extract mirrored remote artifacts for %s", spec.id, exc_info=True)

        self.workspace_manager.save_subagent_sync_manifest(workspace, spec.id, sync_manifest)
        remote_status = self._update_remote_status(
            workspace,
            spec.id,
            {
                "status": status,
                "remote_host": selected_host,
                "remote_workspace": remote_workspace,
                "execution_mode": "remote",
                "poll_interval_sec": int(spec.poll_interval_sec or 5),
                "stop_reason": stop_reason,
                "usage": usage,
            },
            remote_host=selected_host,
            remote_workspace=remote_workspace,
            mirror_remote=True,
        )

        artifact_paths = local_artifact_paths + [
            str(transcript_path),
            str(bundle_path),
            str(local_summary_path),
        ]
        if download_summary_path.exists():
            artifact_paths.append(str(download_summary_path))
        if download_transcript_path.exists():
            artifact_paths.append(str(download_transcript_path))
        if download_tar_path.exists():
            artifact_paths.append(str(download_tar_path))

        record = SubAgentRecord(
            id=spec.id,
            status=status,
            started_at=started_at,
            finished_at=time.time(),
            spec=spec,
            summary=summary,
            stop_reason=stop_reason,
            usage=usage,
            remote_status=remote_status,
            sync_manifest=sync_manifest,
            error=child_state.blocked_reason if stop_reason == "error" else None,
            artifact_paths=artifact_paths,
        )
        record_payload = record.to_dict()
        record_payload["summary_text"] = summary.get("summary_text", "")
        record_payload["transcript_path"] = str(transcript_path)
        self.workspace_manager.save_subagent_summary(workspace, spec.id, record_payload)
        result_entry = {
            "tool": "subagent:{0}".format(spec.id),
            "purpose": spec.purpose,
            "status": record.status,
            "stop_reason": record.stop_reason,
            "usage": dict(record.usage),
            "summary": dict(record.summary),
            "artifact_paths": list(record.artifact_paths),
            "remote_status": dict(record.remote_status),
            "sync_manifest": dict(record.sync_manifest),
            "result": self._format_subagent_result(record),
            "elapsed_ms": int(record.usage.get("elapsed_ms", 0) or 0),
        }
        return record, result_entry

    def _resolve_subagent_tool_names(self, requested):
        safe_tools = [
            "read_file",
            "search_knowledge",
            "http_request",
            "scan_for_flags",
            "decompile_function",
            "browse_url",
            "extract_archive",
            "diff_http",
            "local_tool",
            "run_python",
        ]
        available = set(self._tool_registry().names)
        if requested:
            filtered = [str(item) for item in list(requested or []) if str(item) in available and str(item) != "plan_parallel"]
            if filtered:
                return filtered
        return [name for name in safe_tools if name in available]

    def _resolve_budget_value(self, task, key, default_budget, fallback):
        payload = dict(task or {})
        defaults = dict(default_budget or {})
        for candidate in [payload.get(key), defaults.get(key), fallback]:
            try:
                value = int(candidate or 0)
            except (TypeError, ValueError):
                value = 0
            if value > 0:
                return value
        return int(fallback or 0)

    def _current_total_tokens(self):
        try:
            stats = getattr(self.llm, "stats", {})
        except Exception:
            stats = {}
        if callable(stats):
            try:
                stats = stats()
            except Exception:
                stats = {}
        if isinstance(stats, dict):
            try:
                return max(0, int(stats.get("total_tokens", 0) or 0))
            except (TypeError, ValueError):
                return 0
        return 0

    def _subagent_status_from_reason(self, stop_reason):
        reason = str(stop_reason or "completed").strip().lower() or "completed"
        if reason in {"max_steps", "max_tool_calls", "max_tokens"}:
            return "budget_exhausted"
        if reason == "timeout":
            return "timed_out"
        if reason == "error":
            return "failed"
        return "completed"

    def _format_subagent_result(self, record):
        summary = dict(getattr(record, "summary", {}) or {})
        usage = dict(getattr(record, "usage", {}) or {})
        lines = [
            "[status={0} reason={1}]".format(
                getattr(record, "status", "") or "completed",
                getattr(record, "stop_reason", "") or "completed",
            ),
            "usage: steps={0}, tool_calls={1}, tokens_used={2}, elapsed_ms={3}".format(
                int(usage.get("steps", 0) or 0),
                int(usage.get("tool_calls", 0) or 0),
                int(usage.get("tokens_used", 0) or 0),
                int(usage.get("elapsed_ms", 0) or 0),
            ),
            "tried: {0}".format(summary.get("what_was_tried", "") or "(none)"),
            "found: {0}".format(summary.get("what_was_found", "") or "(none)"),
            "next: {0}".format(summary.get("what_to_do_next", "") or "(none)"),
        ]
        artifact_paths = list(getattr(record, "artifact_paths", []) or [])
        if artifact_paths:
            lines.append("artifacts: {0}".format(", ".join(artifact_paths[:4])))
        return "\n".join(lines)

    def _build_subagent_summary(self, state):
        what_was_tried = "; ".join(
            "{0}:{1}".format(item.action, item.summary[:120])
            for item in list(state.tried_actions or [])[-5:]
        )
        what_was_found = "; ".join(
            item.summary[:140]
            for item in list(state.findings or [])[-5:]
        )
        if not what_was_found and state.candidate_flags:
            what_was_found = "candidate flags: {0}".format(", ".join(item.value for item in state.candidate_flags[:3]))
        what_to_do_next = state.blocked_reason or (state.hypotheses[-1] if state.hypotheses else "")
        summary_text = "tried: {0}\nfound: {1}\nnext: {2}".format(
            what_was_tried or "(none)",
            what_was_found or "(none)",
            what_to_do_next or "(none)",
        )
        return {
            "what_was_tried": what_was_tried or "",
            "what_was_found": what_was_found or "",
            "what_to_do_next": what_to_do_next or "",
            "summary_text": summary_text,
        }

    def _approval_request_status(self, workspace, request_id):
        request_id = str(request_id or "").strip()
        if not request_id or not self.approval_manager:
            return ""
        try:
            self.approval_manager.configure(workspace=str(workspace))
            request = self.approval_manager.get_request(request_id, workspace=str(workspace))
        except Exception:
            request = None
        return str(getattr(request, "status", "") or "")

    def _pending_approval_payload(self, workspace, tool_name, tool_args, tool_call_id, result_payload, step, source):
        payload = dict(result_payload or {})
        request_id = str(payload.get("request_id", "") or dict(payload.get("approval") or {}).get("request_id", "") or "")
        return {
            "request_id": request_id,
            "tool_name": str(tool_name or ""),
            "arguments": dict(tool_args or {}),
            "tool_call_id": str(tool_call_id or ""),
            "step": int(step or 0),
            "source": str(source or ""),
            "status": str(payload.get("status", "needs_approval") or "needs_approval"),
            "message": str(payload.get("message", "approval required") or "approval required"),
            "approval": dict(payload.get("approval") or {}),
            "result_payload": payload,
            "workspace": str(workspace),
        }

    def _persist_session(
        self,
        challenge,
        state,
        messages,
        step,
        workspace,
        pending_approval=None,
        pending_action=None,
        runtime_usage=None,
        stop_reason="",
    ):
        session = _serialize_session(
            challenge,
            state,
            messages,
            step,
            workspace,
            pending_approval=pending_approval,
            pending_action=pending_action,
            runtime_usage=runtime_usage,
            stop_reason=stop_reason,
        )
        return _save_session(workspace, session)

    def _pause_for_approval(self, challenge, workspace, state, memory, messages, step, pending_approval, summary):
        payload = dict(pending_approval or {})
        state.phase = "needs_approval"
        state.blocked_reason = str(summary or payload.get("message") or "approval required")
        if memory is not None:
            memory.record_action(
                "agent-loop",
                "needs_approval",
                "blocked",
                state.blocked_reason[:300],
            )
        self._pending_approval = payload
        self._pending_action = dict(payload.get("result_payload") or {})
        self._persist_session(
            challenge,
            state,
            messages,
            step,
            workspace,
            pending_approval=payload,
            pending_action=self._pending_action,
            runtime_usage=self._last_runtime_usage,
            stop_reason="needs_approval",
        )
        return state

    def _resume_pending_tool_call(self, workspace, challenge, state, memory, messages, pending_approval, active_tools):
        payload = dict(pending_approval or {})
        request_id = str(payload.get("request_id", "") or "")
        if request_id:
            request_status = self._approval_request_status(workspace, request_id)
            if request_status not in {"approved", "consumed"}:
                if request_status == "denied":
                    state.phase = "needs_approval"
                    state.blocked_reason = payload.get("message") or "approval was denied"
                return False
        if str(payload.get("source", "") or "") == "plan_parallel_subagent":
            spec_payload = dict(dict(payload.get("result_payload") or {}).get("subagent_spec") or {})
            if not spec_payload:
                return False
            spec = SubAgentSpec.from_dict(spec_payload)
            record, result_entry = self._run_subagent_spec(challenge, workspace, spec)
            if result_entry.get("status") == "needs_approval":
                state.phase = "needs_approval"
                state.blocked_reason = str(result_entry.get("result", "") or "approval is still required")
                return False
            if record is not None:
                state.subagents = [item for item in state.subagents if item.id != record.id]
                state.subagents.append(record)
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": str(payload.get("tool_call_id", "") or "resume-approval"),
                    "content": "Parallel results:\n\n[{0}] {1}\n{2}".format(
                        result_entry.get("tool", ""),
                        result_entry.get("purpose", ""),
                        str(result_entry.get("result", "") or "")[:1500],
                    ),
                }
            )
            memory.record_action(
                "agent-loop",
                "parallel:{0}".format(result_entry.get("tool", "subagent")),
                "ok",
                str(result_entry.get("result", "") or "")[:300],
            )
            self._pending_approval = {}
            self._pending_action = {}
            return True
        tool_name = str(payload.get("tool_name", "") or "")
        if not tool_name:
            return False
        tool_args = dict(payload.get("arguments") or {})
        result_text = active_tools.execute(tool_name, tool_args)
        tool_result = dict(getattr(active_tools, "_last_result", {}) or {})
        if tool_result.get("status") == "needs_approval":
            state.phase = "needs_approval"
            state.blocked_reason = str(tool_result.get("message", "") or "approval is still required")
            return False
        messages.append(
            {
                "role": "tool",
                "tool_call_id": str(payload.get("tool_call_id", "") or "resume-approval"),
                "content": result_text,
            }
        )
        self._scan_text(result_text, memory, "tool:{0}".format(tool_name))
        memory.record_action(
            "agent-loop",
            "tool:{0}".format(tool_name),
            "ok",
            result_text[:300],
        )
        self._pending_approval = {}
        self._pending_action = {}
        return True

    def _remote_runner_script(self):
        return """\
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import traceback
import zipfile
from pathlib import Path


def write_json(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8-sig")


def read_json(path):
    path = Path(path)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return {}


def process_alive(pid):
    try:
        os.kill(int(pid), 0)
        return True
    except Exception:
        return False


def extract_bundle(workspace):
    workspace = Path(workspace).resolve()
    bundle_path = workspace / "input" / "remote_subagent_bundle.zip"
    bundle_root = workspace / "bundle"
    if bundle_root.exists():
        shutil.rmtree(str(bundle_root), ignore_errors=True)
    bundle_root.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(str(bundle_path), "r") as handle:
        handle.extractall(str(bundle_root))
    sys.path.insert(0, str(bundle_root))
    return bundle_root


def bootstrap_payload(workspace, status="running", phase="heartbeat", job_id="", stop_reason=""):
    workspace = Path(workspace).resolve()
    output_dir = workspace / "output"
    output_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "status": status,
        "phase": phase,
        "updated_at": time.time(),
        "workspace": str(workspace),
        "job_id": str(job_id or ""),
        "stop_reason": str(stop_reason or ""),
    }
    write_json(output_dir / "heartbeat.json", payload)
    write_json(
        output_dir / "state.json",
        {
            "status": payload["status"],
            "updated_at": payload["updated_at"],
            "workspace": payload["workspace"],
            "job_id": payload["job_id"],
            "stop_reason": payload["stop_reason"],
        },
    )
    return payload


def main():
    workspace = Path(sys.argv[1]).resolve()
    phase = str(sys.argv[2] if len(sys.argv) > 2 else "status")
    output_dir = workspace / "output"
    output_dir.mkdir(parents=True, exist_ok=True)
    if phase == "init":
        extract_bundle(workspace)
        bootstrap_payload(workspace, status="queued", phase="init")
        print(json.dumps({"status": "ok", "workspace": str(workspace)}))
        return
    if phase == "start":
        extract_bundle(workspace)
        log_path = output_dir / "runner.log"
        with log_path.open("ab") as handle:
            process = subprocess.Popen(
                [sys.executable, str(Path(__file__).resolve()), str(workspace), "execute"],
                cwd=str(workspace),
                stdout=handle,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        job_payload = {
            "status": "ok",
            "job_id": str(process.pid),
            "workspace": str(workspace),
            "log_path": str(log_path),
        }
        write_json(output_dir / "job.json", job_payload)
        bootstrap_payload(workspace, status="running", phase="start", job_id=str(process.pid))
        print(json.dumps(job_payload))
        return
    if phase == "status":
        job = read_json(output_dir / "job.json")
        state = read_json(output_dir / "state.json")
        summary = read_json(output_dir / "summary.json")
        job_id = str(job.get("job_id", "") or "")
        if summary and str(summary.get("status", "") or ""):
            payload = {
                "status": "ok",
                "state": str(summary.get("status", "") or "completed"),
                "job_id": job_id,
                "workspace": str(workspace),
                "summary_ready": True,
            }
            print(json.dumps(payload))
            return
        state_name = "running" if process_alive(job_id) else "finished"
        bootstrap_payload(workspace, status=str((state.get("status", "") or "running") if state_name == "running" else state.get("status", "failed")), phase="status", job_id=job_id)
        print(json.dumps({"status": "ok", "state": state_name, "job_id": job_id, "workspace": str(workspace)}))
        return
    if phase == "cancel":
        job = read_json(output_dir / "job.json")
        job_id = str(job.get("job_id", "") or "")
        if job_id:
            try:
                os.kill(int(job_id), signal.SIGTERM)
            except Exception:
                pass
        bootstrap_payload(workspace, status="cancelled", phase="cancel", job_id=job_id, stop_reason="cancelled")
        print(json.dumps({"status": "ok", "state": "cancelled", "job_id": job_id, "workspace": str(workspace)}))
        return
    if phase == "execute":
        try:
            extract_bundle(workspace)
            from ctf_agent.core.remote_subagent_runner import execute_remote_subagent

            payload = execute_remote_subagent(workspace)
            print(json.dumps(payload, ensure_ascii=False))
            return
        except Exception as exc:
            payload = {"status": "failed", "message": str(exc), "trace": traceback.format_exc()}
            write_json(output_dir / "summary.json", payload)
            bootstrap_payload(workspace, status="failed", phase="execute", stop_reason="error")
            print(json.dumps(payload))
            return
    bootstrap_payload(workspace, status="failed", phase=phase, stop_reason="unsupported-command")
    print(json.dumps({"status": "failed", "message": "unsupported runner phase", "phase": phase}))


if __name__ == "__main__":
    main()
"""

    def _create_remote_bundle(self, sub_workspace):
        sub_workspace = Path(sub_workspace)
        bundle_path = sub_workspace / "remote_subagent_bundle.zip"
        runner_name = "remote_subagent_runner.py"
        with zipfile.ZipFile(bundle_path, "w", compression=zipfile.ZIP_DEFLATED) as handle:
            package_root = Path(__file__).resolve().parents[1]
            for item in sorted(package_root.rglob("*")):
                if item.is_dir():
                    continue
                if "__pycache__" in item.parts or item.suffix in {".pyc", ".pyo"}:
                    continue
                handle.write(str(item), arcname=str(item.relative_to(package_root.parent)).replace("\\", "/"))
            if self.plugin_registry:
                for plugin in list(self.plugin_registry.enabled_plugins_view() or []):
                    plugin_root = Path(plugin.get("root", "") or "")
                    if not plugin_root.exists():
                        continue
                    for item in sorted(plugin_root.rglob("*")):
                        if item.is_dir():
                            continue
                        if "__pycache__" in item.parts or item.suffix in {".pyc", ".pyo"}:
                            continue
                        arcname = Path("plugins_snapshot") / plugin_root.name / item.relative_to(plugin_root)
                        handle.write(str(item), arcname=str(arcname).replace("\\", "/"))
            handle.writestr(runner_name, self._remote_runner_script())
        return bundle_path, runner_name

    def _remote_llm_payload(self):
        llm = self.llm
        if not llm:
            return {}
        return {
            "api_key": getattr(llm, "api_key", ""),
            "base_url": getattr(llm, "base_url", ""),
            "model": getattr(llm, "model", ""),
            "temperature": getattr(llm, "temperature", None),
            "max_tokens": getattr(llm, "max_tokens", None),
            "timeout": getattr(llm, "timeout", None),
            "python_bin": sys.executable,
            "enabled": bool(getattr(llm, "api_key", "")),
        }

    def _update_remote_status(self, workspace, subagent_id, payload, remote_host="", remote_workspace="", mirror_remote=False):
        remote_payload = dict(payload or {})
        remote_payload.setdefault("updated_at", time.time())
        self.workspace_manager.save_subagent_remote_status(workspace, subagent_id, remote_payload)
        if not mirror_remote or not self.remote_tool or not remote_host or not remote_workspace:
            return remote_payload
        try:
            output_root = str(remote_workspace).rstrip("/") + "/output"
            self.remote_tool.upload_text(
                remote_host,
                json.dumps(remote_payload, ensure_ascii=False, indent=2),
                remote_path=output_root + "/heartbeat.json",
                timeout=20,
            )
            state_payload = {
                "status": str(remote_payload.get("status", "") or ""),
                "updated_at": remote_payload.get("updated_at"),
                "remote_host": remote_host,
                "remote_workspace": remote_workspace,
            }
            self.remote_tool.upload_text(
                remote_host,
                json.dumps(state_payload, ensure_ascii=False, indent=2),
                remote_path=output_root + "/state.json",
                timeout=20,
            )
        except Exception:
            logger.debug("Failed to mirror remote heartbeat for %s", subagent_id, exc_info=True)
        return remote_payload

    def _select_remote_subagent_host(self, challenge, spec):
        preferred = str(getattr(spec, "remote_host", "") or "").strip()
        if preferred:
            return preferred
        if not self.remote_tool:
            return ""
        try:
            recommended = self.remote_tool.recommend_host(
                category=str(getattr(challenge, "category", "") or ""),
                target=str(getattr(challenge, "target", "") or ""),
            )
        except Exception:
            recommended = {}
        return str((recommended or {}).get("selected_host", "") or "")

    # ------------------------------------------------------------------
    # Core loop (shared by solve and continue_solve)
    # ------------------------------------------------------------------

    def _run_loop(self, challenge, workspace, state, memory, messages, start_step=0, active_tools=None, speed_mode="standard", speed_profile=None, runtime_limits=None):
        workspace = Path(workspace)
        active_tools = active_tools or self._tool_registry()
        speed_mode = str(speed_mode or "standard").strip().lower() or "standard"
        speed_profile = dict(speed_profile or {})
        runtime_limits = dict(runtime_limits or {})
        fastest_enabled = speed_mode == "fastest" and bool(speed_profile.get("enabled", True))
        max_tool_calls = int(speed_profile.get("max_tool_calls", 0) or 0)
        runtime_max_steps = int(runtime_limits.get("max_steps", 0) or 0)
        runtime_max_tool_calls = int(runtime_limits.get("max_tool_calls", 0) or 0)
        runtime_max_tokens = int(runtime_limits.get("max_tokens", 0) or 0)
        timeout_sec = float(runtime_limits.get("timeout_sec", 0) or 0.0)
        token_baseline = int(runtime_limits.get("token_baseline", self._current_total_tokens()) or self._current_total_tokens())
        token_budget = runtime_max_tokens if runtime_max_tokens > 0 else int(self.max_tokens_budget or 0)
        tool_call_budget = int(speed_profile.get("tool_call_budget", 0) or 0)
        if tool_call_budget <= 0 and fastest_enabled:
            tool_call_budget = max_tool_calls
        if runtime_max_tool_calls > 0:
            tool_call_budget = runtime_max_tool_calls if tool_call_budget <= 0 else min(tool_call_budget, runtime_max_tool_calls)
        tool_calls_used = 0
        steps_taken = 0
        effective_max_steps = int(self.max_steps or _DEFAULT_MAX_STEPS)
        if runtime_max_steps > 0:
            effective_max_steps = min(effective_max_steps, runtime_max_steps)
        if tool_call_budget > 0:
            effective_max_steps = min(effective_max_steps, max(4, tool_call_budget * 2 + 2))
        started_at = time.time()
        stop_reason = "completed"
        self._last_stop_reason = "completed"
        self._last_runtime_usage = {
            "steps": 0,
            "tool_calls": 0,
            "tokens_used": 0,
            "elapsed_ms": 0,
        }
        self._pending_approval = {}
        self._pending_action = {}

        def _tokens_used():
            return max(0, self._current_total_tokens() - token_baseline)

        def _elapsed_ms():
            return int((time.time() - started_at) * 1000)

        def _runtime_usage():
            return {
                "steps": int(steps_taken),
                "tool_calls": int(tool_calls_used),
                "tokens_used": int(_tokens_used()),
                "elapsed_ms": int(_elapsed_ms()),
            }

        def _stop(reason, action, summary, status="blocked"):
            nonlocal stop_reason
            stop_reason = str(reason or "completed")
            if summary:
                state.blocked_reason = summary
                memory.record_action("agent-loop", action, status, summary[:300])
            return True

        def _check_runtime_limits(step_index, boundary):
            if timeout_sec > 0 and (time.time() - started_at) >= timeout_sec:
                return _stop(
                    "timeout",
                    "timeout",
                    "Soft timeout reached after {0} ms at {1} boundary for step {2}".format(
                        _elapsed_ms(),
                        boundary,
                        step_index,
                    ),
                )
            if token_budget > 0 and _tokens_used() >= token_budget:
                return _stop(
                    "max_tokens",
                    "budget:max_tokens",
                    "Token budget reached ({0}/{1}) at {2} boundary for step {3}".format(
                        _tokens_used(),
                        token_budget,
                        boundary,
                        step_index,
                    ),
                )
            return False

        loop_exhausted = effective_max_steps > start_step
        if effective_max_steps <= start_step:
            _stop(
                "max_steps",
                "budget:max_steps",
                "Step budget reached before step {0} (limit={1})".format(start_step, effective_max_steps),
            )

        for step in range(start_step, effective_max_steps):
            if _check_runtime_limits(step, "step-start"):
                loop_exhausted = False
                break

            steps_taken = max(steps_taken, step - start_step + 1)

            if state.candidate_flags:
                best = self._best_flag(state, challenge)
                if best:
                    state.phase = "solved"
                    memory.record_action("agent-loop", "solved", "ok", best)
                    loop_exhausted = False
                    break

            if (not fastest_enabled
                    and step >= _MIN_STEPS_BEFORE_REFLECTION
                    and step % _REFLECTION_INTERVAL == 0):
                reflection = self._reflect(state)
                if reflection:
                    messages.append({"role": "user", "content":
                        "[系统: 反思检查点]\n" + reflection})
                    memory.add_hypothesis("[reflection@step{0}] {1}".format(step, reflection[:300]))

            try:
                tools_spec = active_tools.to_openai_tools() if active_tools.names else None
                response = self.llm.chat(messages, tools=tools_spec)
            except Exception as exc:
                logger.error("LLM call failed at step %d: %s", step, exc)
                memory.record_action("agent-loop", "llm-error", "error", str(exc)[:300])
                if step < start_step + 2:
                    _stop(
                        "error",
                        "llm-error",
                        "LLM call failed at step {0}: {1}".format(step, str(exc)[:240]),
                        status="error",
                    )
                    loop_exhausted = False
                    break
                continue

            if response.text:
                messages.append({"role": "assistant", "content": response.text})
                self._scan_text(response.text, memory, "llm-step-{0}".format(step))
                declared = FLAG_TAG_RE.search(response.text)
                if declared:
                    val = declared.group(1).strip()
                    memory.add_candidate_flag(val, "agent-loop:declared", 0.93, reproducible=False)

            if response.has_tool_calls():
                if not response.text:
                    messages.append({
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": tc.id,
                                "type": "function",
                                "function": {
                                    "name": tc.name,
                                    "arguments": json.dumps(tc.arguments, ensure_ascii=False),
                                },
                            }
                            for tc in response.tool_calls
                        ],
                    })

                if (len(response.tool_calls) == 1
                        and response.tool_calls[0].name == "plan_parallel"):
                    parallel_results = self.plan_parallel(challenge, state, workspace)
                    if parallel_results:
                        approval_result = next(
                            (item for item in parallel_results if str(item.get("status", "") or "") == "needs_approval"),
                            None,
                        )
                        if approval_result:
                            pending_approval = {
                                "request_id": str(approval_result.get("request_id", "") or ""),
                                "tool_name": "plan_parallel",
                                "arguments": {"reason": "parallel subagent approval"},
                                "tool_call_id": response.tool_calls[0].id,
                                "step": int(step),
                                "source": "plan_parallel_subagent",
                                "status": "needs_approval",
                                "message": str(
                                    approval_result.get("result", "")
                                    or dict(approval_result.get("summary") or {}).get("summary_text", "")
                                    or "approval required"
                                ),
                                "approval": dict(approval_result.get("approval") or {}),
                                "result_payload": dict(approval_result or {}),
                                "workspace": str(workspace),
                            }
                            self._pause_for_approval(
                                challenge,
                                workspace,
                                state,
                                memory,
                                messages,
                                step,
                                pending_approval,
                                pending_approval["message"],
                            )
                            stop_reason = "needs_approval"
                            loop_exhausted = False
                            break
                        summary_parts = []
                        for pr in parallel_results:
                            summary_parts.append("[{0}] {1}\n{2}".format(
                                pr["tool"], pr["purpose"], pr["result"][:1500]))
                            self._scan_text(pr["result"], memory, "parallel:{0}".format(pr["tool"]))
                            memory.record_action("agent-loop",
                                "parallel:{0}".format(pr["tool"]), "ok",
                                pr["result"][:200])
                        messages.append({
                            "role": "tool",
                            "tool_call_id": response.tool_calls[0].id,
                            "content": "Parallel results:\n\n" + "\n---\n".join(summary_parts),
                        })
                        continue

                for tc in response.tool_calls:
                    if tool_call_budget > 0 and tool_calls_used >= tool_call_budget:
                        _stop(
                            "max_tool_calls",
                            "budget:max_tool_calls",
                            "Tool-call budget reached ({0}/{1})".format(tool_calls_used, tool_call_budget),
                        )
                        break

                    memory.record_action("agent-loop",
                        "tool:{0}".format(tc.name), "running",
                        json.dumps(tc.arguments, ensure_ascii=False)[:200])

                    result_text = active_tools.execute(tc.name, tc.arguments)
                    last_result = getattr(active_tools, "_last_result", None)
                    if isinstance(last_result, dict) and last_result.get("status") == "needs_approval":
                        pending_approval = self._pending_approval_payload(
                            workspace,
                            tc.name,
                            tc.arguments,
                            tc.id,
                            last_result,
                            step,
                            "tool:{0}".format(tc.name),
                        )
                        self._pause_for_approval(
                            challenge,
                            workspace,
                            state,
                            memory,
                            messages,
                            step,
                            pending_approval,
                            pending_approval.get("message", ""),
                        )
                        stop_reason = "needs_approval"
                        loop_exhausted = False
                        break
                    tool_calls_used += 1
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": result_text,
                    })
                    self._scan_text(result_text, memory, "tool:{0}".format(tc.name))
                    memory.record_action("agent-loop",
                        "tool:{0}".format(tc.name), "ok",
                        result_text[:300])
                    if fastest_enabled and self.verifier and self.verifier.discover_from_text(result_text):
                        state.phase = "solved"
                        break
                    if _check_runtime_limits(step, "tool-return"):
                        break

                if state.phase in {"solved", "needs_approval"} or state.blocked_reason:
                    loop_exhausted = False
                    break

            elif response.finish_reason == "stop" and not state.candidate_flags:
                if step < effective_max_steps - 2:
                    if fastest_enabled:
                        messages.append({"role": "user", "content": "Continue with the shortest remaining path. Use a tool only if it materially advances toward the flag."})
                    else:
                        messages.append({"role": "user", "content":
                            "请继续。如果已找到 flag 请用 [FLAG]flag值[/FLAG] 标注；"
                            "如果还没有，请调用工具继续分析。"
                            "如果有多个方向可以探索，调用 plan_parallel 并行处理。"})
                else:
                    loop_exhausted = False
                    break
            elif not response.text and not response.has_tool_calls():
                loop_exhausted = False
                break

            if step > 0 and step % 5 == 0:
                try:
                    self._persist_session(
                        challenge,
                        state,
                        messages,
                        step,
                        workspace,
                        pending_approval=self._pending_approval,
                        pending_action=self._pending_action,
                        runtime_usage=_runtime_usage(),
                        stop_reason=stop_reason,
                    )
                except Exception:
                    pass

        if loop_exhausted and stop_reason == "completed" and state.phase not in {"solved", "paused", "needs_approval"}:
            _stop(
                "max_steps",
                "budget:max_steps",
                "Step budget reached ({0}/{1})".format(
                    max(steps_taken, max(0, effective_max_steps - start_step)),
                    effective_max_steps,
                ),
            )

        if state.phase not in {"solved", "paused", "needs_approval"}:
            state.phase = "candidates-found" if state.candidate_flags else "exhausted"

        self._last_stop_reason = stop_reason
        self._last_runtime_usage = _runtime_usage()

        try:
            final_step = start_step + max(steps_taken, 0)
            self._persist_session(
                challenge,
                state,
                messages,
                final_step,
                workspace,
                pending_approval=self._pending_approval,
                pending_action=self._pending_action,
                runtime_usage=self._last_runtime_usage,
                stop_reason=stop_reason,
            )
        except Exception:
            pass

        return state

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _format_challenge(self, challenge, workspace):
        parts = ["# CTF Challenge\n"]
        if challenge.title:
            parts.append("**Title**: {0}".format(challenge.title))
        if challenge.category:
            parts.append("**Category**: {0}".format(challenge.category))
        if challenge.description:
            parts.append("**Description**:\n{0}".format(challenge.description))
        if challenge.target:
            parts.append("**Target**: {0}".format(challenge.target))
        if challenge.flag_format:
            parts.append("**Flag format**: `{0}`".format(challenge.flag_format))
        if challenge.attachments:
            parts.append("**Attachments**:")
            for att in challenge.attachments:
                parts.append("- `{0}`".format(att))
        parts.append("\n**Workspace**: `{0}`".format(workspace))
        return "\n".join(parts)

    def _tool_registry(self):
        return getattr(self, "_active_tools", None) or self.tools

    def _resolve_speed_profile(self, challenge):
        metadata = dict((challenge.metadata or {}))
        autopilot = dict(metadata.get("autopilot_plan") or {})
        speed_mode = str(metadata.get("speed_mode") or autopilot.get("speed_mode") or "standard").strip().lower() or "standard"
        skill_context = self._resolve_skill_context(challenge, speed_mode=speed_mode)
        runtime = dict(skill_context.get("runtime") or {})
        default_budget = dict(runtime.get("default_budget", {}))
        profile = {
            "enabled": speed_mode == "fastest",
            "skip_knowledge": not bool(runtime.get("retrieval_enabled", speed_mode != "fastest")),
            "max_tool_calls": int(default_budget.get("max_tool_calls", 4) or 4) if speed_mode == "fastest" else 0,
            "pwn_remote_only": speed_mode == "fastest",
            "compact_output": speed_mode == "fastest",
            "skip_preview": speed_mode == "fastest",
            "prefer_one_shot_scripts": speed_mode == "fastest",
        }
        profile.update(dict(metadata.get("speed_profile") or autopilot.get("speed_profile") or {}))
        if speed_mode != "fastest":
            profile["enabled"] = False
        return speed_mode, profile

    def _select_active_tools(self, challenge, speed_mode, speed_profile):
        skill_context = self._resolve_skill_context(challenge, speed_mode=speed_mode)
        runtime = dict(skill_context.get("runtime") or {})
        selected = self.tools
        allowed = list(runtime.get("allowed_tools", []))
        denied = list(runtime.get("denied_tools", []))
        if allowed:
            selected = selected.only_names([name for name in allowed if name in selected.names])
        if bool(dict(speed_profile or {}).get("skip_knowledge", False)):
            denied.append("search_knowledge")
        if denied:
            selected = selected.without_names(denied)
        return selected if selected.names else self.tools

    def _retrieve_initial_knowledge(self, challenge, speed_mode="standard", speed_profile=None):
        speed_profile = dict(speed_profile or {})
        skill_context = self._resolve_skill_context(challenge, speed_mode=speed_mode)
        category = dict(skill_context.get("category") or {})
        runtime = dict(skill_context.get("runtime") or {})
        retrieval_enabled = bool(runtime.get("retrieval_enabled", True))
        retrieval_reason = str(runtime.get("retrieval_reason", "") or "").strip()
        if bool(speed_profile.get("skip_knowledge", False)):
            retrieval_enabled = False
            if not retrieval_reason:
                retrieval_reason = "speed profile disabled knowledge retrieval"
        if not retrieval_enabled:
            return "({0})".format(retrieval_reason or "knowledge retrieval disabled")
        if not self.knowledge or not self.knowledge.is_loaded():
            return "(no knowledge base loaded)"
        query = " ".join(filter(None, [
            challenge.title or "",
            challenge.category or "",
            (challenge.description or "")[:500],
        ])).strip()
        if not query:
            return "(empty query)"
        results = self.knowledge.query(
            query,
            top_k=4,
            category_hint=category.get("selected_skill_category", challenge.category),
        )
        if not results:
            return "(no matching knowledge)"
        sections = []
        for r in results:
            label = "PLAYBOOK" if r["source_type"] == "skills" else "WRITEUP"
            sections.append("[{0}] {1}\n{2}".format(label, r.get("heading", ""), r["text"][:_KNOWLEDGE_CAP // 4]))
        return "\n---\n".join(sections)

    def _reflect(self, state):
        tried = "\n".join(
            "- [{0}] {1}: {2}".format(a.status, a.action, a.summary[:120])
            for a in state.tried_actions[-12:]
        ) or "(none)"
        hypotheses = "\n".join("- {0}".format(h) for h in state.hypotheses[-5:]) or "(none)"
        findings = "\n".join(
            "- [{0}] {1}".format(f.source, f.summary[:120])
            for f in state.findings[-5:]
        ) or "(none)"
        prompt = REFLECTION_PROMPT.format(
            phase=state.phase,
            n_actions=len(state.tried_actions),
            n_flags=len(state.candidate_flags),
            tried=tried,
            hypotheses=hypotheses,
            findings=findings,
        )
        try:
            return self.llm.quick(prompt, temperature=0.3)
        except Exception as exc:
            logger.warning("Reflection failed: %s", exc)
            return None

    def _scan_text(self, text, memory, source):
        if not self.verifier or not text:
            return
        for flag in self.verifier.discover_from_text(text):
            memory.add_candidate_flag(flag, source=source, confidence=0.80, reproducible=False)

    def _best_flag(self, state, challenge):
        if not state.candidate_flags:
            return None
        if self.verifier:
            best = self.verifier.choose_best(state, challenge)
            return best.value if best else None
        return state.candidate_flags[0].value

    def _write_notes(self, workspace, state, challenge=None, speed_mode="standard"):
        path = workspace / "agent_loop_notes.md"
        lines = ["# Agent Loop Summary\n"]
        lines.append("Phase: {0}\n".format(state.phase))
        lines.append("LLM stats: {0}\n".format(json.dumps(self.llm.stats)))
        if challenge is not None:
            skill_context = self._resolve_skill_context(challenge, speed_mode=speed_mode)
            category = dict(skill_context.get("category") or {})
            knowledge = dict(skill_context.get("knowledge") or {})
            runtime = dict(skill_context.get("runtime") or {})
            lines.append("\n## Knowledge\n")
            lines.append("- Selected category: {0}\n".format(category.get("selected_skill_category", challenge.category)))
            lines.append("- Playbook: {0}\n".format(knowledge.get("pack_name", "")))
            lines.append("- Retrieval: {0} ({1})\n".format(
                "enabled" if runtime.get("retrieval_enabled", True) else "disabled",
                runtime.get("retrieval_reason", ""),
            ))
            for tactic in list(knowledge.get("top_tactics", []))[:3]:
                lines.append("- tactic: {0}\n".format(tactic[:200]))
        if state.candidate_flags:
            lines.append("\n## Candidate Flags\n")
            for f in state.candidate_flags:
                lines.append("- `{0}` (source={1}, confidence={2:.0%})\n".format(f.value, f.source, f.confidence))
        if state.hypotheses:
            lines.append("\n## Hypotheses\n")
            for h in state.hypotheses:
                lines.append("- {0}\n".format(h[:200]))
        if state.subagents:
            lines.append("\n## Subagents\n")
            for item in state.subagents:
                summary = dict(item.summary or {})
                usage = dict(getattr(item, "usage", {}) or {})
                lines.append(
                    "- {0} [{1}/{2}] steps={3} tools={4} tokens={5} {6}\n".format(
                        item.id,
                        item.status,
                        getattr(item, "stop_reason", "") or "completed",
                        int(usage.get("steps", 0) or 0),
                        int(usage.get("tool_calls", 0) or 0),
                        int(usage.get("tokens_used", 0) or 0),
                        summary.get("what_was_found", "")[:180] or item.spec.purpose,
                    )
                )
        try:
            workspace.mkdir(parents=True, exist_ok=True)
            path.write_text("".join(lines), encoding="utf-8")
        except OSError:
            pass

    def _write_board(self, challenge, workspace, state, speed_mode="standard"):
        try:
            skill_context = self._resolve_skill_context(challenge, speed_mode=speed_mode)
            category = dict(skill_context.get("category") or {})
            knowledge = dict(skill_context.get("knowledge") or {})
            skillpack = dict(skill_context.get("skillpack") or {})
            recommendations = dict(skill_context.get("recommendations") or {})
            used_tools = []
            used_mcp = []
            for item in list(state.tried_actions or []):
                action = str(item.action or "")
                if action.startswith("tool:"):
                    used_tools.append(action.split(":", 1)[1])
                if action.startswith("parallel:subagent:"):
                    used_tools.append("plan_parallel")
            if self.mcp_registry and self.mcp_registry.has_servers():
                used_mcp = [
                    "{0}".format(item.get("name", ""))
                    for item in self.mcp_registry.enabled_servers()
                    if item.get("name")
                ]
            board = build_triage_board(
                challenge,
                state,
                workspace,
                solver_name="agent-loop",
                context={
                    "attachments": [
                        {"name": Path(item).name, "path": str(item)}
                        for item in list(getattr(challenge, "attachments", []) or [])
                    ],
                    "configured_tools": list(self.tools.names),
                    "used_tools": sorted(set(used_tools)),
                    "recommended_tools": list(recommendations.get("recommended_tools", [])),
                    "available_mcp_servers": [
                        item.get("name", "")
                        for item in (self.mcp_registry.enabled_servers() if self.mcp_registry else [])
                        if item.get("name")
                    ],
                    "recommended_mcp": list(recommendations.get("recommended_mcp", [])),
                    "used_mcp": sorted(set(used_mcp)),
                    "available_remote_hosts": self.remote_tool.list_hosts() if self.remote_tool else [],
                    "knowledge": {
                        "selected_skill_category": category.get("selected_skill_category", ""),
                        "pack_name": knowledge.get("pack_name", skillpack.get("label", "")),
                        "knowledge_pack": dict(skillpack.get("knowledge_pack", {})),
                        "knowledge_topics": list(knowledge.get("knowledge_topics", [])),
                        "top_tactics": list(knowledge.get("top_tactics", [])),
                        "reference_docs": list(knowledge.get("reference_docs", [])),
                    },
                },
                run_meta={
                    "run_id": getattr(challenge, "metadata", {}).get("run_id", ""),
                    "status": state.phase,
                },
            )
            self.workspace_manager.save_board(workspace, board)
        except Exception:
            logger.debug("Failed to write agent-loop board", exc_info=True)
