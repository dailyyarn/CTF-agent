import json
import os
import re
import sys
import tempfile
import time
import traceback
from pathlib import Path
from urllib.parse import urljoin, urlparse

from selenium import webdriver
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.common.by import By
from selenium.webdriver.edge.options import Options as EdgeOptions
from selenium.webdriver.support.ui import WebDriverWait


SERVER_INFO = {
    "name": "browser-use",
    "version": "0.1.0",
}
PROTOCOL_VERSION = "2025-03-26"
MAX_ITEMS = 60
LOGIN_USER_HINTS = ("username", "user", "email", "login", "account", "name")
LOGIN_PASS_HINTS = ("password", "pass", "passwd", "pwd")
SUCCESS_HINTS = ("logout", "dashboard", "welcome", "profile", "admin", "token", "jwt")
FAILURE_HINTS = ("invalid", "incorrect", "failed", "error", "retry", "denied", "wrong")
API_PATTERN = re.compile(r"/(?:api|auth|graphql|admin|upload|files|v[0-9])[A-Za-z0-9._~!$&'()*+,;=:@%/\-]{0,180}")
PARAM_PATTERN = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_-]{1,40})=")


def _tool_result(payload, text=None, is_error=False):
    content = []
    if text:
        content.append({"type": "text", "text": str(text)})
    content.append({"type": "data", "data": payload})
    return {
        "content": content,
        "structuredContent": payload,
        "isError": bool(is_error),
    }


def _jsonrpc_ok(request_id, result):
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": result,
    }


def _jsonrpc_error(request_id, code, message, data=None):
    payload = {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": int(code),
            "message": str(message),
        },
    }
    if data is not None:
        payload["error"]["data"] = data
    return payload


def _tool_schema():
    return {
        "name": "run_browser_agent",
        "description": "Open a page in a real browser, inspect DOM/forms/routes, and optionally perform login or upload reproduction.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "task": {"type": "string"},
                "prompt": {"type": "string"},
                "instruction": {"type": "string"},
                "goal": {"type": "string"},
                "url": {"type": "string"},
                "start_url": {"type": "string"},
                "target": {"type": "string"},
                "action": {"type": "string", "enum": ["recon", "login", "upload"]},
                "username": {"type": "string"},
                "password": {"type": "string"},
                "form_index": {"type": "integer"},
                "headless": {"type": "boolean"},
                "wait_seconds": {"type": "number"},
                "file_name": {"type": "string"},
                "file_content": {"type": "string"},
                "mime_type": {"type": "string"},
                "allowed_domains": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["url"],
        },
    }


def _first_text(arguments, keys):
    for key in keys:
        value = arguments.get(key)
        if value:
            return str(value)
    return ""


class BrowserAgent(object):
    def __init__(self, headless=True, wait_seconds=1.5):
        self.headless = bool(headless)
        self.wait_seconds = max(0.2, float(wait_seconds or 1.5))
        self.engine = ""
        self.driver = None
        self._temp_files = []

    def __enter__(self):
        self.driver, self.engine = self._build_driver()
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            if self.driver:
                self.driver.quit()
        except Exception:
            pass
        for item in self._temp_files:
            try:
                Path(item).unlink()
            except Exception:
                pass

    def run(self, url, task="", action="recon", username="", password="", form_index=0, file_name="", file_content="", mime_type=""):
        driver = self.driver
        driver.get(url)
        self._settle()
        before = self._snapshot(task=task, action=action)

        upload_details = {}
        auth_details = {}
        if action == "login" and username and password:
            auth_details = self._perform_login(username=username, password=password, form_index=int(form_index or 0))
            self._settle()
        elif action == "upload" and file_name:
            upload_details = self._perform_upload(file_name=file_name, file_content=file_content or "", mime_type=mime_type, form_index=int(form_index or 0))
            self._settle()

        after = self._snapshot(task=task, action=action)
        merged = self._merge_result(before, after, action, auth_details, upload_details)
        return merged

    def _build_driver(self):
        browser_path = os.environ.get("CTF_AGENT_BROWSER_BINARY", "").strip()
        preferred_kind = os.environ.get("CTF_AGENT_BROWSER_KIND", "").strip().lower()
        attempts = []
        if preferred_kind in {"chrome", "edge"}:
            attempts.append(preferred_kind)
        for item in ["chrome", "edge"]:
            if item not in attempts:
                attempts.append(item)

        errors = []
        for kind in attempts:
            try:
                if kind == "chrome":
                    return self._build_chrome_driver(browser_path), "chrome"
                return self._build_edge_driver(browser_path), "edge"
            except Exception as exc:
                errors.append("{0}: {1}".format(kind, exc))
        raise RuntimeError("unable to start browser driver ({0})".format(" | ".join(errors)))

    def _build_chrome_driver(self, browser_path):
        options = ChromeOptions()
        if self.headless:
            options.add_argument("--headless=new")
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--window-size=1440,1200")
        options.add_argument("--ignore-certificate-errors")
        options.add_argument("--allow-insecure-localhost")
        options.add_argument("--log-level=3")
        binary = browser_path or self._detect_browser_binary("chrome")
        if binary:
            options.binary_location = binary
        return webdriver.Chrome(options=options)

    def _build_edge_driver(self, browser_path):
        options = EdgeOptions()
        if self.headless:
            options.add_argument("--headless=new")
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--window-size=1440,1200")
        options.add_argument("--ignore-certificate-errors")
        options.add_argument("--allow-insecure-localhost")
        binary = browser_path or self._detect_browser_binary("edge")
        if binary:
            options.binary_location = binary
        return webdriver.Edge(options=options)

    def _detect_browser_binary(self, kind):
        candidates = []
        if kind == "chrome":
            candidates = [
                Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
                Path(r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"),
            ]
        elif kind == "edge":
            candidates = [
                Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
                Path(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
            ]
        for item in candidates:
            if item.exists():
                return str(item)
        return ""

    def _settle(self):
        try:
            WebDriverWait(self.driver, max(3, int(self.wait_seconds) + 2)).until(
                lambda drv: drv.execute_script("return document.readyState") == "complete"
            )
        except Exception:
            pass
        time.sleep(self.wait_seconds)

    def _snapshot(self, task="", action="recon"):
        driver = self.driver
        page_source = driver.page_source or ""
        page_text = driver.execute_script(
            """
            const body = document.body ? document.body.innerText || '' : '';
            return body.slice(0, 8000);
            """
        )
        dom = driver.execute_script(
            """
            const abs = (value) => {
              try { return new URL(value || '', window.location.href).href; }
              catch (error) { return value || ''; }
            };
            const body = document.body ? document.body.innerText || '' : '';
            const forms = Array.from(document.forms || []).slice(0, 12).map((form, index) => ({
              index,
              action: abs(form.getAttribute('action') || ''),
              method: (form.getAttribute('method') || 'GET').toUpperCase(),
              enctype: form.getAttribute('enctype') || 'application/x-www-form-urlencoded',
              inputs: Array.from(form.elements || []).slice(0, 30).map((element) => ({
                name: element.getAttribute('name') || '',
                type: (element.getAttribute('type') || element.tagName || 'text').toLowerCase(),
                value: element.getAttribute('value') || '',
                placeholder: element.getAttribute('placeholder') || '',
                required: !!element.required,
              })),
            }));
            const links = Array.from(document.querySelectorAll('a[href]')).slice(0, 80).map((item) => abs(item.getAttribute('href')));
            const scripts = Array.from(document.querySelectorAll('script[src]')).slice(0, 40).map((item) => abs(item.getAttribute('src')));
            return {
              title: document.title || '',
              current_url: window.location.href,
              forms,
              links,
              scripts,
              body_excerpt: body.slice(0, 4000),
              html_excerpt: (document.documentElement ? document.documentElement.outerHTML : '').slice(0, 12000),
              cookie_text: document.cookie || '',
            };
            """
        )
        cookies = []
        try:
            cookies = driver.get_cookies() or []
        except Exception:
            cookies = []

        route_candidates = self._collect_route_candidates(dom, page_source)
        param_candidates = self._collect_param_candidates(dom, page_source)
        api_candidates = sorted({item for item in API_PATTERN.findall(page_source or "") if item})[:MAX_ITEMS]

        return {
            "status": "ok",
            "engine": self.engine,
            "task": task,
            "action": action,
            "url": dom.get("current_url", "") or driver.current_url,
            "title": dom.get("title", "") or driver.title,
            "forms": dom.get("forms", []),
            "links": dom.get("links", []),
            "scripts": dom.get("scripts", []),
            "route_candidates": route_candidates,
            "param_candidates": param_candidates,
            "api_candidates": api_candidates,
            "cookies": cookies,
            "cookie_names": sorted({item.get("name", "") for item in cookies if item.get("name")}),
            "body_excerpt": page_text or dom.get("body_excerpt", ""),
            "html_excerpt": dom.get("html_excerpt", ""),
            "page_source_excerpt": (page_source or "")[:12000],
            "hidden_inputs": self._extract_hidden_inputs(dom.get("forms", [])),
            "login_forms": self._count_login_forms(dom.get("forms", [])),
            "upload_forms": self._count_upload_forms(dom.get("forms", [])),
        }

    def _perform_login(self, username="", password="", form_index=0):
        driver = self.driver
        details = {
            "attempted": False,
            "form_index": form_index,
            "username": username,
        }
        payload = driver.execute_script(
            """
            const userHints = %s;
            const passHints = %s;
            const forms = Array.from(document.forms || []);
            const scoreForm = (form) => {
              let score = 0;
              for (const element of Array.from(form.elements || [])) {
                const name = (element.getAttribute('name') || '').toLowerCase();
                const type = (element.getAttribute('type') || '').toLowerCase();
                if (type === 'password') score += 4;
                if (userHints.some((hint) => name.includes(hint))) score += 2;
                if (passHints.some((hint) => name.includes(hint))) score += 2;
              }
              return score;
            };
            const ranked = forms
              .map((form, index) => ({ form, index, score: scoreForm(form) }))
              .sort((left, right) => right.score - left.score);
            const picked = ranked[%d] || ranked[0];
            if (!picked || picked.score <= 0) {
              return { ok: false, reason: 'no_login_form' };
            }
            picked.form.setAttribute('data-ctf-login-form', '1');
            return { ok: true, index: picked.index };
            """
            % (json.dumps(LOGIN_USER_HINTS), json.dumps(LOGIN_PASS_HINTS), max(0, int(form_index or 0)))
        )
        if not payload.get("ok"):
            details["reason"] = payload.get("reason", "no_login_form")
            return details

        details["attempted"] = True
        script = """
            const username = arguments[0];
            const password = arguments[1];
            const form = document.querySelector('form[data-ctf-login-form="1"]');
            const userHints = %s;
            const passHints = %s;
            if (!form) {
              return { ok: false, reason: 'login_form_missing' };
            }
            let userElement = null;
            let passElement = null;
            for (const element of Array.from(form.elements || [])) {
              const name = (element.getAttribute('name') || '').toLowerCase();
              const type = (element.getAttribute('type') || '').toLowerCase();
              if (!userElement && (userHints.some((hint) => name.includes(hint)) || type === 'email' || type === 'text')) {
                userElement = element;
              }
              if (!passElement && (type === 'password' || passHints.some((hint) => name.includes(hint)))) {
                passElement = element;
              }
            }
            if (!userElement || !passElement) {
              return { ok: false, reason: 'login_fields_missing' };
            }
            userElement.focus();
            userElement.value = username;
            userElement.dispatchEvent(new Event('input', { bubbles: true }));
            userElement.dispatchEvent(new Event('change', { bubbles: true }));
            passElement.focus();
            passElement.value = password;
            passElement.dispatchEvent(new Event('input', { bubbles: true }));
            passElement.dispatchEvent(new Event('change', { bubbles: true }));
            if (form.requestSubmit) {
              form.requestSubmit();
            } else {
              form.submit();
            }
            return { ok: true };
        """ % (json.dumps(LOGIN_USER_HINTS), json.dumps(LOGIN_PASS_HINTS))
        submit_result = driver.execute_script(script, username, password)
        details.update(submit_result or {})
        return details

    def _perform_upload(self, file_name="", file_content="", mime_type="", form_index=0):
        driver = self.driver
        details = {
            "attempted": False,
            "file_name": file_name,
        }
        payload = driver.execute_script(
            """
            const forms = Array.from(document.forms || []);
            const ranked = forms
              .map((form, index) => {
                let score = 0;
                for (const element of Array.from(form.elements || [])) {
                  const type = (element.getAttribute('type') || '').toLowerCase();
                  const name = (element.getAttribute('name') || '').toLowerCase();
                  if (type === 'file') score += 5;
                  if (name.includes('upload') || name.includes('file') || name.includes('image') || name.includes('avatar')) score += 2;
                }
                return { form, index, score };
              })
              .sort((left, right) => right.score - left.score);
            const picked = ranked[%d] || ranked[0];
            if (!picked || picked.score <= 0) {
              return { ok: false, reason: 'no_upload_form' };
            }
            picked.form.setAttribute('data-ctf-upload-form', '1');
            const input = Array.from(picked.form.elements || []).find((element) => ((element.getAttribute('type') || '').toLowerCase() === 'file'));
            if (!input) {
              return { ok: false, reason: 'file_input_missing' };
            }
            input.setAttribute('data-ctf-upload-input', '1');
            return { ok: true, index: picked.index };
            """
            % max(0, int(form_index or 0))
        )
        if not payload.get("ok"):
            details["reason"] = payload.get("reason", "no_upload_form")
            return details

        temp_path = self._write_upload_file(file_name=file_name, file_content=file_content, mime_type=mime_type)
        upload_input = driver.find_element(By.CSS_SELECTOR, "[data-ctf-upload-input='1']")
        upload_input.send_keys(temp_path)
        driver.execute_script(
            """
            const form = document.querySelector('form[data-ctf-upload-form="1"]');
            if (form) {
              if (form.requestSubmit) {
                form.requestSubmit();
              } else {
                form.submit();
              }
            }
            """
        )
        details["attempted"] = True
        details["temp_path"] = temp_path
        return details

    def _write_upload_file(self, file_name="", file_content="", mime_type=""):
        suffix = Path(file_name or "upload.bin").suffix or ".bin"
        handle = tempfile.NamedTemporaryFile(prefix="ctf-agent-upload-", suffix=suffix, delete=False)
        path = Path(handle.name)
        content = file_content or ""
        if isinstance(content, str):
            data = content.encode("utf-8", errors="replace")
        else:
            data = bytes(content)
        handle.write(data)
        handle.flush()
        handle.close()
        self._temp_files.append(str(path))
        return str(path)

    def _merge_result(self, before, after, action, auth_details, upload_details):
        before_text = (before.get("body_excerpt", "") or "").lower()
        after_text = (after.get("body_excerpt", "") or "").lower()
        auth_evidence = []
        auth_state = "unknown"
        if action == "login" and auth_details.get("attempted"):
            success_markers_present = any(item in after_text for item in SUCCESS_HINTS)
            failure_markers_present = any(item in after_text for item in FAILURE_HINTS)
            cookie_delta = set(after.get("cookie_names", [])) - set(before.get("cookie_names", []))
            login_page_disappeared = any(item in before_text for item in ("login", "sign in")) and not any(
                item in after_text for item in ("login", "sign in")
            )
            if after.get("url") != before.get("url"):
                auth_evidence.append("final url changed")
            if cookie_delta:
                auth_evidence.append("cookies changed")
            if success_markers_present:
                auth_evidence.append("success markers present")
            if failure_markers_present:
                auth_evidence.append("failure markers present")
            if failure_markers_present:
                auth_state = "failed"
            elif cookie_delta or success_markers_present:
                auth_state = "authenticated"
            elif login_page_disappeared:
                auth_state = "authenticated"
                auth_evidence.append("login page markers disappeared")

        upload_candidates = []
        executable_candidates = []
        if action == "upload" and upload_details.get("attempted"):
            filename = upload_details.get("file_name", "")
            source = (after.get("page_source_excerpt", "") or "") + "\n" + "\n".join(after.get("links", []))
            for absolute in self._extract_urls_from_text(source, after.get("url", "")):
                if filename.lower() in absolute.lower():
                    upload_candidates.append(absolute)
            if filename:
                stem = filename.rsplit(".", 1)[0].lower()
                if ".php" in filename.lower() or ".phtml" in filename.lower() or ".php5" in filename.lower():
                    executable_candidates = [item for item in upload_candidates if stem in item.lower()]

        payload = dict(after)
        payload.update(
            {
                "status": "ok",
                "action": action,
                "auth_state": auth_state,
                "auth_evidence": auth_evidence,
                "auth_details": auth_details,
                "upload_state": "submitted" if upload_details.get("attempted") else "not-attempted",
                "upload_details": upload_details,
                "upload_candidates": sorted(dict.fromkeys(upload_candidates))[:MAX_ITEMS],
                "executable_candidates": sorted(dict.fromkeys(executable_candidates))[:MAX_ITEMS],
                "transition": {
                    "before_url": before.get("url", ""),
                    "after_url": after.get("url", ""),
                    "before_title": before.get("title", ""),
                    "after_title": after.get("title", ""),
                    "before_cookie_names": before.get("cookie_names", []),
                    "after_cookie_names": after.get("cookie_names", []),
                },
                "summary": self._build_summary(after, auth_state, auth_evidence, upload_candidates),
            }
        )
        return payload

    def _build_summary(self, snapshot, auth_state, auth_evidence, upload_candidates):
        parts = [
            "engine={0}".format(snapshot.get("engine", self.engine)),
            "url={0}".format(snapshot.get("url", "")),
            "title={0}".format(snapshot.get("title", "")),
            "forms={0}".format(len(snapshot.get("forms", []))),
            "routes={0}".format(len(snapshot.get("route_candidates", []))),
        ]
        if auth_state and auth_state != "unknown":
            parts.append("auth_state={0}".format(auth_state))
        if auth_evidence:
            parts.append("auth_evidence={0}".format(", ".join(auth_evidence[:4])))
        if upload_candidates:
            parts.append("upload_candidates={0}".format(len(upload_candidates)))
        return " | ".join(parts)

    def _collect_route_candidates(self, dom, page_source):
        values = set()
        for item in list(dom.get("links", [])) + list(dom.get("scripts", [])):
            parsed = urlparse(item)
            if parsed.path:
                values.add(parsed.path)
        for form in dom.get("forms", []):
            parsed = urlparse(form.get("action", ""))
            if parsed.path:
                values.add(parsed.path)
        for item in API_PATTERN.findall(page_source or ""):
            values.add(item)
        return sorted(item for item in values if item)[:MAX_ITEMS]

    def _collect_param_candidates(self, dom, page_source):
        values = set()
        for form in dom.get("forms", []):
            for field in form.get("inputs", []):
                name = field.get("name", "")
                if name:
                    values.add(name)
        for item in PARAM_PATTERN.findall(page_source or ""):
            values.add(item)
        return sorted(values)[:MAX_ITEMS]

    def _extract_hidden_inputs(self, forms):
        values = []
        for form in forms:
            for field in form.get("inputs", []):
                if (field.get("type") or "").lower() == "hidden" and field.get("name"):
                    values.append(
                        {
                            "form_index": form.get("index"),
                            "name": field.get("name", ""),
                            "value": field.get("value", ""),
                        }
                    )
        return values[:MAX_ITEMS]

    def _count_login_forms(self, forms):
        count = 0
        for form in forms:
            lowered = " ".join(field.get("name", "").lower() for field in form.get("inputs", []))
            has_password = any((field.get("type") or "").lower() == "password" for field in form.get("inputs", []))
            if has_password or any(item in lowered for item in LOGIN_USER_HINTS + LOGIN_PASS_HINTS):
                count += 1
        return count

    def _count_upload_forms(self, forms):
        count = 0
        for form in forms:
            if "multipart/form-data" in (form.get("enctype") or "").lower():
                count += 1
                continue
            if any((field.get("type") or "").lower() == "file" for field in form.get("inputs", [])):
                count += 1
        return count

    def _extract_urls_from_text(self, text, base_url):
        urls = set()
        for match in re.findall(r"https?://[^\s'\"<>]{4,240}", text or ""):
            urls.add(match)
        for match in re.findall(r"/[A-Za-z0-9._~!$&'()*+,;=:@%/\-]{2,200}", text or ""):
            urls.add(urljoin(base_url, match))
        return sorted(urls)[:MAX_ITEMS]


def _infer_action(arguments):
    explicit = str(arguments.get("action") or "").strip().lower()
    if explicit in {"recon", "login", "upload"}:
        return explicit
    task = _first_text(arguments, ["task", "prompt", "instruction", "goal"]).lower()
    if any(item in task for item in ["upload", "file input", "avatar"]):
        return "upload"
    if any(item in task for item in ["login", "sign in", "authenticate"]):
        return "login"
    return "recon"


def _run_browser_agent(arguments):
    url = _first_text(arguments, ["url", "start_url", "target"])
    if not url:
        raise ValueError("url is required")
    task = _first_text(arguments, ["task", "prompt", "instruction", "goal"])
    action = _infer_action(arguments)
    headless = bool(arguments.get("headless", True))
    wait_seconds = float(arguments.get("wait_seconds", 1.5) or 1.5)
    username = str(arguments.get("username") or "")
    password = str(arguments.get("password") or "")
    form_index = int(arguments.get("form_index", 0) or 0)
    file_name = str(arguments.get("file_name") or "")
    file_content = arguments.get("file_content", "")
    mime_type = str(arguments.get("mime_type") or "")

    with BrowserAgent(headless=headless, wait_seconds=wait_seconds) as agent:
        payload = agent.run(
            url=url,
            task=task,
            action=action,
            username=username,
            password=password,
            form_index=form_index,
            file_name=file_name,
            file_content=file_content,
            mime_type=mime_type,
        )
    text = payload.get("summary", "") or "{0} completed".format(action)
    return _tool_result(payload, text=text, is_error=False)


class BrowserMCPServer(object):
    def __init__(self):
        self.tools = [_tool_schema()]

    def handle(self, payload):
        request_id = payload.get("id")
        method = payload.get("method")
        if method == "initialize":
            return _jsonrpc_ok(
                request_id,
                {
                    "protocolVersion": PROTOCOL_VERSION,
                    "serverInfo": SERVER_INFO,
                    "capabilities": {
                        "tools": {},
                    },
                },
            )
        if method == "notifications/initialized":
            return None
        if method == "tools/list":
            return _jsonrpc_ok(request_id, {"tools": self.tools})
        if method == "tools/call":
            params = dict(payload.get("params") or {})
            name = params.get("name")
            arguments = dict(params.get("arguments") or {})
            if name != "run_browser_agent":
                return _jsonrpc_error(request_id, -32601, "unknown tool", {"tool": name})
            try:
                return _jsonrpc_ok(request_id, _run_browser_agent(arguments))
            except Exception as exc:
                details = {
                    "error": str(exc),
                    "traceback": traceback.format_exc(limit=8),
                }
                return _jsonrpc_ok(
                    request_id,
                    _tool_result(
                        {
                            "status": "error",
                            "message": str(exc),
                            "details": details,
                        },
                        text="browser agent failed: {0}".format(exc),
                        is_error=True,
                    ),
                )
        return _jsonrpc_error(request_id, -32601, "unknown method", {"method": method})


def main():
    server = BrowserMCPServer()
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            payload = json.loads(raw)
        except Exception as exc:
            sys.stdout.write(
                json.dumps(_jsonrpc_error(None, -32700, "invalid json", {"error": str(exc)}), ensure_ascii=False) + "\n"
            )
            sys.stdout.flush()
            continue

        response = server.handle(payload)
        if response is None:
            continue
        sys.stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
