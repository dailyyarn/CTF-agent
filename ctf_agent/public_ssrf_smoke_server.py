import argparse
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
from urllib.request import ProxyHandler, build_opener


NO_PROXY_OPENER = build_opener(ProxyHandler({}))


class SSRFSmokeServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, host="0.0.0.0", port=18789):
        ThreadingHTTPServer.__init__(self, (host, int(port)), _Handler)
        self.thread = None

    def start(self):
        if self.thread:
            return self
        self.thread = threading.Thread(target=self.serve_forever, name="ctf-agent-public-ssrf-smoke", daemon=True)
        self.thread.start()
        return self

    def stop(self):
        try:
            self.shutdown()
        except Exception:
            pass
        try:
            self.server_close()
        except Exception:
            pass
        if self.thread:
            self.thread.join(timeout=2.0)
        self.thread = None


class _Handler(BaseHTTPRequestHandler):
    server_version = "CTFAgentPublicSSRFSmoke/1.0"

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            return self._send_json(200, {"status": "ok", "service": "ctf-agent-public-ssrf-smoke"})
        if parsed.path == "/":
            body = """<!doctype html>
<html>
<head><meta charset="utf-8"><title>Public Blind SSRF Smoke</title></head>
<body>
  <h1>Public Blind SSRF Smoke</h1>
  <form action="/fetch" method="get">
    <input type="text" name="url" value="">
    <button type="submit">Fetch</button>
  </form>
  <a href="/fetch?url=http://127.0.0.1/">Fetch route</a>
  <script src="/app.js"></script>
</body>
</html>"""
            return self._send_text(200, body, "text/html; charset=utf-8")
        if parsed.path == "/app.js":
            body = """window.__SSRF__ = { route: "/api/fetch", param: "url" };
fetch("/api/fetch?url=http://127.0.0.1/").catch(() => {});
"""
            return self._send_text(200, body, "application/javascript; charset=utf-8")
        if parsed.path in {"/fetch", "/api/fetch"}:
            params = parse_qs(parsed.query, keep_blank_values=True)
            target = ""
            for key in ["url", "callback", "target", "redirect"]:
                values = params.get(key, [])
                if values:
                    target = values[0]
                    break
            if not target:
                return self._send_text(400, "missing url parameter", "text/plain; charset=utf-8")
            try:
                with NO_PROXY_OPENER.open(target, timeout=6.0) as response:
                    response.read(256)
                return self._send_text(200, "blind fetch attempted", "text/plain; charset=utf-8")
            except Exception as exc:
                return self._send_text(502, "fetch failed: {0}".format(exc), "text/plain; charset=utf-8")
        return self._send_text(404, "missing", "text/plain; charset=utf-8")

    def log_message(self, format, *args):  # pragma: no cover
        return

    def _send_json(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(int(status))
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, status, body, content_type):
        payload = body.encode("utf-8", errors="replace")
        self.send_response(int(status))
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Public blind SSRF smoke server for ctf-agent")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=18789)
    args = parser.parse_args(argv)
    server = SSRFSmokeServer(host=args.host, port=args.port)
    server.start()
    print(json.dumps({"status": "ok", "host": args.host, "port": args.port}, ensure_ascii=False))
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
