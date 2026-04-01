import argparse
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


class OOBEventStore(object):
    def __init__(self):
        self._lock = threading.Lock()
        self._events = {}

    def record(self, token, method, path, query=None, body=""):
        event = {
            "timestamp": time.time(),
            "method": method,
            "path": path,
            "query": dict(query or {}),
            "body": str(body or "")[:4000],
        }
        with self._lock:
            self._events.setdefault(str(token), []).append(event)
            return list(self._events[str(token)])

    def events(self, token):
        with self._lock:
            return list(self._events.get(str(token), []))


class _Handler(BaseHTTPRequestHandler):
    server_version = "CTFAgentOOB/1.0"

    def do_GET(self):
        self._dispatch()

    def do_POST(self):
        self._dispatch()

    def log_message(self, format, *args):  # pragma: no cover
        return

    def _dispatch(self):
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self._send_json(200, {"status": "ok", "service": "ctf-agent-oob-mock"})
            return
        if parsed.path.startswith("/callback/"):
            token = parsed.path.split("/callback/", 1)[1].strip("/")
            length = int(self.headers.get("Content-Length", "0") or "0")
            body = self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else ""
            events = self.server.event_store.record(
                token,
                self.command,
                parsed.path,
                parse_qs(parsed.query, keep_blank_values=True),
                body,
            )
            self._send_json(
                200,
                {
                    "status": "ok",
                    "token": token,
                    "matched": True,
                    "count": len(events),
                },
            )
            return
        if parsed.path.startswith("/poll/"):
            if self.server.auth_token:
                header_value = self.headers.get(self.server.auth_header, "")
                if header_value != self.server.auth_token:
                    self._send_json(401, {"status": "error", "message": "unauthorized"})
                    return
            token = parsed.path.split("/poll/", 1)[1].strip("/")
            events = self.server.event_store.events(token)
            self._send_json(
                200,
                {
                    "status": "ok",
                    "token": token,
                    "matched": bool(events),
                    "count": len(events),
                    "events": events[-10:],
                },
            )
            return
        self._send_json(404, {"status": "missing", "path": parsed.path})

    def _send_json(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(int(status))
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class OOBMockServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, auth_token="", auth_header="Authorization"):
        ThreadingHTTPServer.__init__(self, server_address, _Handler)
        self.auth_token = str(auth_token or "")
        self.auth_header = str(auth_header or "Authorization")
        self.event_store = OOBEventStore()


class LocalOOBServer(object):
    def __init__(self, host="127.0.0.1", port=0, auth_token="", auth_header="Authorization"):
        self.host = host
        self.port = int(port or 0)
        self.auth_token = str(auth_token or "")
        self.auth_header = str(auth_header or "Authorization")
        self.server = None
        self.thread = None

    def start(self):
        if self.server:
            return self
        self.server = OOBMockServer((self.host, self.port), auth_token=self.auth_token, auth_header=self.auth_header)
        self.port = int(self.server.server_address[1])
        self.thread = threading.Thread(target=self.server.serve_forever, name="ctf-agent-oob-mock", daemon=True)
        self.thread.start()
        return self

    def stop(self):
        if self.server:
            try:
                self.server.shutdown()
            except Exception:
                pass
            try:
                self.server.server_close()
            except Exception:
                pass
        if self.thread:
            self.thread.join(timeout=2.0)
        self.server = None
        self.thread = None

    def callback_url(self):
        return "http://{0}:{1}/callback".format(self.host, self.port)

    def poll_url_template(self):
        return "http://{0}:{1}/poll/{{token}}".format(self.host, self.port)

    def describe(self):
        return {
            "host": self.host,
            "port": self.port,
            "callback_base_url": self.callback_url(),
            "poll_url_template": self.poll_url_template(),
            "auth_header": self.auth_header,
            "auth_token_configured": bool(self.auth_token),
        }

    def __enter__(self):
        return self.start()

    def __exit__(self, exc_type, exc, tb):
        self.stop()


def main(argv=None):
    parser = argparse.ArgumentParser(description="Local OOB mock server for ctf-agent")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18788)
    parser.add_argument("--auth-token", default="")
    parser.add_argument("--auth-header", default="Authorization")
    args = parser.parse_args(argv)
    server = LocalOOBServer(
        host=args.host,
        port=args.port,
        auth_token=args.auth_token,
        auth_header=args.auth_header,
    )
    server.start()
    print(json.dumps(server.describe(), ensure_ascii=False))
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
