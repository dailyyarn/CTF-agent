import json
import mimetypes
import ssl
import time
import uuid
from difflib import SequenceMatcher
from html.parser import HTMLParser
from http.cookiejar import CookieJar
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse
from urllib.request import HTTPCookieProcessor, HTTPSHandler, HTTPHandler, ProxyHandler, Request, build_opener


class _HTMLSummaryParser(HTMLParser):
    def __init__(self, base_url):
        HTMLParser.__init__(self)
        self.base_url = base_url
        self.in_title = False
        self.title = ""
        self.scripts = []
        self.links = []
        self.forms = []
        self._current_form = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "title":
            self.in_title = True
        elif tag == "script":
            src = attrs.get("src")
            if src:
                self.scripts.append(urljoin(self.base_url, src))
        elif tag == "a":
            href = attrs.get("href")
            if href:
                self.links.append(urljoin(self.base_url, href))
        elif tag == "form":
            self._current_form = {
                "action": urljoin(self.base_url, attrs.get("action", "")),
                "method": attrs.get("method", "GET").upper(),
                "enctype": attrs.get("enctype", "application/x-www-form-urlencoded"),
                "inputs": [],
            }
            self.forms.append(self._current_form)
        elif tag == "input" and self._current_form is not None:
            self._current_form["inputs"].append(
                {
                    "name": attrs.get("name", ""),
                    "type": attrs.get("type", "text"),
                    "value": attrs.get("value", ""),
                }
            )

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False
        elif tag == "form":
            self._current_form = None

    def handle_data(self, data):
        if self.in_title:
            self.title += data


class HttpTool(object):
    def __init__(self, timeout=8.0, verify_tls=False):
        self.timeout = timeout
        self.ssl_context = ssl.create_default_context()
        if not verify_tls:
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE

        self.cookie_jar = CookieJar()
        self.opener = build_opener(
            ProxyHandler({}),
            HTTPHandler(),
            HTTPSHandler(context=self.ssl_context),
            HTTPCookieProcessor(self.cookie_jar),
        )

    def normalize_target(self, target):
        if "://" not in target:
            return "http://{0}".format(target)
        return target

    def request(self, method, url, data=None, headers=None, params=None, json_data=None, files=None):
        url = self.normalize_target(url)
        headers = dict(headers or {})
        if params:
            url = self.with_query_params(url, params)

        payload = None
        if files:
            payload, content_type = self._build_multipart_body(data or {}, files)
            headers.setdefault("Content-Type", content_type)
        elif json_data is not None:
            payload = json.dumps(json_data).encode("utf-8")
            headers.setdefault("Content-Type", "application/json")
        elif data is not None:
            if isinstance(data, dict):
                payload = urlencode(data, doseq=True).encode("utf-8")
                headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
            elif isinstance(data, str):
                payload = data.encode("utf-8")
            elif isinstance(data, bytes):
                payload = data
            else:
                payload = str(data).encode("utf-8")

        request = Request(url, data=payload, headers=headers, method=method.upper())
        started = time.monotonic()
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                body = response.read()
                elapsed = time.monotonic() - started
                return self._format_response(
                    response.geturl(),
                    response.status,
                    response.headers,
                    body,
                    error=None,
                    elapsed=elapsed,
                )
        except HTTPError as exc:
            body = exc.read()
            elapsed = time.monotonic() - started
            return self._format_response(
                exc.geturl(),
                exc.code,
                exc.headers,
                body,
                error=None,
                elapsed=elapsed,
            )
        except URLError as exc:
            elapsed = time.monotonic() - started
            return self._format_response(url, None, {}, b"", error=str(exc), elapsed=elapsed)
        except Exception as exc:
            elapsed = time.monotonic() - started
            return self._format_response(url, None, {}, b"", error=str(exc), elapsed=elapsed)

    def discover_common_paths(self, base_url, paths):
        results = []
        for path in paths:
            full_url = urljoin(base_url, path)
            results.append(
                {
                    "path": path,
                    "url": full_url,
                    "response": self.request("GET", full_url),
                }
            )
        return results

    def summarize_html(self, text, base_url):
        parser = _HTMLSummaryParser(base_url)
        parser.feed(text or "")
        return {
            "title": parser.title.strip(),
            "scripts": list(dict.fromkeys(parser.scripts)),
            "links": list(dict.fromkeys(parser.links)),
            "forms": parser.forms,
        }

    def with_query_params(self, url, params):
        parsed = urlparse(url)
        existing = dict(parse_qsl(parsed.query, keep_blank_values=True))
        for key, value in (params or {}).items():
            existing[str(key)] = str(value)
        query = urlencode(existing, doseq=True)
        return urlunparse(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                query,
                parsed.fragment,
            )
        )

    def response_signature(self, response):
        title = ""
        if "html" in response.get("content_type", "") and response.get("text"):
            title = self.summarize_html(response["text"], response.get("url", ""))["title"]
        return {
            "status": response.get("status"),
            "length": len(response.get("text", "")),
            "title": title,
            "location": response.get("headers", {}).get("Location", ""),
            "elapsed": response.get("elapsed", 0.0),
        }

    def compare_responses(self, baseline, candidate, markers=None):
        baseline_text = (baseline or {}).get("text", "")[:8000]
        candidate_text = (candidate or {}).get("text", "")[:8000]
        baseline_sig = self.response_signature(baseline or {})
        candidate_sig = self.response_signature(candidate or {})
        baseline_cookies = {
            (item.get("name"), item.get("value"))
            for item in (baseline or {}).get("cookies", [])
        }
        candidate_cookies = {
            (item.get("name"), item.get("value"))
            for item in (candidate or {}).get("cookies", [])
        }

        similarity = SequenceMatcher(None, baseline_text, candidate_text).ratio() if (baseline_text or candidate_text) else 1.0
        length_delta = candidate_sig["length"] - baseline_sig["length"]
        score = 0.0
        reasons = []

        if baseline_sig["status"] != candidate_sig["status"]:
            score += 0.35
            reasons.append("status changed")
        if baseline_sig["location"] != candidate_sig["location"] and candidate_sig["location"]:
            score += 0.25
            reasons.append("redirect changed")
        if baseline_sig["title"] != candidate_sig["title"] and candidate_sig["title"]:
            score += 0.15
            reasons.append("title changed")
        if baseline_cookies != candidate_cookies and candidate_cookies:
            score += 0.18
            reasons.append("cookie jar changed")
        if abs(length_delta) > 120:
            score += min(0.25, abs(length_delta) / 2500.0)
            reasons.append("length delta={0}".format(length_delta))
        if similarity < 0.96:
            score += min(0.4, (0.96 - similarity) * 1.2)
            reasons.append("body similarity={0:.3f}".format(similarity))

        elapsed_delta = candidate_sig["elapsed"] - baseline_sig["elapsed"]
        if elapsed_delta > 2.0:
            score += 0.25
            reasons.append("response delayed by {0:.2f}s".format(elapsed_delta))

        marker_hits = []
        for marker in list(markers or []):
            if marker and marker.lower() in candidate_text.lower():
                marker_hits.append(marker)
        if marker_hits:
            score += min(0.25, 0.08 * len(marker_hits))
            reasons.append("markers hit={0}".format(", ".join(marker_hits[:5])))

        return {
            "score": round(score, 4),
            "similarity": round(similarity, 4),
            "length_delta": length_delta,
            "elapsed_delta": round(elapsed_delta, 4),
            "reasons": reasons,
            "cookie_delta": sorted(list(candidate_cookies - baseline_cookies)),
            "marker_hits": marker_hits,
        }

    def is_meaningful_difference(self, baseline, candidate):
        comparison = self.compare_responses(baseline, candidate)
        return comparison["score"] >= 0.35, ", ".join(comparison["reasons"]) or "responses stayed similar"

    def _format_response(self, url, status, headers, body, error, elapsed):
        if hasattr(headers, "items"):
            headers = dict(headers.items())
        else:
            headers = dict(headers)
        text = body.decode("utf-8", errors="replace")
        content_type = headers.get("Content-Type", "").lower()
        cookies = []
        for item in self.cookie_jar:
            cookies.append(
                {
                    "name": item.name,
                    "value": item.value,
                    "domain": item.domain,
                    "path": item.path,
                }
            )
        return {
            "url": url,
            "status": status,
            "headers": headers,
            "body": body,
            "text": text,
            "content_type": content_type,
            "error": error,
            "cookies": cookies,
            "elapsed": round(float(elapsed), 4),
        }

    def _build_multipart_body(self, fields, files):
        boundary = "----ctf-agent-{0}".format(uuid.uuid4().hex)
        chunks = []

        for key, value in (fields or {}).items():
            chunks.extend(
                [
                    "--{0}".format(boundary).encode("utf-8"),
                    'Content-Disposition: form-data; name="{0}"'.format(key).encode("utf-8"),
                    b"",
                    str(value).encode("utf-8"),
                ]
            )

        for field_name, spec in (files or {}).items():
            filename = spec.get("filename") or "upload.bin"
            content_type = spec.get("content_type") or mimetypes.guess_type(filename)[0] or "application/octet-stream"
            content = spec.get("content", b"")
            if isinstance(content, str):
                content = content.encode("utf-8")
            chunks.extend(
                [
                    "--{0}".format(boundary).encode("utf-8"),
                    'Content-Disposition: form-data; name="{0}"; filename="{1}"'.format(field_name, filename).encode("utf-8"),
                    "Content-Type: {0}".format(content_type).encode("utf-8"),
                    b"",
                    content,
                ]
            )

        chunks.append("--{0}--".format(boundary).encode("utf-8"))
        chunks.append(b"")
        body = b"\r\n".join(chunks)
        return body, "multipart/form-data; boundary={0}".format(boundary)
