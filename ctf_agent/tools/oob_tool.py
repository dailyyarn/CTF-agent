import uuid
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener


class OOBTool(object):
    def __init__(
        self,
        base_url=None,
        poll_url_template=None,
        auth_token=None,
        auth_header="Authorization",
        timeout=8.0,
    ):
        self.base_url = base_url
        self.poll_url_template = poll_url_template
        self.auth_token = auth_token
        self.auth_header = auth_header or "Authorization"
        self.timeout = timeout
        self.opener = build_opener(ProxyHandler({}))

    def generate_callback(self):
        token = str(uuid.uuid4())
        if self.base_url:
            return {
                "token": token,
                "url": "{0}/{1}".format(self.base_url.rstrip("/"), token),
            }
        return {"token": token, "url": None}

    def poll(self, token):
        if not self.poll_url_template:
            return {
                "supported": False,
                "token": token,
                "matched": False,
                "message": "OOB polling is not configured.",
            }

        url = self.poll_url_template.format(token=token)
        headers = {}
        if self.auth_token:
            headers[self.auth_header] = self.auth_token

        request = Request(url, headers=headers, method="GET")
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                body = response.read().decode("utf-8", errors="replace")
                return {
                    "supported": True,
                    "token": token,
                    "matched": token in body,
                    "status": response.status,
                    "url": url,
                    "body": body[:4000],
                }
        except HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            return {
                "supported": True,
                "token": token,
                "matched": token in body,
                "status": exc.code,
                "url": url,
                "body": body[:4000],
            }
        except URLError as exc:
            return {
                "supported": True,
                "token": token,
                "matched": False,
                "url": url,
                "error": str(exc),
            }

    def is_enabled(self):
        return bool(self.base_url)

    def can_poll(self):
        return bool(self.poll_url_template)

    def describe(self):
        return {
            "enabled": self.is_enabled(),
            "can_poll": self.can_poll(),
            "base_url": self.base_url,
            "poll_url_template": self.poll_url_template,
        }
