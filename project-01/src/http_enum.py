"""
src/http_enum.py
HTTP/HTTPS service enumeration: collects response codes, headers, redirects,
timings, page title, and safe HTTP OPTIONS method observations.
"""

import http.client
import re
import ssl
import time
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple


def extract_html_title(body_text: str) -> Optional[str]:
    """Extracts <title> text from HTML markup using regex."""
    if not body_text:
        return None
    match = re.search(r"<title\b[^>]*>(.*?)</title>", body_text, re.IGNORECASE | re.DOTALL)
    if match:
        return match.group(1).strip()
    return None


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Custom redirect handler that tracks the redirect chain without losing data."""
    def __init__(self) -> None:
        super().__init__()
        self.redirects: List[Dict[str, Any]] = []

    def redirect_request(self, req: urllib.request.Request, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Optional[urllib.request.Request]:
        self.redirects.append({
            "status_code": code,
            "status_msg": msg,
            "from_url": req.full_url,
            "to_url": newurl
        })
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def enumerate_http_service(target_url: str, timeout: float = 3.0) -> Dict[str, Any]:
    """
    Collects observable HTTP/HTTPS service metadata via GET request.
    Handles redirects, SSL verification bypass for lab targets, and timings.
    """
    start_time = time.time()
    redirect_handler = SafeRedirectHandler()

    # Create unverified SSL context for local lab testing (self-signed certs)
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    https_handler = urllib.request.HTTPSHandler(context=ssl_context)
    opener = urllib.request.build_opener(redirect_handler, https_handler)

    headers_dict: Dict[str, str] = {}
    status_code: Optional[int] = None
    status_message = ""
    content_type = ""
    content_length: Optional[int] = None
    server_header = ""
    body_sample = ""
    html_title: Optional[str] = None
    final_url = target_url
    error_message: Optional[str] = None

    request = urllib.request.Request(
        target_url,
        headers={"User-Agent": "GraySentinel-Recon/1.0 (Authorized Cyber Defence Lab)"}
    )

    try:
        with opener.open(request, timeout=timeout) as response:
            elapsed_seconds = round(time.time() - start_time, 4)
            status_code = response.getcode()
            status_message = response.msg
            final_url = response.geturl()

            for key, val in response.headers.items():
                headers_dict[key] = val

            content_type = response.headers.get("Content-Type", "")
            cl_val = response.headers.get("Content-Length")
            if cl_val and cl_val.isdigit():
                content_length = int(cl_val)

            server_header = response.headers.get("Server", "")

            # Read up to 64KB for passive analysis
            raw_body = response.read(65536)
            if content_length is None:
                content_length = len(raw_body)

            try:
                body_sample = raw_body.decode("utf-8", errors="replace")
            except Exception:
                body_sample = ""

            html_title = extract_html_title(body_sample)

    except urllib.error.HTTPError as http_err:
        elapsed_seconds = round(time.time() - start_time, 4)
        status_code = http_err.code
        status_message = http_err.msg
        final_url = http_err.geturl()

        for key, val in http_err.headers.items():
            headers_dict[key] = val

        content_type = http_err.headers.get("Content-Type", "")
        server_header = http_err.headers.get("Server", "")
        try:
            raw_body = http_err.read(16384)
            content_length = len(raw_body)
            body_sample = raw_body.decode("utf-8", errors="replace")
            html_title = extract_html_title(body_sample)
        except Exception:
            body_sample = ""

    except Exception as exc:
        elapsed_seconds = round(time.time() - start_time, 4)
        error_message = f"{type(exc).__name__}: {str(exc)}"

    return {
        "target_url": target_url,
        "final_url": final_url,
        "status_code": status_code,
        "status_message": status_message,
        "response_time_seconds": elapsed_seconds,
        "response_time_ms": round(elapsed_seconds * 1000, 2),
        "content_type": content_type,
        "content_length": content_length,
        "server_header": server_header if server_header else "Not exposed in headers",
        "html_title": html_title,
        "redirect_count": len(redirect_handler.redirects),
        "redirects": redirect_handler.redirects,
        "headers": headers_dict,
        "body_sample": body_sample,
        "error": error_message
    }


def observe_http_methods(target_url: str, timeout: float = 3.0) -> Dict[str, Any]:
    """
    Observes allowed HTTP methods on the authorized endpoint using an OPTIONS request.
    This is an observation-only probe and does NOT attempt exploitation or state changes.
    """
    parsed = urllib.parse.urlparse(target_url)
    is_https = parsed.scheme.lower() == "https"
    port = parsed.port if parsed.port else (443 if is_https else 80)
    host = parsed.hostname or "127.0.0.1"
    path = parsed.path if parsed.path else "/"

    allowed_methods: List[str] = []
    status_code: Optional[int] = None
    observation_notes = ""

    try:
        if is_https:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)

        conn.request("OPTIONS", path, headers={"User-Agent": "GraySentinel-Recon/1.0"})
        res = conn.getresponse()
        status_code = res.status
        allow_header = res.getheader("Allow")

        if allow_header:
            allowed_methods = [m.strip().upper() for m in allow_header.split(",") if m.strip()]
            observation_notes = f"Target exposed Allow header: {allow_header}"
        else:
            observation_notes = f"OPTIONS responded with HTTP {status_code}, but did not include an explicit 'Allow' header."

        conn.close()
    except Exception as exc:
        observation_notes = f"OPTIONS probe did not return method list: {type(exc).__name__} ({exc})"

    return {
        "method_probed": "OPTIONS",
        "status_code": status_code,
        "allowed_methods": allowed_methods,
        "observation": observation_notes,
        "disclaimer": "HTTP method observation identifies supported verbs; it does not constitute vulnerability exploitation."
    }
