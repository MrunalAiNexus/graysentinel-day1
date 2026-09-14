"""
src/endpoints.py
Controlled web endpoint enumeration module for authorized lab targets.
Uses a configurable, conservative wordlist with polite rate-limiting.
"""

import http.client
import os
import ssl
import time
import urllib.parse
from typing import Any, Callable, Dict, List, Optional


DEFAULT_ENDPOINT_LIST = [
    "/",
    "/login",
    "/logout",
    "/register",
    "/admin",
    "/dashboard",
    "/api",
    "/api/users",
    "/api/v1",
    "/robots.txt",
    "/sitemap.xml",
    "/uploads",
    "/config",
    "/health",
    "/status"
]


def load_wordlist(wordlist_path: Optional[str]) -> List[str]:
    """
    Loads endpoint paths from a custom file or returns DEFAULT_ENDPOINT_LIST.
    Cleans lines, strips comments and leading/trailing whitespace.
    """
    if not wordlist_path:
        return list(DEFAULT_ENDPOINT_LIST)

    if not os.path.isfile(wordlist_path):
        raise FileNotFoundError(f"Custom wordlist file not found at: {wordlist_path}")

    paths: List[str] = []
    with open(wordlist_path, "r", encoding="utf-8") as f:
        for line in f:
            clean = line.strip()
            if clean and not clean.startswith("#"):
                if not clean.startswith("/"):
                    clean = "/" + clean
                paths.append(clean)

    # De-duplicate while preserving order, cap at 50 to maintain controlled lab scope
    unique_paths = list(dict.fromkeys(paths))[:50]
    return unique_paths if unique_paths else list(DEFAULT_ENDPOINT_LIST)


def categorize_endpoint(path: str, status_code: Optional[int]) -> str:
    """Categorizes endpoint finding for human readability."""
    p_lower = path.lower()
    if status_code in (401, 403):
        return "Protected / Access Restricted"
    if status_code in (301, 302, 307, 308):
        return "Redirect"
    if "admin" in p_lower or "config" in p_lower:
        return "Administrative"
    if "login" in p_lower or "register" in p_lower or "logout" in p_lower:
        return "Authentication"
    if "api" in p_lower:
        return "API Route"
    if status_code == 200:
        return "Accessible Resource"
    if status_code == 404:
        return "Not Found"
    return "Observed Path"


def probe_endpoint(base_url: str, path: str, timeout: float = 2.0) -> Dict[str, Any]:
    """
    Probes a single web path using a polite HTTP/HTTPS GET request.
    Does not follow redirects so the initial status code and redirect target are captured.
    """
    parsed = urllib.parse.urlparse(base_url)
    is_https = parsed.scheme.lower() == "https"
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port if parsed.port else (443 if is_https else 80)
    full_url = urllib.parse.urljoin(base_url, path)

    start = time.time()
    status_code: Optional[int] = None
    reason = ""
    content_length: Optional[int] = None
    redirect_location: Optional[str] = None
    content_type = ""
    error = None

    try:
        if is_https:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)

        conn.request(
            "GET",
            path,
            headers={
                "User-Agent": "GraySentinel-Recon/1.0 (Authorized Lab Enumeration)",
                "Accept": "*/*"
            }
        )
        res = conn.getresponse()
        elapsed_ms = round((time.time() - start) * 1000, 2)

        status_code = res.status
        reason = res.reason
        redirect_location = res.getheader("Location")
        content_type = res.getheader("Content-Type") or ""

        cl_hdr = res.getheader("Content-Length")
        if cl_hdr and cl_hdr.isdigit():
            content_length = int(cl_hdr)
        else:
            # Read body to measure byte length safely
            body = res.read(32768)
            content_length = len(body)

        conn.close()
    except Exception as exc:
        elapsed_ms = round((time.time() - start) * 1000, 2)
        error = f"{type(exc).__name__}: {exc}"

    return {
        "path": path,
        "full_url": full_url,
        "status_code": status_code,
        "reason": reason,
        "content_length": content_length,
        "response_time_ms": elapsed_ms,
        "redirect_to": redirect_location,
        "content_type": content_type,
        "category": categorize_endpoint(path, status_code),
        "error": error
    }


def enumerate_endpoints(
    base_url: str,
    wordlist: List[str],
    delay: float = 0.05,
    timeout: float = 2.0,
    progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None
) -> Dict[str, Any]:
    """
    Sequentially tests paths from the wordlist with polite inter-request delay.
    Collects findings into structured output.
    """
    results: List[Dict[str, Any]] = []
    discovered_count = 0

    for path in wordlist:
        probe = probe_endpoint(base_url, path, timeout=timeout)
        if probe["status_code"] is not None and probe["status_code"] != 404:
            discovered_count += 1

        results.append(probe)
        if progress_callback:
            progress_callback(probe)

        if delay > 0:
            time.sleep(delay)

    return {
        "wordlist_size": len(wordlist),
        "discovered_count": discovered_count,
        "delay_seconds": delay,
        "endpoints": results,
        "rate_limiting_policy": "Polite sequential execution with configurable inter-request delay."
    }
