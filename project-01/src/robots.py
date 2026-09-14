"""
src/robots.py
Robots.txt and Sitemap.xml discovery and parsing module.
Inspects authorized targets for public crawling directives.
Explicitly documents findings as navigational/information observations,
not automated vulnerabilities.
"""

import re
import ssl
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional


def fetch_resource(url: str, timeout: float = 3.0) -> Dict[str, Any]:
    """Fetches a text resource over HTTP/HTTPS with safe SSL handling."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    handler = urllib.request.HTTPSHandler(context=ctx)
    opener = urllib.request.build_opener(handler)

    req = urllib.request.Request(
        url,
        headers={"User-Agent": "GraySentinel-Recon/1.0 (Authorized Cyber Defence Lab)"}
    )

    try:
        with opener.open(req, timeout=timeout) as res:
            status = res.getcode()
            raw = res.read(65536)
            text = raw.decode("utf-8", errors="replace")
            return {
                "present": status == 200,
                "status_code": status,
                "url": url,
                "content": text,
                "error": None
            }
    except urllib.error.HTTPError as err:
        return {
            "present": False,
            "status_code": err.code,
            "url": url,
            "content": "",
            "error": f"HTTP {err.code}: {err.msg}"
        }
    except Exception as exc:
        return {
            "present": False,
            "status_code": None,
            "url": url,
            "content": "",
            "error": f"{type(exc).__name__}: {str(exc)}"
        }


def parse_robots_txt(content: str) -> Dict[str, Any]:
    """Parses robots.txt lines into user-agents, disallow rules, and sitemap references."""
    disallowed: List[str] = []
    allowed: List[str] = []
    sitemaps: List[str] = []
    user_agents: List[str] = []

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        if ":" in line:
            directive, value = line.split(":", 1)
            directive = directive.strip().lower()
            val = value.strip()

            if directive == "disallow" and val:
                disallowed.append(val)
            elif directive == "allow" and val:
                allowed.append(val)
            elif directive == "sitemap" and val:
                sitemaps.append(val)
            elif directive == "user-agent" and val:
                user_agents.append(val)

    return {
        "user_agents": list(dict.fromkeys(user_agents)),
        "disallowed_paths": list(dict.fromkeys(disallowed)),
        "allowed_paths": list(dict.fromkeys(allowed)),
        "sitemaps_declared": list(dict.fromkeys(sitemaps))
    }


def parse_sitemap_xml(content: str) -> List[str]:
    """Extracts URLs from sitemap XML using regex."""
    matches = re.findall(r"<loc>(.*?)</loc>", content, re.IGNORECASE)
    return [m.strip() for m in matches if m.strip()]


def discover_robots_and_sitemap(base_url: str, timeout: float = 3.0) -> Dict[str, Any]:
    """
    Checks the authorized target for /robots.txt and /sitemap.xml.
    Returns structured results with explicit classification notice.
    """
    robots_url = urllib.parse.urljoin(base_url, "/robots.txt")
    sitemap_url = urllib.parse.urljoin(base_url, "/sitemap.xml")

    robots_raw = fetch_resource(robots_url, timeout=timeout)
    sitemap_raw = fetch_resource(sitemap_url, timeout=timeout)

    robots_parsed = parse_robots_txt(robots_raw["content"]) if robots_raw["present"] else {}
    sitemap_urls = parse_sitemap_xml(sitemap_raw["content"]) if sitemap_raw["present"] else []

    # If robots.txt declared a sitemap not already checked, note it
    for declared in robots_parsed.get("sitemaps_declared", []):
        if declared not in sitemap_urls:
            sitemap_urls.append(declared)

    return {
        "robots": {
            "present": robots_raw["present"],
            "url": robots_url,
            "status_code": robots_raw["status_code"],
            "parsed": robots_parsed,
            "raw_sample": robots_raw["content"][:1000] if robots_raw["content"] else None,
            "error": robots_raw["error"]
        },
        "sitemap": {
            "present": sitemap_raw["present"],
            "url": sitemap_url,
            "status_code": sitemap_raw["status_code"],
            "urls_discovered": sitemap_urls,
            "url_count": len(sitemap_urls),
            "raw_sample": sitemap_raw["content"][:1000] if sitemap_raw["content"] else None,
            "error": sitemap_raw["error"]
        },
        "observation_notice": (
            "Robots.txt and Sitemap.xml are public crawler coordination files. "
            "Disallowed paths often reveal administrative or internal routes for enumeration, "
            "but are strictly informational observations and not vulnerabilities."
        )
    }
