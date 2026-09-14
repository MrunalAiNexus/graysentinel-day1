"""
src/technology.py
Passive technology identification module.
Detects web servers, application frameworks, languages, and front-end libraries
using observable HTTP headers, cookies, and HTML DOM signatures.
Uses explicit confidence ratings and concrete evidence strings.
"""

import re
from typing import Any, Dict, List


def identify_technologies(headers: Dict[str, str], body: str = "") -> List[Dict[str, Any]]:
    """
    Passively identifies web technologies without aggressive probing.
    Returns list of detected technologies with category, confidence rating, and evidence.
    """
    techs: List[Dict[str, Any]] = []
    normalized_headers = {k.lower(): v for k, v in headers.items()}
    server_header = normalized_headers.get("server", "")
    powered_by = normalized_headers.get("x-powered-by", "")
    cookie_header = normalized_headers.get("set-cookie", "")

    # 1. Web Servers / Proxies
    if "apache" in server_header.lower():
        techs.append({
            "name": "Apache HTTP Server",
            "category": "Web Server",
            "confidence": "High",
            "evidence": f"Server header: '{server_header}'"
        })
    elif "nginx" in server_header.lower():
        techs.append({
            "name": "Nginx",
            "category": "Web Server / Reverse Proxy",
            "confidence": "High",
            "evidence": f"Server header: '{server_header}'"
        })
    elif "werkzeug" in server_header.lower():
        techs.append({
            "name": "Werkzeug (Python WSGI)",
            "category": "Web Server / WSGI",
            "confidence": "High",
            "evidence": f"Server header: '{server_header}'"
        })
    elif "caddy" in server_header.lower():
        techs.append({
            "name": "Caddy",
            "category": "Web Server",
            "confidence": "High",
            "evidence": f"Server header: '{server_header}'"
        })

    # 2. Application Frameworks & Languages
    # Flask
    if "werkzeug" in server_header.lower() or "session=" in cookie_header:
        techs.append({
            "name": "Flask",
            "category": "Python Web Framework",
            "confidence": "Medium" if "werkzeug" in server_header.lower() else "Low",
            "evidence": (
                f"Observable Python/Werkzeug headers: '{server_header}'"
                if "werkzeug" in server_header.lower()
                else "Session cookie signature resembles Flask client-side cookie."
            )
        })

    # Express / Node.js
    if "express" in powered_by.lower():
        techs.append({
            "name": "Express.js",
            "category": "Node.js Framework",
            "confidence": "High",
            "evidence": f"X-Powered-By header: '{powered_by}'"
        })
    elif "connect.sid" in cookie_header:
        techs.append({
            "name": "Express / Connect Session",
            "category": "Node.js Framework",
            "confidence": "Medium",
            "evidence": "Observed standard 'connect.sid' session cookie."
        })

    # PHP
    if "php" in powered_by.lower():
        techs.append({
            "name": "PHP",
            "category": "Programming Language",
            "confidence": "High",
            "evidence": f"X-Powered-By header: '{powered_by}'"
        })
    elif "phpsessid" in cookie_header.lower():
        techs.append({
            "name": "PHP",
            "category": "Programming Language",
            "confidence": "High",
            "evidence": "Observed standard 'PHPSESSID' session cookie."
        })

    # Django
    if "csrftoken" in cookie_header.lower() or "sessionid" in cookie_header.lower():
        techs.append({
            "name": "Django",
            "category": "Python Web Framework",
            "confidence": "Medium",
            "evidence": "Observed standard Django cookie format ('csrftoken'/'sessionid')."
        })

    # ASP.NET
    if "asp.net" in powered_by.lower() or "x-aspnet-version" in normalized_headers:
        techs.append({
            "name": "ASP.NET",
            "category": "Web Framework",
            "confidence": "High",
            "evidence": f"Headers: '{powered_by or normalized_headers.get('x-aspnet-version')}'"
        })

    # 3. HTML DOM Signatures
    if body:
        # Bootstrap
        if re.search(r"bootstrap(?:\.min)?\.(?:css|js)", body, re.IGNORECASE) or "class=\"container" in body:
            techs.append({
                "name": "Bootstrap",
                "category": "UI Framework",
                "confidence": "High" if re.search(r"bootstrap(?:\.min)?\.(?:css|js)", body, re.IGNORECASE) else "Low",
                "evidence": "HTML references Bootstrap stylesheets/scripts or grid classes."
            })

        # Tailwind CSS
        if re.search(r"tailwindcss|cdn\.tailwindcss\.com", body, re.IGNORECASE):
            techs.append({
                "name": "Tailwind CSS",
                "category": "UI Framework",
                "confidence": "High",
                "evidence": "HTML script or link contains Tailwind CSS source."
            })

        # jQuery
        if re.search(r"jquery(?:\.min)?\.js", body, re.IGNORECASE):
            techs.append({
                "name": "jQuery",
                "category": "JavaScript Library",
                "confidence": "High",
                "evidence": "HTML references jQuery script tag."
            })

        # React / Vue
        if 'id="root"' in body or 'id="__next"' in body or 'data-reactroot' in body:
            techs.append({
                "name": "React",
                "category": "Front-End Library",
                "confidence": "Medium",
                "evidence": "HTML DOM mounts on standard React container ID ('root' / '__next')."
            })
        if 'id="app"' in body and 'v-' in body:
            techs.append({
                "name": "Vue.js",
                "category": "Front-End Framework",
                "confidence": "Medium",
                "evidence": "HTML contains standard Vue mount point and directives."
            })

    # De-duplicate by technology name keeping highest confidence
    unique: Dict[str, Dict[str, Any]] = {}
    for item in techs:
        name = item["name"]
        if name not in unique:
            unique[name] = item

    return list(unique.values())
