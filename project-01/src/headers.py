"""
src/headers.py
Security header analysis module.
Assesses defensive HTTP headers and records findings as security observations,
strictly distinguishing observations from confirmed vulnerabilities.
"""

from typing import Any, Dict, List

# Standard security headers inspected during authorized web reconnaissance
SECURITY_HEADER_DEFINITIONS = {
    "Content-Security-Policy": {
        "description": "Restricts resource loading (scripts, stylesheets, frames) to prevent XSS and data injection.",
        "why_it_matters": "Mitigates Cross-Site Scripting (XSS) and clickjacking by restricting browser resource execution.",
        "limitation_context": (
            "Absence does not inherently imply exploitable XSS. Pure JSON APIs, static endpoints, "
            "or sites with strict context-aware output encoding may be secure even without CSP."
        )
    },
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS connections and prevents SSL/TLS stripping attacks (HSTS).",
        "why_it_matters": "Forces browsers to use encrypted connections, eliminating insecure HTTP downgrade attempts.",
        "limitation_context": (
            "Only applicable to HTTPS targets. Not applicable to plain HTTP lab environments or local test harnesses."
        )
    },
    "X-Frame-Options": {
        "description": "Indicates whether a browser should be allowed to render a page in a <frame>, <iframe>, or <object>.",
        "why_it_matters": "Prevents Clickjacking attacks by forbidding the page from being framed by malicious external sites.",
        "limitation_context": (
            "Endpoints that do not accept user input, API endpoints returning JSON, or modern sites using CSP frame-ancestors "
            "may not require X-Frame-Options."
        )
    },
    "X-Content-Type-Options": {
        "description": "Prevents the browser from MIME-type sniffing away from the declared Content-Type (nosniff).",
        "why_it_matters": "Reduces exposure to drive-by download attacks and content confusion when handling user uploads.",
        "limitation_context": (
            "Relevant primarily where user-uploaded content or untrusted files are served without strict server Content-Type headers."
        )
    },
    "Referrer-Policy": {
        "description": "Governs how much referrer information (via the Referer header) is sent when navigating away from the page.",
        "why_it_matters": "Prevents accidental leakage of sensitive tokens, session IDs, or internal URLs in query parameters.",
        "limitation_context": (
            "Modern browsers default to 'strict-origin-when-cross-origin' even if this header is omitted."
        )
    },
    "Permissions-Policy": {
        "description": "Allows fine-grained control over browser features (camera, microphone, geolocation, payment).",
        "why_it_matters": "Limits attack surface by disabling unnecessary high-privilege browser APIs within the application origin.",
        "limitation_context": (
            "Absence simply allows standard browser default permissions; does not represent an exploitable flaw by itself."
        )
    }
}


def analyze_security_headers(headers: Dict[str, str], is_https: bool = False) -> Dict[str, Any]:
    """
    Evaluates HTTP response headers against recommended defensive security practices.
    Returns structured analysis clearly designated as OBSERVATIONS, not vulnerabilities.
    """
    # Normalize headers to lowercase keys for case-insensitive lookup
    normalized = {k.lower(): (k, v) for k, v in headers.items()}

    findings: List[Dict[str, Any]] = []
    present_count = 0
    missing_count = 0

    for header_name, meta in SECURITY_HEADER_DEFINITIONS.items():
        lookup_key = header_name.lower()
        if lookup_key in normalized:
            original_key, val = normalized[lookup_key]
            present_count += 1
            status = "PRESENT"
            observation = f"Header is configured with value: '{val}'"
        else:
            missing_count += 1
            status = "MISSING"
            if header_name == "Strict-Transport-Security" and not is_https:
                observation = "Header is absent (Expected for plain HTTP target; only valid over HTTPS)."
            else:
                observation = "Header was not observed in the HTTP response."

        findings.append({
            "header": header_name,
            "status": status,
            "value": normalized[lookup_key][1] if lookup_key in normalized else None,
            "observation": observation,
            "why_it_matters": meta["why_it_matters"],
            "limitation_context": meta["limitation_context"]
        })

    return {
        "summary": {
            "total_evaluated": len(SECURITY_HEADER_DEFINITIONS),
            "present_count": present_count,
            "missing_count": missing_count,
            "classification_notice": (
                "GraySentinel Standard: Missing headers are recorded strictly as configuration "
                "observations and defense-in-depth opportunities, NOT confirmed vulnerabilities."
            )
        },
        "details": findings
    }
