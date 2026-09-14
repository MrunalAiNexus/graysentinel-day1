"""
src/target.py
Target input parser, syntax validator, IP resolver, and authorization guard.
"""

import ipaddress
import re
import socket
import urllib.parse
from typing import Any, Dict, Optional, Tuple


class TargetValidationError(Exception):
    """Raised when target syntax or scope validation fails."""
    pass


def is_private_or_lab_ip(ip_str: str) -> bool:
    """Checks whether an IP address belongs to loopback or private lab ranges (RFC 1918 / RFC 6598)."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_loopback
            or ip.is_private
            or ip.is_link_local
            or ip.is_reserved
        )
    except ValueError:
        return False


def is_lab_hostname(hostname: str) -> bool:
    """Checks if hostname matches safe lab naming conventions."""
    clean = hostname.lower().strip()
    if clean in ("localhost", "127.0.0.1", "::1"):
        return True
    if clean.endswith((".local", ".lab", ".internal", ".test", ".lan")):
        return True
    return False


def parse_and_validate_target(raw_target: str, allow_external: bool = False) -> Dict[str, Any]:
    """
    Parses and validates a user-provided target string.

    Accepts formats:
      - http://127.0.0.1:5000
      - https://192.168.56.101
      - http://localhost:8000/app
      - 127.0.0.1:5000 (auto-prepends http://)

    Validates:
      - Protocol (http or https)
      - Hostname / IP syntax
      - Port range (1 - 65535)
      - Path normalization
      - Target authorization scope (lab/private vs external)

    Returns structured dictionary with validated components.
    """
    if not raw_target or not isinstance(raw_target, str):
        raise TargetValidationError("Target must be a non-empty string.")

    target_str = raw_target.strip()

    # Prepend http:// if user passed a bare host or host:port
    if not (target_str.startswith("http://") or target_str.startswith("https://")):
        target_str = "http://" + target_str

    try:
        parsed = urllib.parse.urlparse(target_str)
    except Exception as exc:
        raise TargetValidationError(f"Invalid URL structure: {exc}")

    protocol = parsed.scheme.lower()
    if protocol not in ("http", "https"):
        raise TargetValidationError(f"Unsupported protocol '{protocol}'. Only 'http' and 'https' are allowed.")

    hostname = parsed.hostname
    if not hostname:
        raise TargetValidationError("Could not extract a valid hostname or IP address from target.")

    # Port validation
    try:
        if parsed.port is not None:
            port = parsed.port
            if not (1 <= port <= 65535):
                raise TargetValidationError(f"Port {port} is out of valid range (1 - 65535).")
        else:
            port = 443 if protocol == "https" else 80
    except ValueError as val_err:
        raise TargetValidationError(f"Invalid port: {val_err}")

    path = parsed.path if parsed.path else "/"
    if not path.startswith("/"):
        path = "/" + path

    # IP Resolution with timeout
    resolved_ip: Optional[str] = None
    try:
        # Check if hostname is already a valid IP literal
        ipaddress.ip_address(hostname)
        resolved_ip = hostname
    except ValueError:
        # Hostname resolution
        try:
            resolved_ip = socket.gethostbyname(hostname)
        except socket.gaierror as err:
            raise TargetValidationError(f"Could not resolve hostname '{hostname}' to an IP address: {err}")

    # Authorization scope check
    is_lab = False
    if resolved_ip and is_private_or_lab_ip(resolved_ip):
        is_lab = True
    elif is_lab_hostname(hostname):
        is_lab = True

    if not is_lab and not allow_external:
        raise TargetValidationError(
            f"Target '{hostname}' ({resolved_ip}) is not a recognized private/lab target. "
            "In adherence to GraySentinel scope, arbitrary external scanning is blocked. "
            "To explicitly target an authorized external lab system, pass the --authorized flag."
        )

    # Reconstruct normalized base URL
    if (protocol == "http" and port == 80) or (protocol == "https" and port == 443):
        base_url = f"{protocol}://{hostname}"
    else:
        base_url = f"{protocol}://{hostname}:{port}"

    full_url = f"{base_url}{path}" if path != "/" else base_url

    return {
        "raw_input": raw_target,
        "normalized_url": full_url,
        "base_url": base_url,
        "protocol": protocol,
        "hostname": hostname,
        "resolved_ip": resolved_ip,
        "port": port,
        "path": path,
        "is_lab_scope": is_lab,
        "authorization_status": "AUTHORIZED_LAB_TARGET" if is_lab else "AUTHORIZED_EXPLICIT_TARGET"
    }
