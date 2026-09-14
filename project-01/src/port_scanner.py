"""
src/port_scanner.py
Controlled, conservative port and service enumeration module for authorized lab targets.
"""

import socket
import time
from typing import Any, Dict, List, Optional

# Safe default training lab port list
DEFAULT_PORTS = [22, 80, 443, 3000, 3306, 5000, 8000, 8080]

# Known service mappings for common lab services
PORT_SERVICE_MAP = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP (Web Server)",
    443: "HTTPS (Encrypted Web)",
    3000: "Node.js / React Dev Server",
    3306: "MySQL / MariaDB",
    5000: "Flask / Python Web App",
    5432: "PostgreSQL",
    6379: "Redis",
    8000: "Django / Python HTTP Server",
    8080: "HTTP-Proxy / Apache Tomcat",
    8443: "HTTPS-Alt",
    9000: "PHP-FPM / SonarQube",
}


def parse_ports_argument(ports_arg: Optional[str]) -> List[int]:
    """
    Parses a user-supplied port string (e.g., "80,443,8080" or "8000-8005" or "5000").
    Falls back to DEFAULT_PORTS if None or empty.
    """
    if not ports_arg or not ports_arg.strip():
        return list(DEFAULT_PORTS)

    ports: List[int] = []
    tokens = ports_arg.split(",")
    for token in tokens:
        token = token.strip()
        if "-" in token:
            parts = token.split("-")
            if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                start, end = int(parts[0]), int(parts[1])
                if 1 <= start <= end <= 65535:
                    ports.extend(range(start, end + 1))
        elif token.isdigit():
            val = int(token)
            if 1 <= val <= 65535:
                ports.append(val)

    # De-duplicate while preserving order, cap at 100 ports to prevent aggressive scanning
    unique_ports = list(dict.fromkeys(ports))[:100]
    return unique_ports if unique_ports else list(DEFAULT_PORTS)


def probe_single_port(ip: str, port: int, timeout: float = 1.0) -> Dict[str, Any]:
    """
    Performs a conservative TCP connect probe against an IP and port.
    Attempts polite 1-line banner grabbing if open.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    start_time = time.time()
    state = "CLOSED"
    banner = ""

    try:
        result = sock.connect_ex((ip, port))
        elapsed_ms = round((time.time() - start_time) * 1000, 2)
        if result == 0:
            state = "OPEN"
            # Polite banner probe
            try:
                sock.settimeout(0.5)
                # Send generic probe or read initial greeting
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                raw_banner = sock.recv(256)
                if raw_banner:
                    banner = raw_banner.decode("utf-8", errors="ignore").split("\r\n")[0].strip()
            except Exception:
                banner = ""
        else:
            state = "CLOSED"
    except socket.timeout:
        elapsed_ms = round((time.time() - start_time) * 1000, 2)
        state = "FILTERED"
    except Exception as exc:
        elapsed_ms = round((time.time() - start_time) * 1000, 2)
        state = f"ERROR ({type(exc).__name__})"
    finally:
        sock.close()

    service_name = PORT_SERVICE_MAP.get(port, "Unknown / Custom Lab Service")

    return {
        "port": port,
        "state": state,
        "service": service_name,
        "latency_ms": elapsed_ms,
        "banner": banner if banner else None
    }


def scan_ports(ip: str, port_list: List[int], timeout: float = 1.0) -> Dict[str, Any]:
    """
    Executes a controlled TCP scan across the requested port list.
    Returns structured results including limitations and scope metadata.
    """
    results: List[Dict[str, Any]] = []
    open_count = 0

    for port in port_list:
        probe_res = probe_single_port(ip, port, timeout=timeout)
        if probe_res["state"] == "OPEN":
            open_count += 1
        results.append(probe_res)

    return {
        "scan_scope": {
            "target_ip": ip,
            "total_ports_probed": len(port_list),
            "ports_list": port_list,
            "timeout_seconds": timeout,
            "scan_type": "TCP Connect Probe (Sequential, Polite)"
        },
        "open_ports_count": open_count,
        "ports": results,
        "limitations": [
            "TCP Connect scan requires a full 3-way handshake; host firewalls may log connection attempts.",
            "Filtered states indicate network firewall drops or dropped packets, not necessarily closed services.",
            "Banner grabbing is passive and unauthenticated; non-responsive services may show no banner.",
            "UDP services and non-standard high ports are outside this conservative scope."
        ]
    }
