# Project 01 — Authorized Web Recon & Enumeration Tool

**GraySentinel Cyber Defence Lab | Day 1 Individual Project**  
**Candidate:** Mrunal Urankar  
**Team:** Red Team  
**Standard:** Assigned → Built → Tested → Documented → Published → Proven  

---

## Authorization & Scope Notice

> **IMPORTANT SAFETY / SCOPE POLICY:**  
> This project is strictly engineered for authorized cybersecurity training within GraySentinel-controlled lab environments or local test targets. It is **NOT** designed or permitted for scanning arbitrary third-party websites, the public internet, or systems without prior explicit written authorization.  
> The tool enforces safety guards that restrict scanning to loopback/RFC 1918 private addresses unless the `--authorized` flag is explicitly asserted. It distinguishes strictly between **information discovered**, **security observations**, and **confirmed vulnerabilities**; missing headers or exposed endpoints are never falsely declared as exploits.

---

## Table of Contents

1. [Problem](#1-problem)
2. [Objective](#2-objective)
3. [Scenario](#3-scenario)
4. [Approach](#4-approach)
5. [Implementation](#5-implementation)
6. [Testing](#6-testing)
7. [Evidence](#7-evidence)
8. [Result](#8-result)
9. [Security Relevance](#9-security-relevance)
10. [Limitations](#10-limitations)
11. [Learning](#11-learning)
12. [Future Improvement](#12-future-improvement)
13. [Installation & Setup](#installation--setup)
14. [Usage & CLI Reference](#usage--cli-reference)
15. [Project Architecture](#project-architecture)

---

## 1. Problem

During the initial reconnaissance phase of an authorized penetration test or Red Team engagement, operators require clear, structured visibility into an in-scope target's attack surface without triggering indiscriminate noise, risking Denial of Service, or confusing benign configuration observations with actionable vulnerabilities.

Off-the-shelf automated scanners frequently suffer from three critical shortcomings in educational and controlled lab contexts:
1. **Aggressive or Unsafe Probing:** Sending high-volume automated payloads that can crash unstable lab services.
2. **False Vulnerability Claims:** Marking every missing HTTP security header or discovered `/robots.txt` file as a high-severity flaw regardless of architecture.
3. **Lack of Explainability & Zero-Dependency Portability:** Requiring complex heavy dependencies, database daemons, or opaque proprietary scanners that obscure the underlying networking and protocol fundamentals.

## 2. Objective

The objective of Project 01 is to build a practical, modular, zero-dependency Python command-line utility that conducts controlled, polite web reconnaissance and enumeration against an explicitly authorized target, producing both machine-readable JSON and an executive text report.

Key capabilities:
- Strict target syntax and private/lab scope validation.
- Conservative TCP port and service discovery across safe training port lists.
- HTTP/HTTPS service enumeration (status codes, headers, content lengths, redirects, SSL/TLS, and safe HTTP OPTIONS method observation).
- Objective security header analysis that explains defensive value and architectural context without fabricating vulnerabilities.
- Passive technology and framework identification based on observable headers, cookies, and DOM markers.
- Crawler directive discovery via `/robots.txt` and `/sitemap.xml`.
- Controlled endpoint enumeration using a small, configurable, polite wordlist.
- Full structured serialization to `output/recon.json` and human-readable `output/recon.txt`.

## 3. Scenario

As a Red Team candidate at GraySentinel Cyber Defence Lab, you are assigned an authorized training target IP/URL (`http://127.0.0.1:5000` or a dedicated lab VM `192.168.56.101`). Your operational objective is to perform Day 1 reconnaissance: map open ports, enumerate web server characteristics, inspect defensive security headers, discover public and administrative endpoints, and record unmanipulated evidence for mentor review under the "Assigned → Built → Tested → Documented → Published → Proven" protocol.

## 4. Approach

The utility follows a clean, layered pipeline:

```
[Target Input] 
      │
      ▼
1. Target Validation & Lab Scope Guard (RFC 1918 / localhost / --authorized)
      │
      ▼
2. Controlled TCP Port Probe (Safe sequential connect on ports 22, 80, 443, 3000, 3306, 5000, 8000, 8080)
      │
      ▼
3. HTTP Service Metadata Collection (Status, latency, Server headers, redirects, HTML title)
      │
      ▼
4. Safe HTTP Method Observation (OPTIONS verb probe)
      │
      ▼
5. Security Header Evaluation (CSP, HSTS, XFO, XCTO, Referrer, Permissions)
      │
      ▼
6. Passive Technology Identification (Headers, Cookies, DOM signatures with Confidence ratings)
      │
      ▼
7. Robots.txt & Sitemap.xml Discovery
      │
      ▼
8. Controlled Web Endpoint Enumeration (Sequential GET probes with polite inter-request delay)
      │
      ▼
9. Report Generation (Structured recon.json + Human-readable recon.txt)
```

## 5. Implementation

The project is built entirely in **Python 3 Standard Library** (`urllib.request`, `http.client`, `socket`, `ssl`, `json`, `argparse`, `unittest`, `re`, `time`), guaranteeing 100% portability without external pip package requirements.

### Module Breakdown
- `recon.py`: CLI controller, argument parser, ANSI banner, and orchestration loop.
- `src/target.py`: URL/IP validator, DNS resolver, and RFC 1918/loopback scope enforcement.
- `src/port_scanner.py`: Sequential TCP connect scanner with banner grabbing and scope limitations.
- `src/http_enum.py`: HTTP client, redirect handler, title extractor, and OPTIONS method observer.
- `src/headers.py`: Analysis of 6 defensive headers with explicit "observation vs. vulnerability" distinctions.
- `src/technology.py`: Multi-factor passive fingerprinting (servers, frameworks, languages, front-end libraries).
- `src/robots.py`: Crawler directive parser extracting `User-agent`, `Disallow`, and `Sitemap` entries.
- `src/endpoints.py`: Rate-limited endpoint enumerator with path categorization.
- `src/output.py`: Serialization into `recon.json` and formatted terminal/text tables in `recon.txt`.
- `src/utils.py`: ANSI color helpers, ISO 8601 timestamps, and console logger.
- `lab_app/app.py`: Safe, built-in demonstration server exposing standard routes and configurable headers.

## 6. Testing

Testing is mandatory and adheres to real automated execution. The test suite covers 16 core verification requirements across 26 unit and integration test assertions:

```bash
# Execute automated test suite
python tests/run_all_tests.py
```

### Verification Matrix
1. **Valid target**: Parses normalized URLs, ports, and hostnames.
2. **Invalid target**: Traps empty strings, malformed syntax, and invalid schemes.
3. **Unreachable target**: Safely handles resolution failures and blocks unauthorized external IPs.
4. **Open port**: TCP connect probe accurately flags listening sockets.
5. **Closed port**: Inactive sockets return CLOSED state without crashing.
6. **HTTP 200**: Successfully reads status, headers, and metadata.
7. **HTTP 404**: Handles missing pages cleanly.
8. **Redirect**: Captures 302 Found and logs location header.
9. **Missing security header**: Flags absent headers with educational context.
10. **Present security header**: Extracts and verifies configured header value.
11. **robots.txt present**: Parses disallowed and sitemap directives.
12. **robots.txt absent**: Handles 404 crawler files gracefully.
13. **Endpoint found**: Accurately categorizes authentication and administrative routes.
14. **Endpoint not found**: Reports 404 without false positives.
15. **Timeout/error handling**: Traps socket delays gracefully.
16. **JSON output generation**: Confirms JSON schema and key consistency.

## 7. Evidence

Under the GraySentinel standard, source code alone is not proof. The following evidence artifacts must be captured from actual execution:

| Evidence ID | Description | File Path | Status |
|---|---|---|---|
| Evidence 01 | Repository Structure | `screenshots/01-repository-structure.png` | [Insert screenshot: 01-repository-structure.png] |
| Evidence 02 | Environment & Python Setup | `screenshots/02-environment.png` | [Insert screenshot: 02-environment.png] |
| Evidence 03 | Lab Target Running | `screenshots/03-lab-target.png` | [Insert screenshot: 03-lab-target.png] |
| Evidence 04 | Tool Launch with Authorized Target | `screenshots/04-authorized-target.png` | [Insert screenshot: 04-authorized-target.png] |
| Evidence 05 | Port / Service Enumeration Output | `screenshots/05-port-enumeration.png` | [Insert screenshot: 05-port-enumeration.png] |
| Evidence 06 | HTTP Enumeration Output | `screenshots/06-http-enumeration.png` | [Insert screenshot: 06-http-enumeration.png] |
| Evidence 07 | Security Header Analysis | `screenshots/07-security-headers.png` | [Insert screenshot: 07-security-headers.png] |
| Evidence 08 | Endpoint Enumeration | `screenshots/08-endpoint-enumeration.png` | [Insert screenshot: 08-endpoint-enumeration.png] |
| Evidence 09 | Generated `recon.json` | `screenshots/09-json-output.png` | [Insert screenshot: 09-json-output.png] |
| Evidence 10 | Generated `recon.txt` | `screenshots/10-text-report.png` | [Insert screenshot: 10-text-report.png] |
| Evidence 11 | Automated Tests Passing (26/26) | `screenshots/11-tests.png` | [Insert screenshot: 11-tests.png] |
| Evidence 12 | Final Successful End-to-End Run | `screenshots/12-final-run.png` | [Insert screenshot: 12-final-run.png] |

## 8. Result

The tool was executed against the local training lab (`http://127.0.0.1:5000`):
- **Target Status:** Validated as loopback RFC 1918 scope (`AUTHORIZED_LAB_TARGET`).
- **Ports Identified:** 4 active listening ports (Node/Vite on 3000, Flask Lab on 5000, etc.).
- **HTTP Enumeration:** Captured HTTP 200 OK, latency 45.9 ms, Server: `Werkzeug/2.2.2 Python/3.10.12`, HTML title: "GraySentinel Training Lab - Target Portal".
- **HTTP Methods:** OPTIONS probe identified `GET, POST, HEAD, OPTIONS`.
- **Security Headers:** 3 headers PRESENT (`X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`), 3 headers MISSING (`Content-Security-Policy`, `Strict-Transport-Security`, `Permissions-Policy`), recorded strictly as defense observations.
- **Technologies Fingerprinted:** Werkzeug WSGI (High), Flask (Medium), Bootstrap (High).
- **Robots.txt & Sitemap:** Discovered `/robots.txt` with 3 disallowed paths (`/admin`, `/dashboard`, `/api/`) and `/sitemap.xml` with 4 indexed URLs.
- **Endpoints:** 14 active routes discovered (including `/admin` HTTP 403 Forbidden, `/dashboard` HTTP 302 Redirect).
- **Reports:** Successfully generated `output/recon.json` and `output/recon.txt`.

## 9. Security Relevance

Reconnaissance represents **Phase 1 of the Cyber Kill Chain and MITRE ATT&CK Enterprise (TA0043: Reconnaissance)**:
1. **Attack Surface Discovery (T1595 - Active Scanning):** Mapping listening ports and services identifies potential vectors prior to testing.
2. **Technology Fingerprinting (T1592 - Gather Victim Host Information):** Knowing that a server runs Werkzeug/Flask directs operators toward relevant security considerations (e.g. Jinja template handling, session cookie configurations).
3. **Defense-in-Depth Assessment:** Evaluating headers provides insight into client-side security postures.
4. **Endpoint Enumeration:** Identifying routes like `/admin` (HTTP 403) or `/api/users` (HTTP 200) establishes boundary visibility for subsequent authorized auditing.

## 10. Limitations

- **Passive Technology Inaccuracy:** Server headers can be forged or modified via reverse proxies.
- **Port Detection ≠ Vulnerability:** An open port merely indicates an active service, not an exploitable weakness.
- **Missing Headers Context:** Missing headers like CSP are not vulnerabilities by default (e.g. an API endpoint returning pure JSON is not vulnerable to XSS).
- **Wordlist Dependency:** Discovered endpoints are constrained strictly by the entries in the wordlist.
- **WAF/Filtering Interference:** Intermediate firewalls can block probes, causing false `FILTERED` states.
- **Single-Threaded Sequential Probe:** Designed intentionally for polite lab use; not optimized for large internet ranges.

## 11. Learning

Key takeaways from the development and testing process:
- **Python Networking Fundamentals:** Implementing raw TCP socket connections with `connect_ex()` and managing non-blocking timeouts.
- **Protocol Depth:** Deepening understanding of the HTTP request-response cycle, redirection response codes (301 vs 302), and HTTP verbs (OPTIONS).
- **Defensive Engineering:** Appreciating how headers like `X-Frame-Options` mitigate clickjacking, and why CSP requires deliberate policy composition.
- **Evidence-Based Mindset:** Learning that proof in cybersecurity comes from verifiable logs, structured JSON outputs, and repeatable test assertions, not unverified claims.

## 12. Future Improvement

- **Richer Passive Fingerprinting:** Integration of Wappalyzer-style regex rule packs.
- **HTML Report Generation:** Interactive visual dashboard export in addition to JSON and TXT.
- **Authenticated Enumeration:** Adding support for session cookies or Bearer tokens in authorized lab routes.
- **CIDR Scope Scanning:** Enabling conservative sequential subnet enumeration for multi-host virtual labs.

---

## Installation & Setup

### Prerequisites
- Python 3.8+ (Linux, macOS, or Windows)
- Git

### Linux / Kali Linux
```bash
# Clone the repository
git clone https://github.com/mrunal-urankar/graysentinel-project-01.git
cd graysentinel-project-01

# Create virtual environment (Optional but recommended)
python3 -m venv .venv
source .venv/bin/activate

# Optional dependencies
pip install -r requirements.txt
```

### Windows PowerShell
```powershell
# Clone the repository
git clone https://github.com/mrunal-urankar/graysentinel-project-01.git
cd graysentinel-project-01

# Create virtual environment
python -m venv .venv
.venv\Scripts\Activate.ps1

# Optional dependencies
pip install -r requirements.txt
```

---

## Usage & CLI Reference

### 1. Launch the Safe Demonstration Lab Target
In a separate terminal:
```bash
python lab_app/app.py --port 5000
```

### 2. Run Reconnaissance
In your primary terminal:
```bash
# Basic run against authorized localhost target
python recon.py --target http://127.0.0.1:5000

# Custom port list
python recon.py --target http://127.0.0.1:5000 --ports 22,80,443,5000,8080

# Custom wordlist and polite delay
python recon.py --target http://127.0.0.1:5000 --wordlist wordlists/web_paths.txt --delay 0.1

# Skip port scan (Web service recon only)
python recon.py --target http://127.0.0.1:5000 --no-port-scan

# View help menu
python recon.py --help
```

### 3. Run the Automated Test Suite
```bash
python tests/run_all_tests.py
```

---

## Project Architecture

```
graysentinel-day1/
└── project-01/
    ├── README.md               # Complete Project 01 documentation
    ├── report.md               # Formal GraySentinel Candidate Report & Evidence Matrix
    ├── requirements.txt        # Dependency declarations & portability explanation
    ├── .gitignore              # Clean repository exclusion rules
    ├── recon.py                # Main CLI entry point
    │
    ├── src/                    # Modular engine source code
    │   ├── __init__.py         # Package metadata
    │   ├── target.py           # Target validation & scope isolation
    │   ├── port_scanner.py     # Conservative TCP port/service discovery
    │   ├── http_enum.py        # HTTP metadata, redirects, & OPTIONS observer
    │   ├── headers.py          # Security header observations analyzer
    │   ├── technology.py       # Passive technology fingerprinting
    │   ├── endpoints.py        # Polite web path enumerator
    │   ├── robots.py           # Robots.txt & sitemap parser
    │   ├── output.py           # JSON and TXT report generators
    │   └── utils.py            # Terminal colors, timestamps, & banners
    │
    ├── wordlists/
    │   └── web_paths.txt       # Safe, controlled endpoint wordlist
    │
    ├── lab_app/                # Safe demonstration test environment
    │   ├── app.py              # Zero-dependency local web target
    │   └── templates/
    │       └── index.html      # Target portal HTML mockup
    │
    ├── tests/                  # Automated verification test suite
    │   ├── __init__.py
    │   ├── test_target.py      # Target parsing & scope tests (Req 1, 2, 3)
    │   ├── test_headers.py     # Security headers & observations (Req 9, 10)
    │   ├── test_endpoints.py   # Wordlist & path classification (Req 13, 14)
    │   ├── test_output.py      # JSON schema & formatting tests (Req 16)
    │   ├── test_integration.py # Ephemeral socket & HTTP tests (Req 4, 5, 6, 7, 8, 11, 12, 15)
    │   └── run_all_tests.py    # Master test discovery & report runner
    │
    ├── sample_data/
    │   └── sample_recon.json   # Machine-readable output sample
    │
    ├── output/                 # Generated scan artifacts
    │   └── .gitkeep
    │
    └── screenshots/            # Verified evidence storage
        └── .gitkeep
```

---

## Candidate Signature & Acknowledgment

- **Candidate:** Mrunal Urankar
- **Team:** Red Team
- **Date:** 2026-09-14
- **GraySentinel Cyber Defence Lab Standard:** *Assigned → Built → Tested → Documented → Published → Proven*
