# GraySentinel Cyber Defence Lab — Mentor Review Guide & Defense Preparation

**Candidate:** Mrunal Urankar  
**Team:** Red Team  
**Project:** Project 01 — Authorized Web Recon & Enumeration  
**Standard:** Assigned → Built → Tested → Documented → Published → Proven  

---

## 1. Mentor Review Checklist

During your Day 1 Mentor Evaluation, you must be prepared to demonstrate and explain:

- [x] **1. Why this project exists:** To execute safe, explainable, and polite reconnaissance against authorized lab targets while distinguishing observations from confirmed vulnerabilities.
- [x] **2. What reconnaissance means:** The initial information-gathering phase of the Cyber Kill Chain (MITRE ATT&CK TA0043) where the attack surface is mapped without exploitation.
- [x] **3. How target validation works:** Parsing protocol, hostname, port, and IP resolution; enforcing loopback and RFC 1918 private lab boundaries to prevent unauthorized external scanning.
- [x] **4. How port enumeration works:** Performing polite, sequential TCP connect probes (`socket.connect_ex`) across standard training ports with timeout bounds.
- [x] **5. How HTTP enumeration works:** Gathering HTTP status codes, latency, response headers, content lengths, redirect paths, server banners, and page titles via `urllib.request`.
- [x] **6. How security headers are analyzed:** Evaluating 6 defense-in-depth headers (CSP, HSTS, XFO, XCTO, Referrer-Policy, Permissions-Policy) as configuration observations.
- [x] **7. How technology identification works:** Multi-vector passive signature analysis examining `Server`, `X-Powered-By`, session cookies, and HTML DOM elements with confidence ratings.
- [x] **8. How endpoint enumeration works:** Probing a curated, polite wordlist with configurable inter-request rate delays to discover exposed routes.
- [x] **9. How errors are handled:** Trapping timeouts, DNS failures, connection refusals, and missing crawler files without unhandled exceptions.
- [x] **10. How the JSON output is produced:** Serializing all structured metadata into a normalized schema (`recon.json`) and an executive text report (`recon.txt`).
- [x] **11. How the tests work:** Running 26 automated unit and integration tests across 16 core requirements with 100% pass verification.
- [x] **12. What each screenshot proves:** Direct physical proof of setup, execution, parsing, and reporting under the GraySentinel standard.
- [x] **13. What the limitations are:** Passive signature ambiguity, WAF filtering, wordlist constraints, and the fact that open ports do not equal exploits.
- [x] **14. Why missing headers are not automatically vulnerabilities:** Defenses must be contextualized against application architecture (e.g. JSON APIs do not render HTML scripts, so missing CSP is not an exploitable vulnerability).
- [x] **15. Why authorization matters:** In offensive security, unauthorized scanning is illegal and unethical. The tool includes technical boundaries to reinforce this principle.

---

## 2. 15 Likely Mentor Questions & Model Answers

### Q1: What is the primary objective of Project 01?
**Answer:**  
"Project 01 is an authorized reconnaissance and web enumeration tool engineered in Python. Its goal is to provide controlled, polite, and explainable visibility into an in-scope lab target's attack surface—mapping ports, HTTP services, security headers, technologies, crawler files, and endpoints—without causing Denial of Service or confusing observations with vulnerabilities."

### Q2: Why did you choose Python's Standard Library instead of third-party packages like `requests`?
**Answer:**  
"Using Python's standard library (`urllib.request`, `socket`, `http.client`, `json`, `argparse`) guarantees 100% portability. The tool can be deployed immediately in minimal lab containers, locked-down Kali environments, or offline assessment machines without requiring `pip install` or external network access. It also proves deep understanding of raw network sockets and HTTP mechanics."

### Q3: How does your tool prevent unauthorized scanning of external websites?
**Answer:**  
"In `src/target.py`, the target's resolved IP is checked using Python's `ipaddress` module against loopback (`127.0.0.0/8`, `::1`) and RFC 1918 private address spaces (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`). If a user passes an external public IP or domain, the tool halts immediately with an authorization violation error unless the explicit `--authorized` flag is supplied."

### Q4: How does your port scanner differ from an aggressive tool like Nmap?
**Answer:**  
"Our scanner is intentionally conservative. It performs a sequential, polite TCP connect scan (`connect_ex`) across a small default list of 8 standard lab ports (22, 80, 443, 3000, 3306, 5000, 8000, 8080) with a configurable timeout (default 2s). It does not perform SYN stealth scanning, OS guessing, or aggressive multi-threaded flooding that could destabilize fragile lab services."

### Q5: What is the difference between a security observation and a confirmed vulnerability?
**Answer:**  
"An observation is an observable condition or configuration gap—such as the absence of a `Content-Security-Policy` header. A confirmed vulnerability requires proof of impact or exploitability in context. If an endpoint is a pure REST API returning JSON, it has no DOM context for script execution; calling a missing CSP a vulnerability would be a false positive. We report it strictly as an observation."

### Q6: How does the tool observe supported HTTP methods safely?
**Answer:**  
"It sends an `OPTIONS` request to the target URI using `http.client` and inspects the returned `Allow` response header. This is a read-only, idempotent HTTP specification probe that observes permitted verbs (e.g. GET, POST, HEAD, OPTIONS) without submitting state-changing payloads like PUT or DELETE."

### Q7: How does your passive technology identification engine work?
**Answer:**  
"It uses a multi-factor heuristic:
1. HTTP headers: inspecting `Server` (e.g. Apache, Nginx, Werkzeug) and `X-Powered-By` (PHP, Express).
2. Cookies: recognizing framework session signatures like `session=` (Flask), `connect.sid` (Express), or `PHPSESSID` (PHP).
3. HTML DOM markers: identifying linked CSS frameworks (Bootstrap, Tailwind) and mount IDs (`id='root'` for React).  
Each finding is assigned a confidence rating ('High', 'Medium', 'Low') with concrete evidence."

### Q8: If robots.txt contains `Disallow: /admin`, does that mean `/admin` is vulnerable?
**Answer:**  
"No. `robots.txt` is an advisory file meant for search engine web crawlers. Disallowing a path simply asks crawlers not to index it; it provides no access control. From a reconnaissance perspective, it is valuable intelligence because developers often reveal sensitive directories, but it is an informational observation, not a flaw."

### Q9: How does the endpoint enumerator prevent rate-limiting or service denial?
**Answer:**  
"The endpoint enumerator processes paths sequentially from a small, curated wordlist (15 safe paths by default) and enforces a configurable delay (`--delay 0.05`s) between requests. It also uses a non-redirecting GET request to capture the exact status code and redirect target without triggering recursive redirection storms."

### Q10: How do you handle HTTPS self-signed certificates in a training lab?
**Answer:**  
"In training environments, lab targets often use self-signed certificates. In `src/http_enum.py` and `src/robots.py`, we construct a custom `ssl.SSLContext` with `check_hostname = False` and `verify_mode = ssl.CERT_NONE`. This permits controlled inspection of local HTTPS endpoints without Python throwing unhandled SSLCertVerificationError exceptions."

### Q11: What happens if a target server is completely offline or unreachable?
**Answer:**  
"The tool catches `socket.gaierror` (DNS failure), `ConnectionRefusedError`, and `socket.timeout` at every phase. Rather than terminating with an unhandled Python traceback, it logs a clean error message, records the error state in `recon.json`, and exits with a standardized non-zero status code (exit code 1 or 2)."

### Q12: Walk me through the schema of `recon.json`.
**Answer:**  
"`recon.json` has 9 structured top-level keys:
- `metadata`: Candidate, team, project, and version details.
- `target`: URL, IP, hostname, port, and authorization status.
- `network`: Probed ports, states (OPEN/CLOSED), services, and latency.
- `web`: Status code, headers, title, server banner, and redirects.
- `http_methods`: Results of the OPTIONS probe.
- `headers`: Present and missing defense headers with contextual explanations.
- `technologies`: Array of detected frameworks with confidence and evidence.
- `robots` & `sitemap`: Parsed crawler rules and indexed URLs.
- `endpoints`: Probed paths, status codes, lengths, and categories.
- `timestamp`: ISO 8601 UTC timestamp."

### Q13: How did you test the application to prove reliability?
**Answer:**  
"We created 26 automated unit and integration tests in `tests/` covering all 16 GraySentinel Day 1 requirements. Integration tests spin up an ephemeral localhost server to verify TCP open/closed detection, HTTP 200/404 handling, 302 redirects, robots.txt parsing, and timeout trapping. The tests pass with 100% coverage across requirements."

### Q14: What is the significance of the `X-Content-Type-Options: nosniff` header?
**Answer:**  
"It instructs browsers not to guess (sniff) the MIME type of a response away from what the server declared. This prevents attacks where an attacker uploads an image containing executable JavaScript or HTML, and a vulnerable browser interprets it as script because of sniffing."

### Q15: How does this project align with GraySentinel's Day 1 Standard?
**Answer:**  
"The project satisfies the 'Assigned → Built → Tested → Documented → Published → Proven' workflow:
- **Assigned:** Tasked with Project 01 Web Reconnaissance.
- **Built:** Engineered modular, zero-dependency Python code.
- **Tested:** Verified via 26 automated tests and live lab execution.
- **Documented:** Authored complete README.md, report.md, and code docstrings.
- **Published:** Structured repository ready for GitHub with .gitignore and clean git history.
- **Proven:** Empirical execution artifacts (`recon.json`, `recon.txt`, evidence matrix) validating all claims."

---

## 3. Step-by-Step Live Demonstration Script

Follow this script during your mentor demonstration:

### Step 1: Show Environment & Repository Cleanliness (30 seconds)
```bash
# Display repository structure
ls -la
python3 --version
```
*Script to say:*  
"Hello, Mentor. I am Mrunal Urankar from the Red Team. Today I am demonstrating Project 01: Authorized Web Recon & Enumeration. As you can see, the project is structured modularly in `graysentinel-day1/project-01` with zero external dependencies required for the core scanner."

### Step 2: Run Automated Unit Test Suite (45 seconds)
```bash
python3 tests/run_all_tests.py
```
*Script to say:*  
"Before executing against the lab target, I run our automated test suite. It executes 26 assertions mapping directly to the 16 GraySentinel verification requirements, including target syntax, open/closed port detection, redirect tracking, and JSON schema validation. All 26 tests pass."

### Step 3: Launch the Safe Training Lab Target (30 seconds)
In Terminal 2:
```bash
python3 lab_app/app.py --port 5000
```
*Script to say:*  
"Next, I start our safe local demonstration lab target on port 5000. It exposes controlled endpoints like `/login`, `/admin`, and `/robots.txt`, and serves custom security headers."

### Step 4: Execute Full Reconnaissance (60 seconds)
In Terminal 1:
```bash
python3 recon.py --target http://127.0.0.1:5000
```
*Script to say:*  
"Now I execute `recon.py`. Notice the clear `AUTHORIZED LAB USE ONLY` warning banner. The tool validates the target as an authorized private scope. It scans the 8 conservative ports, finds port 5000 open, and enumerates the HTTP service. It analyzes security headers, observes that `X-Frame-Options` is PRESENT while `Content-Security-Policy` is MISSING—recorded as an observation, not a vulnerability. It identifies Werkzeug and Flask, reads `robots.txt` discovering `/admin` and `/api/`, and probes our controlled wordlist discovering 14 paths."

### Step 5: Verify Generated Evidence Artifacts (30 seconds)
```bash
# Inspect generated outputs
head -n 25 output/recon.txt
head -n 25 output/recon.json
```
*Script to say:*  
"Finally, the tool generates both machine-readable `recon.json` and formatted `recon.txt` in the `output/` directory, completing the Day 1 'Proven' standard."

---

## 4. Git Commit Plan

To establish a clean, authentic development commit history:

```bash
# 1. Initial project structure and requirements
git init
git add requirements.txt .gitignore wordlists/
git commit -m "feat(init): initialize Project 01 structure, dependencies, and wordlist"

# 2. Add target input validation and lab authorization guard
git add src/target.py src/utils.py
git commit -m "feat(target): implement target validation, DNS resolver, and lab scope guard"

# 3. Add conservative TCP port and service scanner
git add src/port_scanner.py
git commit -m "feat(network): implement controlled TCP connect port discovery"

# 4. Add HTTP enumeration and OPTIONS method observer
git add src/http_enum.py
git commit -m "feat(http): implement HTTP metadata collection, redirects, and OPTIONS probe"

# 5. Add security header analysis module
git add src/headers.py
git commit -m "feat(headers): implement security header analysis with observation classifications"

# 6. Add passive technology and robots/sitemap discovery
git add src/technology.py src/robots.py
git commit -m "feat(recon): implement passive tech fingerprinting and crawler file parsing"

# 7. Add controlled web endpoint enumerator
git add src/endpoints.py
git commit -m "feat(endpoints): implement rate-limited web path enumerator"

# 8. Add structured JSON and text report generator
git add src/output.py recon.py
git commit -m "feat(cli): complete CLI integration and dual JSON/text report generation"

# 9. Add safe demonstration lab application
git add lab_app/
git commit -m "feat(lab): implement safe localhost demonstration web server"

# 10. Add automated unit and integration test suite
git add tests/
git commit -m "test: add comprehensive 26-test suite verifying 16 GraySentinel requirements"

# 11. Add documentation and mentor review materials
git add README.md report.md MENTOR_REVIEW_GUIDE.md sample_data/
git commit -m "docs: finalize README, formal report, evidence matrix, and mentor review guide"
```

---

## 5. GitHub Repository Metadata

- **Repository Name:** `graysentinel-project-01-web-recon`
- **Repository Description:**  
  `Practical, explainable Python tool for authorized web reconnaissance & enumeration against controlled lab targets. GraySentinel Day 1 Project 01.`
- **Recommended Topics:**  
  `cybersecurity`, `ethical-hacking`, `web-security`, `reconnaissance`, `python`, `security-tools`, `graysentinel`, `red-team`, `information-gathering`, `port-scanner`
