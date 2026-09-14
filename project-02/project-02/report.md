# GraySentinel Web Security Assessment Report

> **DATA CLASSIFICATION:** SANITIZED DEMO DATA — NOT A REAL TARGET  
> **ENGAGEMENT ID:** `GS-SCAN-20260914-DEMO` | **TARGET:** `lab.graysentinel.internal` | **DATE:** 2026-09-14 11:56:31 UTC  
> **AUDITOR / LEAD:** GraySentinel Security Team | **STATUS:** FINAL ASSESSMENT

---

## 1. Executive Summary

GraySentinel performed a structured web application and perimeter security evaluation against **`lab.graysentinel.internal`**. The primary objective was to validate attack surface exposure, analyze correlations from reconnaissance telemetry, and establish an actionable risk remediation roadmap.

A total of **6 finding(s)** were identified, validated, and categorized. The overall security posture is evaluated as **CRITICAL RISK** with a cumulative weighted risk score of **36.0**.

**Posture Diagnosis:** Immediate exploitation potential present. Perimeter or critical secrets exposed.

## 2. Scope

The scope of this assessment was bounded strictly by the following assets:

- **Primary Target Host:** `lab.graysentinel.internal`
- **Reconnaissance Scan ID:** `GS-SCAN-20260914-DEMO`
- **Scan Ingestion Timestamp:** `2026-09-14T10:30:00Z`
- **Discovered Network Ports:** 4 exposed port(s)
- **Enumerated Web Endpoints:** 6 route(s)

All assessment activities were conducted strictly in compliance with GraySentinel Rules of Engagement. No denial-of-service, invasive exploitation, or uncoordinated perimeter attacks occurred.

## 3. Methodology

Assessments adhere to the **GraySentinel Threat-First Validation Methodology**, comprising four distinct phases:

1. **Reconnaissance Ingestion & Attack Surface Correlation:** Ingestion of standardized JSON reconnaissance telemetry from Project 01, mapping open ports, endpoints, and HTTP response headers.
2. **Evidence Cryptographic Verification:** Generating and cross-referencing SHA-256 integrity digests for proof-of-concept artifacts to prevent tampering and ensure verifiable auditing.
3. **Schema & Policy Validation:** Enforcing strict schema rules, mandatory reproduction steps, and evidence requirements for high/critical findings.
4. **Risk Quantification & Phased Roadmapping:** Calculating weighted risk metrics (`Severity Weight × Confidence Multiplier`) and deriving a 3-phase remediation schedule.

## 4. Assets Reviewed

| Endpoint / Resource | HTTP Status | Method | Content Type | Exposure / Notes |
| :--- | :---: | :---: | :--- | :--- |
| `/` | `200` | `GET` | `text/html` | GraySentinel Portal Home |
| `/login` | `200` | `GET` | `text/html` | Authentication Portal |
| `/admin` | `200` | `GET` | `text/html` | Administrative Dashboard |
| `/.env.bak` | `200` | `GET` | `text/plain` | Standard Route |
| `/debug/metrics` | `200` | `GET` | `application/json` | Prometheus Metrics Dump |
| `/api/v1/health` | `200` | `GET` | `application/json` | Service Health Check |

### Discovered Network Services

| Port | Protocol | Service | State | Identified Banner |
| :---: | :---: | :--- | :---: | :--- |
| `80` | `tcp` | `http` | `open` | `nginx/1.22.1` |
| `443` | `tcp` | `https` | `open` | `nginx/1.22.1` |
| `3306` | `tcp` | `mysql` | `open` | `8.0.35-MySQL Community Server` |
| `8080` | `tcp` | `http-proxy` | `open` | `Golang Debug Metrics Portal` |

## 5. Severity Summary

| Severity Level | Count | Weight Factor | Impact Description |
| :--- | :---: | :---: | :--- |
| **CRITICAL** | `1` | 10.0 | Immediate systemic compromise or credential exposure |
| **HIGH** | `3` | 7.0 | Direct attack surface or significant authorization bypass |
| **MEDIUM** | `1` | 4.0 | Administrative interface exposure or perimeter hygiene flaw |
| **LOW** | `1` | 1.0 | Absence of defensive HTTP response headers |
| **INFO** | `0` | 0.0 | Informational observation |
| **Total Findings** | **`6`** | — | **Weighted Score: 36.0** |

## 6. Detailed Findings

### 6.1. [GS-SEC-001] Absence of Baseline Defensive HTTP Security Headers

- **Severity:** `LOW` | **Confidence:** `HIGH` | **Status:** `VALIDATED`
- **Affected Asset:** `https://lab.graysentinel.internal/`
- **CVSS v3.1 Score:** `3.7` (`CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N`)
- **Classification:** `CWE-693` (Protection Mechanism Failure) | `A05:2021-Security Misconfiguration`
- **Weighted Risk Points:** `1.0`

#### Description
Web service at lab.graysentinel.internal lacks modern protective HTTP response headers (Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options). This degrades browser defense-in-depth protections against clickjacking, MIME-sniffing, and cross-site scripting.

#### Reproduction Steps
1. Send an HTTP GET request to https://lab.graysentinel.internal/
2. Inspect response headers using curl or an intercepting proxy.
3. Verify the absence of headers: Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options.

#### Supporting Evidence
- **Evidence ID:** `EVD-001-01` (DEMO / SAMPLE DATA)
  - **Source:** HTTP Header Audit on lab.graysentinel.internal
  - **Observation:** Response headers lack defensive directives: Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options
  - **Payload / Response Snippet:**
    ```text
    Target: lab.graysentinel.internal
Missing: Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options
    ```

#### Remediation Guidance
- **Tactical Action:** Configure edge reverse proxy (Nginx, Caddy, or Cloudflare) to attach: Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, and X-Content-Type-Options.
- **Strategic Fix:** Enforce centralized baseline header configurations in CI/CD container templates and conduct automated weekly header regression checks.
```bash
# Nginx security header baseline
add_header Content-Security-Policy "default-src 'self';" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
```

### 6.2. [GS-SEC-002] Unrestricted Access to Internal Interface (/admin)

- **Severity:** `HIGH` | **Confidence:** `HIGH` | **Status:** `REVIEW`
- **Affected Asset:** `https://lab.graysentinel.internal/admin`
- **CVSS v3.1 Score:** `7.3` (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`)
- **Classification:** `CWE-284` (Improper Access Control) | `A01:2021-Broken Access Control`
- **Weighted Risk Points:** `7.0`

#### Description
Administrative or monitoring endpoint discovered at /admin returning HTTP 200. Exposing internal portals increases the attack surface for credential stuffing, brute-force attacks, and reconnaissance.

#### Reproduction Steps
1. Issue GET request to https://lab.graysentinel.internal/admin
2. Verify that endpoint responds with status 200 without requiring network isolation.

#### Supporting Evidence
- **Evidence ID:** `EVD-002-01` (DEMO / SAMPLE DATA)
  - **Source:** Recon Web Spidering
  - **Observation:** Route /admin returned HTTP 200
  - **Payload / Response Snippet:**
    ```text
    GET /admin -> HTTP 200 (Administrative Dashboard)
    ```

#### Remediation Guidance
- **Tactical Action:** Restrict access to /admin using IP whitelisting or VPN gateway authentication.
- **Strategic Fix:** Enforce Zero Trust architecture principles for all internal administrative planes.

### 6.3. [GS-SEC-003] Publicly Accessible Configuration Artifact (/.env.bak)

- **Severity:** `CRITICAL` | **Confidence:** `HIGH` | **Status:** `VALIDATED`
- **Affected Asset:** `https://lab.graysentinel.internal/.env.bak`
- **CVSS v3.1 Score:** `8.6` (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N`)
- **Classification:** `CWE-200` (Exposure of Sensitive Information to an Unauthorized Actor) | `A01:2021-Broken Access Control`
- **Weighted Risk Points:** `10.0`

#### Description
The server exposes sensitive application configuration artifact at /.env.bak (HTTP Status 200). If unauthenticated visitors access this resource, operational secrets, API keys, and database credentials could be compromised.

#### Reproduction Steps
1. Send unauthenticated GET request to https://lab.graysentinel.internal/.env.bak
2. Observe HTTP status code 200 returned by web server.
3. Confirm sensitive environment variable keys or credentials in response payload.

#### Supporting Evidence
- **Evidence ID:** `EVD-003-01` (DEMO / SAMPLE DATA)
  - **Source:** HTTP Endpoint Enumeration
  - **Observation:** Accessible endpoint returned HTTP 200 with size 782 bytes
  - **Payload / Response Snippet:**
    ```text
    GET /.env.bak HTTP/1.1 -> 200 OK (Content-Type: text/plain)
    ```

#### Remediation Guidance
- **Tactical Action:** Immediately block external access to /.env.bak and rotate any exposed credentials.
- **Strategic Fix:** Audit build pipelines to exclude dot-files and backup archives from web document roots.
```bash
location ~ /\.(?!well-known).* { deny all; return 404; }
```

### 6.4. [GS-SEC-004] Unrestricted Access to Internal Interface (/debug/metrics)

- **Severity:** `HIGH` | **Confidence:** `HIGH` | **Status:** `REVIEW`
- **Affected Asset:** `https://lab.graysentinel.internal/debug/metrics`
- **CVSS v3.1 Score:** `7.3` (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`)
- **Classification:** `CWE-284` (Improper Access Control) | `A01:2021-Broken Access Control`
- **Weighted Risk Points:** `7.0`

#### Description
Administrative or monitoring endpoint discovered at /debug/metrics returning HTTP 200. Exposing internal portals increases the attack surface for credential stuffing, brute-force attacks, and reconnaissance.

#### Reproduction Steps
1. Issue GET request to https://lab.graysentinel.internal/debug/metrics
2. Verify that endpoint responds with status 200 without requiring network isolation.

#### Supporting Evidence
- **Evidence ID:** `EVD-004-01` (DEMO / SAMPLE DATA)
  - **Source:** Recon Web Spidering
  - **Observation:** Route /debug/metrics returned HTTP 200
  - **Payload / Response Snippet:**
    ```text
    GET /debug/metrics -> HTTP 200 (Prometheus Metrics Dump)
    ```

#### Remediation Guidance
- **Tactical Action:** Restrict access to /debug/metrics using IP whitelisting or VPN gateway authentication.
- **Strategic Fix:** Enforce Zero Trust architecture principles for all internal administrative planes.

### 6.5. [GS-SEC-005] Direct Exposure of Management/Database Port (3306/tcp)

- **Severity:** `HIGH` | **Confidence:** `HIGH` | **Status:** `VALIDATED`
- **Affected Asset:** `lab.graysentinel.internal:3306`
- **CVSS v3.1 Score:** `7.5` (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`)
- **Classification:** `CWE-1188` (Insecure Default Initialization of Resource) | `A05:2021-Security Misconfiguration`
- **Weighted Risk Points:** `7.0`

#### Description
Port 3306 (mysql) is reachable directly over the public/perimeter network. Service banner: '8.0.35-MySQL Community Server'. Direct exposure allows remote adversaries to conduct uninhibited brute-force attacks or exploit protocol-level vulnerabilities.

#### Reproduction Steps
1. Execute TCP probe against lab.graysentinel.internal on port 3306
2. Confirm open state (open) and service identification (mysql).

#### Supporting Evidence
- **Evidence ID:** `EVD-005-01` (DEMO / SAMPLE DATA)
  - **Source:** Network Port Sweep
  - **Observation:** Port 3306/tcp open. Service identified: mysql
  - **Payload / Response Snippet:**
    ```text
    lab.graysentinel.internal:3306 OPEN (8.0.35-MySQL Community Server)
    ```

#### Remediation Guidance
- **Tactical Action:** Apply firewall ingress rules (Security Group / iptables) to restrict port 3306.
- **Strategic Fix:** Migrate administrative access behind dedicated bastion hosts or Zero Trust access proxies.

### 6.6. [GS-SEC-006] Direct Exposure of Management/Database Port (8080/tcp)

- **Severity:** `MEDIUM` | **Confidence:** `HIGH` | **Status:** `VALIDATED`
- **Affected Asset:** `lab.graysentinel.internal:8080`
- **CVSS v3.1 Score:** `5.3` (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`)
- **Classification:** `CWE-1188` (Insecure Default Initialization of Resource) | `A05:2021-Security Misconfiguration`
- **Weighted Risk Points:** `4.0`

#### Description
Port 8080 (http-proxy) is reachable directly over the public/perimeter network. Service banner: 'Golang Debug Metrics Portal'. Direct exposure allows remote adversaries to conduct uninhibited brute-force attacks or exploit protocol-level vulnerabilities.

#### Reproduction Steps
1. Execute TCP probe against lab.graysentinel.internal on port 8080
2. Confirm open state (open) and service identification (http-proxy).

#### Supporting Evidence
- **Evidence ID:** `EVD-006-01` (DEMO / SAMPLE DATA)
  - **Source:** Network Port Sweep
  - **Observation:** Port 8080/tcp open. Service identified: http-proxy
  - **Payload / Response Snippet:**
    ```text
    lab.graysentinel.internal:8080 OPEN (Golang Debug Metrics Portal)
    ```

#### Remediation Guidance
- **Tactical Action:** Apply firewall ingress rules (Security Group / iptables) to restrict port 8080.
- **Strategic Fix:** Migrate administrative access behind dedicated bastion hosts or Zero Trust access proxies.

## 7. Evidence & Cryptographic Verification

Every high and critical finding documented in this report is bound to empirical evidence. Proof-of-concept artifacts are indexed with SHA-256 digests to ensure non-repudiation.

| Evidence ID | Finding ID | Source | SHA-256 Digest | Data Classification |
| :--- | :--- | :--- | :--- | :--- |
| `EVD-001-01` | `GS-SEC-001` | HTTP Header Audit on lab.graysentinel.internal | *Observation-Only* | DEMO / SAMPLE |
| `EVD-002-01` | `GS-SEC-002` | Recon Web Spidering | *Observation-Only* | DEMO / SAMPLE |
| `EVD-003-01` | `GS-SEC-003` | HTTP Endpoint Enumeration | *Observation-Only* | DEMO / SAMPLE |
| `EVD-004-01` | `GS-SEC-004` | Recon Web Spidering | *Observation-Only* | DEMO / SAMPLE |
| `EVD-005-01` | `GS-SEC-005` | Network Port Sweep | *Observation-Only* | DEMO / SAMPLE |
| `EVD-006-01` | `GS-SEC-006` | Network Port Sweep | *Observation-Only* | DEMO / SAMPLE |

## 8. Risk Assessment

The overall environment risk posture is scored at **CRITICAL RISK** (36.0 points). Vulnerability density across discovered endpoints is **1.0 finding(s) per endpoint**.

Confidence-weighted metrics verify that critical exposure points are confirmed and actionable, warranting prioritized engineering attention.

## 9. Remediation Recommendations

Remediation activities must follow this 3-phase chronological sequence:

### Phase 1: Emergency Tactical Remediation (0 - 48 Hours)
- **[GS-SEC-002] Unrestricted Access to Internal Interface (/admin)** (`https://lab.graysentinel.internal/admin`): Restrict access to /admin using IP whitelisting or VPN gateway authentication.
- **[GS-SEC-003] Publicly Accessible Configuration Artifact (/.env.bak)** (`https://lab.graysentinel.internal/.env.bak`): Immediately block external access to /.env.bak and rotate any exposed credentials.
- **[GS-SEC-004] Unrestricted Access to Internal Interface (/debug/metrics)** (`https://lab.graysentinel.internal/debug/metrics`): Restrict access to /debug/metrics using IP whitelisting or VPN gateway authentication.
- **[GS-SEC-005] Direct Exposure of Management/Database Port (3306/tcp)** (`lab.graysentinel.internal:3306`): Apply firewall ingress rules (Security Group / iptables) to restrict port 3306.

### Phase 2: Systematic Hardening & Access Control (3 - 14 Days)
- **[GS-SEC-006] Direct Exposure of Management/Database Port (8080/tcp)** (`lab.graysentinel.internal:8080`): Apply firewall ingress rules (Security Group / iptables) to restrict port 8080.

### Phase 3: Defensive Governance & Hygiene (15 - 30 Days)
- **[GS-SEC-001] Absence of Baseline Defensive HTTP Security Headers** (`https://lab.graysentinel.internal/`): Enforce centralized baseline header configurations in CI/CD container templates and conduct automated weekly header regression checks.

## 10. Limitations

- **Non-Destructive Constraint:** Testing was conducted non-destructively; no exploits were executed to achieve remote code execution.
- **Time-Bounded Scope:** Findings reflect the security posture at the exact moment of reconnaissance ingestion.
- **Data Classification Transparency:** Sample datasets are explicitly demarcated to prevent mistaking simulation for live operational assessments.
- **No Third-Party Targets:** In strict adherence to GraySentinel policy, only explicitly authorized lab environments or sanitized fixtures were evaluated.

## 11. Conclusion

The evaluation against `lab.graysentinel.internal` yielded high-fidelity, reproducible findings. By executing the prioritized 3-phase remediation plan—specifically resolving public configuration artifacts and deploying defensive HTTP headers—the target environment's risk rating will decrease from **CRITICAL RISK** to **LOW RISK**.

---
*Report generated by GraySentinel Project 02: Web Security Findings Reporter.*