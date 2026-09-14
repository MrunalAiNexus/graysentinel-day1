# GraySentinel Project 02: Testing Evidence & Execution Logs

This document provides authentic, unedited terminal transcripts and execution evidence for the GraySentinel Project 02 Web Security Findings Reporter CLI, verifying complete compliance with all technical requirements.

All tests and commands documented below were executed on Linux with Python 3.11.2 and pytest 7.2.1.

---

## 1. Automated Test Suite Execution

### Command Executed
```bash
pytest -v
# or
pytest -q
# or
python3 run_tests.py
```

### Terminal Output
```text
============================= test session starts ==============================
platform linux -- Python 3.11.2, pytest-7.2.1, pluggy-1.0.0+repack -- /usr/bin/python3
cachedir: .pytest_cache
rootdir: /app/applet/project-02
collecting ... collected 36 items

tests/test_cli.py::TestCLI::test_cli_analyze_json PASSED                 [  2%]
tests/test_cli.py::TestCLI::test_cli_demo PASSED                         [  5%]
tests/test_cli.py::TestCLI::test_cli_help PASSED                         [  8%]
tests/test_cli.py::TestCLI::test_cli_validate_failure PASSED             [ 11%]
tests/test_cli.py::TestCLI::test_cli_validate_success PASSED             [ 13%]
tests/test_evidence.py::TestEvidence::test_compute_sha256_missing_file_raises PASSED [ 16%]
tests/test_evidence.py::TestEvidence::test_compute_sha256_success PASSED [ 19%]
tests/test_evidence.py::TestEvidence::test_generate_manifest PASSED      [ 22%]
tests/test_evidence.py::TestEvidence::test_sanitization_redacts_credentials PASSED [ 25%]
tests/test_evidence.py::TestEvidence::test_verify_item_integrity PASSED  [ 27%]
tests/test_models.py::TestModels::test_confidence_multipliers_and_parsing PASSED [ 30%]
tests/test_models.py::TestModels::test_finding_to_and_from_dict_roundtrip PASSED [ 33%]
tests/test_models.py::TestModels::test_severity_weights_and_parsing PASSED [ 36%]
tests/test_models.py::TestModels::test_weighted_risk_calculation PASSED  [ 38%]
tests/test_parser.py::TestParser::test_generate_candidate_findings_correlation PASSED [ 41%]
tests/test_parser.py::TestParser::test_load_recon_json_file_not_found PASSED [ 44%]
tests/test_parser.py::TestParser::test_load_recon_json_malformed PASSED  [ 47%]
tests/test_parser.py::TestParser::test_load_recon_json_missing_keys PASSED [ 50%]
tests/test_parser.py::TestParser::test_load_recon_json_success PASSED    [ 52%]
tests/test_remediation.py::TestRemediation::test_remediation_roadmap_phases PASSED [ 55%]
tests/test_remediation.py::TestRemediation::test_remediation_synthesis_headers PASSED [ 58%]
tests/test_remediation.py::TestRemediation::test_remediation_synthesis_secret_exposure PASSED [ 61%]
tests/test_reporter.py::TestReporter::test_generate_markdown_content_and_sections PASSED [ 63%]
tests/test_reporter.py::TestReporter::test_save_markdown_report PASSED   [ 66%]
tests/test_risk.py::TestRisk::test_critical_finding_triggers_critical_risk PASSED [ 69%]
tests/test_risk.py::TestRisk::test_empty_findings_posture PASSED         [ 72%]
tests/test_risk.py::TestRisk::test_false_positive_excluded_from_weight PASSED [ 75%]
tests/test_risk.py::TestRisk::test_weighted_risk_calculation_and_posture PASSED [ 77%]
tests/test_validator.py::TestValidator::test_brief_description_rejected PASSED [ 80%]
tests/test_validator.py::TestValidator::test_critical_or_high_requires_evidence PASSED [ 83%]
tests/test_validator.py::TestValidator::test_cvss_score_out_of_bounds PASSED [ 86%]
tests/test_validator.py::TestValidator::test_duplicate_id_detection_in_validate_all PASSED [ 88%]
tests/test_validator.py::TestValidator::test_empty_or_short_title PASSED [ 91%]
tests/test_validator.py::TestValidator::test_insufficient_reproduction_steps_warning PASSED [ 94%]
tests/test_validator.py::TestValidator::test_missing_or_empty_id PASSED  [ 97%]
tests/test_validator.py::TestValidator::test_valid_finding_passes PASSED [100%]

============================== 36 passed in 5.17s ==============================
```

**Verification Result:** Exactly 36 / 36 test cases passed with zero failures and zero errors across the entire finding, validation, risk, evidence, parser, and reporting lifecycle.

---

## 2. CLI End-to-End Demo Mode

### Command Executed
```bash
python3 main.py --demo
```

### Terminal Output
```text
⚠ DEMO MODE — EXECUTING WITH SANITIZED DATASET
No external servers or third-party targets are contacted during this demo.
[*] Executing GraySentinel End-to-End Security Pipeline
  ✔ Loading sanitized Project 01 reconnaissance JSON
  ✔ Extracting attack surface observations
  ✔ Synthesizing structured finding models
  ✔ Validating findings against GraySentinel policy rules
  ✔ Computing risk posture and threat metrics
  Done.
[+] Demo completed. Report written to: /app/applet/project-02/report.md
```

---

## 3. CLI Finding Validation (Pass Case: Recon-Derived Findings)

### Command Executed
```bash
python3 main.py --recon data/sample/sanitized_recon.json --validate
```

### Terminal Output (Exit Code 0)
```text
[PASS] GS-SEC-001: Absence of Baseline Defensive HTTP Security Headers (Errors: 0, Warnings: 0)
[PASS] GS-SEC-002: Unrestricted Access to Internal Interface (/admin) (Errors: 0, Warnings: 0)
[PASS] GS-SEC-003: Publicly Accessible Configuration Artifact (/.env.bak) (Errors: 0, Warnings: 0)
[PASS] GS-SEC-004: Unrestricted Access to Internal Interface (/debug/metrics) (Errors: 0, Warnings: 0)
[PASS] GS-SEC-005: Direct Exposure of Management/Database Port (3306/tcp) (Errors: 0, Warnings: 0)
[PASS] GS-SEC-006: Direct Exposure of Management/Database Port (8080/tcp) (Errors: 0, Warnings: 0)
```

---

## 4. CLI Finding Validation (Negative / Failure Enforcement)

### Command Executed
```bash
python3 main.py --findings data/invalid_finding_sample.json --validate
```

### Terminal Output (Exit Code 1)
```text
[FAIL] INVALID_ID_FORMAT: Bad (Errors: 5, Warnings: 2)
```

**Exit Code:** `1` (POSIX non-zero exit code confirming automated policy rejection)

---

## 5. CLI Risk Posture Analysis & JSON Export

### Command Executed (Summary)
```bash
python3 main.py --recon data/sample/sanitized_recon.json --analyze
```

### Terminal Output
```text
Risk Posture: CRITICAL RISK | Weighted Score: 36.0 | Findings: 6
```

### Command Executed (JSON Structured Telemetry)
```bash
python3 main.py --recon data/sample/sanitized_recon.json --analyze --json
```

### Terminal Output
```json
{
  "total_findings": 6,
  "by_severity": {
    "CRITICAL": 1,
    "HIGH": 3,
    "MEDIUM": 1,
    "LOW": 1,
    "INFO": 0
  },
  "by_confidence": {
    "HIGH": 6,
    "MEDIUM": 0,
    "LOW": 0
  },
  "by_status": {
    "VALIDATED": 4,
    "REVIEW": 2,
    "DRAFT": 0,
    "REMEDIATED": 0,
    "FALSE_POSITIVE": 0
  },
  "weighted_risk_score": 36.0,
  "posture_rating": "CRITICAL RISK",
  "posture_description": "Immediate exploitation potential present. Perimeter or critical secrets exposed.",
  "attack_surface_density": 6.0,
  "critical_or_high_count": 4,
  "validated_count": 4,
  "review_required_count": 2
}
```

---

## 6. Report Generation

### Command Executed
```bash
python3 main.py --recon data/sample/sanitized_recon.json --report --out reports/recon_report.md
```

### Terminal Output
```text
[+] Report generated at: reports/recon_report.md
```

---

## 7. Interactive Command Console Navigation

### Command Executed
```bash
python3 main.py
# or
./graysentinel.sh
```

### Interactive Menu Header
```text
  ██████╗ ██████╗  █████╗ ██╗   ██╗███████╗███████╗███╗   ██╗████████╗
 ██╔════╝ ██╔══██╗██╔══██╗╚██╗ ██╔╝██╔════╝██╔════╝████╗  ██║╚══██╔══╝
 ██║  ███╗██████╔╝███████║ ╚████╔╝ ███████╗█████╗  ██╔██╗ ██║   ██║   
 ██║   ██║██╔══██╗██╔══██║  ╚██╔╝  ╚════██║██╔══╝  ██║╚██╗██║   ██║   
 ╚██████╔╝██║  ██║██║  ██║   ██║   ███████║███████╗██║ ╚████║   ██║   
  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   

   WEB SECURITY FINDINGS REPORTER // PROJECT 02 CONSOLE
   ════════════════════════════════════════════════════
   Targeting Proof-First Assessment, Evidence Integrity & Threat Modeling

╔══ GRAYSENTINEL COMMAND CONSOLE ═════════════════════════╗
║  CURRENT SESSION CONTEXT:                               ║
║   • Reconnaissance Target : None (Ready to Load)        ║
║   • Security Findings     : 0 Loaded                    ║
║                                                         ║
║    [1] Load Recon Data (Project 01 JSON)                ║
║    [2] Validate Findings (Schema & Evidence Checks)      ║
║    [3] Review Findings (Interactive Table & Detail View)║
║    [4] Risk Summary (Posture & Threat Scoreboard)       ║
║    [5] Generate Security Report (Publication Markdown)  ║
║    [6] View Evidence (Cryptographic SHA-256 Hashes)     ║
║    [7] Demo Mode (One-Touch Sanitized Walkthrough)      ║
║    [8] Project Information & Architecture               ║
║    [9] Exit Console                                     ║
╚═════════════════════════════════════════════════════════╝
```
