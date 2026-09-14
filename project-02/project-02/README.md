# GraySentinel Project 02: Web Security Findings Reporter

A terminal-native, standalone Python CLI application and interactive security console engineered for vulnerability finding validation, Project 01 reconnaissance data integration, cryptographic evidence verification, risk posture calculation, and automated Markdown security report generation.

Built according to the **GraySentinel Day 1 Proof-First Requirement**:
> *Problem → Objective → Scenario → Approach → Implementation → Testing → Evidence → Result → Security Relevance → Limitations → Learning → Future Improvement*

---

## Key Highlights

- **Fluid, Interactive Terminal UI:** Complete with GraySentinel ASCII banners, live progress spinners, structured findings tables, risk distribution charts, and interactive keyboard navigation without heavy external dependencies.
- **Zero Runtime External Dependencies:** Built 100% on the Python Standard Library (Python 3.10+). No pip packages required to run, validate, verify, or report.
- **Universal Testing Support:** Supports both `pytest` and Python's standard `unittest` framework with 36 automated unit and integration tests (100% passing).
- **Cryptographic Evidence Sealing:** Every finding's proof artifact is hashed with SHA-256 and verified for tamper resistance with credential sanitization.
- **Project 01 Recon JSON Ingestion:** Directly ingests attack surface reconnaissance data from Project 01, correlates exposed services/endpoints, and auto-generates candidate findings.
- **Rigorous Validation Engine:** Enforces finding schema structure, CVSS score boundaries, reproduction step depth, required evidence for high-severity issues, and dual-track remediation.
- **Weighted Risk Posture Scoring:** Calculates posture scores dynamically based on severity weights and confidence multipliers, classifying overall posture into actionable risk bands.
- **Automated Report Generation:** Generates comprehensive 11-section Markdown reports (`report.md`) featuring executive summaries, attack surface matrices, reproduction steps, evidence hashes, and a 3-phase prioritized remediation roadmap.

---

## Project Structure

```text
project-02/
├── main.py                       # Main CLI executable entry point
├── run_tests.py                  # Universal test runner (pytest / unittest)
├── pyproject.toml / setup.py     # Python standard packaging specifications
├── requirements.txt              # Dependency documentation (zero external runtime dependencies)
├── README.md                     # Comprehensive operator and architecture guide
├── PROOF_OF_WORK.md              # Complete 12-section Day 1 proof-first document
├── PROOF_MATRIX.md               # Matrix connecting requirements to code and test evidence
├── TESTING_EVIDENCE.md           # Real terminal transcripts and test execution logs
├── report.md                     # 11-section Markdown security assessment report
├── src/
│   └── gray_sentinel/            # Core application package
│       ├── __init__.py           # Package exports and version metadata
│       ├── cli.py                # Fluid interactive console & headless CLI
│       ├── ui.py                 # ANSI terminal design engine (spinners, tables, panels)
│       ├── models.py             # Dataclasses: Finding, EvidenceItem, Remediation, ReconData
│       ├── validator.py          # Schema, CVSS, and policy rule validation engine
│       ├── evidence.py           # SHA-256 evidence integrity & secret sanitization
│       ├── parser.py             # Project 01 JSON ingestion & candidate correlation
│       ├── risk.py               # Weighted risk scoring & posture evaluation
│       ├── remediation.py        # Phased remediation roadmap generator
│       ├── reporter.py           # 11-section Markdown assessment generator
│       └── errors.py             # Domain-specific typed exceptions
├── data/                         # Sample datasets
│   ├── sample/
│   │   └── sanitized_recon.json  # Sanitized Project 01 attack surface reconnaissance data
│   └── invalid_finding_sample.json # Deliberately malformed findings for negative testing
├── evidence/                     # Proof artifacts
│   ├── screenshots/              # Screenshot checklist guide for live evaluation
│   ├── terminal/                 # Real captured terminal session transcripts
│   └── samples/                  # Sanitized lab HTTP captures and header dumps
└── tests/                        # Automated test suite (36 tests)
    ├── test_cli.py
    ├── test_evidence.py
    ├── test_models.py
    ├── test_parser.py
    ├── test_remediation.py
    ├── test_reporter.py
    ├── test_risk.py
    └── test_validator.py
```

---

## Quickstart & Installation

### Requirements
- Python 3.10 or higher
- Standard terminal emulator (Linux / macOS / WSL)

```bash
# Verify Python version
python3 --version  # Must be 3.10+
```

### Launching the Interactive Console

Run the interactive GraySentinel command console:

```bash
cd project-02
python3 main.py
# or
./graysentinel.sh
# or via module:
python3 -m gray_sentinel.cli
```

---

## CLI Usage & Automation Modes

In addition to the interactive console, GraySentinel supports headless automated modes for scripting, CI/CD, and fast evaluation:

### 1. Run Complete End-to-End Demo
Executes the full pipeline: loading sanitized Project 01 recon data, extracting attack surface, generating findings, validating policy rules, calculating risk posture, and emitting `report.md`:
```bash
python3 main.py --demo
```

### 2. Finding Validation
Validates finding JSON against strict schema, CVSS ranges, text depth, reproduction step count, and evidence existence:
```bash
# Validate loaded demo findings
python3 main.py --validate

# Validate findings derived directly from Project 01 recon data
python3 main.py --recon data/sample/sanitized_recon.json --validate

# Test negative validation against deliberately invalid findings (exits with code 1)
python3 main.py --findings data/invalid_finding_sample.json --validate
```

### 3. Risk Posture Analysis
Calculates the overall security posture rating, weighted risk points, severity breakdown, and attack surface density:
```bash
# Terminal summary
python3 main.py --analyze

# Machine-readable JSON output
python3 main.py --analyze --json

# Analyze directly from Project 01 recon input
python3 main.py --recon data/sample/sanitized_recon.json --analyze --json
```

### 4. Custom Report Output
Compiles all findings, recon data, and evidence hashes into a custom report path:
```bash
python3 main.py --report --out reports/custom_assessment.md
```

---

## Running Automated Tests

Run the automated test suite using either `pytest` or `run_tests.py`:

```bash
# Option A: Standard pytest (Recommended)
pytest -v
# or compact
pytest -q

# Option B: Universal test runner (auto-selects pytest if available, else unittest)
python3 run_tests.py

# Option C: Standard unittest discovery
python3 -m unittest discover -s tests -v
```

Expected output:
```text
============================== 36 passed in 5.17s ==============================
```

---

## Mentor Review / Evaluation Walkthrough

Follow this 5-step sequence during mentor evaluation or submission demos:

1. **Step 1: Test Suite Verification**
   ```bash
   pytest -q
   ```
   *Confirms 36 unit and integration tests passing across all components (0 failed).*

2. **Step 2: Negative Validation Test**
   ```bash
   python3 main.py --findings data/invalid_finding_sample.json --validate
   ```
   *Demonstrates the validator rejecting incomplete findings, missing fields, out-of-range CVSS, and missing evidence (exits with code 1).*

3. **Step 3: End-to-End Demonstration**
   ```bash
   python3 main.py --demo
   ```
   *Executes the complete GraySentinel workflow with terminal spinners and generates `report.md`.*

4. **Step 4: Interactive Console Exploration**
   ```bash
   python3 main.py
   ```
   *Navigate the menu options: view the findings table, inspect finding details, and view risk posture scoreboard.*

5. **Step 5: Inspect Evidence & Verification Proof**
   - Review `PROOF_MATRIX.md` for requirement-to-evidence mappings.
   - Review `TESTING_EVIDENCE.md` for complete unedited terminal execution transcripts.
   - Review `evidence/screenshots/SCREENSHOT_CHECKLIST.md` for the screenshot checklist.
   - Review `evidence/terminal/` for captured raw terminal session transcripts.

---

## Ethical Disclosure & Scope Notice

This tool and sample data are strictly designed for **authorized security audits, academic review, and security laboratory exercises** on explicitly approved infrastructure (`lab.graysentinel.internal`). All credentials, tokens, and personally identifiable information in sample files are synthetic or sanitized according to AppSec best practices.

