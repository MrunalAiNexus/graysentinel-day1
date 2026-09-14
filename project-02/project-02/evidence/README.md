# GraySentinel Evidence Management & Cryptographic Chain-of-Custody

This directory stores raw and sanitized evidence artifacts referenced in security assessment findings.

## Evidence Handling Guidelines

1. **Proof-First Standard**: Every Critical, High, and Medium finding must reference at least one verifiable proof artifact.
2. **Cryptographic Integrity**: All evidence artifacts are tracked by their SHA-256 digest. Any modification or tampering causes immediate validation failure.
3. **Strict Data Sanitization**:
   - Live production passwords, customer PII, session cookies, and API secrets **MUST** be sanitized before inclusion.
   - Use standard redaction tokens: `[REDACTED_PASSWORD]`, `[REDACTED_SESSION_COOKIE]`, `[REDACTED_KEY]`.
4. **Distinction from Real Production Scans**:
   - Artifacts in `evidence/samples/` represent sanitized captures from authorized GraySentinel training labs (`lab.graysentinel.internal`).
   - They are provided for verification, automated testing, and mentor assessment.

## Manifest Verification
To verify evidence integrity:
```bash
python3 main.py evidence-verify --evidence-dir evidence/samples
```
