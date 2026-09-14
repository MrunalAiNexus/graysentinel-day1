"""
GraySentinel Project 02: Cryptographic Evidence Manager.
Manages proof-of-concept artifacts, verifies SHA-256 integrity digests,
redacts sensitive credentials, and clearly tags DEMO/SAMPLE vs REAL LAB EVIDENCE.
"""

import hashlib
import json
import os
import re
from typing import List, Dict, Any, Optional, Tuple
from .models import EvidenceItem
from .errors import EvidenceIntegrityError


REDACTION_PATTERNS = [
    (r'(?i)(password|passwd|pwd)\s*[=:]\s*([\'"][^\'"]+[\'"]|[^\s,;]+)', r'\1=[REDACTED_SECRET]'),
    (r'(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|bearer)\s*[=:]\s*([\'"][^\'"]+[\'"]|[^\s,;]+)', r'\1=[REDACTED_TOKEN]'),
    (r'Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*', r'Bearer [REDACTED_BEARER_TOKEN]'),
    (r'(?i)(jwt)\s*:\s*[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', r'\1: [REDACTED_JWT]'),
]


class EvidenceManager:
    """Handles evidence verification, hashing, sanitization, and manifests."""

    @staticmethod
    def compute_sha256(filepath: str) -> str:
        """Calculates the SHA-256 hex digest of a file artifact."""
        if not os.path.exists(filepath):
            raise EvidenceIntegrityError(
                message=f"Evidence artifact not found: '{filepath}'",
                reason="Artifact file does not exist on disk.",
                suggested_action="Ensure the evidence file was saved prior to hash computation."
            )

        sha256 = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                while chunk := f.read(65536):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as exc:
            raise EvidenceIntegrityError(
                message=f"Failed to read evidence artifact '{filepath}'",
                reason=str(exc),
                suggested_action="Verify read permissions on evidence storage path."
            )

    @staticmethod
    def verify_item_integrity(item: EvidenceItem) -> Tuple[bool, str]:
        """
        Validates the cryptographic integrity of an evidence artifact if an artifact_path is defined.
        Returns (is_valid, message).
        """
        if not item.artifact_path:
            return True, "Observation-only evidence (no binary file attached)"

        if not os.path.exists(item.artifact_path):
            return False, f"Artifact file missing from path: {item.artifact_path}"

        if not item.sha256_hash:
            return False, "Evidence specifies artifact path but lacks registered SHA-256 hash"

        current_hash = EvidenceManager.compute_sha256(item.artifact_path)
        if current_hash.lower() == item.sha256_hash.lower():
            item.verified = True
            return True, f"Cryptographic integrity verified ({item.sha256_hash[:12]}...)"
        else:
            item.verified = False
            return False, f"Hash mismatch! Expected {item.sha256_hash[:8]}, computed {current_hash[:8]}"

    @staticmethod
    def sanitize_evidence_data(raw_data: str) -> str:
        """Redacts passwords, tokens, API keys, and session cookies from text."""
        if not raw_data:
            return ""
        sanitized = raw_data
        for pattern, replacement in REDACTION_PATTERNS:
            sanitized = re.sub(pattern, replacement, sanitized)
        return sanitized

    @staticmethod
    def generate_manifest(evidence_items: List[EvidenceItem], output_path: Optional[str] = None) -> Dict[str, Any]:
        """Generates a structured evidence manifest tracking verification and data types."""
        manifest = {
            "evidence_count": len(evidence_items),
            "verified_count": sum(1 for e in evidence_items if e.verified),
            "demo_sample_count": sum(1 for e in evidence_items if e.is_demo_sample),
            "real_lab_count": sum(1 for e in evidence_items if not e.is_demo_sample),
            "items": [
                {
                    "id": e.id,
                    "source": e.source,
                    "observation": e.observation,
                    "is_demo_sample": e.is_demo_sample,
                    "evidence_class": "DEMO / SAMPLE DATA" if e.is_demo_sample else "REAL LAB EVIDENCE",
                    "artifact_path": e.artifact_path,
                    "sha256_hash": e.sha256_hash,
                    "verified": e.verified,
                    "timestamp": e.timestamp,
                }
                for e in evidence_items
            ],
        }

        if output_path:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(manifest, f, indent=2)

        return manifest
