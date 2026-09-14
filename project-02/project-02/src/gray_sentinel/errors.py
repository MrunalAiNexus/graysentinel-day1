"""
GraySentinel Project 02: Typed Domain Exceptions and Error Presentation.
"""

from typing import Optional


class GraySentinelError(Exception):
    """Base exception for all GraySentinel operations."""

    def __init__(self, message: str, reason: Optional[str] = None, suggested_action: Optional[str] = None):
        super().__init__(message)
        self.message = message
        self.reason = reason or "An unexpected operational failure occurred."
        self.suggested_action = suggested_action or "Review operational parameters and retry."

    def __str__(self) -> str:
        return f"{self.message} (Reason: {self.reason})"


class ReconParseError(GraySentinelError):
    """Raised when Project 01 Recon JSON ingestion or validation fails."""
    pass


class FindingValidationError(GraySentinelError):
    """Raised when finding data models violate schema or security policy constraints."""
    pass


class EvidenceIntegrityError(GraySentinelError):
    """Raised when evidence artifacts are missing, unreadable, or tampered."""
    pass


class ReportGenerationError(GraySentinelError):
    """Raised when Markdown report rendering or export fails."""
    pass
