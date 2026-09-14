"""
GraySentinel Project 02: Typed Data Models for Security Findings, Evidence, and Recon.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        val = value.strip().upper()
        if val in cls.__members__:
            return cls[val]
        if val in ("INFORMATIONAL", "NOTE"):
            return cls.INFO
        raise ValueError(f"Invalid severity level '{value}'. Must be one of: {list(cls.__members__.keys())}")

    @property
    def weight(self) -> float:
        """Numeric severity weight for risk scoring calculations."""
        weights = {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 7.0,
            Severity.MEDIUM: 4.0,
            Severity.LOW: 1.0,
            Severity.INFO: 0.0,
        }
        return weights.get(self, 0.0)


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @classmethod
    def from_str(cls, value: str) -> "Confidence":
        val = value.strip().upper()
        if val in cls.__members__:
            return cls[val]
        if val in ("CONFIRMED", "CERTAIN"):
            return cls.HIGH
        if val in ("TENTATIVE", "SUSPECTED"):
            return cls.LOW
        raise ValueError(f"Invalid confidence level '{value}'. Must be one of: {list(cls.__members__.keys())}")

    @property
    def multiplier(self) -> float:
        """Confidence multiplier applied to weighted risk calculations."""
        multipliers = {
            Confidence.HIGH: 1.0,
            Confidence.MEDIUM: 0.7,
            Confidence.LOW: 0.4,
        }
        return multipliers.get(self, 1.0)


class ValidationStatus(str, Enum):
    VALIDATED = "VALIDATED"
    REVIEW = "REVIEW"
    DRAFT = "DRAFT"
    REMEDIATED = "REMEDIATED"
    FALSE_POSITIVE = "FALSE_POSITIVE"

    @classmethod
    def from_str(cls, value: str) -> "ValidationStatus":
        val = value.strip().upper()
        if val in cls.__members__:
            return cls[val]
        return cls.REVIEW


@dataclass
class EvidenceItem:
    """Represents a cryptographic or observational proof-of-concept artifact."""
    id: str
    source: str
    observation: str
    relevant_data: str = ""
    timestamp: Optional[str] = None
    artifact_path: Optional[str] = None
    sha256_hash: Optional[str] = None
    is_demo_sample: bool = True
    verified: bool = False
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EvidenceItem":
        return cls(
            id=data.get("id", "EVD-000"),
            source=data.get("source", "Manual Observation"),
            observation=data.get("observation", ""),
            relevant_data=data.get("relevant_data", ""),
            timestamp=data.get("timestamp"),
            artifact_path=data.get("artifact_path"),
            sha256_hash=data.get("sha256_hash"),
            is_demo_sample=data.get("is_demo_sample", True),
            verified=data.get("verified", False),
            notes=data.get("notes", ""),
        )


@dataclass
class Remediation:
    """Remediation guidance separating immediate tactical fixes from strategic architectural controls."""
    tactical: str
    strategic: str
    code_example: Optional[str] = None
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Remediation":
        return cls(
            tactical=data.get("tactical", ""),
            strategic=data.get("strategic", ""),
            code_example=data.get("code_example"),
            references=data.get("references", []),
        )


@dataclass
class Finding:
    """Structured security finding data model representing an assessed risk."""
    id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    affected_asset: str
    source: str = "PROJECT_01_RECON"
    validation_status: ValidationStatus = ValidationStatus.DRAFT
    cwe_id: Optional[str] = None
    cwe_name: Optional[str] = None
    owasp_category: Optional[str] = None
    cvss_score: float = 0.0
    cvss_vector: Optional[str] = None
    reproduction_steps: List[str] = field(default_factory=list)
    evidence: List[EvidenceItem] = field(default_factory=list)
    remediation: Optional[Remediation] = None
    references: List[str] = field(default_factory=list)
    created_at: Optional[str] = None
    tags: List[str] = field(default_factory=list)

    @property
    def weighted_risk(self) -> float:
        """Calculates effective weighted risk points based on severity and confidence."""
        if self.validation_status == ValidationStatus.FALSE_POSITIVE:
            return 0.0
        return round(self.severity.weight * self.confidence.multiplier, 2)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "affected_asset": self.affected_asset,
            "source": self.source,
            "validation_status": self.validation_status.value,
            "cwe_id": self.cwe_id,
            "cwe_name": self.cwe_name,
            "owasp_category": self.owasp_category,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "weighted_risk": self.weighted_risk,
            "reproduction_steps": self.reproduction_steps,
            "evidence": [e.to_dict() for e in self.evidence],
            "remediation": self.remediation.to_dict() if self.remediation else None,
            "references": self.references,
            "created_at": self.created_at,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        sev = Severity.from_str(data["severity"]) if isinstance(data.get("severity"), str) else Severity.INFO
        conf = Confidence.from_str(data["confidence"]) if isinstance(data.get("confidence"), str) else Confidence.MEDIUM
        status = ValidationStatus.from_str(data["validation_status"]) if "validation_status" in data else ValidationStatus.DRAFT

        evidence_items = [
            EvidenceItem.from_dict(item) if isinstance(item, dict) else item
            for item in data.get("evidence", [])
        ]

        rem = None
        if data.get("remediation"):
            if isinstance(data["remediation"], dict):
                rem = Remediation.from_dict(data["remediation"])
            elif isinstance(data["remediation"], Remediation):
                rem = data["remediation"]

        return cls(
            id=data["id"],
            title=data["title"],
            description=data["description"],
            severity=sev,
            confidence=conf,
            affected_asset=data.get("affected_asset", ""),
            source=data.get("source", "PROJECT_01_RECON"),
            validation_status=status,
            cwe_id=data.get("cwe_id"),
            cwe_name=data.get("cwe_name"),
            owasp_category=data.get("owasp_category"),
            cvss_score=float(data.get("cvss_score", 0.0)),
            cvss_vector=data.get("cvss_vector"),
            reproduction_steps=data.get("reproduction_steps", []),
            evidence=evidence_items,
            remediation=rem,
            references=data.get("references", []),
            created_at=data.get("created_at"),
            tags=data.get("tags", []),
        )


@dataclass
class ReconService:
    port: int
    protocol: str
    service: str
    state: str = "open"
    banner: str = ""


@dataclass
class ReconEndpoint:
    path: str
    status_code: int
    method: str = "GET"
    content_type: str = "text/html"
    response_size: int = 0
    title: str = ""
    parameters: List[str] = field(default_factory=list)


@dataclass
class ReconData:
    """Data ingested from Project 01 Web Reconnaissance scan output."""
    target: str
    scan_id: str
    timestamp: str
    scan_type: str = "Authorized Web Reconnaissance"
    is_demo: bool = True
    open_ports: List[ReconService] = field(default_factory=list)
    endpoints: List[ReconEndpoint] = field(default_factory=list)
    missing_security_headers: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
