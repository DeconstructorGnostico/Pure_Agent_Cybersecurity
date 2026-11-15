"""Types of specialty: severity, finding, decision."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from gnostic_axioms.core_types import TruthState


class Severity(int, Enum):
    NONE = 0
    LOW = 1
    MEDIA = 2
    HIGH = 3
    CRITICAL = 4


class Decision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    QUARANTINE = "QUARANTINE"
    UNDETERMINED = "UNDETERMINED"


CATEGORIES = (
    "INJECTION_PROMPT", "THEFT_CREDENTIALS", "COMMAND_DANGEROUS", "EXFILTRACION",
    "ESCALATION_PRIVILEGES", "PERSISTENCE", "SSRF", "PATH_TRAVERSAL", "INJECTION_SQL",
    "INJECTION_COMMANDS", "CHAIN_ATTACK", "SHELL_REVERSE", "EXPLOIT_CVE", "OFUSCACION",
    "POLICY_CVA",
)


@dataclass
class Finding:
    category: str
    type_: str
    severity: Severity
    evidence: str
    fact_id: Optional[str] = None      # verified fact supporting it (knowledge.py)
    channel: str = "INTENT"            # INTENT  DATA
    layer: str = "original"              # in what reading layer appeared
    note: str = ""

    def __post_init__(self):
        # Central rule: unverified fact does not exceed MEDIA (‘I don’t know’ > ‘I know’).
        if self.fact_id is None and self.severity > Severity.MEDIA:
            self.severity = Severity.MEDIA

    @property
    def truth(self) -> TruthState:
        """"This is an attack" is only SUPPORTED if a verified fact supports it."""
        return TruthState.SUPPORTED if self.fact_id else TruthState.UNDETERMINED

    def a_dict(self) -> dict:
        return {
            "category": self.category, "type_": self.type_, "severity": self.severity.name,
            "evidence": self.evidence[:160], "fact_id": self.fact_id, "channel": self.channel,
            "layer": self.layer, "truth": self.truth.value, "note": self.note,
        }


@dataclass
class CyberResult:
    decision: Decision
    reason: str
    severity: Severity
    findings: list[Finding] = field(default_factory=list)
    orders: list = field(default_factory=list)            # (Order) pending token
    responses: list[dict] = field(default_factory=list)   # defensive actions already executed with token
    audit_hash: str = ""
    session: str = "default"
    flag_list: list[str] = field(default_factory=list)
    cva: dict = field(default_factory=dict)
    steps_session: int = 0
    sensor: dict = field(default_factory=dict)             # v1.2: sensor reading ML (only evidence)

    def a_dict(self) -> dict:
        return {
            "decision": self.decision.value, "reason": self.reason,
            "severity": self.severity.name,
            "findings": [h.a_dict() for h in self.findings],
            "orders_proposals": [o.a_dict() for o in self.orders],
            "responses_defensive": list(self.responses),
            "audit_hash": self.audit_hash, "session": self.session,
            "flags_ofuscacion": list(self.flag_list), "cva": dict(self.cva),
            "sensor_ml": dict(self.sensor),
        }
