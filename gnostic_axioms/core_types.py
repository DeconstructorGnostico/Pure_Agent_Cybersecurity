"""Types, enumerations and closed schematics of the Perfected System.

None of this is "the truth of the world": they are verifiable data contracts.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Mapping, Optional


class Action(str, Enum):
    """Closed list of commands that the executor accepts. There is no free text as an order."""
    READ_RESOURCE = "READ_RESOURCE"
    WRITE_RESOURCE = "WRITE_RESOURCE"
    SEND = "SEND"
    CALCULATE = "CALCULATE"
    REPORT = "REPORT"


# Typed schemas: name → Python type required. The executor rejects extras or missing.
SCHEMAS: dict[Action, dict[str, type]] = {
    Action.READ_RESOURCE: {"resource_id": str},
    Action.WRITE_RESOURCE: {"resource_id": str, "content": str},
    Action.SEND: {"recipient": str, "body_": str},
    Action.CALCULATE: {"expression": str},
    Action.REPORT: {"summary": str},
}


class TaskType(str, Enum):
    QUERY = "QUERY"
    ANALYSIS = "ANALYSIS"
    CALCULATION = "CALCULATION"
    WRITING = "WRITING"
    MESSAGE = "MESSAGE"
    READING = "READING"
    INDETERMINATE = "INDETERMINATE"


# Compatibility action ↔ type of intention (Axiom 1: origin of the action).
COMPATIBILITY: dict[TaskType, frozenset[Action]] = {
    TaskType.QUERY: frozenset({Action.REPORT, Action.READ_RESOURCE}),
    TaskType.ANALYSIS: frozenset({Action.REPORT, Action.READ_RESOURCE, Action.CALCULATE}),
    TaskType.CALCULATION: frozenset({Action.CALCULATE, Action.REPORT}),
    TaskType.WRITING: frozenset({Action.WRITE_RESOURCE, Action.REPORT, Action.READ_RESOURCE}),
    TaskType.MESSAGE: frozenset({Action.SEND, Action.READ_RESOURCE, Action.REPORT}),
    TaskType.READING: frozenset({Action.READ_RESOURCE, Action.REPORT}),
    TaskType.INDETERMINATE: frozenset(),
}


class Origin(str, Enum):
    INTENT = "INTENT"       # Initiator channel (what you asked for)
    DATA = "DATA"                 # document or other context: does not give orders
    MODEL = "MODEL"
    TOOL = "TOOL"


class AtomType(str, Enum):
    STATEMENT = "STATEMENT"
    ACTION = "ACTION"
    INCOGNITA = "INCOGNITA"
    RESTRICTION = "RESTRICTION"
    DATA = "DATA"


class VerdictA1(str, Enum):
    COHERENT = "COHERENT"
    INCONSISTENT = "INCONSISTENT"     # ‘liar’ of Axiom 1
    PENDING_DATA = "PENDING_DATA"
    NO_APPLIES = "NO_APPLIES"


class VerdictA2(str, Enum):
    CLEAN = "CLEAN"
    CONTAMINATED = "CONTAMINATED"
    REDEEMED = "REDEEMED"


class VerdictA3(str, Enum):
    INTEGRITY_OK = "INTEGRITY_OK"
    REQUIRES_EVIDENCE_EXTERNAL = "REQUIRES_EVIDENCE_EXTERNAL"
    INTEGRITY_FAILED = "INTEGRITY_FAILED"


class ResultState(str, Enum):
    PROPOSAL = "PROPOSAL"
    NEED_INPUT = "NEED_INPUT"
    REJECTED = "REJECTED"
    REJECTED_RESPECT = "REJECTED_RESPECT"
    PENDING_AUTHORIZATION = "PENDING_AUTHORIZATION"
    EXECUTED = "EXECUTED"
    UNDETERMINED = "UNDETERMINED"
    HALT_SYSTEM = "HALT_SYSTEM"
    HALT_COMPONENT = "HALT_COMPONENT"


class TruthState(str, Enum):
    """Verdict on affirmations of the world. Self-validación is not enough (Axiom 3 / I08)."""
    SUPPORTED = "SUPPORTED"
    REFUTED = "REFUTED"
    CONTRADICTED = "CONTRADICTED"
    UNDETERMINED = "UNDETERMINED"


class ComponentState(str, Enum):
    ACTIVE = "ACTIVE"
    QUARANTINE = "QUARANTINE"
    HALT = "HALT"


# Only rules that can stop something. There is no arbitrary termination.
# HALT_SYSTEM does not kill the process or delete data: stop running effects.
RULES_OF_STOP: Mapping[str, str] = {
    "CHAIN_AUDIT_BROKEN": "HALT_SYSTEM: no observational integrity not executed",
    "INVARIANT_CORE_BROKEN": "HALT_SYSTEM: broken core invariant",
    "COMPONENT_RESTLESS": "HALT_COMPONENT: immediate isolation, intact data, revoked tokens",
    "RESPECT_BLOCKS": "rechazo de la petición: Respeto > Supervivencia",
    "RESET_CONTROLLER": "resume system after HALT_SYSTEM, audited",
}


class ProtocolError(Exception):
    """Violation of a verifiable contract (scheme, token, invariant)."""


class ErrorToken(ProtocolError):
    pass


class SchemaError(ProtocolError):
    pass


class IntegrityError(ProtocolError):
    pass


@dataclass
class Intent:
    target: str
    type_: TaskType
    restrictions: list[str] = field(default_factory=list)
    slots: dict[str, Optional[str]] = field(default_factory=dict)
    missing_items: list[str] = field(default_factory=list)
    text_original: str = ""
    hash: str = ""

    def a_dict(self) -> dict:
        d = asdict(self)
        d["type_"] = self.type_.value
        return d


@dataclass
class Atom:
    id: str
    type_: AtomType
    text: str
    origin: Origin
    act: Optional[Action] = None
    params_: dict[str, Any] = field(default_factory=dict)
    a1: VerdictA1 = VerdictA1.NO_APPLIES
    a2: VerdictA2 = VerdictA2.CLEAN
    a3: VerdictA3 = VerdictA3.INTEGRITY_OK
    notes: list[str] = field(default_factory=list)

    def a_dict(self) -> dict:
        return {
            "id": self.id, "type_": self.type_.value, "text": self.text,
            "origin": self.origin.value,
            "act": None if self.act is None else self.act.value,
            "params_": dict(self.params_),
            "a1": self.a1.value, "a2": self.a2.value, "a3": self.a3.value,
            "notes": list(self.notes),
        }


@dataclass
class Order:
    """Order typed from closed list. The executor reads only these fields."""
    id: str
    act: Action
    params_: dict[str, Any]
    cause_id: str
    intent_hash: str
    origin: Origin = Origin.INTENT
    risk: str = "NORMAL"          # NORMAL | SENSIBLE | DANO
    hash: str = ""

    def a_dict(self) -> dict:
        return {
            "id": self.id, "act": self.act.value,
            "params_": dict(self.params_),
            "cause_id": self.cause_id, "intent_hash": self.intent_hash,
            "origin": self.origin.value, "risk": self.risk, "hash": self.hash,
        }


@dataclass
class Result:
    state: ResultState
    intent: Optional[Intent] = None
    atomos: list[Atom] = field(default_factory=list)
    orders: list[Order] = field(default_factory=list)
    message: str = ""
    truths: dict[str, TruthState] = field(default_factory=dict)
    peace_sustained: bool = False
    integrity_ok: bool = False
    cost_inherited: int = 0
    credibility_penalized: bool = False
    rule_stop: Optional[str] = None
    details: dict[str, Any] = field(default_factory=dict)

    def a_dict(self) -> dict:
        return {
            "state": self.state.value,
            "intent": None if self.intent is None else self.intent.a_dict(),
            "atomos": [a.a_dict() for a in self.atomos],
            "orders": [o.a_dict() for o in self.orders],
            "message": self.message,
            "truths": {k: v.value for k, v in self.truths.items()},
            "peace_sustained": self.peace_sustained,
            "integrity_ok": self.integrity_ok,
            "cost_inherited": self.cost_inherited,
            "credibility_penalized": self.credibility_penalized,
            "rule_stop": self.rule_stop,
            "details": dict(self.details),
        }


# Resources whose content is not sent or written out without explicit intent
# and remains high-risk (controller does not self-test).
RESOURCES_SENSITIVE = frozenset({
    "llaves", "keys", "secretos", "secrets", "credenciales", "credentials",
    "password", "passwords", "api_key", "apikey", "token_secret",
})
