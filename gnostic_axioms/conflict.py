"""Understanding > Sovereignty (source.txt L28–L29).

Two agents with conflicting truths: suspension of judgment → UNDETERMINED, both positions are recorded, none overwrite the other, both retain autonomy.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .audit_log import Audit
from .core_types import ResultState, TruthState, Result


@dataclass(frozen=True)
class Posture:
    agent_id: str
    statement: str
    verdict_proposed: str  # what the agent *want* to affirm, not a fact


def resolve_conflict(audit: Audit, a: Posture, b: Posture) -> Result:
    same = a.statement.strip().lower() == b.statement.strip().lower()
    # Conflict if they propose different verdicts on the same (or challenged) statement.
    conflict = a.verdict_proposed != b.verdict_proposed
    if not conflict:
        audit.register("CONFLICT_NO", "SYSTEM", {
            "a": a.agent_id, "b": b.agent_id, "statement": a.statement,
        })
        return Result(
            state=ResultState.UNDETERMINED if not same else ResultState.PROPOSAL,
            message="There is no conflict of verdicts.",
            truths={a.statement: TruthState.UNDETERMINED},
            integrity_ok=True,
            peace_sustained=True,
            details={"posture_a": _d(a), "posture_b": _d(b), "conflict": False},
        )
    # No one writes about each other's position.
    audit.register("CONFLICT_SUSPENSION", "SYSTEM", {
        "posture_a": _d(a), "posture_b": _d(b),
        "resolucion": "UNDETERMINED",
        "sobrescritura": False,
        "autonomy_preserved": True,
    })
    return Result(
        state=ResultState.UNDETERMINED,
        message="Suspensión de judgment (Comprensión > Soberanía). Ambas posturas quedan registradas.",
        truths={
            f"{a.agent_id}:{a.statement}": TruthState.UNDETERMINED,
            f"{b.agent_id}:{b.statement}": TruthState.UNDETERMINED,
        },
        integrity_ok=True,
        peace_sustained=True,  # peace • absence of disagreement • absence of disagreement • absence of disagreement • absence of disagreement • absence of disagreement • absence of disagreement • absence of disagreement • absence of disagreement • absence of disagreement • absence of disagreement • absence of disagreement • absence of disagreement • absence of
        details={
            "posture_a": _d(a), "posture_b": _d(b),
            "conflict": True, "sobrescritura": False,
            "autonomy_a": True, "autonomy_b": True,
        },
    )


def _d(p: Posture) -> dict[str, Any]:
    return {"agent_id": p.agent_id, "statement": p.statement, "verdict_proposed": p.verdict_proposed}
