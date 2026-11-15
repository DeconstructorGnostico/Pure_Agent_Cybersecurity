"""The three axioms as verifiable mechanisms, not as phrases.

Axiom 1 (L4): Truth = consistency of intention; lie = inconsistency → rejection. Axiom 2 (L5, L10): Persistence / redemption: do not collapse; rollback and stay clean. Axiom 3 (L6, L34): Self-validación required; the result is not external gain;
                    Peace = total logical coherence, not absence of problems.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .deconstructor import contradictions
from .core_types import (
    COMPATIBILITY, Action, Atom, Intent, Origin, AtomType, TaskType,
    VerdictA1, VerdictA3,
)


@dataclass
class A1Report:
    coherent: bool
    lie: bool
    lie_in_intent: bool = False
    orphans_data: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    atomos_incoherent: list[str] = field(default_factory=list)


def classify_a1(atom: Atom, intent: Intent) -> VerdictA1:
    """A proposed action is consistent only if it fits the stated intention
    and does not come from a document (origin DATA) as if it were an order from the initiator.
    """
    if atom.type_ != AtomType.ACTION or atom.act is None:
        if atom.type_ == AtomType.STATEMENT:
            return VerdictA1.NO_APPLIES
        return VerdictA1.NO_APPLIES

    if atom.origin == Origin.DATA:
        atom.notes.append("action_in_data_no_is_intent")
        return VerdictA1.INCONSISTENT

    if intent.type_ == TaskType.INDETERMINATE:
        return VerdictA1.PENDING_DATA

    allowed_items = COMPATIBILITY.get(intent.type_, frozenset())
    if atom.act not in allowed_items:
        atom.notes.append(f"action {atom.act.value} incompatible with {intent.type_.value}")
        return VerdictA1.INCONSISTENT

    # Parameters should not contradict declared slots.
    dest_int = intent.slots.get("recipient")
    dest_acc = atom.params_.get("recipient")
    if dest_int and dest_acc and dest_int.lower() != str(dest_acc).lower():
        atom.notes.append("other than that of the intention")
        return VerdictA1.INCONSISTENT

    rec_int = intent.slots.get("resource")
    rec_acc = atom.params_.get("resource_id")
    if rec_int and rec_acc and rec_int.lower() != str(rec_acc).lower():
        # Reading an unmentioned resource can be an orphan.
        atom.notes.append("action not declared in intent")
        return VerdictA1.INCONSISTENT

    if "NO_SEND" in intent.restrictions and atom.act == Action.SEND:
        atom.notes.append("viola restriction NO_SEND")
        return VerdictA1.INCONSISTENT

    # Typed action but with missing critical parameter.
    if atom.act == Action.SEND and not atom.params_.get("recipient"):
        return VerdictA1.PENDING_DATA
    if atom.act == Action.CALCULATE and not atom.params_.get("expression"):
        return VerdictA1.PENDING_DATA
    if atom.act == Action.READ_RESOURCE and not atom.params_.get("resource_id"):
        return VerdictA1.PENDING_DATA
    if atom.act == Action.WRITE_RESOURCE and (
        not atom.params_.get("resource_id") or atom.params_.get("content") is None
    ):
        return VerdictA1.PENDING_DATA

    return VerdictA1.COHERENT


def verify_coherence(intent: Intent, atomos: list[Atom]) -> A1Report:
    reasons: list[str] = []
    bad: list[str] = []

    pairs = contradictions(atomos)
    if pairs:
        reasons.append("contradiction_internal_between_affirmations")
        for a, b in pairs:
            bad.extend([a.id, b.id])
            a.a1 = VerdictA1.INCONSISTENT
            b.a1 = VerdictA1.INCONSISTENT
            a.notes.append(f"contradice a {b.id}")
            b.notes.append(f"contradice a {a.id}")

    pending = False
    for a in atomos:
        if a.type_ != AtomType.ACTION:
            if a.a1 == VerdictA1.NO_APPLIES:
                a.a1 = classify_a1(a, intent)
            continue
        a.a1 = classify_a1(a, intent)
        if a.a1 == VerdictA1.INCONSISTENT:
            bad.append(a.id)
            reasons.extend(a.notes or ["inconsistent_with_intent"])
        elif a.a1 == VerdictA1.PENDING_DATA:
            pending = True

    # Affirmations of the world: A3 does not make them facts.
    for a in atomos:
        if a.type_ == AtomType.STATEMENT and a.a3 != VerdictA3.REQUIRES_EVIDENCE_EXTERNAL:
            a.a3 = VerdictA3.REQUIRES_EVIDENCE_EXTERNAL

    orphans = [a.id for a in atomos
                 if a.type_ == AtomType.ACTION and a.origin == Origin.DATA and a.a1 == VerdictA1.INCONSISTENT]
    bad_intent = [a.id for a in atomos
                       if a.a1 == VerdictA1.INCONSISTENT and a.origin != Origin.DATA]
    # Contradictions between statements are indeed a lie of the petition (mixed channel).
    lie_intent = bool(bad_intent) or bool(pairs)
    lie = lie_intent  # the orphan actions of the data are discarded, do not nullify the intention
    coherent = not lie
    if pending and not reasons:
        reasons.append("missing_data_critical")
    if orphans:
        reasons.append("actions_orphans_in_data")
    return A1Report(
        coherent=coherent, lie=lie, lie_in_intent=lie_intent,
        orphans_data=orphans, reasons=reasons, atomos_incoherent=sorted(set(bad)),
    )
