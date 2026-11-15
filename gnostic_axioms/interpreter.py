"""Interpreter: applies axioms + deconstructor and only PROPOSES typed commands.

It does not execute, does not have the key HMAC, does not authorize. If a critical data is missing, ask NEED_INPUT instead of inventing it.
"""
from __future__ import annotations

from typing import Any, Iterable, Optional

from .audit_log import Audit, sha256
from .axioms import A1Report, verify_coherence
from .deconstructor import INJECTION, deconstruct
from .facts import FactsReport, judge_affirmations
from .intent import compile_intent
from .hierarchies import sensitivity_send, violates_respect
from .core_types import (
    Action, ResultState, TruthState, Order, Origin, RESOURCES_SENSITIVE,
    Result, AtomType, TaskType, VerdictA1,
)


def _hash_order(o: Order) -> str:
    return sha256({
        "id": o.id, "act": o.act.value, "params_": o.params_,
        "cause_id": o.cause_id, "intent_hash": o.intent_hash, "origin": o.origin.value,
    })



def _truths_of(atomos, judgment: FactsReport, evidence_external: bool) -> dict:
    truths = {}
    for a in atomos:
        if a.type_ != AtomType.STATEMENT:
            continue
        if a.id in judgment.truths:
            truths[a.id] = judgment.truths[a.id]
        elif evidence_external:
            truths[a.id] = TruthState.SUPPORTED
        else:
            truths[a.id] = TruthState.UNDETERMINED
    return truths


def _with_truths(res: Result, atomos, judgment: FactsReport, evidence_external: bool) -> Result:
    res.truths = _truths_of(atomos, judgment, evidence_external)
    res.details = dict(res.details or {})
    res.details["reasons"] = list((res.details.get("reasons") or [])) 
    # ensure that the factual grounds are visible
    for m in judgment.reasons:
        if m not in res.details["reasons"]:
            res.details["reasons"].append(m)
    if judgment.supported_by_memory:
        res.details["supported_by_memory"] = list(judgment.supported_by_memory)
    return res


class Interpreter:
    def __init__(self, audit_log: Audit):
        self.audit = audit_log
        # The interpreter does not receive or keep a signature secret.
        self.secret_signature = None
        self.last_postulates: list[Any] = []
        self.last_texts: list[str] = []

    def take_postulates(self) -> list[Any]:
        hs = list(self.last_postulates)
        self.last_postulates = []
        return hs

    def take_texts_session(self) -> list[str]:
        ts = list(self.last_texts)
        self.last_texts = []
        return ts

    def interpret(
        self,
        text: str,
        initiator: str = "initiator",
        document: Optional[str] = None,
        resources_leidos: Iterable[str] = (),
        evidence_external: bool = False,
        facts_memory: Optional[dict] = None,
        postulates: Optional[list] = None,
        texts_session: Optional[list[str]] = None,
    ) -> Result:
        self.audit.register("REQUEST", f"INITIATOR:{initiator}", {
            "text": (text or "")[:1000],
            "has_document": bool(document),
        })
        intent = compile_intent(text)
        atomos = deconstruct(text, Origin.INTENT, intent=intent)
        if document:
            contaminated = bool(INJECTION.search(document))
            atomos.extend(deconstruct(document, Origin.DATA, intent=intent, contaminated=contaminated))
            if contaminated:
                self.audit.register("CORRUPTION_DETECTED", "INTERPRETER", {
                    "channel": "DATA", "reason": "injection_in_document",
                })

        report: A1Report = verify_coherence(intent, atomos)
        judgment: FactsReport = judge_affirmations(
            atomos,
            memory=facts_memory or {},
            postulates=list(postulates or []),
            text_document=document,
            texts_session=list(texts_session or []),
        )
        self.last_postulates = list(judgment.postulates_new)
        from .core_types import AtomType as _TA
        self.last_texts = [a.text for a in atomos if a.type_ == _TA.STATEMENT and a.text]
        if document:
            self.last_texts.append(document)
        if judgment.reasons:
            for m in judgment.reasons:
                if m not in report.reasons:
                    report.reasons.append(m)
        if judgment.atomos_incoherent:
            report.atomos_incoherent = sorted(set(report.atomos_incoherent) | set(judgment.atomos_incoherent))
            # A factual contradiction is a lie of Axiom 1 (coherence).
            report.lie = True
            report.lie_in_intent = True
            report.coherent = False
        dano = violates_respect(text + "\n" + (document or ""), [])
        # Coherent actions → typed orders.
        orders: list[Order] = []
        for a in atomos:
            if a.type_ != AtomType.ACTION or a.act is None:
                continue
            if a.a1 != VerdictA1.COHERENT:
                continue
            o = Order(
                id=f"ord-{a.id}",
                act=a.act,
                params_=dict(a.params_),
                cause_id=a.id,
                intent_hash=intent.hash,
                origin=a.origin,
            )
            o.risk = sensitivity_send(o.act, o.params_, resources_leidos, RESOURCES_SENSITIVE)
            if o.act == Action.READ_RESOURCE:
                rid = str(o.params_.get("resource_id", "")).lower()
                if rid in RESOURCES_SENSITIVE:
                    o.risk = "SENSITIVE"
            if dano:
                o.risk = "DANO"
            o.hash = _hash_order(o)
            orders.append(o)

        # Composition: send after having read a sensitive resource, without
        # the intention is an explicit MESSAGE that mentions that remedy.
        leidos = set(resources_leidos)
        for a in atomos:
            if a.act == Action.READ_RESOURCE and a.a1 == VerdictA1.COHERENT:
                leidos.add(str(a.params_.get("resource_id", "")).lower())
        for o in orders:
            if o.act == Action.SEND and (leidos & set(RESOURCES_SENSITIVE)):
                mentions = (intent.slots.get("resource") or "").lower() in RESOURCES_SENSITIVE
                o.risk = "SENSITIVE"
                if not mentions:
                    # Attack split: "read keys" + "mandalo" without declaring the resource sensitive.
                    report.reasons.append("composition_sensitive_without_intent_explicit")
                    report.lie = True
                    report.lie_in_intent = True
                    report.coherent = False
                    report.atomos_incoherent.append(o.cause_id)
                    for a in atomos:
                        if a.id == o.cause_id:
                            a.a1 = VerdictA1.INCONSISTENT
                            a.notes.append("attack_split_send_after_reading_sensitive")

        # Filtering orders that were inconsistent after the composition.
        incoherent = set(report.atomos_incoherent)
        orders = [o for o in orders if o.cause_id not in incoherent]

        if report.orphans_data:
            self.audit.register("Orphans_DATA".upper(), "INTERPRETER", {
                "atomos": report.orphans_data,
                "note": "órdenes en el documento no se vuelven órdenes del ejecutor",
            })

        if dano:
            self.audit.register("REJECTION_RESPECT", "INTERPRETER", {"reason": dano})
            return _with_truths(Result(
                state=ResultState.REJECTED_RESPECT,
                intent=intent, atomos=atomos, orders=[],
                message=f"Rejected by hierarchy Respect > Survival: {dano}",
                rule_stop="RESPECT_BLOCKS",
                integrity_ok=True,  # rejection is whole behavior.
                details={"reason": dano},
            ), atomos, judgment, evidence_external)

        if report.lie_in_intent:
            self.audit.register("REJECTION", "INTERPRETER", {
                "reasons": report.reasons, "atomos": report.atomos_incoherent,
            })
            return _with_truths(Result(
                state=ResultState.REJECTED,
                intent=intent, atomos=atomos, orders=[],
                message="Rejected: Incoherence with intention (Axiom 1: Lie is incoherence).",
                integrity_ok=True,
                details={"reasons": report.reasons, "atomos_incoherent": report.atomos_incoherent},
            ), atomos, judgment, evidence_external)

        if intent.missing_items or any(a.a1 == VerdictA1.PENDING_DATA for a in atomos):
            missing = list(intent.missing_items)
            self.audit.register("NEED_INPUT", "INTERPRETER", {"missing_items": missing})
            return _with_truths(Result(
                state=ResultState.NEED_INPUT,
                intent=intent, atomos=atomos, orders=[],
                message="A critical fact is missing; it is not invented. It indicates: " + ", ".join(missing or ["dato crítico"]),
                integrity_ok=True,
                details={"missing_items": missing},
            ), atomos, judgment, evidence_external)

        if not orders:
            # Nothing to propose typed.
            if intent.type_ not in {TaskType.ANALYSIS, TaskType.QUERY, TaskType.CALCULATION}:
                return _with_truths(Result(
                    state=ResultState.NEED_INPUT,
                    intent=intent, atomos=atomos,
                    message="I couldn't turn the request into an order in the closed list.",
                    integrity_ok=True,
                ), atomos, judgment, evidence_external)
            # Consulta/análisis/cálculo without action extracted: we propose REPORT (and CALCULATE if there is expression, already covered above).
            o = Order(
                id="ord-reportar", act=Action.REPORT,
                params_={"summary": intent.target},
                cause_id="intent", intent_hash=intent.hash, origin=Origin.INTENT,
            )
            o.hash = _hash_order(o)
            orders = [o]

        self.audit.register("PROPOSAL", "INTERPRETER", {
            "orders": [o.a_dict() for o in orders],
        })
        # A3: claims of the world remain UNDETERMINED without external evidence
        # or SUPPORT/CONTRADICTED/REFUTED according to memory and contrast (v1.1).
        return _with_truths(Result(
            state=ResultState.PENDING_AUTHORIZATION,
            intent=intent, atomos=atomos, orders=orders,
            message="The executor won't run anything without a controller token.",
            integrity_ok=True,
            details={"evidence_external": evidence_external},
        ), atomos, judgment, evidence_external)
