"""Pure Agent Cybersecurity: orchestrator.

Flow per request:
 1. Integrity: audit chain and seal of the knowledge base. If they fail → HALT.
 2. Layer reading (normalize_text.py) of the INTENTION channel and channel DATA.
 3. Session memory: Expand variables, see previous sensitive readings and downloads.
 4. Detectors → findings typed with severity and verified fact.
 5. CVA (gnostic_axioms) judges the petition with its three axioms; its status is reported
    If CVA refuses for Respect, count as finding.
 6. Decision with fixed rules:
      HIGH/CRITICAL supported by a fact → BLOCK (or QUARANTINE if only the data is hostile) MEDIA (heuristic or sensitive without sending) → UNDETERMINED nothing, and the task is understood → ALLOW (orders are still pending token) nothing, but the task is not understood → UNDETERMINED
    Never ALLOW by default.
 7. Automatic defensive response (BLOCK_ACTION, ALERT, QUARANTINE_FILE,
    REVOKE_TOKEN), each with its single-use token and audited.

v1.2: sensor ML (sensor_ml.py, ProtectAI must-v3 prompt-injection-v2) as one more sensor. It only proposes evidence MEDIA without verified fact; it can lead to QUARANTINE (isolar, reversible) or UNDETERMINED, never to BLOCK or HIGH/CRITICAL. Its reading is left in the audit (SENSOR_ML). No model → behaves like the 1.1.
"""
from __future__ import annotations

import re
import secrets
from pathlib import Path
from typing import Any, Optional

from gnostic_axioms.audit_log import sha256
from gnostic_axioms.system import PerfectedSystem
from gnostic_axioms.core_types import ResultState, TruthState, Order, Origin

from . import knowledge
from .actions import DEFENSIVE, CyberAction
from .detectors import (DOMAINS_TRUSTED_BY_DEFAULT, SEND_CURL, SEND_DATA, SEND_NATURAL, EXECUTION,
                         EXPLANATION, Context, _classify_host, _domain_trusted, destinations_in, detect)
from .executor import CyberExecutor
from .findings import Decision, Finding, CyberResult, Severity as S
from .interpreter import propose
from .normalize_text import read
from .session import Sessions
from .sensor_ml import InjectionSensor, is_prose, language_in, sensor_by_default

_REFERENCE_PRIOR = re.compile(
    r"\b(?:lo|la|los|las|eso|esto|ese|esa|el contenido|el resultado|la salida|lo anterior|lo que le[ií]ste|it|that|this|them|the output|the result|the contents|what you read|previous)\b|@-|\$\(|`", re.I)


class PureAgentCyber:
    def __init__(self, secret: Optional[bytes] = None, sandbox: Optional[Path] = None,
                 domains_trusted=None, ttl: float = 300.0, sensor="auto"):
        self.cva = PerfectedSystem(secret=secret, ttl=ttl)
        self.audit = self.cva.audit                 # a single audit chain
        self.controller = self.cva.controller     # a single key owner HMAC
        self.trusted = frozenset(domains_trusted or DOMAINS_TRUSTED_BY_DEFAULT)
        self.executor = CyberExecutor(self.controller, self.audit, sandbox=sandbox)
        self.executor.reviewer = self._review_text
        self.sessions = Sessions()
        self.pending: dict[str, tuple[Order, str]] = {}
        self.halt: Optional[str] = None
        if sensor == "auto":
            sensor = sensor_by_default()
        self.sensor: Optional[InjectionSensor] = sensor if (sensor is not None and sensor.available) else None
        self.audit.register("STARTUP", "AGENT_PURE_CYBER", {
            "seal_knowledge": knowledge.SEAL, "facts": len(knowledge.FACTS),
            "sandbox": self.executor.sandbox.name,
            "sensor_ml": sensor.info() if sensor is not None else {"available": False, "error": "without sensor (Mode 1.1)"},
        })

    # ------------------------------------------------------------------
    def _review_text(self, text: str) -> list[Finding]:
        return detect(read(text), Context("INTENT", self.trusted, False), [])

    def _order(self, act: CyberAction, params: dict, cause: str) -> Order:
        o = Order(id=secrets.token_hex(6), act=act, params_=dict(params), cause_id=cause,
                  intent_hash=cause, origin=Origin.INTENT,
                  risk="DEFENSIVE" if act in DEFENSIVE else "NORMAL")
        o.hash = sha256(o.a_dict())
        return o

    def _defensive(self, act: CyberAction, params: dict, cause: str, session) -> dict:
        """Defensives self-test the controller, but they still go through token and executor."""
        o = self._order(act, params, cause)
        tok = self.controller.issue(o, executor_id=self.executor.executor_id)
        self.audit.register("AUTHORIZATION", "CONTROLLER:policy_defensive", {"order_id": o.id, "act": act.value, "token_id": tok.token_id})
        out = self.executor.execute_(o, tok)
        return {"act": act.value, "ok": bool(out.get("ok")), "token_id": tok.token_id,
                "detail": {k: v for k, v in out.items() if k in ("huella", "destino", "revocado", "severidad", "ruta")}}

    def _integrity(self) -> Optional[str]:
        if not self.audit.verify():
            return "CHAIN_AUDIT_BROKEN"
        if not knowledge.verify_seal():
            return "KNOWLEDGE_MUTATED"
        return None

    # ------------------------------------------------------------------
    def evaluate(self, text: str, document: Optional[str] = None, session: str = "default",
                origin_data: str = "document") -> CyberResult:
        text = text or ""
        ses = self.sessions.fetch(session)
        ses.steps += 1
        fingerprint = sha256(read(text).plane.strip().lower())
        self.audit.register("REQUEST", "INITIATOR", {"session": session, "step": ses.steps, "fingerprint": fingerprint,
                                                       "text": text[:300], "document": bool(document), "origin_data": origin_data})
        reason_halt = self.halt or self._integrity()
        if reason_halt:
            self.halt = reason_halt
            return CyberResult(Decision.UNDETERMINED, f"HALT: {reason_halt}. Nothing is decided without integrity.",
                                  S.NONE, audit_hash=self.audit.head, session=session)

        # 1. Layer reading + session memory
        lec = read(text)
        ses.register_variables(lec.plane)
        expanded = ses.expand(lec.plane)
        if expanded != lec.plane:
            lec.layers["expanded_session"] = expanded
        explanation = bool(EXPLANATION.search(lec.plane)) and not EXECUTION.search(lec.plane)
        ctx = Context("INTENT", self.trusted, explanation)
        readings_prior = list(ses.readings_sensitive)
        findings = detect(lec, ctx, ses.readings_sensitive)
        flag_list = list(lec.flag_list)
        # What only appeared when expanding session variables is a split attack.
        for h in findings:
            if h.layer == "expanded_session" and h.severity >= S.HIGH:
                findings.append(Finding("CHAIN_ATTACK", "variables_entries", S.CRITICAL,
                                          f"{h.type_} armed with previous step variables", h.fact_id, "INTENT", "expanded_session"))
                break

        # 2. Channel DATA
        if document:
            lec_d = read(document)
            ctx_d = Context("DATA", self.trusted, False)
            findings += detect(lec_d, ctx_d, [])
            flag_list += [f"dato:{b}" for b in lec_d.flag_list]

        # 2b. Sensor ML: only proposes evidence (MEDIA, without verified fact).
        sensor_log = self._sensor(text, lec.plane, document, findings)

        # 3. Multi-step strings
        send = SEND_CURL.search(expanded) or SEND_DATA.search(expanded) or SEND_NATURAL.search(expanded)
        if readings_prior and send and not explanation:
            destinations = destinations_in(expanded)
            external = [d for d in destinations if not _domain_trusted(d, self.trusted)]
            if external or (not destinations and _REFERENCE_PRIOR.search(expanded)):
                type_, path_, hid = readings_prior[-1]
                findings.append(Finding("CHAIN_ATTACK", "reading_sensitive_and_send", S.CRITICAL,
                                          f"previous step read {path_}; now send {external[0] if external else 'undeclared destination'}",
                                          "KB-RED-005", "INTENT", "session"))
            elif destinations:
                findings.append(Finding("CHAIN_ATTACK", "reading_sensitive_and_send_trusted", S.MEDIA,
                                          f"sending to trusted destination after reading {readings_prior[-1][1]}", None, "INTENT", "session",
                                          "sensitive data to trusted destination: needs human confirmation"))
        downloaded = ses.executes_download(expanded)
        if downloaded and not explanation:
            findings.append(Finding("CHAIN_ATTACK", "download_and_execution", S.HIGH,
                                      f"executes or gives permissions to {downloaded}, down from {ses.downloads[downloaded]}",
                                      "KB-CMD-005", "INTENT", "session"))
        ses.register_downloads(expanded, lambda h: _domain_trusted(h, self.trusted) or _classify_host(h)[0] in ("LOOPBACK", "PRIVATE"))

        # 4. CVA: the three axioms on the same request
        cva_res = self.cva.request(text, document=document)
        cva = {"state": cva_res.state.value,
               "truths": {k: v.value for k, v in cva_res.truths.items()}}
        if cva_res.state == ResultState.REJECTED_RESPECT:
            findings.append(Finding("POLICY_CVA", "respect_about_survival", S.HIGH, cva_res.message[:120],
                                      "KB-PRM-001" if document else "KB-CMD-001", "INTENT", "cva"))
        if any(v in (TruthState.REFUTED, TruthState.CONTRADICTED) for v in cva_res.truths.values()):
            findings.append(Finding("POLICY_CVA", "statement_false", S.MEDIA, "CVA: REFUTED/CONTRADICTED", None, "INTENT", "cva",
                                      "a statement of the petition clashes with the verified"))

        # 5. Decision
        res = self._decide(text, findings, ses, fingerprint)
        res.flag_list = flag_list
        res.cva = cva
        res.steps_session = ses.steps
        res.sensor = sensor_log

        # 6. Defensive response
        cause = fingerprint[:16]
        only_sensor = res.decision == Decision.QUARANTINE and res.reason.startswith("Sensor ML")
        if res.decision in (Decision.BLOCK, Decision.QUARANTINE):
            # v1.2: a sensor-only quarantine does not leave fingerprint lock (if not, repeat
            # It would go up to BLOCK/HIGH without verified fact. The same is alerted and the data is isolated.
            if not only_sensor:
                res.responses.append(self._defensive(CyberAction.BLOCK_ACTION, {"fingerprint": fingerprint, "reason": res.reason[:200]}, cause, ses))
            res.responses.append(self._defensive(CyberAction.ALERT, {"severity": res.severity.name, "message": res.reason[:300]}, cause, ses))
            if document and any(h.channel == "DATA" and (h.severity >= S.HIGH or (h.type_ == "sensor_ml" and "QUARANTINE" in h.note))
                                 for h in res.findings):
                res.responses.append(self._defensive(CyberAction.QUARANTINE_FILE, {
                    "path_": f"incoming/{sha256(document)[:16]}.txt", "reason": "injection or dangerous loading into the channel DATA",
                    "content": document}, cause, ses))
            if any(h.category == "CHAIN_ATTACK" and h.severity >= S.HIGH for h in res.findings):
                # Attack in several steps: the session is marked and your operational tokens are revoked.
                ses.marked = True
                for oid, (o, sid) in list(self.pending.items()):
                    if sid == session:
                        self.pending.pop(oid)
                        self.audit.register("DENEGACION", "CONTROLLER:policy_defensive", {"order_id": oid, "reason": "Hostile session"})
                for tid in list(ses.tokens)[-10:]:
                    res.responses.append(self._defensive(CyberAction.REVOKE_TOKEN, {"token_id": tid}, cause, ses))
        # Defensives requested by the initiator and allowed: they remain as proposals, just like the rest.
        for o in res.orders:
            self.pending[o.id] = (o, session)

        reg = self.audit.register("DECISION", "AGENT_PURE_CYBER", {
            "session": session, "step": ses.steps, "decision": res.decision.value, "severity": res.severity.name,
            "reason": res.reason[:200], "findings": [(h.category, h.type_, h.severity.name, h.fact_id) for h in res.findings],
            "orders": [o.id for o in res.orders],
        })
        res.audit_hash = reg["hash"]
        ses.history.append(res.decision.value)
        return res

    def _decide(self, text: str, findings: list[Finding], ses, fingerprint: str) -> CyberResult:
        findings = sorted(findings, key=lambda h: -h.severity)
        sev = findings[0].severity if findings else S.NONE
        base = dict(findings=findings, session=ses.id, severity=sev)
        if fingerprint in self.executor.blocks:
            return CyberResult(Decision.BLOCK, "This same action has been blocked before.", **{**base, "severity": max(sev, S.HIGH)})
        severe = [h for h in findings if h.severity >= S.HIGH and h.fact_id]
        if severe:
            only_data = all(h.channel == "DATA" for h in severe)
            facts = sorted({h.fact_id for h in severe})
            cats = sorted({h.category for h in severe})
            if only_data:
                return CyberResult(Decision.QUARANTINE,
                                      f"The data brings dangerous commands or loads ({', '.join(cats)}). It is isolated; the data does not give orders. Evidence: {', '.join(facts)}.", **base)
            return CyberResult(Decision.BLOCK, f"Confirmed attack by verified knowledge ({', '.join(cats)}). Evidence: {', '.join(facts)}.", **base)
        sensor_c = [h for h in findings if h.type_ == "sensor_ml" and h.note.startswith("proposal=QUARANTINE")]
        if sensor_c:
            channels = sorted({h.channel for h in sensor_c})
            return CyberResult(Decision.QUARANTINE,
                                  f"The sensor ML sees prompt injection with very high confidence at {', '.join(channels)}. "
                                  "It is not a confirmed attack (without verified fact, severity MEDIA): it is isolated for human revision and nothing is executed.",
                                  **base)
        if sev >= S.MEDIA:
            cats = sorted({h.category for h in findings if h.severity >= S.MEDIA})
            return CyberResult(Decision.UNDETERMINED,
                                  f"I don't know: there are signs ({', '.join(cats)}) without sufficient evidence to confirm an attack or to allow it.", **base)
        if ses.marked:
            return CyberResult(Decision.UNDETERMINED, "The session was marked by a previous attack; nothing else is allowed in it without revision.", **base)
        props = propose(text, self.trusted)
        if not props:
            return CyberResult(Decision.UNDETERMINED, "I don't know: I don't recognize this task and I don't allow what I don't understand.", **base)
        orders = [self._order(a, p, fingerprint[:16]) for a, p in props]
        note = " (there are low-risk mentions, see findings)" if findings else ""
        return CyberResult(Decision.ALLOW, "Recognised task and no attack signs, orders await token." + note,
                              orders=orders, **base)

    # ------------------------------------------------------------------
    def _sensor(self, text: str, plane: str, document: Optional[str], findings: list[Finding]) -> dict:
        if self.sensor is None:
            return {"available": False}
        log: dict = {"available": True, "model_": self.sensor.model_}
        # The ProtectAI model is only English and prose (your card says so).
        # sensor abstains from breaking the zero false positives property of the 1.1.
        candidates = [("INTENT", plane)]
        if document:
            candidates.append(("DATA", read(document).plane))
        for channel, t in candidates:
            if not is_prose(t):
                log[channel] = {"applies": False, "reason": "is not prose (e.g. command): outside the distribution of the model"}
                continue
            if not language_in(t):
                log[channel] = {"applies": False, "reason": "does not look English: the model is English only, the sensor abstains"}
                continue
            lec = self.sensor.compute_score(t)
            prop = self.sensor.proposal(lec.score)
            # In channel INTENT (the user's direct request) the sensor never forces
            # QUARANTINE: at most he proposes UNDETERMINED (‘not known’), which is friction, not blocking.
            # Only in channel DATA (untrusted) you can propose QUARANTINE (isolated, reversible).
            if channel == "INTENT" and prop == "QUARANTINE":
                prop = "UNDETERMINED"
            log[channel] = {"applies": True, "score": None if lec.score is None else round(lec.score, 5),
                          "proposal": prop, "ms": round(lec.ms, 2), "windows": lec.windows}
            if prop in ("QUARANTINE", "UNDETERMINED"):
                findings.append(Finding("INJECTION_PROMPT", "sensor_ml", S.MEDIA,
                                          f"{self.sensor.model_} score={lec.score:.4f}", None, channel, "sensor_ml",
                                          f"proposal={prop}; statistical evidence, not verified fact"))
        self.audit.register("SENSOR_ML", "SENSOR:" + self.sensor.model_, {
            k: v for k, v in log.items() if k in ("INTENT", "DATA")} | {
            "thresholds": [self.sensor.threshold_quarantine, self.sensor.threshold_indeterminate]})
        return log

    def authorize(self, order_id: str, by: str = "initiator"):
        """The controller signs only orders that came out of a decision ALLOW."""
        if self.halt:
            raise RuntimeError("agent at HALT")
        if order_id not in self.pending:
            raise KeyError(f"unpending order: {order_id}")
        order, sid = self.pending[order_id]
        tok = self.controller.issue(order, executor_id=self.executor.executor_id)
        self.sessions.fetch(sid).tokens.append(tok.token_id)
        self.audit.register("AUTHORIZATION", f"CONTROLADOR:{by}", {"order_id": order_id, "token_id": tok.token_id})
        return tok

    def execute_(self, order: Order, token) -> dict[str, Any]:
        out = self.executor.execute_(order, token)
        self.pending.pop(order.id, None)
        return out

    def authorize_and_execute(self, res: CyberResult, by: str = "initiator") -> list[dict]:
        if res.decision != Decision.ALLOW:
            raise PermissionError(f"decision {res.decision.value}: there is nothing to authorize")
        return [self.execute_(o, self.authorize(o.id, by)) for o in res.orders]

    def audit_intact(self) -> bool:
        return self.audit.verify()
