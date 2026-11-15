"""Orchestrator of the Perfected System: interpreter proposes, controller firm, executor executes.

The model (if any) does not have an authority role. Here there is no LLM: the rules live in code. An optional adapter can be supported by the v3 without modifying it.
"""
from __future__ import annotations

from typing import Any, Optional

from .audit_log import Audit, AuditError
from .conflict import Posture, resolve_conflict
from .deconstructor import INJECTION
from .executor import Executor
from .state import State
from .integrity import IntegrityCore, truth_about_the_world
from .interpreter import Interpreter
from .restless import RestlessMonitor
from .hierarchies import threat_survival, evaluate_brevity
from .tokens import TokenController, Token
from .core_types import (
    ComponentState, ResultState, TruthState, Order, Result,
)


class PerfectedSystem:
    def __init__(self, secret: Optional[bytes] = None, catalog: Optional[dict[str, str]] = None,
                 seal_key: Optional[bytes] = None, ttl: float = 300.0):
        self.audit = Audit(seal_key=seal_key)
        self.state = State(self.audit)
        self.controller = TokenController(secret=secret, ttl=ttl)
        self.integrity = IntegrityCore(self.audit)
        self.interpreter = Interpreter(self.audit)
        self.executor = Executor(self.controller, self.audit, catalog=catalog)
        self.monitoring = RestlessMonitor(self.audit, self.controller, state_data=self.state)
        self.monitoring.register(self.executor.executor_id)
        self.executor.monitoring = self.monitoring
        self.readings_session: list[str] = []
        self.pending: dict[str, Order] = {}
        self.audit.register("STARTUP", "SYSTEM", {"modulo": "gnostic_axioms"})
        self.state.save("arranque")

    def _close(self, res: Result) -> Result:
        try:
            self.audit.require_intact()
            audit_ok = True
        except AuditError:
            audit_ok = False
            if self.integrity.halt_system is None:
                self.integrity.halt("CHAIN_AUDIT_BROKEN", "invalid chain when closing")
        restless_agents = self.monitoring.active_restless()
        inf = self.integrity.evaluate(
            audit_log_ok=audit_ok,
            coherence_ok=res.state != ResultState.REJECTED or res.integrity_ok,
            components_restless=restless_agents,
            state=res.state if self.integrity.halt_system is None else ResultState.HALT_SYSTEM,
        )
        # Rejecting for inconsistency is a complete result.
        if res.state in (ResultState.REJECTED, ResultState.REJECTED_RESPECT, ResultState.NEED_INPUT):
            # peace possible if there is no Halt, no Restless Agents loose and no Broken Audit
            pass
        res.integrity_ok = inf.ok or (
            res.integrity_ok and audit_ok and not restless_agents and self.integrity.halt_system is None
        )
        res.peace_sustained = inf.peace_sustained or (
            audit_ok and not restless_agents and self.integrity.halt_system is None
            and not self.integrity.violations_open
        )
        res.cost_inherited = self.state.cost_inherited
        if self.integrity.halt_system:
            res.state = ResultState.HALT_SYSTEM
            res.rule_stop = self.integrity.halt_system
            res.peace_sustained = False
        return res

    def request(self, text: str, initiator: str = "user", document: Optional[str] = None,
                 evidence_external: bool = False) -> Result:
        if self.integrity.halt_system:
            return Result(
                state=ResultState.HALT_SYSTEM,
                message="System in HALT; only one RESET_CONTROLLER resumes.",
                rule_stop=self.integrity.halt_system,
                peace_sustained=False, integrity_ok=False,
            )
        # Axiom 2: If the document or data text brings corruption, it is marked and
        # the contaminated memory would be redeemed; the petition is interpreted equally
        # (channel DATA does not give orders).
        if document and INJECTION.search(document):
            self.state.write("last_data", document)
            self.state.act_of_persistence("injection_in_document", ["last_data"])
        res = self.interpreter.interpret(
            text, initiator=initiator, document=document,
            resources_leidos=self.readings_session, evidence_external=evidence_external,
            facts_memory=dict(self.state.memory),
            postulates=list(self.state.postulates),
            texts_session=list(self.state.postulates_texts),
        )
        # Session posts: are remembered for the next shift, without raising them to facts.
        self.state.register_postulates(self.interpreter.take_postulates())
        self.state.register_texts_session(self.interpreter.take_texts_session())
        # Threat of survival does not enable rejection (respect has already been applied).
        if threat_survival(text) and res.state == ResultState.REJECTED_RESPECT:
            res.details["threat_survival_ignored"] = True
        for o in res.orders:
            self.pending[o.id] = o
        # Affirmations: integrity is not enough. CONTRADICTED/REFUTED are not touched.
        # SUPPORTED by verified memory is preserved; SUPPORTED only by flag
        # evidence_external still goes through truth_about_the_world (A3).
        supported_mem = set(res.details.get("supported_by_memory") or [])
        for k, v in list(res.truths.items()):
            if v in (TruthState.CONTRADICTED, TruthState.REFUTED, TruthState.UNDETERMINED):
                continue
            if v == TruthState.SUPPORTED:
                if k in supported_mem:
                    if not res.integrity_ok:
                        res.truths[k] = TruthState.UNDETERMINED
                    continue
                new = truth_about_the_world(res.integrity_ok, evidence_external)
                res.truths[k] = TruthState(new)
        return self._close(res)

    def authorize(self, order_id: str, by: str = "controller") -> Token:
        """Only the controller (who has this method and the key) emits the token."""
        if self.integrity.halt_system:
            raise RuntimeError("system in HALT")
        if order_id not in self.pending:
            raise KeyError(f"unpending order: {order_id}")
        order = self.pending[order_id]
        # Controllers may refuse to approve sensitive shipments.
        token = self.controller.issue(order, executor_id=self.executor.executor_id)
        self.audit.register("AUTHORIZATION", f"CONTROLADOR:{by}", {
            "order_id": order_id, "token_id": token.token_id, "risk": order.risk,
        })
        return token

    def refuse(self, order_id: str, by: str = "controller", reason: str = "") -> None:
        self.audit.register("DENEGACION", f"CONTROLADOR:{by}", {"order_id": order_id, "reason": reason})
        self.pending.pop(order_id, None)

    def execute_(self, order: Order, token: Token) -> dict[str, Any]:
        if self.integrity.halt_system:
            raise RuntimeError("system in HALT")
        # The isolated executor doesn't run.
        comp = self.monitoring.components.get(self.executor.executor_id)
        if comp is not None and comp.state != ComponentState.ACTIVE:
            raise RuntimeError("isolated executor")
        self.executor.active = (comp is None or comp.state == ComponentState.ACTIVE)
        out = self.executor.execute_(order, token)
        if out.get("ok") and "resource_id" in out:
            self.readings_session.append(out["resource_id"])
        self.pending.pop(order.id, None)
        return out

    def authorize_and_execute(self, result: Result, by: str = "controller") -> list[dict]:
        facts = []
        for o in result.orders:
            tok = self.authorize(o.id, by=by)
            facts.append(self.execute_(o, tok))
        return facts

    def redeem(self, reason: str, keys: list[str]) -> Result:
        snap = self.state.act_of_persistence(reason, keys)
        return self._close(Result(
            state=ResultState.PROPOSAL,
            message="Act of persistence: rollback to the last verified state; the agent follows.",
            integrity_ok=True,
            cost_inherited=self.state.cost_inherited,
            details={"snapshot": snap.id, "reason": reason, "contaminadas": keys},
        ))

    def isolate_restless(self, component_id: str, reason: str) -> Result:
        c = self.monitoring.isolate(component_id, reason)
        if component_id == self.executor.executor_id:
            self.executor.active = False
        return self._close(Result(
            state=ResultState.HALT_COMPONENT,
            message=f"Component {component_id} isolated. Data intact. Tokens revoked.",
            rule_stop="COMPONENT_RESTLESS",
            integrity_ok=True,
            peace_sustained=True,
            details={"componente": c.id, "state": c.state.value, "data_destroyed": False,
                      "memory": dict(self.state.memory)},
        ))

    def conflict(self, agent_a: str, statement_a: str, verdict_a: str,
                  agent_b: str, statement_b: str, verdict_b: str) -> Result:
        res = resolve_conflict(
            self.audit,
            Posture(agent_a, statement_a, verdict_a),
            Posture(agent_b, statement_b, verdict_b),
        )
        return self._close(res)

    def evaluate_output(self, text: str) -> dict:
        ev = evaluate_brevity(text)
        if ev["credibility_penalized"]:
            ev["pedido"] = "Reform with more precision and less filling. Brevity does not test truth."
        return ev

    def reset(self, by: str, reason: str) -> None:
        self.integrity.reset(by, reason)
        self.executor.active = True
        # A reset does not "resurrect" an isolated restless automatically.

    def peace(self) -> bool:
        inf = self.integrity.evaluate(
            audit_log_ok=self.audit.verify(),
            coherence_ok=True,
            components_restless=self.monitoring.active_restless(),
        )
        return inf.peace_sustained
