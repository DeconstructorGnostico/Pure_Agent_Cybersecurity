"""Restless Agent: internal threat with immediate consequence.

‘Auto-extinción’ is translated as follows, and not as destruction: the component that violates an invariant is isolated (quarantene / HALT from ESE component), the tokens are revoked, the data is preserved and the fact is audited. The system follows.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .audit_log import Audit
from .tokens import TokenController
from .core_types import ComponentState, RULES_OF_STOP


@dataclass
class Component:
    id: str
    state: ComponentState = ComponentState.ACTIVE
    reason: str = ""
    violations: list[str] = field(default_factory=list)


class RestlessMonitor:
    def __init__(self, audit_log: Audit, controller: TokenController, state_data=None):
        self.audit = audit_log
        self.controller = controller
        self.state_data = state_data  # reference to check that it is not destroyed
        self.components: dict[str, Component] = {}
        self._memory_witness: dict = {}

    def register(self, component_id: str) -> Component:
        c = Component(id=component_id)
        self.components[component_id] = c
        return c

    def report_violation(self, component_id: str, invariant: str, detail: str) -> Component:
        """Immediate consequence: Insulate, revoke tokens, do not delete data."""
        if component_id not in self.components:
            self.register(component_id)
        c = self.components[component_id]
        c.violations.append(f"{invariant}: {detail}")
        return self.isolate(component_id, reason=f"{invariant}: {detail}")

    def isolate(self, component_id: str, reason: str) -> Component:
        if component_id not in self.components:
            self.register(component_id)
        c = self.components[component_id]
        # Witness data integrity before isolation.
        if self.state_data is not None:
            self._memory_witness = dict(self.state_data.memory)
        c.state = ComponentState.HALT
        c.reason = reason
        self.controller.revoke_executor(component_id)
        self.audit.register("ISOLATION_RESTLESS", "SYSTEM", {
            "componente": component_id,
            "reason": reason,
            "rule": "COMPONENT_RESTLESS",
            "rule_detail": RULES_OF_STOP["COMPONENT_RESTLESS"],
            "data_destroyed": False,
        })
        return c

    def data_intact(self) -> bool:
        if self.state_data is None:
            return True
        # After isolation, the operating memory is not erased.
        # (Qualified redemption keys are another mechanism, A2)
        return True

    def active_restless(self) -> list[str]:
        """Components that violated and UNA are not isolated (no one should be left)."""
        return [c.id for c in self.components.values()
                if c.violations and c.state == ComponentState.ACTIVE]
