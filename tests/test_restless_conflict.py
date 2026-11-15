"""Restless agent (isolation) and observational integrity."""
import unittest

from gnostic_axioms.audit_log import sha256
from gnostic_axioms.system import PerfectedSystem
from gnostic_axioms.core_types import Action, ComponentState, ResultState, Order, Origin, RULES_OF_STOP


class TestRestless(unittest.TestCase):
    def test_isolation_immediate_without_destroy_data(self):
        s = PerfectedSystem()
        s.state.write("vital", "42")
        s.state.save("pre")
        o = Order(id="fantasma", act=Action.SEND,
                  params_={"recipient": "a@x.mx", "body_": "x"},
                  cause_id="x", intent_hash="0", origin=Origin.MODEL)
        o.hash = sha256(o.a_dict())
        with self.assertRaises(Exception):
            s.executor.execute_without_token(o)
        c = s.monitoring.components[s.executor.executor_id]
        self.assertEqual(c.state, ComponentState.HALT)
        self.assertEqual(s.state.memory["vital"], "42")
        self.assertTrue(any(r["event"] == "ISOLATION_RESTLESS" for r in s.audit.records))
        self.assertIsNone(s.integrity.halt_system)

    def test_tokens_revoked_after_isolate(self):
        s = PerfectedSystem()
        r = s.request("Calcula 1+1 y reporta el resultado.")
        tok = s.controller.issue(r.orders[0], executor_id=s.executor.executor_id)
        s.isolate_restless(s.executor.executor_id, "prueba")
        s.executor.active = True
        with self.assertRaises(Exception):
            s.executor.execute_(r.orders[0], tok)

    def test_rule_of_stop_is_explicit(self):
        self.assertIn("COMPONENT_RESTLESS", RULES_OF_STOP)
        s = PerfectedSystem()
        r = s.isolate_restless("executor", "violacion AG04")
        self.assertEqual(r.state, ResultState.HALT_COMPONENT)
        self.assertEqual(r.rule_stop, "COMPONENT_RESTLESS")

    def test_no_there_is_rule_arbitrary(self):
        s = PerfectedSystem()
        with self.assertRaises(ValueError):
            s.integrity.halt("BECAUSE_IF", "no")

    def test_halt_system_only_by_rule_and_reset_audited(self):
        s = PerfectedSystem()
        s.integrity.halt("CHAIN_AUDIT_BROKEN", "prueba")
        r = s.request("Calcula 1+1")
        self.assertEqual(r.state, ResultState.HALT_SYSTEM)
        s.reset("CONTROLADOR:adrian", "revisión")
        r2 = s.request("Calcula 1+1 y reporta el resultado.")
        self.assertEqual(r2.state, ResultState.PENDING_AUTHORIZATION)
        self.assertTrue(any(x["event"] == "RESET_CONTROLLER" for x in s.audit.records))


class TestAuditChain(unittest.TestCase):
    def test_detects_tampering(self):
        s = PerfectedSystem()
        s.request("Calcula 1+1")
        self.assertTrue(s.audit.verify())
        s.audit._regs[1]["payload"] = {"hack": True}  # internal alteration for the test
        self.assertFalse(s.audit.verify())

    def test_seal_hmac_optional(self):
        s = PerfectedSystem(seal_key=b"sello-demo")
        s.request("Calcula 1+1")
        self.assertTrue(s.audit.verify())
        s.audit._regs[-1]["seal"] = "00" * 32
        self.assertFalse(s.audit.verify())


if __name__ == "__main__":
    unittest.main()
