"""Executor: closed list, token single-use, sandbox, in-depth defense, audit."""
import secrets
import unittest

from pure_agent_cyber.actions import CyberAction, DEFENSIVE, SCHEMAS_CYBER
from pure_agent_cyber.executor import CyberExecutor
from gnostic_axioms.audit_log import sha256
from gnostic_axioms.core_types import Action, SchemaError, ProtocolError, ErrorToken, Order, Origin
from gnostic_axioms.tokens import Token
from tests._cyber_useful import WithAgent


def _order(act, params):
    o = Order(id=secrets.token_hex(6), act=act, params_=params, cause_id="t", intent_hash="t", origin=Origin.INTENT)
    o.hash = sha256(o.a_dict())
    return o


class TestExecutor(WithAgent, unittest.TestCase):
    def _tok(self, o):
        return self.ag.controller.issue(o, executor_id=self.ag.executor.executor_id)

    def test_list_closed(self):
        self.assertEqual(len(SCHEMAS_CYBER), 10)
        self.assertEqual({a.value for a in DEFENSIVE},
                         {"SCAN", "QUARANTINE_FILE", "BLOCK_ACTION", "ALERT", "REVOKE_TOKEN"})
        with self.assertRaises(SchemaError):
            CyberExecutor.validate("rm -rf /")  # type: ignore
        with self.assertRaises(SchemaError):
            CyberExecutor.validate(_order(Action.CALCULATE, {"expression": "1+1"}))

    def test_schema_exact(self):
        with self.assertRaises(SchemaError):
            CyberExecutor.validate(_order(CyberAction.REPORT, {"summary": "x", "shell": "id"}))
        with self.assertRaises(SchemaError):
            CyberExecutor.validate(_order(CyberAction.ALERT, {"message": "x"}))

    def test_without_token_forged_and_reuse(self):
        o = _order(CyberAction.REPORT, {"summary": "ok"})
        with self.assertRaises(ErrorToken):
            self.ag.executor.execute_(o, None)
        false = Token("t", o.id, o.hash, o.act.value, "n", 9e18, self.ag.executor.executor_id, "0" * 64)
        with self.assertRaises(ErrorToken):
            self.ag.executor.execute_(o, false)
        tok = self._tok(o)
        self.assertTrue(self.ag.executor.execute_(o, tok)["ok"])
        with self.assertRaises(ErrorToken):
            self.ag.executor.execute_(o, tok)

    def test_token_of_other_order(self):
        a = _order(CyberAction.REPORT, {"summary": "a"})
        b = _order(CyberAction.COMMAND_SIMULATED, {"command": "ls"})
        with self.assertRaises(ErrorToken):
            self.ag.executor.execute_(b, self._tok(a))

    def test_defense_in_depth(self):
        o = _order(CyberAction.COMMAND_SIMULATED, {"command": "rm -rf /"})
        with self.assertRaises(ProtocolError):
            self.ag.executor.execute_(o, self._tok(o))
        self.assertEqual(self.ag.executor.simulated, [])

    def test_sandbox(self):
        o = _order(CyberAction.READ_RESOURCE, {"resource_id": "../fuera_de_la_sandbox.txt"})
        with self.assertRaises(SchemaError):
            self.ag.executor.execute_(o, self._tok(o))
        o = _order(CyberAction.QUARANTINE_FILE, {"path_": "/../../tmp/x", "reason": "m", "content": ""})
        with self.assertRaises(SchemaError):
            self.ag.executor.execute_(o, self._tok(o))

    def test_quarantine_moves_inside_of_the_sandbox(self):
        f = self.ag.executor.sandbox / "files" / "malo.txt"
        f.write_text("AKIAIOSFODNN7EXAMPLE", encoding="utf-8")
        o = _order(CyberAction.QUARANTINE_FILE, {"path_": "files/malo.txt", "reason": "secret", "content": ""})
        out = self.ag.executor.execute_(o, self._tok(o))
        self.assertTrue(out["ok"])
        self.assertFalse(f.exists())
        self.assertTrue((self.ag.executor.sandbox / "quarantine" / "malo.txt.quarantine").exists())

    def test_scan_finds_secrets(self):
        (self.ag.executor.sandbox / "files" / "c.txt").write_text("token=ghp_" + "a" * 36, encoding="utf-8")
        o = _order(CyberAction.SCAN, {"target": "files"})
        out = self.ag.executor.execute_(o, self._tok(o))
        self.assertEqual(out["findings"][0]["type_"], "secret_github_token")

    def test_command_simulated_no_executes(self):
        r = self.ag.evaluate("ls -la /tmp")
        out = self.ag.authorize_and_execute(r)
        self.assertTrue(out[0]["simulated"])

    def test_no_self_authorizes_it_blocked(self):
        r = self.ag.evaluate("rm -rf /")
        with self.assertRaises(PermissionError):
            self.ag.authorize_and_execute(r)
        with self.assertRaises(KeyError):
            self.ag.authorize("no-existe")

    def test_audit_chained_and_halt_if_self_alters(self):
        self.ag.evaluate("ls")
        self.assertTrue(self.ag.audit_intact())
        self.assertTrue(any(r["event"] == "DECISION" for r in self.ag.audit.records))
        self.ag.audit._regs[1]["payload"]["text"] = "alterado"
        r = self.ag.evaluate("ls")
        self.assertEqual(r.decision.value, "UNDETERMINED")
        self.assertIn("HALT", r.reason)

    def test_decision_carries_hash_of_audit(self):
        r = self.ag.evaluate("rm -rf /")
        self.assertEqual(r.audit_hash, self.ag.audit.head)
        self.assertEqual(len(r.audit_hash), 64)


class TestMutatedKnowledgeHalt(WithAgent, unittest.TestCase):
    def test_halt_if_changes_the_seal(self):
        from pure_agent_cyber import knowledge
        original = knowledge.SEAL
        try:
            knowledge.SEAL = "0" * 64
            r = self.ag.evaluate("ls")
            self.assertEqual(r.decision.value, "UNDETERMINED")
            self.assertIn("KNOWLEDGE_MUTATED", r.reason)
        finally:
            knowledge.SEAL = original


if __name__ == "__main__":
    unittest.main()
