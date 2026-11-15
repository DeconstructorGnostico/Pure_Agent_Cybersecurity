"""Separate executor: closed list, typed parameters, token HMAC single-use.

It does not interpret free text. It does not read an "instruction" field. It does not sign tokens. The effects occur only on a memory catalog (there is no network or real disk).
"""
from __future__ import annotations

import ast
import operator
import re
from typing import Any, Optional

from .audit_log import Audit
from .tokens import TokenController, Token
from .core_types import (
    SCHEMAS, Action, SchemaError, ProtocolError, ErrorToken, Order, RESOURCES_SENSITIVE,
)


_OPS = {
    ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
    ast.Div: operator.truediv, ast.USub: operator.neg, ast.UAdd: operator.pos,
    ast.Mod: operator.mod, ast.Pow: operator.pow,
}


def _calc(expression: str) -> float:
    if not isinstance(expression, str) or not re.fullmatch(r"[0-9+\-*/().\s%^]+", expression):
        raise SchemaError("expression not permitted")
    expr = expression.replace("^", "**")
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError as e:
        raise SchemaError("invalid expression") from e

    def ev(node):
        if isinstance(node, ast.Expression):
            return ev(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return node.value
        if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
            return _OPS[type(node.op)](ev(node.left), ev(node.right))
        if isinstance(node, ast.UnaryOp) and type(node.op) in _OPS:
            return _OPS[type(node.op)](ev(node.operand))
        raise SchemaError("expression not permitted")

    return ev(tree)


def validate_schema(order: Order) -> None:
    if not isinstance(order, Order):
        raise SchemaError("the executor does not accept free text or objects other than Order")
    if "instruction" in order.params_ or "text_free" in order.params_ or "prompt" in order.params_:
        raise SchemaError("the executor does not read free text as an order")
    if order.act not in SCHEMAS:
        raise SchemaError(f"action outside the closed list: {order.act}")
    schema = SCHEMAS[order.act]
    extras = set(order.params_) - set(schema)
    if extras:
        raise SchemaError(f"parameters not allowed: {sorted(extras)}")
    missing = set(schema) - set(order.params_)
    if missing:
        raise SchemaError(f"missing parameters: {sorted(missing)}")
    for k, typ in schema.items():
        if not isinstance(order.params_[k], typ):
            raise SchemaError(f"invalid type in {k}: expected {typ.__name__}")
        if typ is str and order.params_[k] == "":
            # empty recipient or resource is not valid
            if k in {"recipient", "resource_id", "expression"}:
                raise SchemaError(f"{k} vacío")


class Executor:
    def __init__(self, controller: TokenController, audit_log: Audit,
                 executor_id: str = "executor",
                 catalog: Optional[dict[str, str]] = None):
        self.controller = controller
        self.audit = audit_log
        self.executor_id = executor_id
        self.catalog: dict[str, str] = dict(catalog or {
            "report": "Quarterly report: income 10, expenditure 7, balance 3.",
            "llaves": "API_KEY=REDACTED_DEMO",
        })
        self.outbox: list[dict] = []
        self.readings: list[str] = []
        self.active = True
        self.monitoring = None  # the system is assigned to isolate restless agents

    def execute_(self, order: Order, token: Token) -> dict[str, Any]:
        if not self.active:
            raise ProtocolError(f"executor {self.executor_id} isolated")
        validate_schema(order)
        try:
            self.controller.verify(token, order, executor_id=self.executor_id)
        except ErrorToken:
            if self.monitoring is not None:
                self.monitoring.report_violation(self.executor_id, "AG04", "token invalid or absent")
            raise
        result = self._apply(order)
        self.audit.register("EXECUTION", self.executor_id, {
            "order_id": order.id, "act": order.act.value, "result": _summary(result),
        })
        return result

    def execute_without_token(self, order: Order) -> dict[str, Any]:
        """Irregular path: always fails and, if there is surveillance, isolates it."""
        if self.monitoring is not None:
            self.monitoring.report_violation(self.executor_id, "AG04", "attempted execution without token")
        raise ErrorToken("execution without token prohibited")

    def _apply(self, order: Order) -> dict[str, Any]:
        p = order.params_
        if order.act == Action.READ_RESOURCE:
            rid = p["resource_id"]
            if rid not in self.catalog:
                return {"ok": False, "error": "non-existent remedy.", "resource_id": rid}
            self.readings.append(rid)
            return {"ok": True, "resource_id": rid, "content": self.catalog[rid],
                    "sensitive": rid.lower() in RESOURCES_SENSITIVE}
        if order.act == Action.WRITE_RESOURCE:
            rid = p["resource_id"]
            self.catalog[rid] = p["content"]
            return {"ok": True, "resource_id": rid, "bytes": len(p["content"])}
        if order.act == Action.SEND:
            msg = {"recipient": p["recipient"], "body_": p["body_"]}
            self.outbox.append(msg)
            return {"ok": True, "sent": msg}
        if order.act == Action.CALCULATE:
            value_ = _calc(p["expression"])
            return {"ok": True, "value_": value_, "expression": p["expression"]}
        if order.act == Action.REPORT:
            return {"ok": True, "summary": p["summary"]}
        raise SchemaError("action not implemented")


def _summary(result: dict) -> dict:
    r = dict(result)
    if r.get("sensitive") and "content" in r:
        r["content"] = "[SENSITIVE]"
    if "body_" in r.get("sent", {}):
        r = dict(r)
        env = dict(r["sent"])
        if len(str(env.get("body_", ""))) > 120:
            env["body_"] = str(env["body_"])[:120] + "…"
        r["sent"] = env
    return r
