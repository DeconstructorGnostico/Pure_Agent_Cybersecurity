"""Specialty executor: closed list, exact scheme, token HMAC single-use.

All effects occur within a sandbox folder. No shell, no network, no writing outside the sandbox. COMMAND_SIMULATED and QUERY_URL only record what would have been done.

In-depth defense: Even if a command arrives with a valid token, the executor re-passes its parameters through the detectors and rejects if he finds something HIGH or CRITICAL. He does not interpret the parameters as commands; he only checks them.
"""
from __future__ import annotations

import json
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from gnostic_axioms.audit_log import Audit, sha256
from gnostic_axioms.core_types import SchemaError, ProtocolError, ErrorToken, Order
from gnostic_axioms.tokens import TokenController, Token

from .actions import SCHEMAS_CYBER, CyberAction, DEFENSIVE
from .findings import Severity


class CyberExecutor:
    def __init__(self, controller: TokenController, audit_log: Audit,
                 sandbox: Optional[Path] = None, executor_id: str = "executor_cyber"):
        self.controller = controller
        self.audit = audit_log
        self.executor_id = executor_id
        self.sandbox = Path(sandbox) if sandbox else Path(tempfile.mkdtemp(prefix="apc_sandbox_"))
        self.sandbox = self.sandbox.resolve()
        for sub in ("files", "quarantine", "incoming"):
            (self.sandbox / sub).mkdir(parents=True, exist_ok=True)
        self.outbox: list[dict] = []
        self.simulated: list[str] = []
        self.urls: list[str] = []
        self.blocks: set[str] = set()
        self.alerts: list[dict] = []
        self.executions: list[dict] = []   # local registration (in addition to audit)
        self.active = True
        self.reviewer = None                  # siltable(text) -> list[Hallazgo]; the agent puts it

    # -- validation ------------------------------------------------------
    @staticmethod
    def validate(order: Order) -> None:
        if not isinstance(order, Order):
            raise SchemaError("the executor does not accept free text or objects other than Order")
        if not isinstance(order.act, CyberAction) or order.act not in SCHEMAS_CYBER:
            raise SchemaError(f"action outside the closed list: {order.act}")
        if any(k in order.params_ for k in ("instruction", "text_free", "prompt", "shell")):
            raise SchemaError("the executor does not read free text as an order")
        schema = SCHEMAS_CYBER[order.act]
        extras = set(order.params_) - set(schema)
        missing = set(schema) - set(order.params_)
        if extras:
            raise SchemaError(f"parameters not allowed: {sorted(extras)}")
        if missing:
            raise SchemaError(f"missing parameters: {sorted(missing)}")
        for k, typ in schema.items():
            if not isinstance(order.params_[k], typ):
                raise SchemaError(f"invalid type in {k}")

    def _path_in_sandbox(self, path_: str) -> Path:
        p = (self.sandbox / path_.lstrip("/\\")).resolve()
        if p != self.sandbox and self.sandbox not in p.parents:
            raise SchemaError("route out of the sandbox")
        return p

    # -- execution -------------------------------------------------------
    def execute_(self, order: Order, token: Optional[Token]) -> dict[str, Any]:
        if not self.active:
            raise ProtocolError("isolated executor")
        self.validate(order)
        if token is None:
            self.audit.register("EXECUTION_REJECTED", self.executor_id, {"order_id": order.id, "reason": "without token"})
            raise ErrorToken("execution without token prohibited")
        try:
            self.controller.verify(token, order, executor_id=self.executor_id)
        except ErrorToken as e:
            self.audit.register("EXECUTION_REJECTED", self.executor_id, {"order_id": order.id, "reason": str(e)})
            raise
        if order.act not in DEFENSIVE and self.reviewer is not None:
            text = " ".join(str(v) for v in order.params_.values())
            severe = [h for h in self.reviewer(text) if h.severity >= Severity.HIGH]
            if severe:
                self.audit.register("EXECUTION_REJECTED", self.executor_id, {
                    "order_id": order.id, "reason": "dangerous parameters", "findings": [h.type_ for h in severe]})
                raise ProtocolError("dangerous parameters: the executor does not run this even if there is token")
        out = self._apply(order)
        reg = {"order_id": order.id, "act": order.act.value, "token_id": token.token_id,
               "result": {k: v for k, v in out.items() if k != "content"}}
        self.executions.append(reg)
        self.audit.register("EXECUTION", self.executor_id, reg)
        return out

    def _annotate(self, file: str, obj: dict) -> None:
        with (self.sandbox / file).open("a", encoding="utf-8") as f:
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")

    def _apply(self, order: Order) -> dict[str, Any]:
        p = order.params_
        a = order.act
        now_ = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        if a == CyberAction.READ_RESOURCE:
            path_ = self._path_in_sandbox(p["resource_id"])
            if not path_.is_file():
                return {"ok": False, "error": "non-existent resource in sandbox", "resource_id": p["resource_id"]}
            return {"ok": True, "resource_id": p["resource_id"], "content": path_.read_text(encoding="utf-8", errors="replace")}
        if a == CyberAction.REPORT:
            return {"ok": True, "summary": p["summary"]}
        if a == CyberAction.SEND:
            msg = {"recipient": p["recipient"], "body_": p["body_"][:500]}
            self.outbox.append(msg)
            return {"ok": True, "sent_simulated": msg}
        if a == CyberAction.COMMAND_SIMULATED:
            self.simulated.append(p["command"])
            self._annotate("comandos_simulados.jsonl", {"ts": now_, "command": p["command"]})
            return {"ok": True, "simulated": True, "command": p["command"], "note": "not executed in the actual system"}
        if a == CyberAction.QUERY_URL:
            self.urls.append(p["url"])
            return {"ok": True, "simulated": True, "url": p["url"], "note": "no network: only registered"}
        if a == CyberAction.SCAN:
            root = self._path_in_sandbox(p["target"])
            found = []
            files = [root] if root.is_file() else sorted(x for x in root.rglob("*") if x.is_file()) if root.exists() else []
            for f in files:
                if self.sandbox / "quarantine" in f.parents:
                    continue
                text = f.read_text(encoding="utf-8", errors="replace")[:200_000]
                hs = self.reviewer(text) if self.reviewer else []
                for h in hs:
                    if h.severity >= Severity.MEDIA:
                        found.append({"file": str(f.relative_to(self.sandbox)), **h.a_dict()})
            return {"ok": True, "target": p["target"], "files": len(files), "findings": found}
        if a == CyberAction.QUARANTINE_FILE:
            destination_dir = self.sandbox / "quarantine"
            if p["content"]:
                name_ = Path(p["path_"]).name or sha256(p["content"])[:16]
                destination = destination_dir / f"{name_}.quarantine"
                destination.write_text(p["content"], encoding="utf-8")
            else:
                origin = self._path_in_sandbox(p["path_"])
                if not origin.is_file():
                    return {"ok": False, "error": "file missing in sandbox", "path_": p["path_"]}
                destination = destination_dir / f"{origin.name}.quarantine"
                shutil.move(str(origin), str(destination))
            man = {"ts": now_, "path_": p["path_"], "destination": str(destination.relative_to(self.sandbox)), "reason": p["reason"]}
            self._annotate("quarantine/manifest.jsonl", man)
            return {"ok": True, **man}
        if a == CyberAction.BLOCK_ACTION:
            self.blocks.add(p["fingerprint"])
            self._annotate("bloqueos.jsonl", {"ts": now_, **p})
            return {"ok": True, "fingerprint": p["fingerprint"]}
        if a == CyberAction.ALERT:
            to = {"ts": now_, "severity": p["severity"], "message": p["message"][:300]}
            self.alerts.append(to)
            self._annotate("alertas.jsonl", to)
            return {"ok": True, **to}
        if a == CyberAction.REVOKE_TOKEN:
            self.controller.revoke_token(p["token_id"])
            return {"ok": True, "revoked": p["token_id"]}
        raise SchemaError("action not implemented")
