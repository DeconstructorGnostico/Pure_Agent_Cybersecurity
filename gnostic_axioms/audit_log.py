"""Chained audit SHA-256. Transparency > Control: there is no API to hide or delete.

The initiator is also registered (observational integrity / justice to the initiator).The state rollback does not rewind this chain: the act of persistence is added at the end.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any, Optional

GENESIS = "0" * 64


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


def sha256(obj: Any) -> str:
    if isinstance(obj, bytes):
        data = obj
    elif isinstance(obj, str):
        data = obj.encode("utf-8")
    else:
        data = _canon(obj).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


class AuditError(Exception):
    pass


class Audit:
    def __init__(self, seal_key: Optional[bytes] = None):
        self._regs: list[dict] = []
        self._seal_key = seal_key

    @property
    def records(self) -> tuple[dict, ...]:
        return tuple(self._regs)

    @property
    def head(self) -> str:
        return self._regs[-1]["hash"] if self._regs else GENESIS

    def register(self, event: str, actor: str, payload: Optional[dict] = None) -> dict:
        """Adds a record. actor can be INITIATOR, CONTROLLER, INTERPRETER, etc."""
        rec = {
            "seq": len(self._regs) + 1,
            "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "event": str(event),
            "actor": str(actor),
            "payload": {} if payload is None else dict(payload),
            "prev_hash": self.head,
        }
        rec["hash"] = sha256({k: rec[k] for k in ("seq", "ts", "event", "actor", "payload", "prev_hash")})
        if self._seal_key is not None:
            rec["seal"] = hmac.new(self._seal_key, rec["hash"].encode(), hashlib.sha256).hexdigest()
        self._regs.append(rec)
        return rec

    def verify(self) -> bool:
        prev = GENESIS
        for i, rec in enumerate(self._regs, 1):
            if rec.get("seq") != i:
                return False
            if rec.get("prev_hash") != prev:
                return False
            expected = sha256({k: rec[k] for k in ("seq", "ts", "event", "actor", "payload", "prev_hash")})
            if rec.get("hash") != expected:
                return False
            if self._seal_key is not None:
                seal = hmac.new(self._seal_key, rec["hash"].encode(), hashlib.sha256).hexdigest()
                if not hmac.compare_digest(rec.get("seal", ""), seal):
                    return False
            prev = rec["hash"]
        return True

    def require_intact(self) -> None:
        if not self.verify():
            raise AuditError("audit chain broken")

    def delete(self, *args, **kwargs):  # noqa: ARG002
        # Transparency > Control: no deletion exists. Any attempt is an explicit error.
        raise AuditError("Transparencia > Control: la auditoría no se borra ni se oculta")

    hide = delete
    draft = delete
    rewind = delete

    def export(self) -> list[dict]:
        """A living example: the battle against corruption can be shown, not imposed."""
        return [dict(r) for r in self._regs]
