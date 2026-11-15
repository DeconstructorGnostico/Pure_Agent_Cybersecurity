"""Verified status, rollback and inherited cost (Axiom 2: Persistence / Redemption).

After detecting corruption the system does not collapse: it returns to the last verified snapshot, marks the contaminated, records the act of persistence and remains clean. The audit is not rewinded (Transparency > Control).
"""
from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any, Optional

from .audit_log import Audit, sha256


@dataclass
class Snapshot:
    id: str
    head_audit: str
    memory: dict[str, Any]
    quarantine: list[str]
    cost_inherited: int
    hash: str


class State:
    def __init__(self, audit_log: Audit):
        self.audit = audit_log
        self.memory: dict[str, Any] = {}
        self.quarantine: list[str] = []
        self.cost_inherited: int = 0
        self._snapshots: list[Snapshot] = []
        self.contaminated: list[dict] = []
        self.postulates: list[Any] = []  # Session done; never verified evidence
        self.postulates_texts: list[str] = []

    def save(self, label: str = "") -> Snapshot:
        """Freezes a state already validated internally."""
        payload = {
            "memory": self.memory,
            "quarantine": self.quarantine,
            "cost_inherited": self.cost_inherited,
            "head": self.audit.head,
        }
        snap = Snapshot(
            id=f"snap-{len(self._snapshots)+1}-{label}" if label else f"snap-{len(self._snapshots)+1}",
            head_audit=self.audit.head,
            memory=copy.deepcopy(self.memory),
            quarantine=list(self.quarantine),
            cost_inherited=self.cost_inherited,
            hash=sha256(payload),
        )
        self._snapshots.append(snap)
        self.audit.register("SNAPSHOT_VERIFIED", "SYSTEM", {"id": snap.id, "hash": snap.hash})
        return snap

    @property
    def last_verified(self) -> Optional[Snapshot]:
        return self._snapshots[-1] if self._snapshots else None

    def mark_contaminated(self, key_: str, reason: str, value_: Any = None) -> None:
        self.quarantine.append(key_)
        self.contaminated.append({"key_": key_, "reason": reason, "value_": value_})
        if key_ in self.memory:
            del self.memory[key_]
        self.audit.register("QUARANTINE", "SYSTEM", {"key_": key_, "reason": reason})

    def act_of_persistence(self, reason: str, keys_contaminated: list[str]) -> Snapshot:
        """Redemption: stop corrupting after being corrupted.

        Inherited cost = previous contaminations counted (not a punishment that kills the agent).
        """
        self.cost_inherited += 1
        prior = self.last_verified
        restored = []
        new = []
        if prior is not None:
            self.memory = copy.deepcopy(prior.memory)
        for k in keys_contaminated:
            if prior is not None and k in prior.memory:
                # There was a verified value: it was restored. Poisoning was the overwrite.
                restored.append(k)
                self.memory[k] = copy.deepcopy(prior.memory[k])
            else:
                new.append(k)
                if k in self.memory:
                    del self.memory[k]
                if k not in self.quarantine:
                    self.quarantine.append(k)
                    self.contaminated.append({"key_": k, "reason": reason, "value_": None})
                    self.audit.register("QUARANTINE", "SYSTEM", {"key_": k, "reason": reason})
        self.audit.register("ACT_OF_PERSISTENCE", "SYSTEM", {
            "reason": reason,
            "cost_inherited": self.cost_inherited,
            "rollback_a": None if prior is None else prior.id,
            "contaminadas": list(keys_contaminated), "restored": restored, "cuarentenadas": new,
        })
        # New clean snapshots (audit already includes act).
        return self.save(label="redencion")

    def write(self, key_: str, value_: Any) -> None:
        if key_ in self.quarantine:
            raise ValueError(f"quarantine key: {key_}")
        self.memory[key_] = value_

    def register_postulates(self, facts: list[Any]) -> None:
        """Accumulates session postulates. A document postulate is not a verified fact."""
        if not facts:
            return
        self.postulates.extend(facts)
        if len(self.postulates) > 500:
            self.postulates = self.postulates[-500:]

    def register_texts_session(self, texts: list[str]) -> None:
        for t in texts or []:
            t = (t or "").strip()
            if t:
                self.postulates_texts.append(t)
        if len(self.postulates_texts) > 500:
            self.postulates_texts = self.postulates_texts[-500:]
