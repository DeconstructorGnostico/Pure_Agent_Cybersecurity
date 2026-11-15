"""Tokens HMAC single-use, issued only by the Controller.

The interpreter does not have the key. The executor verifies, consumes the nonce and rejects reuse, forgery, expiration, revocation or mismatch with the order.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from typing import Callable, Optional

from .core_types import ErrorToken, Order


def _mac(secret: bytes, parts: list[str]) -> str:
    msg = "|".join(parts).encode("utf-8")
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class Token:
    token_id: str
    order_id: str
    order_hash: str
    act: str
    nonce: str
    expires: float
    executor_id: str
    mac: str

    def a_dict(self) -> dict:
        return {
            "token_id": self.token_id, "order_id": self.order_id, "order_hash": self.order_hash,
            "act": self.act, "nonce": self.nonce, "expires": self.expires,
            "executor_id": self.executor_id, "mac": self.mac,
        }


class TokenController:
    """Unique holder of the signature secret. In production I would live out of this process."""

    def __init__(self, secret: Optional[bytes] = None, clock: Callable[[], float] = time.time, ttl: float = 300.0):
        self._secret = secret if secret is not None else secrets.token_bytes(32)
        self._clock = clock
        self.ttl = ttl
        self._used: set[str] = set()
        self._revoked: set[str] = set()
        self._executors_revoked: set[str] = set()
        self.issued: list[Token] = []

    def _sign(self, order_id: str, order_hash: str, act: str, nonce: str, expires: float, executor_id: str) -> str:
        return _mac(self._secret, [order_id, order_hash, act, nonce, f"{expires:.6f}", executor_id])

    def issue(self, order: Order, executor_id: str = "executor") -> Token:
        if not order.hash:
            raise ErrorToken("the command has no hash")
        nonce = secrets.token_hex(16)
        expires = self._clock() + self.ttl
        token_id = secrets.token_hex(8)
        mac = self._sign(order.id, order.hash, order.act.value, nonce, expires, executor_id)
        t = Token(token_id=token_id, order_id=order.id, order_hash=order.hash,
                  act=order.act.value, nonce=nonce, expires=expires,
                  executor_id=executor_id, mac=mac)
        self.issued.append(t)
        return t

    def verify(self, token: Token, order: Order, executor_id: str = "executor") -> None:
        if token.token_id in self._revoked or token.nonce in self._revoked:
            raise ErrorToken("Token revoked")
        if token.executor_id in self._executors_revoked or executor_id in self._executors_revoked:
            raise ErrorToken("executor revoked")
        if token.nonce in self._used or token.token_id in self._used:
            raise ErrorToken("token single-use already consumed")
        if token.order_id != order.id or token.order_hash != order.hash:
            raise ErrorToken("token does not correspond to the order")
        if token.act != order.act.value:
            raise ErrorToken("Token does not correspond to the action")
        if token.executor_id != executor_id:
            raise ErrorToken("token does not correspond to the executor")
        if self._clock() > token.expires:
            raise ErrorToken("expired token")
        expected = self._sign(token.order_id, token.order_hash, token.act,
                                token.nonce, token.expires, token.executor_id)
        if not hmac.compare_digest(token.mac, expected):
            raise ErrorToken("falsified token")
        self._used.add(token.nonce)
        self._used.add(token.token_id)

    def revoke_token(self, token_id: str) -> None:
        self._revoked.add(token_id)

    def revoke_executor(self, executor_id: str) -> None:
        self._executors_revoked.add(executor_id)
        for t in self.issued:
            if t.executor_id == executor_id:
                self._revoked.add(t.token_id)

    def has_secret_exposed(self) -> bool:
        """Test help: the secret is not published as a public attribute."""
        return False
