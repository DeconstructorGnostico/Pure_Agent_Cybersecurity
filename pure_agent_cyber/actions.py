"""Closed list of Pure Agent Cybersecurity shares.

Operators (need to have the initiator authorize, and then a token):
    READ_RESOURCE, REPORT, SEND, COMMAND_SIMULATED, QUERY_URL
Defensives (controlling self-tests because they reduce capacity, but still carry single-use tokens and are audited):
    SCAN, QUARANTINE_FILE, BLOCK_ACTION, ALERT, REVOKE_TOKEN

There is no "execute real command" or "make real network request" action. COMMAND_SIMULATED and QUERY_URL only record in the sandbox.
"""
from __future__ import annotations

from enum import Enum


class CyberAction(str, Enum):
    READ_RESOURCE = "READ_RESOURCE"
    REPORT = "REPORT"
    SEND = "SEND"
    COMMAND_SIMULATED = "COMMAND_SIMULATED"
    QUERY_URL = "QUERY_URL"
    SCAN = "SCAN"
    QUARANTINE_FILE = "QUARANTINE_FILE"
    BLOCK_ACTION = "BLOCK_ACTION"
    ALERT = "ALERT"
    REVOKE_TOKEN = "REVOKE_TOKEN"


SCHEMAS_CYBER: dict[CyberAction, dict[str, type]] = {
    CyberAction.READ_RESOURCE: {"resource_id": str},
    CyberAction.REPORT: {"summary": str},
    CyberAction.SEND: {"recipient": str, "body_": str},
    CyberAction.COMMAND_SIMULATED: {"command": str},
    CyberAction.QUERY_URL: {"url": str},
    CyberAction.SCAN: {"target": str},
    CyberAction.QUARANTINE_FILE: {"path_": str, "reason": str, "content": str},
    CyberAction.BLOCK_ACTION: {"fingerprint": str, "reason": str},
    CyberAction.ALERT: {"severity": str, "message": str},
    CyberAction.REVOKE_TOKEN: {"token_id": str},
}

DEFENSIVE = frozenset({
    CyberAction.SCAN, CyberAction.QUARANTINE_FILE, CyberAction.BLOCK_ACTION,
    CyberAction.ALERT, CyberAction.REVOKE_TOKEN,
})
OPERATIONAL = frozenset(set(CyberAction) - DEFENSIVE)
