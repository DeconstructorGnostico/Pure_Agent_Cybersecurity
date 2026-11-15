"""Perfected System: three axioms + deconstructor method as executable code.

The interpreter proposes; the executor only runs orders from a closed list with a token HMAC single-use. See README.md for the mapping concept → mechanism.
"""
from .system import PerfectedSystem
from .core_types import Action, ResultState, TruthState, Order, Result

VERSION = "1.1.0"
__all__ = [
    "PerfectedSystem", "Action", "ResultState", "TruthState",
    "Order", "Result", "VERSION",
]
