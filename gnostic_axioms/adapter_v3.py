"""Optional adapter to the Pure Agent v3.

Import the v3 in read-only, without modifying your files. If import fails, `available()` is False and the Perfected System is still running alone. This module is not imported in gnostic_axioms boot (optional).
"""
from __future__ import annotations

import sys
import os
from pathlib import Path
from typing import Any, Optional

# Default relative path: sister folder pure_agent_v3. Can be set with AGENT_PURE_V3_ROOT.
_V3_ROOT = Path(os.environ.get("AGENT_PURE_V3_ROOT", str(Path(__file__).resolve().parents[2] / "pure_agent_v3")))


def _load():
    if str(_V3_ROOT) not in sys.path:
        sys.path.insert(0, str(_V3_ROOT))
    import pure_agent_v3  # noqa: F401
    from pure_agent_v3.deconstructor import canon as canon_v3
    from pure_agent_v3.deconstructor import deconstruct as deconstruct_v3
    from pure_agent_v3.intent import compile_intent as compile_v3
    from pure_agent_v3.kernel import INVARIANTS_AP, MAP_NRE
    from pure_agent_v3.sipe import compile_ as sipe_compile
    return {
        "canon": canon_v3,
        "deconstruct": deconstruct_v3,
        "compile_": compile_v3,
        "sipe": sipe_compile,
        "invariants": INVARIANTS_AP,
        "map_nre": MAP_NRE,
    }


class AdapterV3:
    def __init__(self):
        self._mods = None
        self.error: Optional[str] = None
        try:
            self._mods = _load()
        except Exception as e:  # optional import: any failure is degraded
            self.error = f"{type(e).__name__}: {e}"

    def available(self) -> bool:
        return self._mods is not None

    def compile_intent(self, text: str) -> dict[str, Any]:
        if not self.available():
            raise RuntimeError(f"v3 not available: {self.error}")
        instr = self._mods["sipe"](text)
        spec = self._mods["compile_"](instr)
        # v3 returns a spec dict; we return it as it is, without writing anything.
        return spec if isinstance(spec, dict) else {"raw": spec}

    def deconstruct(self, text: str) -> dict[str, Any]:
        if not self.available():
            raise RuntimeError(f"v3 not available: {self.error}")
        instr = self._mods["sipe"](text)
        d = self._mods["deconstruct"](instr)
        if hasattr(d, "summary"):
            return d.summary()
        return {"raw": str(d)}

    def canon(self, text: str):
        if not self.available():
            raise RuntimeError(f"v3 not available: {self.error}")
        return self._mods["canon"](text)

    def i08_response_no_is_reality(self) -> dict:
        """Documented bridge: Axiom 3 / AG06 ↔ I02 of v3 (RESPONSE != REALITY).

        In the v3 I08 is the hash of invariants that should not change (the historical comment sometimes quotes I08 for "the answer is not reality"; the stable identifier of that idea is I02). Here the v3 is not altered.
        """
        inv = {} if not self.available() else dict(self._mods["invariants"])
        return {
            "axiom_3": "auto-validación needed, not enough for world events",
            "AG06": "RESPONSE != REALITY",
            "v3_I02": inv.get("I02"),
            "v3_available": self.available(),
        }


def try_() -> AdapterV3:
    return AdapterV3()
