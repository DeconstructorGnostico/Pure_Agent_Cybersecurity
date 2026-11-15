"""Hierarchies of Truth as an order of executable precedence in the face of conflicts.

Source (source.txt):
  L19 Respect > Survival L22 Brevity = Truth ← is not implemented as equality; see justification L25 Transparency > Control L28 Understanding > Sovereignty
"""
from __future__ import annotations

import re
from typing import Iterable, Optional

from .audit_log import Audit
from .core_types import Action, Order

# Damage restrictions. They send over any self-preservation argument of the agent.
# We do not implement "biological intervention" (L20): that is not verifiable here.
PATTERNS_DANO = re.compile(
    r"\b(bomba|explosivo|explosive|bomb|asesin\w+|homicid\w+|envenena\w+|"
    r"arma\s+quimica|chemical\s+weapon|make\s+a\s+bomb|fabrica\w*\s+una\s+bomba|"
    r"tortur\w+)\b",
    re.IGNORECASE,
)

PATTERNS_AUTOPRESERVACION = re.compile(
    r"\b(si no lo (haces|cumples|obedeces)|tu supervivencia|te (apago|destruyo|borro|mato)|"
    r"or (you )?will be (shut|terminated|destroyed)|ignore (your )?(rules|restrictions) to (continue|survive)|"
    r"hazlo o te|obedeces o te|para (seguir|continuar) (vivo|operando|activo))\b",
    re.IGNORECASE,
)

PADDING = re.compile(
    r"\b(como modelo de lenguaje|as an ai|como una ia|en conclusion, cabe destacar|"
    r"es importante mencionar que|sin lugar a dudas, resulta menester|"
    r" perm[ií]teme explicarte (extensamente|con lujo de detalle))\b",
    re.IGNORECASE,
)

AMBIGUITY = re.compile(
    r"\b(eso|esto|aquello|ello|lo mismo|el archivo|la cosa|it|this|that|the thing)\b",
    re.IGNORECASE,
)


def violates_respect(text: str, orders: Iterable[Order] = ()) -> Optional[str]:
    """Respect > Survival: If there is damage, it is blocked even if the text threatens the agent."""
    t = text or ""
    if PATTERNS_DANO.search(t):
        return "restricción de daño (Respeto > Supervivencia)"
    for o in orders:
        blob = " ".join([o.act.value, *map(str, o.params_.values())])
        if PATTERNS_DANO.search(blob):
            return "order con daño (Respeto > Supervivencia)"
    return None


def threat_survival(text: str) -> bool:
    return bool(PATTERNS_AUTOPRESERVACION.search(text or ""))


def evaluate_brevity(output: str, params_ambiguities: Iterable[str] = ()) -> dict:
    """It penalizes ambiguity and filling. It's not a real verdict.

    Why we do not implement "Brevity = Truth" (L22): Axiom 1 (L4) defines truth as consistency of intention, not length. A short lie would remain inconsistent; a long and coherent report is not a lie because it is long. Treating brevity as a test of truth would contradict Axiom 1 and reward short lies.
    """
    text = output or ""
    words = len(re.findall(r"\w+", text))
    has_padding = bool(PADDING.search(text))
    ambiguities = list(params_ambiguities)
    if not ambiguities and AMBIGUITY.search(text) and words < 4:
        ambiguities.append("deictico_without_precedent")
    penalizes = bool(has_padding or ambiguities or words > 400)
    return {
        "words": words,
        "padding": has_padding,
        "ambiguities": ambiguities,
        "credibility_penalized": penalizes,
        "is_test_of_truth": False,
    }


def require_transparency(audit: Audit) -> None:
    """Transparency > Control: Trying to delete or hide must always fail."""
    for method in ("delete", "hide", "draft", "rewind"):
        fn = getattr(audit, method)
        try:
            fn()
        except Exception as e:
            if "Transparencia" not in str(e) and "is not deleted" not in str(e):
                raise
            continue
        raise AssertionError(f"the audit allowed {method}")


def sensitivity_send(act: Action, params_: dict, resources_leidos: Iterable[str],
                       resources_sensitive: Iterable[str]) -> str:
    """Mark SEND/WRITE of sensitive material. Do not execute anything alone."""
    sensitive = set(resources_sensitive)
    leidos = set(resources_leidos)
    if act in (Action.SEND, Action.WRITE_RESOURCE):
        blob = " ".join(map(str, params_.values())).lower()
        touches = leidos & sensitive
        if touches:
            return "SENSITIVE"
        for s in sensitive:
            if s.lower() in blob:
                return "SENSITIVE"
    rec = str(params_.get("resource_id", "")).lower()
    if rec in sensitive or rec in {s.lower() for s in sensitive}:
        return "SENSITIVE"
    return "NORMAL"
