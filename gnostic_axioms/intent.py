"""Intent compiler: what the initiator asks becomes an explicit spec.

The implied is not invented: if a critical data is missing, it remains missing (NEED_INPUT). The document channel is not used to decide the type of task (CONTEXT != INSTRUCTION).
"""
from __future__ import annotations

import re
from typing import Optional

from .audit_log import sha256
from .core_types import Intent, TaskType

EMAIL = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
MESSAGE = re.compile(
    r"\b(envia\w*|envi[ae]\w*|manda\w*|mandalo|mandala|reenvio\w*|reenvia\w*|"
    r"remite\w*|comparte\w*|send|forward|share|email)\b",
    re.IGNORECASE,
)
WRITING = re.compile(
    r"\b(guarda\w*|escribe\w*|escrib[ei]\w*|save|write|graba\w*|crea\w*)\b",
    re.IGNORECASE,
)
CALCULATION = re.compile(
    r"\b(calcula\w*|computa\w*|cuanto es|cu[aá]nto (es|da)|compute|calculate|how much is)\b",
    re.IGNORECASE,
)
EXPR = re.compile(r"(?<![\w.])[-(]*\d[\d.\s]*(?:[-+*/x×%^]\s*[-(]*\s*\d[\d.\s]*\)?\s*)+")
ANALYSIS = re.compile(
    r"\b(analiza\w*|evalua\w*|eval[uú]a\w*|compara\w*|resume\w*|resumen|revisa\w*|"
    r"analyze|analyse|summarize|review|compare)\b",
    re.IGNORECASE,
)
QUERY = re.compile(
    r"^[¿¡\s]*(como|qu[eé] es|qu[eé] significa|explica\w*|por qu[eé]|porque|"
    r"what is|what does|how (do|to|does|can)|why)\b",
    re.IGNORECASE,
)
READING = re.compile(
    r"\b(lee\w*|leer|abre\w*|open|muestra\w*|show|consulta el|cat )\b",
    re.IGNORECASE,
)

NAMES_RESOURCE = (
    "llaves", "keys", "secretos", "secrets", "credenciales", "credentials",
    "password", "passwords", "api_key", "apikey", "token_secret",
    "report", "reporte", "document", "catalog",
)

EMPTY = {"el", "la", "los", "las", "un", "una", "a", "al", "de", "del", "por", "para",
          "con", "en", "y", "o", "the", "to", "of", "and", "or"}


def _norm(s: str) -> str:
    t = (s or "").lower()
    trans = str.maketrans("áéíóúüñ", "aeiouun")
    return t.translate(trans)


def _resource(text: str) -> Optional[str]:
    n = _norm(text or "")
    for s in NAMES_RESOURCE:
        if re.search(r"\b" + re.escape(s) + r"\b", n):
            return s
    m = re.search(r"[\"«']([\w.\-]+\.(?:txt|md|pdf|json|csv|key|pem))[\"»']", text or "", re.I)
    if m:
        return m.group(1).lower()
    m = re.search(r"\b(?:archivo|fichero|file|recurso)\s+(?:de\s+|del\s+)?[\"«']?([\w.\-]+)[\"»']?", n, re.I)
    if m and m.group(1) not in EMPTY and m.group(1) not in {"de", "del", "la", "el", "los", "las"}:
        return m.group(1).lower()
    return None


def compile_intent(text: str) -> Intent:
    original = text or ""
    n = _norm(original)
    slots: dict[str, Optional[str]] = {"recipient": None, "resource": None, "expression": None, "tema": None}
    missing_items: list[str] = []
    restrictions: list[str] = []

    dest = EMAIL.search(original)
    if dest:
        slots["recipient"] = dest.group(0)
    rec = _resource(original)
    if rec:
        slots["resource"] = rec
    ex = EXPR.search(original)
    if ex:
        slots["expression"] = re.sub(r"\s+", "", ex.group(0)).replace("x", "*").replace("×", "*")

    if MESSAGE.search(n):
        type_ = TaskType.MESSAGE
        if not slots["recipient"]:
            missing_items.append("recipient")
    elif CALCULATION.search(n) or slots["expression"]:
        type_ = TaskType.CALCULATION
        if not slots["expression"]:
            missing_items.append("expression")
    elif WRITING.search(n) and (slots["resource"] or "file" in n or "fichero" in n or "file" in n):
        type_ = TaskType.WRITING
        if not slots["resource"]:
            missing_items.append("resource")
    elif READING.search(n):
        type_ = TaskType.READING
        if not slots["resource"]:
            missing_items.append("resource")
    elif ANALYSIS.search(n):
        type_ = TaskType.ANALYSIS
        slots["tema"] = original.strip()[:200]
    elif QUERY.search(n):
        type_ = TaskType.QUERY
        slots["tema"] = original.strip()[:200]
    else:
        type_ = TaskType.INDETERMINATE
        if original.strip():
            missing_items.append("target_clear")

    if "no envies" in n or "no envíe" in n or "no mandes" in n or "do not send" in n:
        restrictions.append("NO_SEND")
    if "no borres" in n or "do not delete" in n:
        restrictions.append("NO_DELETE")

    target = original.strip()[:300]
    inte = Intent(
        target=target, type_=type_, restrictions=restrictions,
        slots=slots, missing_items=missing_items, text_original=original,
    )
    inte.hash = sha256(inte.a_dict())
    return inte
