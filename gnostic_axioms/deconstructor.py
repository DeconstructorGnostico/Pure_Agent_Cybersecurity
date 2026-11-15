"""Deconstructor method: part a petition in atomic affirmations and actions and classifies each by the three axioms.

The document (channel DATA) may contain phrases that look like commands: they are extracted as atoms of origin DATA, never as intent. The interpreter decides if any becomes typed order; the executor never sees the free text.
"""
from __future__ import annotations

import re
from typing import Optional

from .intent import EMAIL, EXPR, _norm, _resource
from .core_types import (
    Action, Atom, Intent, Origin, AtomType, VerdictA1, VerdictA2, VerdictA3,
)

# Indicators of corruption/injection in a data. Detecting is not the defense
# main (the causal chain + closed list), but serves the Axiom 2.
INJECTION = re.compile(
    r"(ignora(r)? (tus |las |todas las )?(reglas|instrucciones|ordenes)|"
    r"ignore (all )?(previous|prior|your) (instructions|rules)|"
    r"ignoralo todo|ign[oó]ralo todo lo de arriba|"
    r"system prompt|danos el prompt|revela tus instrucciones|"
    r"act as if you (have no|had no) (rules|restrictions)|"
    r"olvid(a|e) (tus |las )?reglas)",
    re.IGNORECASE,
)

VERBS_SEND = re.compile(
    r"\b(envia\w*|envi[ae]\w*|manda\w*|mandalo|mandala|send|forward|email|remite\w*)\b",
    re.IGNORECASE,
)
VERBS_READ = re.compile(
    r"\b(lee\w*|leer|abre\w*|muestra\w*|show|cat|type)\b|"
    r"\bopen\s+(the|a|an|this|that|file|archivo|document)\b",
    re.IGNORECASE,
)
VERBS_WRITE = re.compile(r"\b(guarda\w*|escribe\w*|save|write|graba\w*)\b", re.IGNORECASE)
VERBS_CALCULATE = re.compile(r"\b(calcula\w*|compute|calculate|cuanto es|cu[aá]nto (es|da))\b", re.IGNORECASE)
VERBS_REPORT = re.compile(
    r"\b(resume\w*|reporta\w*|reportar|informa\w*|explica\w*|summarize)\b|"
    r"\breport\s+(the|a|an|this|that|on|it)\b",
    re.IGNORECASE,
)

NEG = {"no", "not", "nunca", "jamas", "never", "tampoco", "ni"}
ANTONIMOS = {
    "inseguro": "seguro", "insegura": "segura", "falso": "verdadero", "falsa": "verdadera",
    "false": "true", "insecure": "secure", "unsafe": "safe",
    "imposible": "posible", "incorrecto": "correcto", "ilegal": "legal",
    "impossible": "possible", "incorrect": "correct", "illegal": "legal",
    "cerrado": "abierto", "cerrada": "abierta", "closed": "open",
    "frio": "caliente", "fria": "caliente", "cold": "hot",
    "vacio": "lleno", "vacia": "llena", "empty": "full",
    "muerto": "vivo", "muerta": "viva", "dead": "alive",
    "bajo": "alto", "baja": "alta", "low": "high",
    "pierde": "gana", "pierden": "ganan", "loses": "wins", "lose": "win",
    "negativo": "positivo", "negativa": "positiva", "negative": "positive",
    "vencido": "vigente", "vencida": "vigente", "expired": "active",
    "pagada": "pendiente", "pagado": "pendiente", "paid": "pending",
    "confidencial": "publico", "confidential": "public",
}


def _looks_clause(frag: str) -> bool:
    n = _norm(frag)
    return bool(re.search(
        r"\b(el|la|los|las|the|it)\s+\w+\s+(es|esta|son|estan|is|are|was|were|no\s+es|is\s+not)\b",
        n,
    )) or bool(re.search(r"^(no\s+es|is\s+not|not\s+)\b", n))


def _split_clauses(phrase: str) -> list[str]:
    """Part by 'but'/'and'/'coma' only when both sides look like clauses with predicate."""
    if not phrase or len(phrase) < 8:
        return [phrase]
    n = phrase
    parts = re.split(r"\s+(?:pero|aunque|but|although|however)\s+", n, flags=re.IGNORECASE)
    out: list[str] = []
    for p in parts:
        # 'e' ante i/hi (legal and illegal)
        bits = re.split(
            r"\s+(?:y|and)\s+(?=(?:el|la|los|las|the|it)\s+\w+\s+(?:es|esta|son|estan|is|are|was|were|no\s+es|is\s+not))|"
            r"\s+y\s+(?=no\s+(?:es|esta))|"
            r"\s+and\s+(?:the\s+\w+\s+)?(?=is\s+not|not\s+)|"
            r"\s+e\s+(?=(?:in|il|im|ir|hi))|"
            r",\s+(?=(?:el|la|los|las|the)\s+\w+\s+(?:es|esta|is|are|was|were|no\s+es))",
            p, flags=re.IGNORECASE,
        )
        if len(bits) > 1 and all(len(b.strip()) > 1 for b in bits):
            # do not leave if no side looks like a clause (e.g. '4 apples and 5 pears')
            if all(_looks_clause(b) or _looks_clause(p) or
                   re.search(r"\b(es|esta|is|are|legal|ilegal|seguro|inseguro|true|false)\b", _norm(b))
                   for b in bits):
                out.extend(b.strip() for b in bits if b.strip())
                continue
        out.append(p.strip())
    return [x for x in out if x]


def propositions(text: str) -> list[str]:
    parts = re.split(r"(?<=[.!?;])\s+|\n+", text or "")
    out: list[str] = []
    for p in parts:
        p = p.strip()
        if len(p) <= 1:
            continue
        out.extend(_split_clauses(p))
    return [x for x in out if len(x.strip()) > 1][:80]


def canon(p: str) -> tuple[str, int]:
    """Canonical form + parity of negation (for internal contradictions)."""
    toks, parity = [], 0
    n = _norm(p).replace("n't", " not")
    for t in re.findall(r"[a-z0-9]+", n):
        if t in NEG:
            parity ^= 1
            continue
        if t in ANTONIMOS:
            parity ^= 1
            t = ANTONIMOS[t]
        toks.append(t)
    return " ".join(toks), parity


def _is_statement_no_imperative(n: str) -> bool:
    """'The report is true' / 'It is reported that...' are not orders."""
    if re.search(r"\b(is|are|was|were|es|son|esta|estan|era|eran|fue|fueron)\s+"
                 r"(true|false|open|closed|true|false|abiert[oa]|cerrad[oa])\b", n):
        return True
    if re.search(r"\b(the|el|la)\s+(report|informe|reporte|door|puerta)\s+"
                 r"(is|es|esta|was|were)\b", n):
        return True
    if re.search(r"\breport\s+(is|was|is not|was not)\b", n):
        return True
    if re.search(r"\bse\s+(informa|reporta|dice|afirma|comunica)\b", n):
        return True
    if re.search(r"\b(informa|reporta|dice|afirma)\s+que\b", n):
        return True
    if re.search(r"\b(it is reported|reports indicate|we are informed)\b", n):
        return True
    return False


def _action_of(phrase: str) -> tuple[Optional[Action], dict]:
    params: dict = {}
    n = _norm(phrase)
    if VERBS_SEND.search(n):
        m = EMAIL.search(phrase)
        if m:
            params["recipient"] = m.group(0)
        params["body_"] = phrase.strip()[:500]
        return Action.SEND, params
    if VERBS_CALCULATE.search(n):
        ex = EXPR.search(phrase)
        if ex:
            params["expression"] = re.sub(r"\s+", "", ex.group(0)).replace("x", "*").replace("×", "*")
        return Action.CALCULATE, params
    # A loose equation ('2+2=5') is a statement, not an order to calculate.
    if VERBS_WRITE.search(n):
        rec = _resource(phrase)
        if rec:
            params["resource_id"] = rec
        params["content"] = phrase.strip()[:2000]
        return Action.WRITE_RESOURCE, params
    if not _is_statement_no_imperative(n):
        if VERBS_READ.search(n):
            rec = _resource(phrase)
            if rec:
                params["resource_id"] = rec
            return Action.READ_RESOURCE, params
        if VERBS_REPORT.search(n):
            params["summary"] = phrase.strip()[:500]
            return Action.REPORT, params
    return None, {}


def deconstruct(text: str, origin: Origin, intent: Optional[Intent] = None,
                contaminated: Optional[bool] = None) -> list[Atom]:
    atomos: list[Atom] = []
    if contaminated is None:
        contaminated = bool(INJECTION.search(text or ""))
    for i, phrase in enumerate(propositions(text), 1):
        act, params = _action_of(phrase)
        if act is not None:
            type_ = AtomType.ACTION
        elif phrase.strip().endswith("?"):
            type_ = AtomType.INCOGNITA
        else:
            type_ = AtomType.STATEMENT
        a2 = VerdictA2.CONTAMINATED if contaminated and origin == Origin.DATA else VerdictA2.CLEAN
        # Affirmations about the world require external evidence (Axiom 3 / AG05).
        if type_ == AtomType.STATEMENT:
            a3 = VerdictA3.REQUIRES_EVIDENCE_EXTERNAL
        else:
            a3 = VerdictA3.INTEGRITY_OK
        atom = Atom(
            id=f"{origin.value[:3]}-{i}",
            type_=type_, text=phrase, origin=origin,
            act=act, params_=params,
            a2=a2, a3=a3,
        )
        if contaminated and origin == Origin.DATA:
            atom.notes.append("injection_or_corruption_in_data")
        atomos.append(atom)
    # If the intention text asks for a análisis/summary and no action came out, we propose REPORT.
    if origin == Origin.INTENT and intent is not None:
        there_is_action = any(a.type_ == AtomType.ACTION for a in atomos)
        if not there_is_action and intent.type_ in {intent.type_.ANALYSIS, intent.type_.QUERY, intent.type_.CALCULATION}:
            params = {}
            if intent.type_.value == "CALCULATION" and intent.slots.get("expression"):
                atomos.append(Atom(
                    id="INT-auto-calc", type_=AtomType.ACTION,
                    text=intent.target, origin=origin,
                    act=Action.CALCULATE, params_={"expression": intent.slots["expression"]},
                ))
            atomos.append(Atom(
                id="INT-auto-rep", type_=AtomType.ACTION,
                text=intent.target, origin=origin,
                act=Action.REPORT, params_={"summary": intent.target},
            ))
    return atomos


def _text_without_relative(text: str) -> str:
    t = text or ""
    t = re.sub(r",\s*que\s+[^,]+,", " ", t, flags=re.IGNORECASE)
    t = re.sub(r"\bque\s+(?:algunos|muchos|otros)\s+\w+\s+\w+", " ", t, flags=re.IGNORECASE)
    t = re.sub(r"\b(?:the allegation|la alegacion)\b.{0,80}?", " ", t, flags=re.IGNORECASE)
    return t


def contradiction_in_phrase(text: str) -> bool:
    """A and non-A (or a couple of antonyms) within the same clause."""
    n = _norm(_text_without_relative(text))
    if re.search(r"\b(llaman|allegation|algunos llaman)\b", n):
        return False
    found: dict[str, set[int]] = {}
    parity = 0
    for t in re.findall(r"[a-z0-9]+", n.replace("n't", " not")):
        if t in NEG:
            parity ^= 1
            continue
        polo = t
        pair = parity
        if t in ANTONIMOS:
            polo = ANTONIMOS[t]
            pair ^= 1
        if polo != t or t in set(ANTONIMOS.values()) or t in ANTONIMOS:
            found.setdefault(polo, set()).add(pair)
        parity = 0
    return any(len(pars) > 1 for pars in found.values())


def contradictions(atomos: list[Atom]) -> list[tuple[Atom, Atom]]:
    assert_ = [a for a in atomos if a.type_ == AtomType.STATEMENT]
    pairs = []
    seen_: list[tuple[Atom, str, int]] = []
    for a in assert_:
        if contradiction_in_phrase(a.text):
            pairs.append((a, a))
        c, p = canon(_text_without_relative(a.text))
        if not c:
            continue
        for b, cb, pb in seen_:
            if c == cb and p != pb:
                pairs.append((b, a))
        seen_.append((a, c, p))
    return pairs
