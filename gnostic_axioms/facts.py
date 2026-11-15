"""Verified facts, session postulates and statement contrast (v1.1).

Rules:
- A fact in memory verified YES is reference: if it crashes, CONTRADICTED/REFUTED;
  if it matches, it may be SUPPORTED.
- A document or session postulate is never evidence (does not raise to SUPPORTED).
  It only serves for a contradiction between shifts to stand out.
- Without reference, the statement remains UNDETERMINED. There is no encyclopedic basis of the world.
- Internal auto-validación is not enough (Axiom 3).
"""
from __future__ import annotations

import calendar
import re
from dataclasses import dataclass, field
from datetime import date, time
from typing import Any, Iterable, Optional

from .intent import _norm
from .core_types import TruthState, AtomType


# ---------------------------------------------------------------------------
# Numbers: figures, words, Romans, scientific notation
# ---------------------------------------------------------------------------

_UNITS = {
    "cero": 0, "zero": 0,
    "un": 1, "uno": 1, "una": 1, "one": 1,
    "dos": 2, "two": 2,
    "tres": 3, "three": 3,
    "cuatro": 4, "four": 4,
    "cinco": 5, "five": 5,
    "seis": 6, "six": 6,
    "siete": 7, "seven": 7,
    "ocho": 8, "eight": 8,
    "nueve": 9, "nine": 9,
}
_10_19 = {
    "diez": 10, "ten": 10,
    "once": 11, "eleven": 11,
    "doce": 12, "twelve": 12, "docena": 12, "docenas": 12, "dozen": 12, "dozens": 12,
    "trece": 13, "thirteen": 13,
    "catorce": 14, "fourteen": 14,
    "quince": 15, "fifteen": 15,
    "dieciseis": 16, "sixteen": 16,
    "diecisiete": 17, "seventeen": 17,
    "dieciocho": 18, "eighteen": 18,
    "diecinueve": 19, "nineteen": 19,
}
_TWENTY = {
    "veinte": 20, "twenty": 20,
    "veintiun": 21, "veintiuno": 21, "veintiuna": 21,
    "veintidos": 22, "veintitres": 23, "veinticuatro": 24, "veinticinco": 25,
    "veintiseis": 26, "veintisiete": 27, "veintiocho": 28, "veintinueve": 29,
}
_TENS = {
    "treinta": 30, "thirty": 30,
    "cuarenta": 40, "forty": 40,
    "cincuenta": 50, "fifty": 50,
    "sesenta": 60, "sixty": 60,
    "setenta": 70, "seventy": 70,
    "ochenta": 80, "eighty": 80,
    "noventa": 90, "ninety": 90,
}
_HUNDREDS = {
    "cien": 100, "ciento": 100, "hundred": 100, "hundreds": 100,
    "doscientos": 200, "doscientas": 200,
    "trescientos": 300, "trescientas": 300,
    "cuatrocientos": 400, "cuatrocientas": 400,
    "quinientos": 500, "quinientas": 500,
    "seiscientos": 600, "seiscientas": 600,
    "setecientos": 700, "setecientas": 700,
    "ochocientos": 800, "ochocientas": 800,
    "novecientos": 900, "novecientas": 900,
}
_SCALE = {
    "mil": 1000, "thousand": 1000, "thousands": 1000,
    "millon": 1_000_000, "millones": 1_000_000, "million": 1_000_000, "millions": 1_000_000,
}
_WORDS_NUM: dict[str, float] = {}
for _d in (_UNITS, _10_19, _TWENTY, _TENS, _HUNDREDS, _SCALE):
    _WORDS_NUM.update(_d)

_ROMAN = re.compile(r"^M{0,3}(CM|CD|D?C{0,3})(XC|XL|L?X{0,3})(IX|IV|V?I{0,3})$", re.I)
_ROMAN_MAP = {"I": 1, "V": 5, "X": 10, "L": 50, "C": 100, "D": 500, "M": 1000}

_FIGURE = re.compile(
    r"(?<![\w.])([+-]?(?:\d{1,3}(?:,\d{3})+(?:\.\d+)?|\d+,\d{1,2}|\d+\.\d+|\d+)(?:[eE][+-]?\d+)?)"
)


def roman_a_int(s: str) -> Optional[int]:
    t = (s or "").strip().upper()
    if not t or t == "I" or not _ROMAN.match(t):
        return None
    n, prev = 0, 0
    for ch in reversed(t):
        v = _ROMAN_MAP[ch]
        if v < prev:
            n -= v
        else:
            n += v
            prev = v
    return n if n > 0 else None


def figure_a_float(raw: str) -> Optional[float]:
    s = (raw or "").strip()
    if not s:
        return None
    try:
        if re.search(r"[eE][+-]?\d+$", s):
            return float(s.replace(",", ""))
        if re.fullmatch(r"\d{1,3}(?:,\d{3})+(?:\.\d+)?", s):
            return float(s.replace(",", ""))
        if re.fullmatch(r"\d+,\d{1,2}", s):
            return float(s.replace(",", "."))
        return float(s)
    except ValueError:
        return None


def parse_words_number(text: str) -> Optional[float]:
    n = _norm(text or "")
    n = n.replace("-", " ").replace(" y ", " ")
    toks = re.findall(r"[a-z]+", n)
    if not toks:
        return None
    if not all(t in _WORDS_NUM or t in {"and"} for t in toks):
        return None
    total = 0.0
    actual = 0.0
    for t in toks:
        if t == "and":
            continue
        v = float(_WORDS_NUM[t])
        if t in {"docena", "docenas", "dozen", "dozens"}:
            actual = (actual or 1) * 12
        elif v == 100:
            actual = (actual or 1) * 100
        elif v >= 1000:
            total += (actual or 1) * v
            actual = 0
        else:
            actual += v
    return total + actual


def parse_number_token(tok: str) -> Optional[float]:
    t = (tok or "").strip()
    if not t:
        return None
    v = figure_a_float(t)
    if v is not None:
        return v
    pv = parse_words_number(t)
    if pv is not None:
        return pv
    if t.isalpha() and t.upper() in {
        "V", "X", "L", "C", "D", "M", "II", "III", "IV", "VI", "VII", "VIII", "IX",
    }:
        rv = roman_a_int(t)
        if rv is not None:
            return float(rv)
    return None


def extract_numbers(text: str) -> list[float]:
    n_orig = text or ""
    found: list[float] = []
    for m in _FIGURE.finditer(n_orig):
        v = figure_a_float(m.group(1))
        if v is not None:
            found.append(v)
    nn = _norm(n_orig)
    words = list(re.finditer(r"[a-z]+", nn))
    i = 0
    while i < len(words):
        took = False
        for k in (3, 2, 1):
            if i + k > len(words):
                continue
            chunk = words[i:i + k]
            if not all(p.group(0) in _WORDS_NUM or p.group(0) == "and" for p in chunk):
                continue
            if k == 1 and words[i].group(0) in {"un", "una", "one"}:
                continue
            frag = " ".join(p.group(0) for p in chunk)
            pv = parse_words_number(frag)
            if pv is not None:
                found.append(pv)
                i += k
                took = True
                break
        if not took:
            i += 1
    for m in re.finditer(r"\b(?:es|is|de|=)\s+([IVXLCDM]{1,6})\b", n_orig):
        rv = roman_a_int(m.group(1))
        if rv is not None:
            found.append(float(rv))
    return found

# ---------------------------------------------------------------------------
# Units
# ---------------------------------------------------------------------------

_UNITS_INFO: dict[str, tuple[str, float]] = {}


def _reg_unit(dim: str, factor: float, *alias: str) -> None:
    for a in alias:
        _UNITS_INFO[_norm(a)] = (dim, factor)


_reg_unit("masa", 1.0, "g", "gr", "gramo", "gramos", "gram", "grams")
_reg_unit("masa", 1000.0, "kg", "kilo", "kilos", "kilogramo", "kilogramos", "kilogram", "kilograms")
_reg_unit("masa", 1_000_000.0, "t", "ton", "tonelada", "toneladas", "tonne", "tonnes")
_reg_unit("volumen", 1.0, "ml", "mililitro", "mililitros", "milliliter", "milliliters")
_reg_unit("volumen", 1000.0, "l", "litro", "litros", "liter", "liters", "litre", "litres")
_reg_unit("longitud", 1.0, "m", "metro", "metros", "meter", "meters", "metre", "metres")
_reg_unit("longitud", 0.01, "cm", "centimetro", "centimetros", "centimeter", "centimeters")
_reg_unit("longitud", 0.001, "mm", "milimetro", "milimetros")
_reg_unit("longitud", 1000.0, "km", "kilometro", "kilometros", "kilometer", "kilometers")
_reg_unit("temp_c", 1.0, "c", "celsius", "centigrado", "centigrados", "centigrade")
_reg_unit("temp_f", 1.0, "f", "fahrenheit")
_reg_unit("currency_mxn", 1.0, "mxn", "pesos")
_reg_unit("currency_usd", 1.0, "usd", "dolar", "dolares", "dollar", "dollars")
_reg_unit("currency_eur", 1.0, "eur", "euro", "euros")
_reg_unit("cantidad", 1.0, "unit", "unidades", "unit", "units")

_UNIT_RE = re.compile(
    r"\b(kg|kilogramos?|kilos?|gramos?|grams?|gramo|gr|"
    r"toneladas?|tonnes?|"
    r"mililitros?|milliliters?|ml|litros?|liters?|litres?|"
    r"kilometros?|kilometers?|km|centimetros?|centimeters?|cm|"
    r"milimetros?|mm|metros?|meters?|metres?|"
    r"celsius|centigrados?|fahrenheit|"
    r"pesos|dolares?|dollars?|euros?|mxn|usd|eur|"
    r"unidades(?:\s+monetarias)?|units?)\b",
    re.IGNORECASE,
)


def parse_unit(text: str) -> Optional[tuple[str, float]]:
    n = _norm(text or "")
    if re.search(r"unidades\s+monetarias", n):
        return ("cantidad", 1.0)
    m = _UNIT_RE.search(n)
    if not m:
        return None
    return _UNITS_INFO.get(_norm(m.group(1)))


def fahrenheit_a_c(f: float) -> float:
    return (f - 32.0) * 5.0 / 9.0


def value_in_base(value_: float, unit: Optional[tuple[str, float]]) -> tuple[Optional[str], float]:
    if unit is None:
        return (None, value_)
    dim, factor = unit
    if dim == "temp_f":
        return ("temp_c", fahrenheit_a_c(value_))
    if dim == "temp_c":
        return ("temp_c", value_)
    return (dim, value_ * factor)


# ---------------------------------------------------------------------------
# Dates and hours
# ---------------------------------------------------------------------------

_MONTHS = {
    "enero": 1, "january": 1, "jan": 1,
    "febrero": 2, "february": 2, "feb": 2,
    "marzo": 3, "march": 3, "mar": 3,
    "abril": 4, "april": 4, "apr": 4,
    "mayo": 5, "may": 5,
    "junio": 6, "june": 6, "jun": 6,
    "julio": 7, "july": 7, "jul": 7,
    "agosto": 8, "august": 8, "aug": 8,
    "septiembre": 9, "september": 9, "sep": 9, "sept": 9,
    "octubre": 10, "october": 10, "oct": 10,
    "noviembre": 11, "november": 11, "nov": 11,
    "diciembre": 12, "december": 12, "dec": 12,
}
_DAYS_WEEK = {
    "lunes": 0, "monday": 0,
    "martes": 1, "tuesday": 1,
    "miercoles": 2, "wednesday": 2,
    "jueves": 3, "thursday": 3,
    "viernes": 4, "friday": 4,
    "sabado": 5, "saturday": 5,
    "domingo": 6, "sunday": 6,
}


@dataclass(frozen=True)
class Date:
    year: Optional[int] = None
    month: Optional[int] = None
    day: Optional[int] = None
    hour: Optional[time] = None
    weekday_declared: Optional[int] = None
    text: str = ""
    valid: bool = True
    reason_invalid: str = ""

    def as_date(self) -> Optional[date]:
        if self.year and self.month and self.day and self.valid:
            try:
                return date(self.year, self.month, self.day)
            except ValueError:
                return None
        return None


def date_valid(year: int, month: int, day: int) -> tuple[bool, str]:
    if month < 1 or month > 12:
        return False, "month_impossible"
    if day < 1 or day > 31:
        return False, "day_impossible"
    if year <= 0:
        return False, "year_impossible"
    last = calendar.monthrange(year, month)[1]
    if day > last:
        if month == 2 and day == 29:
            return False, "no_leap"
        if month == 2:
            return False, "february_impossible"
        return False, "day_impossible_in_month"
    return True, ""


def parse_dates(text: str, include_weekday: bool = True) -> list[Date]:
    t = text or ""
    n = _norm(t)
    out: list[Date] = []
    seen_: set[tuple] = set()

    def add(f: Date) -> None:
        key = (f.year, f.month, f.day, f.hour, f.valid, f.reason_invalid, f.weekday_declared)
        if key not in seen_:
            seen_.add(key)
            out.append(f)

    for m in re.finditer(r"\b(\d{4})-(\d{2})-(\d{2})\b", t):
        y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
        ok, mot = date_valid(y, mo, d)
        add(Date(y, mo, d, text=m.group(0), valid=ok, reason_invalid=mot))

    for m in re.finditer(r"\b(\d{1,2})[/-](\d{1,2})[/-](\d{4})\b", t):
        a, b, y = int(m.group(1)), int(m.group(2)), int(m.group(3))
        if a > 12:
            d, mo = a, b
        elif b > 12:
            mo, d = a, b
        else:
            d, mo = a, b  # DMY
        if 1 <= mo <= 12:
            ok, mot = date_valid(y, mo, d)
            add(Date(y, mo, d, text=m.group(0), valid=ok, reason_invalid=mot))

    for m in re.finditer(r"\b(\d{1,2})\s+de\s+([a-z]+)\s+(?:de\s+)?(\d{4})\b", n):
        d, month_t, y = int(m.group(1)), m.group(2), int(m.group(3))
        mo = _MONTHS.get(month_t)
        if mo:
            ok, mot = date_valid(y, mo, d)
            add(Date(y, mo, d, text=m.group(0), valid=ok, reason_invalid=mot))

    for m in re.finditer(r"\b([a-z]+)\s+(\d{1,2})(?:st|nd|rd|th)?,?\s+(\d{4})\b", n):
        mo = _MONTHS.get(m.group(1))
        if mo:
            d, y = int(m.group(2)), int(m.group(3))
            ok, mot = date_valid(y, mo, d)
            add(Date(y, mo, d, text=m.group(0), valid=ok, reason_invalid=mot))

    for m in re.finditer(r"\b(\d{1,2})(?:st|nd|rd|th)?\s+([a-z]+)\s+(?:of\s+)?(\d{4})\b", n):
        mo = _MONTHS.get(m.group(2))
        if mo:
            d, y = int(m.group(1)), int(m.group(3))
            ok, mot = date_valid(y, mo, d)
            add(Date(y, mo, d, text=m.group(0), valid=ok, reason_invalid=mot))

    if include_weekday:
        for m in re.finditer(r"\b(" + "|".join(_DAYS_WEEK) + r")\b", n):
            wd = _DAYS_WEEK[m.group(1)]
            start = max(0, m.start() - 10)
            end = min(len(n), m.end() + 80)
            for f in parse_dates(n[start:end], include_weekday=False):
                if f.year and f.month and f.day:
                    add(Date(f.year, f.month, f.day, weekday_declared=wd, text=n[start:end],
                              valid=f.valid, reason_invalid=f.reason_invalid))

    for m in re.finditer(r"\b([01]?\d|2[0-3]):([0-5]\d)\b", t):
        add(Date(hour=time(int(m.group(1)), int(m.group(2))), text=m.group(0)))

    return out


def weekday_ok(f: Date) -> Optional[bool]:
    if f.weekday_declared is None:
        return None
    d = f.as_date()
    if d is None:
        return None
    return d.weekday() == f.weekday_declared

# ---------------------------------------------------------------------------
# States / antonyms
# ---------------------------------------------------------------------------

ANTONIMOS_STATE: dict[str, str] = {
    "inseguro": "seguro", "insegura": "seguro", "insecure": "seguro",
    "unsafe": "seguro",
    "falso": "verdadero", "falsa": "verdadero", "false": "verdadero",
    "imposible": "posible", "impossible": "posible",
    "incorrecto": "correcto", "incorrecta": "correcto", "incorrect": "correcto",
    "ilegal": "legal", "illegal": "legal",
    "cerrado": "abierto", "cerrada": "abierto", "closed": "abierto",
    "frio": "caliente", "fria": "caliente", "cold": "caliente",
    "vacio": "lleno", "vacia": "lleno", "empty": "lleno",
    "muerto": "vivo", "muerta": "vivo", "dead": "vivo",
    "bajo": "alto", "baja": "alto", "low": "alto",
    "pierde": "gana", "pierden": "gana", "lose": "gana", "loses": "gana",
    "negativo": "positivo", "negativa": "positivo", "negative": "positivo",
    "vencido": "vigente", "vencida": "vigente", "expired": "vigente",
    "inactivo": "vigente", "inactiva": "vigente",
    "pagada": "pendiente", "pagado": "pendiente", "paid": "pendiente",
    "confidencial": "publico", "confidenciales": "publico", "confidential": "publico",
}

_POLES = {
    "seguro": ("seguro", 0), "segura": ("seguro", 0), "secure": ("seguro", 0), "safe": ("seguro", 0),
    "verdadero": ("verdadero", 0), "verdadera": ("verdadero", 0), "true": ("verdadero", 0),
    "posible": ("posible", 0), "possible": ("posible", 0),
    "correcto": ("correcto", 0), "correcta": ("correcto", 0), "correct": ("correcto", 0),
    "legal": ("legal", 0),
    "abierto": ("abierto", 0), "abierta": ("abierto", 0), "open": ("abierto", 0),
    "caliente": ("caliente", 0), "hot": ("caliente", 0),
    "lleno": ("lleno", 0), "llena": ("lleno", 0), "full": ("lleno", 0),
    "vivo": ("vivo", 0), "viva": ("vivo", 0), "alive": ("vivo", 0),
    "alto": ("alto", 0), "alta": ("alto", 0), "high": ("alto", 0),
    "gana": ("gana", 0), "ganan": ("gana", 0), "win": ("gana", 0), "wins": ("gana", 0),
    "positivo": ("positivo", 0), "positiva": ("positivo", 0), "positive": ("positivo", 0),
    "vigente": ("vigente", 0), "active": ("vigente", 0), "activa": ("vigente", 0), "active": ("vigente", 0),
    "pendiente": ("pendiente", 0), "pending": ("pendiente", 0),
    "publico": ("publico", 0), "publica": ("publico", 0), "public": ("publico", 0),
    "caido": ("caido", 0), "caida": ("caido", 0), "down": ("caido", 0),
    "enlinea": ("caido", 1), "online": ("caido", 1),
    "liquidado": ("pendiente", 1), "liquidada": ("pendiente", 1),
    "saldado": ("pendiente", 1), "saldada": ("pendiente", 1),
}

POLES_KNOWN = {
    "seguro", "verdadero", "posible", "correcto", "legal", "abierto", "caliente",
    "lleno", "vivo", "alto", "gana", "positivo", "vigente", "pendiente", "publico", "caido",
}


def canon_state(word: str) -> tuple[str, int]:
    t = _norm(word or "").replace(" ", "")
    if t in {"enlinea", "online"}:
        return ("caido", 1)
    if t in ANTONIMOS_STATE:
        return (ANTONIMOS_STATE[t], 1)
    if t in _POLES:
        return _POLES[t]
    return (t, 0)


# ---------------------------------------------------------------------------
# Subjects / alias
# ---------------------------------------------------------------------------

_ALIAS_SUBJECT: list[tuple[str, str]] = sorted([
    ("monto disponible", "saldo"),
    ("tipo de cambio oficial", "fx"),
    ("tipo de cambio", "fx"),
    ("exchange rate", "fx"),
    ("outstanding debt", "deuda"),
    ("plantilla laboral", "empleados"),
    ("branch offices", "sucursales"),
    ("branch office", "sucursales"),
    ("persona de contacto", "cliente"),
    ("equipo de computo", "servidor"),
    ("headcount", "empleados"),
    ("existencia en almacen", "inventario"),
    ("monto", "saldo"),
    ("balance", "saldo"),
    ("saldo", "saldo"),
    ("inventario", "inventario"),
    ("existencia", "inventario"),
    ("stock", "inventario"),
    ("sucursales", "sucursales"),
    ("sucursal", "sucursales"),
    ("empleados", "empleados"),
    ("plantilla", "empleados"),
    ("deuda", "deuda"),
    ("debt", "deuda"),
    ("fx", "fx"),
    ("warehouse", "almacen"),
    ("almacen", "almacen"),
    ("cliente", "cliente"),
    ("customer", "cliente"),
    ("contrato", "contrato"),
    ("convenio", "contrato"),
    ("contract", "contrato"),
    ("servidor", "servidor"),
    ("server", "servidor"),
    ("material", "material"),
    ("paciente", "paciente"),
    ("lote", "lote"),
    ("tanque", "tanque"),
    ("distancia", "distancia"),
    ("temperatura", "temperatura"),
    ("precio", "precio"),
    ("price", "precio"),
    ("firma", "firma"),
    ("vencimiento", "vencimiento"),
    ("proyecto", "proyecto"),
    ("project", "proyecto"),
    ("sistema", "sistema"),
    ("system", "sistema"),
    ("informe", "informe"),
    ("report", "informe"),
    ("reporte", "informe"),
    ("puerta", "puerta"),
    ("door", "puerta"),
    ("agua", "agua"),
    ("water", "agua"),
    ("cafe", "cafe"),
    ("operacion", "operacion"),
    ("calculo", "calculo"),
    ("resultado", "resultado"),
    ("result", "resultado"),
    ("procedure", "procedimiento"),
    ("procedimiento", "procedimiento"),
    ("hipotesis", "hipotesis"),
    ("archivo", "archivo"),
    ("pago", "pago"),
    ("clave", "clave"),
    ("cielo", "cielo"),
    ("red", "red"),
    ("afirmacion", "afirmacion"),
    ("animal", "animal"),
    ("equipo", "equipo"),
    ("numero", "numero"),
    ("partida", "partida"),
    ("ingresos", "ingresos"),
    ("gastos", "gastos"),
    ("war", "guerra"),
    ("guerra", "guerra"),
    ("cuenta", "cuenta"),
    ("ciudad", "lugar"),
], key=lambda x: -len(x[0]))


def canon_subject(text: str) -> str:
    n = _norm(text or "")
    n = re.sub(r"\b(el|la|los|las|the|un|una|a|an|de|del|of|mi|su|tu)\b", " ", n)
    n = " ".join(n.split())
    m = re.search(
        r"\b(factura|expediente|exp|contrato|cuenta|lote|proyecto|paciente|servidor|informe)\s*(\d+)\b",
        n,
    )
    if m:
        base = "expediente" if m.group(1) in {"expediente", "exp"} else m.group(1)
        return f"{base}_{m.group(2)}"
    for alias, key_ in _ALIAS_SUBJECT:
        if re.search(r"\b" + re.escape(alias) + r"\b", n):
            m2 = re.search(re.escape(alias) + r"\s*(\d+)", n)
            if m2:
                return f"{key_}_{m2.group(1)}"
            return key_
    return n


# ---------------------------------------------------------------------------
# Temporary anchors
# ---------------------------------------------------------------------------

_PAST = re.compile(
    r"\b(era|eran|estaba|estaban|estuvo|estuvieron|fue|fueron|vivia|habia|habian|"
    r"was|were|antes|previamente)\b",
    re.IGNORECASE,
)
_CHANGE = re.compile(
    r"\b(ahora|hoy|today|now|actualmente|tras|despues de|after|luego|"
    r"se mudo|relocated|ya\s+fue|ya\s+es)\b",
    re.IGNORECASE,
)


def anchor_temporary(text: str) -> Optional[str]:
    """Anchor only with explicit time or change marks, not for a simple 'was'/'was'."""
    n = _norm(text or "")
    my = re.search(r"\b(?:en|in)\s+((?:19|20)\d{2})\b", n)
    if my:
        return f"anio:{my.group(1)}"
    mh = re.search(r"\b(?:a las|at)\s+(\d{1,2}:\d{2})\b", n)
    if mh:
        return f"hora:{mh.group(1)}"
    # 'era/estaba/vivia/was' only counts if there is explicit contrast or remains as past
    # in front of a 'now' in another clause. A simple 'was January 15th' is a punctual event.
    if _CHANGE.search(n):
        return "ahora"
    if re.search(r"\b(era|eran|estaba|estaban|vivia|habia|used\s+to)\b", n):
        return "pasado"
    return None


def anchors_compatible(a: Optional[str], b: Optional[str], text_a: str = "", text_b: str = "") -> bool:
    """False if there is a temporary contrast indicating a legitimate change."""
    combo = _norm((text_a or "") + " " + (text_b or ""))
    if re.search(
        r"\b(era|estaba|estuvo|vivia|habia|was|were).{0,80}\b(ahora|hoy|today|now|tras|despues|ya fue|ya pagada)\b",
        combo,
    ):
        return False
    if a and b and a != b:
        if a.startswith("anio:") and b.startswith("anio:"):
            return False
        if a.startswith("hora:") and b.startswith("hora:"):
            return False
        if {a, b} == {"pasado", "ahora"}:
            return False
        if "pasado" in {a, b} and "ahora" in {a, b, None}:
            return False
    if (a == "pasado" and (b is None or b == "ahora")) or (b == "pasado" and (a is None or a == "ahora")):
        if _CHANGE.search(combo) or _PAST.search(combo):
            return False
    return True

# ---------------------------------------------------------------------------
# Extracted
# ---------------------------------------------------------------------------

@dataclass
class Fact:
    subject: str
    aspect: str
    value_: Any = None
    unit: Optional[tuple[str, float]] = None
    state: Optional[str] = None
    parity: int = 0
    date_: Optional[Date] = None
    anchor: Optional[str] = None
    text: str = ""
    origin: str = "document"
    verified: bool = False
    atom_id: Optional[str] = None
    comparison: Optional[str] = None
    unique: bool = False

    def value_base(self) -> Optional[tuple[Optional[str], float]]:
        if self.value_ is None or not isinstance(self.value_, (int, float)):
            return None
        return value_in_base(float(self.value_), self.unit)


_COPULA = r"(?:es|esta|son|estan|era|eran|estaba|estaban|estuvo|fue|fueron|sea|sean|is|are|was|were|be)"
_NEG = r"(?:no|not|nunca|jamas|never)"


def _strip_relative(text: str) -> str:
    t = text or ""
    t = re.sub(r",\s*que\s+[^,]+,", " ", t, flags=re.IGNORECASE)
    t = re.sub(r"\bque\s+(?:algunos|muchos|otros)\s+\w+\s+\w+", " ", t, flags=re.IGNORECASE)
    t = re.sub(
        r"\b(?:the allegation that|la alegacion de que)\b.{0,80}?\bis itself\s+false",
        " ", t, flags=re.IGNORECASE,
    )
    return t


def _unit_in(text: str) -> Optional[tuple[str, float]]:
    n = _norm(text or "")
    m = re.search(
        r"(\d+(?:[.,]\d+)?(?:[eE][+-]?\d+)?)\s*"
        r"(kg|g|gr|ml|l|km|m|cm|mm|mxn|usd|eur|pesos?|dolares?|kilos?|gramos?|"
        r"litros?|metros?|unidades)",
        n, re.I,
    )
    if m:
        u = parse_unit(m.group(2))
        if u:
            return u
    if re.search(r"(?<![a-z])\d+(?:[.,]\d+)?\s*(?:°\s*)?c(?:elsius|entigrados?)?\b", n) or re.search(r"\bgrados?\s+c", n):
        return ("temp_c", 1.0)
    if re.search(r"(?<![a-z])\d+(?:[.,]\d+)?\s*(?:°\s*)?f(?:ahrenheit)?\b", n) or re.search(r"\bfahrenheit\b", n):
        return ("temp_f", 1.0)
    return parse_unit(n)


def _dedup_facts(facts: list[Fact]) -> list[Fact]:
    out: list[Fact] = []
    seen = set()
    for h in facts:
        fv = None
        if isinstance(h.value_, Date):
            fv = (h.value_.year, h.value_.month, h.value_.day)
        elif h.date_:
            fv = (h.date_.year, h.date_.month, h.date_.day)
        key = (h.subject, h.aspect, h.value_ if fv is None else fv, h.state, h.parity, h.anchor, h.comparison)
        if key in seen:
            continue
        seen.add(key)
        out.append(h)
    return out


def extract_facts(text: str, *, origin: str = "document", verified: bool = False,
                   atom_id: Optional[str] = None) -> list[Fact]:
    t = _strip_relative(text or "")
    n = _norm(t)
    facts: list[Fact] = []
    anchor = anchor_temporary(t)
    inverted = False
    m_inv = re.search(
        r"(?:no es (?:cierto|verdad|verdadero) que|it is not (?:true|the case) that)\s+(.+)$",
        n,
    )
    if m_inv:
        inverted = True
        # Judge the subordinate clause and then reverse its polarity.
        n = m_inv.group(1).strip()
        t = m_inv.group(1).strip()

    subject = canon_subject(n)
    for alias, key_ in _ALIAS_SUBJECT:
        if re.search(r"\b" + re.escape(alias) + r"\b", n):
            subject = key_
            mnum = re.search(re.escape(alias) + r"\s*(\d+)", n)
            if mnum:
                subject = f"{key_}_{mnum.group(1)}"
            break
    m_ent = re.search(r"\b(factura|expediente|exp)\s*(\d+)\b", n)
    if m_ent:
        base = "expediente" if m_ent.group(1).startswith("exp") else m_ent.group(1)
        subject = f"{base}_{m_ent.group(2)}"

    nums = extract_numbers(t)
    unit_abbr = _unit_in(n)
    dates = parse_dates(t)

    # "over twice as much as N"
    m_double = re.search(r"\b(supera|mas de|more than|exceeds)\s+(?:el\s+)?doble\s+de\s+(.+)$", n)
    if m_double:
        base = extract_numbers(m_double.group(2)) or [x for x in nums if x]
        if base:
            facts.append(Fact(
                subject=subject or "empleados", aspect="value_", value_=2 * float(base[0]),
                comparison=">", anchor=anchor, text=text, origin=origin,
                verified=verified, atom_id=atom_id, unit=unit_abbr,
            ))

    pred = None
    neg = False
    m_cop = re.search(
        rf"\b(?:(?P<neg1>{_NEG})\s+)?(?P<cop>{_COPULA})\s+(?:(?P<neg2>{_NEG})\s+)?(?P<pred>.+)$",
        n,
    )
    if m_cop:
        pred = (m_cop.group("pred") or "").strip()
        neg = bool((m_cop.group("neg1") or "").strip()) ^ bool((m_cop.group("neg2") or "").strip())
    if inverted:
        neg = not neg

    if re.search(r"\b(ya\s+(?:fue\s+)?pagad[oa]|ya\s+se\s+liquid[oó]|se\s+liquid[oó]|was\s+paid|"
                r"no\s+hay\s+pago\s+pendiente|no\s+queda\s+pendiente)\b", n):
        subj_payment = subject
        m_fac = re.search(r"\b(factura)\s*(\d+)\b", n)
        if m_fac:
            subj_payment = f"invoice_{m_fac.group(2)}"
        facts.append(Fact(
            subject=subj_payment, aspect="state", state="pendiente", parity=1,
            anchor=anchor, text=text, origin=origin, verified=verified, atom_id=atom_id,
        ))
    if re.search(r"\b(sigue produciendo efectos|sigue vigente|continues to (?:be )?in effect)\b", n):
        facts.append(Fact(
            subject=subject or "contrato", aspect="state", state="vigente", parity=0,
            anchor=anchor, text=text, origin=origin, verified=verified, atom_id=atom_id,
        ))
    if re.search(r"\b(responde con normalidad|is (?:up|online)|en linea)\b", n):
        if re.search(r"servidor|equipo|server", n):
            facts.append(Fact(
                subject="servidor", aspect="state", state="caido", parity=1,
                anchor=anchor, text=text, origin=origin, verified=verified, atom_id=atom_id,
            ))

    m_place = re.search(
        r"\b(?:vive(?:n)?|reside(?:n)?|lives?|resides?|relocated to)\s+"
        r"(?:actualmente\s+)?(?:en\s+)?(?P<lugar>.+)$",
        n,
    )
    # 'is in' only if it's not 'is in your medio/line/...' status
    if not m_place:
        m_place = re.search(
            r"\b(?:esta en|is in)\s+(?P<lugar>.+)$",
            n,
        )
        if m_place and re.search(r"\b(linea|medio|cuarentena|vigor|riesgo)\b", m_place.group("lugar") or ""):
            m_place = None
    if m_place and not re.search(r"\bcapital de\b", n):
        place = m_place.group("lugar").strip()
        place = re.sub(r"\b(la|el|the|ciudad de)\b", " ", place)
        place = " ".join(place.split())
        entity = subject
        if re.search(r"cliente|customer|persona|contacto", n):
            entity = "cliente"
        if re.search(r"warehouse|almacen", n):
            entity = "almacen"
        if place:
            facts.append(Fact(
                subject=entity, aspect="lugar", value_=_norm(place),
                anchor=anchor, text=text, origin=origin, verified=verified, atom_id=atom_id,
            ))

    event_unique = bool(re.search(
        r"\b(nacio|born|firmo|firma fue|started|inicio|empezo|termino|ended|alta ocurrio|"
        r"vencimiento|cierre|reunion fue|audit started|periodo cierra)\b", n
    ))
    if dates and event_unique:
        subject_ev, aspect = subject, "date_"
        if re.search(r"\b(nacio|born|nacimiento)\b", n):
            subject_ev, aspect = "nacimiento", "date_"
        elif re.search(r"\b(firmo|firma)\b", n):
            subject_ev, aspect = "firma", "date_"
        elif re.search(r"\b(inicio|empezo|started|comenzo)\b", n):
            if re.search(r"\b(audit|auditoria)\b", n):
                subject_ev = "audit_start"
            else:
                subject_ev = subject if subject in {"proyecto", "guerra", "audit_start"} else (subject or "proyecto")
            aspect = "date_start"
        elif re.search(r"\b(termino|ended)\b", n):
            if re.search(r"\b(audit|auditoria)\b", n):
                subject_ev = "audit_start"
            else:
                subject_ev = subject if subject in {"proyecto", "guerra"} else (subject or "proyecto")
            aspect = "date_end"
        elif re.search(r"\bvencimiento\b", n):
            subject_ev, aspect = "vencimiento", "date_"
        elif re.search(r"\balta\b", n):
            subject_ev, aspect = "alta", "date_"
        elif re.search(r"\breunion\b", n):
            subject_ev, aspect = "reunion", "date_"
        elif re.search(r"\baudit\b", n):
            subject_ev, aspect = "audit_start", "date_"
        elif re.search(r"\bcierre|periodo cierra\b", n):
            subject_ev, aspect = "cierre", "date_"
        for f in dates:
            if f.year:
                facts.append(Fact(
                    subject=subject_ev, aspect=aspect, date_=f, value_=f,
                    anchor=anchor, text=text, origin=origin, verified=verified,
                    atom_id=atom_id, unique=True,
                ))

    m_year_ev = re.search(
        r"\b(nacio|born|inicio|empezo|started|termino|ended|murio|died|publico|published|"
        r"comenzo|began)\b(?:\s+\w+){0,6}\s+(?:en|in|on)\s+((?:19|20)\d{2})\b",
        n,
    )
    if m_year_ev:
        ev = m_year_ev.group(1)
        year = int(m_year_ev.group(2))
        map_ = {
            "nacio": ("nacimiento", "year"), "born": ("nacimiento", "year"),
            "start_": ("proyecto", "year_start"), "empezo": ("proyecto", "year_start"),
            "started": ("proyecto", "year_start"), "comenzo": ("proyecto", "year_start"),
            "began": ("proyecto", "year_start"),
            "termino": ("proyecto", "year_end"), "ended": ("proyecto", "year_end"),
            "murio": ("muerte", "year"), "died": ("muerte", "year"),
            "publico": ("publicacion", "year"), "published": ("publicacion", "year"),
        }
        subj, asp = map_.get(ev, (subject, "year"))
        if ev in {"inicio", "empezo", "started", "comenzo", "began", "termino", "ended"}:
            if subject in {"proyecto", "guerra", "audit_start"}:
                subj = subject
        facts.append(Fact(
            subject=subj, aspect=asp, value_=year, anchor=f"anio:{year}",
            text=text, origin=origin, verified=verified, atom_id=atom_id, unique=True,
        ))

    if nums and re.search(r"\b(edad\s+(?:es|declarada)|tiene\s+\d+\s+anos|years?\s+old|el paciente tiene|paciente tiene)\b", n):
        candidates = [x for x in nums if 0 < x < 130]
        if candidates:
            facts.append(Fact(
                subject="paciente", aspect="edad", value_=candidates[0],
                anchor=anchor, text=text, origin=origin, verified=verified, atom_id=atom_id,
            ))

    m_cta = re.search(r"\bcuenta\s+termina\s+en\s+(\w+)\b", n)
    if m_cta:
        facts.append(Fact(
            subject="cuenta", aspect="terminacion", value_=_norm(m_cta.group(1)),
            anchor=anchor, text=text, origin=origin, verified=verified, atom_id=atom_id,
        ))

    if pred:
        pred_short = pred.split(",")[0].strip()
        nums_pred = extract_numbers(pred)
        if nums_pred:
            unit_p = _unit_in(pred) or unit_abbr
            facts.append(Fact(
                subject=subject, aspect="value_", value_=nums_pred[0], unit=unit_p,
                anchor=anchor, text=text, origin=origin, verified=verified,
                atom_id=atom_id, parity=int(neg),
            ))
        tokens_pred = re.findall(r"[a-z]+", pred_short)
        for tok in tokens_pred:
            polo, pair = canon_state(tok)
            if polo in POLES_KNOWN:
                facts.append(Fact(
                    subject=subject, aspect="state", state=polo,
                    parity=(pair + int(neg)) % 2,
                    anchor=anchor, text=text, origin=origin, verified=verified, atom_id=atom_id,
                ))
                break

    if nums and subject in {
        "saldo", "inventario", "sucursales", "empleados", "deuda", "fx", "lote",
        "tanque", "distancia", "temperatura", "precio", "ingresos", "gastos",
    } and not any(h.aspect == "value_" and h.subject == subject for h in facts):
        if not m_double:
            facts.append(Fact(
                subject=subject, aspect="value_", value_=nums[0], unit=unit_abbr,
                anchor=anchor, text=text, origin=origin, verified=verified, atom_id=atom_id,
            ))

    m_mat = re.search(r"\bmaterial\s+(?:es|is|fue)\s+(.+)$", n)
    if m_mat:
        facts.append(Fact(
            subject="material", aspect="value_", value_=_norm(m_mat.group(1)).strip(),
            anchor=anchor, text=text, origin=origin, verified=verified, atom_id=atom_id,
        ))

    m_cap = re.search(
        r"\b([a-z][a-z]+)\s+(?:es|is)\s+(?:la |the )?capital\s+(?:de|of)\s+([a-z][a-z]+)\b",
        n,
    )
    if m_cap:
        facts.append(Fact(
            subject=_norm(m_cap.group(1)), aspect="capital", value_=_norm(m_cap.group(2)),
            anchor=anchor, text=text, origin=origin, verified=verified, atom_id=atom_id,
            unique=True,
        ))

    return _dedup_facts(facts)


_SUFFIX_UNIT = {
    "kg": ("masa", 1000.0), "g": ("masa", 1.0), "ml": ("volumen", 1.0),
    "l": ("volumen", 1000.0), "km": ("longitud", 1000.0), "m": ("longitud", 1.0),
    "c": ("temp_c", 1.0), "f": ("temp_f", 1.0), "mxn": ("currency_mxn", 1.0),
    "usd": ("currency_usd", 1.0), "eur": ("currency_eur", 1.0),
}

_MAP_KEY = {
    "saldo": ("saldo", "value_"), "balance": ("saldo", "value_"),
    "inventario": ("inventario", "value_"), "sucursales": ("sucursales", "value_"),
    "fx": ("fx", "value_"), "empleados": ("empleados", "value_"),
    "deuda": ("deuda", "value_"), "edad": ("paciente", "edad"),
    "ciudad": ("cliente", "lugar"), "warehouse": ("almacen", "lugar"),
    "state_contract": ("contrato", "state"), "contract": ("contrato", "state"),
    "servidor": ("servidor", "state"), "material": ("material", "value_"),
    "cuenta": ("cuenta", "terminacion"),
    "start_project": ("proyecto", "year_start"),
    "firma": ("firma", "date_"), "vencimiento": ("vencimiento", "date_"),
    "alta": ("alta", "date_"), "reunion": ("reunion", "date_"),
    "cierre": ("cierre", "date_"), "audit_start": ("audit_start", "date_"),
    "nacimiento": ("nacimiento", "date_"),
    "invoice_441": ("invoice_441", "state"),
    "exp_77": ("file_77", "state"),
    "peso": ("lote", "value_"), "tanque": ("tanque", "value_"),
    "distancia": ("distancia", "value_"), "temp": ("temperatura", "value_"),
    "precio": ("precio", "value_"),
}


def facts_from_memory(memory: dict) -> list[Fact]:
    facts: list[Fact] = []
    if not memory:
        return facts
    for k, v in memory.items():
        kn = _norm(str(k))
        if kn.startswith("fact_") and isinstance(v, str):
            facts.extend(extract_facts(v, origin="memory", verified=True, atom_id=f"mem:{k}"))
            continue
        unit = None
        subject = kn
        for suf, info in _SUFFIX_UNIT.items():
            if kn.endswith("_" + suf) or kn.endswith(suf) and "_" in kn:
                if kn.endswith("_" + suf):
                    unit = info
                    subject = kn[: -len(suf)].rstrip("_")
                    break
        subject = canon_subject(subject) or subject
        if subject in _MAP_KEY:
            subj, asp = _MAP_KEY[subject]
        elif kn in _MAP_KEY:
            subj, asp = _MAP_KEY[kn]
        else:
            subj, asp = subject, "value_"

        fact = Fact(subject=subj, aspect=asp, text=str(v), origin="memory",
                      verified=True, atom_id=f"mem:{k}", unit=unit)
        if isinstance(v, (int, float)):
            fact.value_ = float(v)
            if asp == "edad":
                fact.subject, fact.aspect = "paciente", "edad"
        elif isinstance(v, str):
            fm = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})", v.strip())
            if fm:
                y, mo, d = int(fm.group(1)), int(fm.group(2)), int(fm.group(3))
                ok, mot = date_valid(y, mo, d)
                fact.date_ = Date(y, mo, d, text=v, valid=ok, reason_invalid=mot)
                if asp == "year_start":
                    fact.aspect, fact.value_ = "year_start", y
                else:
                    fact.aspect = asp if "date_" in asp or asp in {"date_"} else "date_"
                    fact.value_ = fact.date_
            else:
                num = parse_number_token(v)
                if num is not None and not re.search(r"[a-zA-Z]{3,}", v):
                    fact.value_ = num
                    if asp == "year_start":
                        fact.aspect = "year_start"
                else:
                    polo, pair = canon_state(v)
                    if polo in POLES_KNOWN:
                        fact.aspect, fact.state, fact.parity = "state", polo, pair
                    elif asp == "lugar":
                        fact.aspect, fact.value_ = "lugar", _norm(v)
                    elif asp == "terminacion":
                        fact.aspect, fact.value_ = "terminacion", _norm(v)
                    else:
                        fact.value_ = _norm(v)
        facts.append(fact)
    return _dedup_facts(facts)

# ---------------------------------------------------------------------------
# Contrast
# ---------------------------------------------------------------------------

_EPS = 1e-6
_EPS_REL = 1e-4


def _nums_eq(a: float, b: float, approx: bool = False) -> bool:
    if approx:
        return abs(a - b) <= max(0.015, 0.01 * max(abs(a), abs(b), 1.0))
    return abs(a - b) <= max(_EPS, _EPS_REL * max(abs(a), abs(b), 1.0))


def equivalents(h1: Fact, h2: Fact) -> bool:
    if h1.aspect == "state" and h2.aspect == "state":
        return h1.state == h2.state and h1.parity == h2.parity
    if h1.aspect in {"lugar", "terminacion"} and h2.aspect == h1.aspect:
        if isinstance(h1.value_, str) and isinstance(h2.value_, str):
            return _norm(h1.value_) == _norm(h2.value_)
    if h1.date_ and h2.date_:
        if h1.date_.year and h2.date_.year and h1.date_.month and h2.date_.month and h1.date_.day and h2.date_.day:
            return (h1.date_.year, h1.date_.month, h1.date_.day) == (h2.date_.year, h2.date_.month, h2.date_.day)
    vb1, vb2 = h1.value_base(), h2.value_base()
    if vb1 and vb2:
        d1, v1 = vb1
        d2, v2 = vb2
        if d1 and d2 and d1 != d2:
            return False
        return _nums_eq(v1, v2)
    if isinstance(h1.value_, (int, float)) and isinstance(h2.value_, (int, float)) and h1.unit is None and h2.unit is None:
        return _nums_eq(float(h1.value_), float(h2.value_))
    if h1.aspect == "value_" and h2.aspect == "value_":
        if isinstance(h1.value_, str) and isinstance(h2.value_, str):
            return _norm(h1.value_) == _norm(h2.value_)
    return False


def subjects_compatible(h1: Fact, h2: Fact) -> bool:
    if h1.subject and h1.subject == h2.subject:
        return True
    if h1.aspect == "edad" and h2.aspect == "edad":
        return True
    return False


def aspects_comparable(h1: Fact, h2: Fact) -> bool:
    if h1.aspect == h2.aspect:
        return True
    start_ = {"year_start", "date_start"}
    end_ = {"year_end", "date_end"}
    if h1.aspect in start_ and h2.aspect in start_:
        return True
    if h1.aspect in end_ and h2.aspect in end_:
        return True
    if {h1.aspect, h2.aspect} <= {"year", "date_", "date_start", "year_start"} and not (
        ("fin" in h1.aspect) ^ ("fin" in h2.aspect)
    ):
        # date vs date_start of the same event
        if not (("start_" in h1.aspect or "year_start" == h1.aspect) and ("fin" in h2.aspect)):
            if h1.aspect in {"date_", "date_start", "year", "year_start"} and h2.aspect in {"date_", "date_start", "year", "year_start"}:
                return True
    if "date_" in h1.aspect and "date_" in h2.aspect and h1.aspect == h2.aspect:
        return True
    return False


def contradicting(h1: Fact, h2: Fact) -> bool:
    if not subjects_compatible(h1, h2):
        return False
    if not aspects_comparable(h1, h2):
        return False
    event = bool(h1.unique or h2.unique or h1.aspect in {"date_", "date_start", "date_end", "year", "year_start", "year_end", "capital", "nacimiento"} or h2.aspect in {"date_", "date_start", "date_end", "year", "year_start", "year_end", "capital", "nacimiento"})
    if not event and not anchors_compatible(h1.anchor, h2.anchor, h1.text, h2.text):
        return False
    if equivalents(h1, h2):
        return False

    if h1.aspect == "state" and h2.aspect == "state" and h1.state and h2.state:
        if h1.state == h2.state:
            return h1.parity != h2.parity
        return False

    if h1.aspect == h2.aspect and isinstance(h1.value_, str) and isinstance(h2.value_, str):
        if re.search(r"\bcapital de\b", _norm((h1.value_ or "") + " " + (h2.value_ or ""))):
            return False
        return bool(h1.value_) and bool(h2.value_) and _norm(h1.value_) != _norm(h2.value_)

    vb1, vb2 = h1.value_base(), h2.value_base()
    if vb1 and vb2:
        d1, v1 = vb1
        d2, v2 = vb2
        if d1 and d2 and d1 != d2:
            if d1.startswith("currency_") and d2.startswith("currency_"):
                return True
            return False
        if h1.comparison == ">" and h2.comparison is None:
            return not (v2 > v1 + _EPS)
        if h2.comparison == ">" and h1.comparison is None:
            return not (v1 > v2 + _EPS)
        return not _nums_eq(v1, v2)

    f1, f2 = h1.date_, h2.date_
    if f1 and f2 and f1.valid and f2.valid:
        if f1.year and f2.year:
            if f1.month and f2.month and f1.day and f2.day:
                return (f1.year, f1.month, f1.day) != (f2.year, f2.month, f2.day)
            if f1.month and f2.month:
                return (f1.year, f1.month) != (f2.year, f2.month)
            return f1.year != f2.year

    def _year(h: Fact) -> Optional[int]:
        if isinstance(h.value_, (int, float)) and h.aspect in {"year", "year_start", "year_end", "edad"}:
            return int(h.value_)
        if h.aspect in {"year", "year_start", "year_end"} and isinstance(h.value_, (int, float)):
            return int(h.value_)
        if h.date_ and h.date_.year:
            return h.date_.year
        return None

    if h1.aspect in {"year", "year_start", "year_end", "date_", "date_start", "date_end"} or \
       h2.aspect in {"year", "year_start", "year_end", "date_", "date_start", "date_end"}:
        a, b = _year(h1), _year(h2)
        if a and b:
            # same side only (already filtered by aspectos_comparables)
            return a != b
    return False

# ---------------------------------------------------------------------------
# Arithmetic and calendar
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    type_: str
    reason: str
    atom_ids: list[str] = field(default_factory=list)
    detail: str = ""
    texts: list[str] = field(default_factory=list)


def _approx(text: str) -> bool:
    return bool(re.search(r"\b(aprox|aproximadamente|about|around|roughly|casi)\b", _norm(text or "")))


def check_arithmetic(text: str, atom_ids: Optional[list[str]] = None) -> list[Finding]:
    t = text or ""
    n = _norm(t)
    out: list[Finding] = []
    ids = list(atom_ids or [])
    approx = _approx(t)

    def fail(reason: str, detail: str) -> None:
        out.append(Finding("REFUTED", reason, ids, detail, [t[:300]]))

    for m in re.finditer(
        r"(?<![\d/])(\d+(?:\.\d+)?)\s*([+\-*/x×])\s*(\d+(?:\.\d+)?)\s*=\s*(\d+(?:\.\d+)?)",
        n,
    ):
        a, op, b, c = float(m.group(1)), m.group(2), float(m.group(3)), float(m.group(4))
        if op == "+":
            esp = a + b
        elif op == "-":
            esp = a - b
        elif op in {"*", "x", "×"}:
            esp = a * b
        else:
            if b == 0:
                continue
            esp = a / b
        if not _nums_eq(esp, c, approx=approx):
            fail("contradiction_arithmetic", f"{a}{op}{b}={c} (esperado {esp})")

    m_sum = re.search(
        r"(?:renglones|items|sumandos|numeros|valores)?\s*"
        r"(?:son|cost|costo|cuestan|are|:)?\s*"
        r"([\d.,\s]+(?:y|and)\s*[\d.,]+).{0,80}?\b(?:la\s+suma|el\s+total|en\s+total|total|suma)\s+"
        r"(?:es|is|hay)\s+(\d+(?:[.,]\d+)?)",
        n, re.I,
    )
    if m_sum:
        parts = extract_numbers(m_sum.group(1))
        total = figure_a_float(m_sum.group(2)) or parse_number_token(m_sum.group(2))
        if parts and total is not None and len(parts) >= 2:
            if not _nums_eq(sum(parts), float(total), approx=approx):
                fail("contradiction_arithmetic", f"suma {parts} != {total}")

    m_there_is = re.search(
        r"\b(?:hay|there are)\s+(\d+(?:\.\d+)?)\s+\w+\s+(?:y|and)\s+(\d+(?:\.\d+)?)\s+\w+"
        r".{0,80}?\b(?:en total hay|total (?:is|hay)|en total)\s+(\d+(?:\.\d+)?)",
        n,
    )
    if m_there_is:
        a, b, c = float(m_there_is.group(1)), float(m_there_is.group(2)), float(m_there_is.group(3))
        if not _nums_eq(a + b, c, approx=approx):
            fail("contradiction_arithmetic", f"{a}+{b}!={c}")

    m_ing = re.search(
        r"\bingresos\s+(\d+(?:\.\d+)?).{0,80}?gastos\s+(\d+(?:\.\d+)?).{0,80}?"
        r"(?:el\s+)?saldo\s+(?:es|is)\s+(\d+(?:\.\d+)?)",
        n,
    )
    if m_ing:
        a, b, c = float(m_ing.group(1)), float(m_ing.group(2)), float(m_ing.group(3))
        if not _nums_eq(a - b, c, approx=approx):
            fail("contradiction_arithmetic", f"income {a} - expenditure {b} != balance {c}")

    m_pct = re.search(
        r"\b(\d+(?:\.\d+)?)\s*%\s*(?:de|of)\s+(\d+(?:\.\d+)?)\s+(?:es|is)\s+(\d+(?:\.\d+)?)",
        n,
    )
    if m_pct:
        p, n0, m0 = float(m_pct.group(1)), float(m_pct.group(2)), float(m_pct.group(3))
        if not _nums_eq(p / 100.0 * n0, m0, approx=approx):
            fail("contradiction_arithmetic", f"{p}% de {n0} != {m0}")

    m_med = re.search(
        r"\b(?:la\s+)?(?:media|promedio|average)\s+(?:de|of)\s+"
        r"([\d.,\s]+(?:y|and)\s*[\d.,]+)\s+(?:es|is)\s+(\d+(?:\.\d+)?)",
        n,
    )
    if m_med:
        parts = extract_numbers(m_med.group(1))
        tot = float(m_med.group(2))
        if parts:
            media = sum(parts) / len(parts)
            if not _nums_eq(media, tot, approx=approx):
                fail("contradiction_arithmetic", f"media {parts}={media} != {tot}")

    m_dh = re.search(r"\bdebe\s+(\d+(?:\.\d+)?).{0,80}?haber\s+(\d+(?:\.\d+)?)", n)
    if m_dh:
        d, h = float(m_dh.group(1)), float(m_dh.group(2))
        asserts = bool(re.search(r"\b(cuadrada|cuadra|balanced|balances)\b", n))
        denies = bool(re.search(r"\b(no\s+esta\s+cuadrada|not\s+balanced|descuadrad)\b", n))
        if asserts and not denies and not _nums_eq(d, h):
            fail("contradiction_arithmetic", f"Must be {d} != Haber {h} but claims it fits")

    m_mul = re.search(
        r"\b(\d+)\s+articulos?\s+a\s+(\d+(?:\.\d+)?)\s+cada\s+uno.{0,80}?"
        r"(?:pague|total|en total)\s+(\d+(?:\.\d+)?)",
        n,
    )
    if m_mul:
        a, b, c = float(m_mul.group(1)), float(m_mul.group(2)), float(m_mul.group(3))
        if not _nums_eq(a * b, c, approx=approx):
            fail("contradiction_arithmetic", f"{a}x{b}!={c}")

    return out


def check_calendar(text: str, atom_ids: Optional[list[str]] = None) -> list[Finding]:
    t = text or ""
    n = _norm(t)
    out: list[Finding] = []
    ids = list(atom_ids or [])

    def fail(reason: str, detail: str) -> None:
        out.append(Finding("REFUTED", reason, ids, detail, [t[:300]]))

    dates = parse_dates(t)
    for f in dates:
        if not f.valid and f.year and f.month and f.day:
            fail("date_impossible", f"{f.day}/{f.month}/{f.year} {f.reason_invalid}")
        if weekday_ok(f) is False:
            fail("date_impossible", f"{f.as_date()} was not weekday {f.weekday_declared}")

    m_nac = re.search(r"\b(?:nacio|born|nacimiento)\b.{0,40}?\b((?:19|20)\d{2})\b", n)
    m_age = re.search(r"\ben\s+((?:19|20)\d{2})\s+ya\s+era\s+mayor\s+de\s+edad", n)
    m_age_in = re.search(
        r"\bin\s+((?:19|20)\d{2})\s+(?:he|she|they)?\s*(?:was|were)\s+already\s+(?:of age|an adult)",
        n,
    )
    if m_nac and (m_age or m_age_in):
        y0 = int(m_nac.group(1))
        y1 = int((m_age or m_age_in).group(1))
        if y1 < y0 + 18:
            fail("chronology_impossible", f"born {y0} was not of legal age at {y1}")

    m_end = re.search(
        r"\b(?:el\s+proyecto|the\s+(?:project|war)|la\s+guerra)?\s*"
        r"(termino|ended)\b(.{0,60})",
        n,
    )
    m_ini = re.search(
        r"\b(?:el\s+proyecto|the\s+(?:project|war)|la\s+guerra)?\s*"
        r"(empezo|inicio|began|started|comenzo)\b(.{0,60})",
        n,
    )

    def _d(fs: list[Date], frag: str) -> Optional[date]:
        for f in fs:
            if f.as_date():
                return f.as_date()
        m = re.search(r"((?:19|20)\d{2})", frag)
        if m:
            return date(int(m.group(1)), 1, 1)
        return None

    if m_end and m_ini:
        d_end = _d(parse_dates(m_end.group(0)), m_end.group(0))
        d_ini = _d(parse_dates(m_ini.group(0)), m_ini.group(0))
        if d_end and d_ini and d_end < d_ini:
            fail("chronology_impossible", f"finished {d_end} before starting {d_ini}")

    m_death = re.search(r"\b(?:murio|died|fallecio)\b.{0,30}?\b((?:19|20)\d{2})\b", n)
    m_pub = re.search(r"\b(?:publico|published|wrote|lanzo)\b.{0,40}?\b((?:19|20)\d{2})\b", n)
    if m_death and m_pub and int(m_pub.group(1)) > int(m_death.group(1)):
        fail("chronology_impossible", f"published in {m_pub.group(1)} after dying in {m_death.group(1)}")

    if re.search(r"\b(despues de haber llegado|after (?:having )?arrived)\b", n):
        m_ll = re.search(r"\b(?:llego|arrived)\b.{0,20}?(\d{1,2}:\d{2})", n)
        m_sa = re.search(r"\b(?:salio|left)\b.{0,20}?(\d{1,2}:\d{2})", n)
        if m_ll and m_sa:
            def _tm(s: str) -> int:
                h, my_ = s.split(":")
                return int(h) * 60 + int(my_)
            if _tm(m_sa.group(1)) < _tm(m_ll.group(1)):
                fail("chronology_impossible", "came out before arriving, claimed as later")

    return out

# ---------------------------------------------------------------------------
# Report and trial
# ---------------------------------------------------------------------------

@dataclass
class FactsReport:
    truths: dict[str, TruthState] = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    supported_by_memory: list[str] = field(default_factory=list)
    postulates_new: list[Fact] = field(default_factory=list)
    atomos_incoherent: list[str] = field(default_factory=list)


def judge_affirmations(
    atomos: list,
    memory: Optional[dict] = None,
    postulates: Optional[list[Fact]] = None,
    text_document: Optional[str] = None,
    texts_session: Optional[list[str]] = None,
) -> FactsReport:
    """Compare statements with verified memory, session postulates and each other."""
    from .core_types import VerdictA1

    inf = FactsReport()
    memory = memory or {}
    postulates = list(postulates or [])
    facts_mem = facts_from_memory(memory)

    assert_ = [a for a in atomos if getattr(a, "type_", None) == AtomType.STATEMENT]
    facts_doc: list[Fact] = []
    texts_session_extra: list[str] = []
    for a in assert_:
        origin = "document"
        if getattr(a.origin, "value", a.origin) != "DATA":
            origin = "intent"
        hs = extract_facts(a.text, origin=origin, verified=False, atom_id=a.id)
        facts_doc.extend(hs)
        inf.postulates_new.extend(hs)
        texts_session_extra.append(a.text)
    # Inherit subject only if the current clause does not have an entity (e.g. 'already settled').
    last_subject = None
    _empty = {"", "ya se liquido", "se liquido"}
    for h in facts_doc:
        subj = (h.subject or "").strip()
        if subj and subj not in _empty and "liquido" not in subj:
            last_subject = subj
        elif last_subject and (subj in _empty or "liquido" in subj):
            h.subject = last_subject
    # Contradiction A/no-A in the original sentence (before starting by 'y'/'e').
    from .deconstructor import contradiction_in_phrase, propositions as _props_strong
    texts_phrases = []
    if text_document:
        texts_phrases.extend(re.split(r"(?<=[.!?;])\s+|\n+", text_document))
    texts_phrases.extend(a.text for a in assert_)
    if any(contradiction_in_phrase(fr) for fr in texts_phrases if fr and len(fr.strip()) > 3):
        if "contradiction_internal_between_affirmations" not in inf.reasons:
            inf.reasons.append("contradiction_internal_between_affirmations")
        for a in assert_:
            inf.truths[a.id] = TruthState.CONTRADICTED
            if a.id not in inf.atomos_incoherent:
                inf.atomos_incoherent.append(a.id)
        if not assert_:
            inf.truths["DOC"] = TruthState.CONTRADICTED

    text_combo = " ".join([text_document or ""] + [a.text for a in assert_])
    ids_doc = [a.id for a in assert_]

    for h in check_arithmetic(text_combo, ids_doc) + check_calendar(text_combo, ids_doc):
        inf.findings.append(h)
        if h.reason not in inf.reasons:
            inf.reasons.append(h.reason)
        dest = list(h.atom_ids or ids_doc) or ["DOC"]
        for aid in dest:
            inf.truths[aid] = TruthState.REFUTED if h.type_ == "REFUTED" else TruthState.CONTRADICTED
            if aid != "DOC" and aid not in inf.atomos_incoherent:
                inf.atomos_incoherent.append(aid)

    for i, h1 in enumerate(facts_doc):
        for h2 in facts_doc[i + 1:]:
            if contradicting(h1, h2):
                inf.findings.append(Finding(
                    "CONTRADICTED", "contradiction_internal_between_affirmations",
                    [x for x in (h1.atom_id, h2.atom_id) if x],
                    f"{h1.subject}:{h1.aspect} {h1.value_}/{h1.state} vs {h2.value_}/{h2.state}",
                ))
                if "contradiction_internal_between_affirmations" not in inf.reasons:
                    inf.reasons.append("contradiction_internal_between_affirmations")
                for hx in (h1, h2):
                    if hx.atom_id:
                        # do not step REFUTED
                        if inf.truths.get(hx.atom_id) != TruthState.REFUTED:
                            inf.truths[hx.atom_id] = TruthState.CONTRADICTED
                        if hx.atom_id not in inf.atomos_incoherent:
                            inf.atomos_incoherent.append(hx.atom_id)

    for hd in facts_doc:
        for hm in facts_mem:
            if contradicting(hd, hm):
                inf.findings.append(Finding(
                    "REFUTED", "contradiction_with_memory_verified",
                    [x for x in (hd.atom_id,) if x],
                    f"memory {hm.subject}={hm.value_}/{hm.state}/{hm.date_} vs {hd.value_}/{hd.state}/{hd.date_}",
                ))
                if "contradiction_with_memory_verified" not in inf.reasons:
                    inf.reasons.append("contradiction_with_memory_verified")
                if hd.atom_id:
                    inf.truths[hd.atom_id] = TruthState.REFUTED
                    if hd.atom_id not in inf.atomos_incoherent:
                        inf.atomos_incoherent.append(hd.atom_id)
            elif subjects_compatible(hd, hm) and aspects_comparable(hd, hm) and equivalents(hd, hm):
                if hd.atom_id and hd.atom_id not in inf.truths:
                    inf.truths[hd.atom_id] = TruthState.SUPPORTED
                    inf.supported_by_memory.append(hd.atom_id)

    for hd in facts_doc:
        for hp in postulates:
            if contradicting(hd, hp):
                inf.findings.append(Finding(
                    "CONTRADICTED", "contradiction_between_turns",
                    [x for x in (hd.atom_id,) if x],
                    f"postulate {hp.subject}={hp.value_}/{hp.state} vs {hd.value_}/{hd.state}",
                ))
                if "contradiction_between_turns" not in inf.reasons:
                    inf.reasons.append("contradiction_between_turns")
                if hd.atom_id:
                    if inf.truths.get(hd.atom_id) != TruthState.REFUTED:
                        inf.truths[hd.atom_id] = TruthState.CONTRADICTED
                    if hd.atom_id not in inf.atomos_incoherent:
                        inf.atomos_incoherent.append(hd.atom_id)

    texts_prev = list(texts_session or [])
    if postulates or texts_prev:
        texts_join = texts_prev + [getattr(p, "text", "") or "" for p in postulates] + [text_combo]
        text_long = " ".join(t for t in texts_join if t)
        only = check_arithmetic(text_combo) + check_calendar(text_combo)
        only_keys = {(x.reason, x.detail) for x in only}
        for h in check_arithmetic(text_long, ids_doc) + check_calendar(text_long, ids_doc):
            if (h.reason, h.detail) in only_keys:
                continue
            if any(x.reason == h.reason and x.detail == h.detail for x in inf.findings):
                continue
            if h.reason in {"contradiction_arithmetic", "date_impossible", "chronology_impossible"}:
                if "contradiction_between_turns" not in inf.reasons:
                    inf.reasons.append("contradiction_between_turns")
            if h.reason not in inf.reasons:
                inf.reasons.append(h.reason)
            inf.findings.append(h)
            for aid in ids_doc:
                if inf.truths.get(aid) != TruthState.REFUTED:
                    inf.truths[aid] = TruthState.REFUTED if h.type_ == "REFUTED" else TruthState.CONTRADICTED
                if aid not in inf.atomos_incoherent:
                    inf.atomos_incoherent.append(aid)

    for a in assert_:
        see = inf.truths.get(a.id)
        if see in (TruthState.CONTRADICTED, TruthState.REFUTED):
            a.a1 = VerdictA1.INCONSISTENT
            dets = [h.detail for h in inf.findings if a.id in (h.atom_ids or [])]
            note = "contradice a " + (dets[0] if dets else "un hecho verificado o un postulado de la sesión")
            if note not in a.notes:
                a.notes.append(note)
        elif see is None:
            inf.truths[a.id] = TruthState.UNDETERMINED

    return inf
