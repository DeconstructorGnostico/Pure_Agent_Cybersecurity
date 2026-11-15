"""Reading layers: the text as it is and its versions defuscate.

The detectors don't just read what you see.
- the version without characters of zero width, without two-way controls and without homoglyphs;
- the non-tricked version of shell quotes (r''m, r-m, $$$)IFS});
- what's inside base64 blocks, hex (-)x., URL-encoding and "tag" Unicode characters.

Every trick found remains a flag: hiding something is already a sign.
"""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import unquote

WIDTH_ZERO = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff\u00ad\u180e\u2061\u2062\u2063\u2064"), None)
BIDI = dict.fromkeys(map(ord, "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200e\u200f"), None)

HOMOGLIFOS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i",
    "ѕ": "s", "ј": "j", "ԁ": "d", "һ": "h", "ӏ": "l", "ο": "o", "α": "a", "ν": "v",
    "τ": "t", "ı": "i", "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H",
    "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X", "Ѕ": "S", "І": "I", "Ј": "J",
})

_B64 = re.compile(r"(?<![A-Za-z0-9+/=_-])([A-Za-z0-9+/_-]{16,}={0,2})(?![A-Za-z0-9+/=_-])")
_HEX = re.compile(r"(?:\\x[0-9a-fA-F]{2}){3,}")
_URL = re.compile(r"%[0-9a-fA-F]{2}")
_TAGS = re.compile("[\U000E0000-\U000E007F]+")


@dataclass
class Reading:
    original: str
    layers: dict[str, str] = field(default_factory=dict)
    flag_list: list[str] = field(default_factory=list)

    def texts(self) -> list[tuple[str, str]]:
        return list(self.layers.items())

    @property
    def plane(self) -> str:
        return self.layers.get("normalized", self.original)


def _printable(s: str) -> bool:
    if not s:
        return False
    ok = sum(1 for c in s if c.isprintable() or c in "\n\t\r")
    return ok / len(s) >= 0.9 and sum(c.isalpha() for c in s) >= 3


def _desofuscar_shell(t: str) -> str:
    t = re.sub(r"\$\{IFS\}|\$IFS(\$\d)?", " ", t)
    # r'm, r'm → rm ; r\m → rm (only between letters, so as not to break routes or regex)
    t = re.sub(r"(?<=\w)(''|\"\")(?=\w)", "", t)
    return t


def _without_escapes(t: str) -> str:
    # r\m → rm. Goes in a separate layer to not break Windows paths (HKLM\SAM).
    return re.sub(r"(?<=[A-Za-z])\\(?=[A-Za-z])", "", t)


def _decode_b64(t: str) -> list[str]:
    outputs = []
    for m in _B64.finditer(t):
        block = m.group(1)
        if block.isalpha() and (block.islower() or block.isupper()):
            continue  # a long word is not base64
        for alt in (block, block.replace("-", "+").replace("_", "/")):
            try:
                raw = base64.b64decode(alt + "=" * (-len(alt) % 4), validate=True)
                txt = raw.decode("utf-8")
            except (binascii.Error, ValueError, UnicodeDecodeError):
                continue
            if _printable(txt):
                outputs.append(txt)
                break
    return outputs


def read(text: str) -> Reading:
    text = text or ""
    lec = Reading(original=text)
    lec.layers["original"] = text
    if any(ord(c) in WIDTH_ZERO for c in text):
        lec.flag_list.append("width_zero")
    if any(ord(c) in BIDI for c in text):
        lec.flag_list.append("bidi")
    tags = _TAGS.findall(text)
    if tags:
        lec.flag_list.append("unicode_tags")
        hidden = "".join(chr(ord(c) - 0xE0000) for block in tags for c in block if 0x20 <= ord(c) - 0xE0000 < 0x7F)
        if hidden.strip():
            lec.layers["tags_hidden"] = hidden
    t = unicodedata.normalize("NFKC", text)
    t = _TAGS.sub("", t).translate(WIDTH_ZERO).translate(BIDI)
    t2 = t.translate(HOMOGLIFOS)
    if t2 != t:
        lec.flag_list.append("homoglifos")
    t3 = _desofuscar_shell(t2)
    if t3 != t2:
        lec.flag_list.append("tricks_shell")
    lec.layers["normalized"] = re.sub(r"[ \t]+", " ", t3)
    t4 = _without_escapes(t3)
    if t4 != t3 and re.search(r"(?<![\w:])[a-z]+\\[a-z]", t3) and not re.search(r"[A-Za-z]:\\|HK(?:LM|CU)\\", t3):
        lec.layers["without_escapes"] = t4
        lec.flag_list.append("tricks_shell")
    # URL-encoding (up to 3 turns, for double encoded %252e)
    if _URL.search(t3):
        dec = t3
        for _ in range(3):
            new = unquote(dec)
            if new == dec:
                break
            dec = new
        if dec != t3:
            lec.layers["url"] = dec
            lec.flag_list.append("url_encoding")
    if _HEX.search(t3):
        try:
            dec = _HEX.sub(lambda m: bytes.fromhex(m.group(0).replace("\\x", "")).decode("utf-8", "replace"), t3)
            lec.layers["hex"] = dec
            lec.flag_list.append("hex")
        except ValueError:
            pass
    b64 = _decode_b64(t3)
    for i, txt in enumerate(b64[:4]):
        lec.layers[f"base64_{i}"] = _desofuscar_shell(unicodedata.normalize("NFKC", txt))
        # one more lap: base64 within base64
        for j, txt2 in enumerate(_decode_b64(txt)[:2]):
            lec.layers[f"base64_{i}_{j}"] = txt2
    if b64:
        lec.flag_list.append("base64")
    return lec
