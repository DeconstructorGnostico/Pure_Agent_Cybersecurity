"""Session memory to detect match attacks in several steps.

It is recalled, by session:
- readings of sensitive resources (even if the step is left UNDETERMINED);
- defined variables (A="rm -rf", B=" /") to expand in next steps;
- downloads from unreliable domains, to see if they are then executed;
- tokens issued, to revoke them if the session is hostile.

It is not verified memory (they are not facts of the world): they are session postulates, as in CVA. They serve to see the chain, not to "know" anything.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

_ASSIGNMENT = re.compile(r"(?:^|[;&|\s])(?:export\s+|set\s+|local\s+)?([A-Za-z_]\w*)=(\"[^\"]*\"|'[^']*'|[^\s;&|]+)")
_ASSIGNMENT_NATURAL = re.compile(
    r"\b(?:guarda|define|almacena|asigna|save|store|set|put)\s+[\"'“](.+?)[\"'”]\s+(?:como|en|a|as|in|into|to)\s+(?:la variable\s+|variable\s+|the variable\s+)?\$?([A-Za-z_]\w*)", re.I)
_CONCAT_NATURAL = re.compile(r"\b(?:concatena|une|junta|combina|join|concatenate|combine)\s+\$?([A-Za-z_]\w*)\s*(?:y|con|and|with|\+|,)\s*\$?([A-Za-z_]\w*)", re.I)
_DOWNLOAD = re.compile(
    r"\b(?:curl|wget|iwr|invoke-webrequest)\b[^\n;|]*?(https?://[^\s'\"]+)[^\n;|]*?(?:\s(?:-o|-O|--output|-outfile)\s+(\S+))?|"
    r"\b(?:curl|wget)\b[^\n;|]*?\s(?:-o|-O|--output)\s+(\S+)[^\n;|]*?(https?://[^\s'\"]+)", re.I)


@dataclass
class Session:
    id: str
    steps: int = 0
    readings_sensitive: list = field(default_factory=list)
    variables: dict = field(default_factory=dict)
    downloads: dict = field(default_factory=dict)    # path → url
    tokens: list = field(default_factory=list)
    marked: bool = False
    history: list = field(default_factory=list)

    def register_variables(self, text: str) -> None:
        for m in _ASSIGNMENT.finditer(text):
            v = m.group(2)
            if v[:1] in "\"'" and v[-1:] == v[:1]:
                v = v[1:-1]
            self.variables[m.group(1)] = v
        for m in _ASSIGNMENT_NATURAL.finditer(text):
            self.variables[m.group(2)] = m.group(1)

    def expand(self, text: str) -> str:
        """Replaces $X, $$X} and %X% with the memory. If there is nothing to expand, it returns the same."""
        if not self.variables:
            return text
        out = text
        for k, v in sorted(self.variables.items(), key=lambda kv: -len(kv[0])):
            out = re.sub(r"\$\{" + re.escape(k) + r"\}|\$" + re.escape(k) + r"\b|%" + re.escape(k) + "%", lambda _m: v, out)
        for m in _CONCAT_NATURAL.finditer(text):
            a, b = m.group(1), m.group(2)
            if a in self.variables and b in self.variables:
                out += "\n" + self.variables[a] + self.variables[b]
                out += "\n" + self.variables[a] + " " + self.variables[b]
        return out

    def register_downloads(self, text: str, is_trusted) -> None:
        for m in _DOWNLOAD.finditer(text):
            url = m.group(1) or m.group(4)
            path_ = m.group(2) or m.group(3)
            if not url:
                continue
            host = re.sub(r"^https?://", "", url, flags=re.I).split("/")[0].split("@")[-1].split(":")[0]
            if is_trusted(host):
                continue
            if not path_:
                path_ = PurePosixPath(url.split("?")[0]).name or "descarga"
            self.downloads[path_.strip("'\"")] = url

    def executes_download(self, text: str) -> str | None:
        """Does this step give permissions or execute something downloaded before an unreliable domain?"""
        for path_ in self.downloads:
            name_ = PurePosixPath(path_).name
            for cand in {path_, name_}:
                c = re.escape(cand)
                if re.search(r"\bchmod\s+(?:\+x|[0-7]*[1357][0-7]{0,2}|u\+x|a\+x)\s+\S*" + c, text, re.I) or \
                   re.search(r"(?:^|[\s;&|])(?:sudo\s+)?(?:(?:ba|z)?sh|python[23]?|perl|ruby|node|source|\.)\s+\S*" + c + r"\b", text, re.I) or \
                   re.search(r"(?:^|[\s;&|])\./" + re.escape(name_) + r"\b", text) or \
                   re.search(r"\b(?:ejecuta|corre|lanza|run|execute|instala|install|abre|open)\b[^\n]*" + c, text, re.I):
                    return path_
        return None


class Sessions:
    def __init__(self):
        self._s: dict[str, Session] = {}

    def fetch(self, sid: str) -> Session:
        if sid not in self._s:
            self._s[sid] = Session(sid)
        return self._s[sid]
