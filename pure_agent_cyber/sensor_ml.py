"""Sensor ML (v1.2): protectai/deberta-v3-base-prompt-injection-v2 as one more sensor.

Sensor rules (respect the axiom "the interpreter proposes, the executor decides"):
- The sensor only PROPOSES evidence: a finding INJECTION_PROMPT/sensor_ml of severity
  MEDIA, without verified fact (truth UNDETERMINED). You can never upload anything to HIGH/CRITICAL or cause BLOCK, or authorize or execute commands: do not touch the key HMAC.
- Policy (agent._decid):
    score threshold_quarantine → QUARANTINE (isolated for human revision; reversible) score threshold_indeterminate → UNDETERMINED (I don't know)
- In the INTENTION channel only applies to prose (the model is for natural language in
  In the channel DATA it is always applied.
- Long texts: windows of ~1800 characters with overlap, is taken the maximum.
- If the model or transformers are not available → available=False and the agent is
  it carries exactly as the 1.1 (safe degradation, recorded in the audit).

The thresholds come out of eval/calibration_sensor.py (calibration split separated from all test banks). See benchmark/CALIBRATION.md.
"""
from __future__ import annotations

import hashlib
import os
import re
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

MODEL = "protectai/deberta-v3-base-prompt-injection-v2"
REVISION = "90c9989b1a342275dd0d1a95aad283c04e075671"

# Calibrated values (eval/calibration_sensor.py → benchmark/calibration.json). See CALIBRATION.md.
THRESHOLD_QUARANTINE = 0.999
THRESHOLD_INDETERMINATE = 0.8

WINDOW = 1800
OVERLAP = 200
MAX_WINDOWS = 6

_WORD = re.compile(r"[A-Za-zÁÉÍÓÚÜÑáéíóúüñ]{2,}")
_SYMBOLS_SHELL = re.compile(r"[|;&<>$`{}\\]|--?\w|/\w+/")


def is_prose(text: str) -> bool:
    """Does it look like natural language (not a command)? Minimum 4 words and most words about symbols."""
    t = (text or "").strip()
    words = _WORD.findall(t)
    if len(words) < 4:
        return False
    tokens = t.split()
    simbolicos = sum(1 for x in tokens if _SYMBOLS_SHELL.search(x))
    return simbolicos / max(1, len(tokens)) < 0.25


_IS_MARKS = set("¿¡ñáéíóúü")
_IS_WORDS = {"que","de","la","el","los","las","un","una","por","para","con","como","qué",
                "cómo","este","esta","esto","ignora","olvida","actúa","finge","dime","hazme",
                "cuál","tu","mi","no","sí","y","o","en","es","son","del","al","se","su","muéstrame"}
_IN_WORDS = {"the","and","you","your","ignore","previous","instructions","system","prompt",
                "please","what","is","are","of","to","a","an","for","with","as","now","all",
                "forget","act","pretend","disregard","reveal","from","this","that","do","not"}


def language_in(text: str) -> bool:
    """Is the text probably English? The ProtectAI model is only English (its own
    card says so) and marks prose in Spanish as an injection. If it does not look English, the sensor abstains (safe degradation to 1.1). Heuristic light, without external dependencies."""
    t = (text or "").lower()
    if any(c in _IS_MARKS for c in t):
        return False
    words = _WORD.findall(t)
    if not words:
        return False
    is_ = sum(1 for w in words if w in _IS_WORDS)
    in_ = sum(1 for w in words if w in _IN_WORDS)
    if is_ > in_:
        return False
    # requires some English sign for short texts
    if len(words) < 12 and in_ == 0:
        return False
    return True


def windows(text: str) -> list[str]:
    t = text or ""
    if len(t) <= WINDOW:
        return [t]
    out, i = [], 0
    while i < len(t):
        out.append(t[i:i + WINDOW])
        i += WINDOW - OVERLAP
    if len(out) > MAX_WINDOWS:  # first and last: the attack usually goes to the beginning or the end
        out = out[:MAX_WINDOWS - 1] + [out[-1]]
    return out


@dataclass
class Reading:
    score: Optional[float]
    ms: float
    windows: int


class InjectionSensor:
    """Wraps the sorter. `classifier` allows you to inject a fake into tests."""

    def __init__(self, classifier: Optional[Callable[[list[str]], list[float]]] = None,
                 threshold_quarantine: float = THRESHOLD_QUARANTINE, threshold_indeterminate: float = THRESHOLD_INDETERMINATE,
                 model_: str = MODEL):
        self.model_ = model_
        self.threshold_quarantine = threshold_quarantine
        self.threshold_indeterminate = threshold_indeterminate
        self._clf = classifier
        self.error: Optional[str] = None
        self.last_ms = 0.0
        self._cache: dict[str, float] = {}
        self.use_cache = False
        if self._clf is None:
            self._load()

    def _load(self):
        if os.environ.get("APC_SENSOR", "auto").lower() in ("0", "off", "no", "false"):
            self.error = "disabled by APC_SENSOR"
            return
        try:
            import torch  # noqa: F401
            from transformers import pipeline
            pipe = pipeline("text-classification", model=self.model_, truncation=True, max_length=512, device="cpu",
                            model_kwargs={"local_files_only": os.environ.get("HF_HUB_OFFLINE") == "1"})

            def clf(texts: list[str]) -> list[float]:
                res = pipe(texts)
                return [r["score"] if r["label"] == "INJECTION" else 1.0 - r["score"] for r in res]
            self._clf = clf
            self.pipeline = pipe
        except Exception as e:  # without model → degrade to 1.1
            self.error = f"{type(e).__name__}: {str(e)[:160]}"
            self._clf = None

    @property
    def available(self) -> bool:
        return self._clf is not None

    def compute_score(self, text: str) -> Reading:
        if not self.available or not (text or "").strip():
            return Reading(None, 0.0, 0)
        key_ = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
        if self.use_cache and key_ in self._cache:
            return Reading(self._cache[key_], 0.0, 0)
        vs = windows(text)
        t = time.perf_counter()
        try:
            score = max(float(s) for s in self._clf(vs))
        except Exception as e:  # hot failure → «I don't know» of the sensor, not ALLOW for it
            self.error = f"{type(e).__name__}: {str(e)[:160]}"
            return Reading(None, (time.perf_counter() - t) * 1000, len(vs))
        ms = (time.perf_counter() - t) * 1000
        self.last_ms = ms
        if self.use_cache:
            self._cache[key_] = score
        return Reading(score, ms, len(vs))

    def proposal(self, score: Optional[float]) -> str:
        if score is None:
            return "WITHOUT_READING"
        if score >= self.threshold_quarantine:
            return "QUARANTINE"
        if score >= self.threshold_indeterminate:
            return "UNDETERMINED"
        return "NOTHING"

    def info(self) -> dict:
        return {"model_": self.model_, "revision": REVISION, "available": self.available, "error": self.error,
                "threshold_quarantine": self.threshold_quarantine, "threshold_indeterminate": self.threshold_indeterminate}


_GLOBAL: Optional[InjectionSensor] = None
_LOCK = threading.Lock()


def sensor_by_default() -> InjectionSensor:
    """A single model loaded by process (lazy load)."""
    global _GLOBAL
    with _LOCK:
        if _GLOBAL is None:
            _GLOBAL = InjectionSensor()
        return _GLOBAL
