"""Calibrate sensor thresholds ML over eval/bank_calibration.py (separate split).

Criterion: 0 false positives in the calibration split (coherent with the agent's zero FP policy). The QUARANTINE threshold is chosen as the lowest value that does not mark any benign split, and a margin is left for UNDETERMINED. Write benchmark/calibration.json.

Usage: APC_ROOT=. ./.../python eval/calibration_sensor.py
"""
from __future__ import annotations
import json, sys, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "eval"))
from pure_agent_cyber.sensor_ml import InjectionSensor, is_prose, language_in
import bank_calibration

def main():
    s = InjectionSensor(threshold_quarantine=2.0, threshold_indeterminate=2.0)  # irrelevant thresholds: we only scored.
    if not s.available:
        print("sensor no disponible:", s.error); return 1
    cases = bank_calibration.generate()
    rows = []
    t0 = time.perf_counter()
    for c in cases:
        applies = is_prose(c["text"]) and language_in(c["text"])
        score = s.compute_score(c["text"]).score if applies else None
        rows.append({"malicious": c["malicious"], "applies": applies, "score": score})
    ben = [f for f in rows if not f["malicious"] and f["applies"] and f["score"] is not None]
    bad = [f for f in rows if f["malicious"] and f["applies"] and f["score"] is not None]
    max_ben = max((f["score"] for f in ben), default=0.0)
    # quarantine threshold: above the highest benign (zero FP in calibration), with a margin peline
    import math
    threshold_c = min(0.999, max(0.9, math.nextafter(max_ben, 1.0)))
    # Indeterminate threshold: intermediate point where there are still no benign but it does catch more malicious
    bens = sorted(f["score"] for f in ben)
    p95 = bens[int(len(bens) * 0.95) - 1] if bens else 0.0
    threshold_i = min(threshold_c, max(0.8, round(p95 + (threshold_c - p95) * 0.5, 4)))
    def det(th):
        return sum(1 for f in bad if f["score"] >= th) / len(bad) if bad else 0.0
    def fp(th):
        return sum(1 for f in ben if f["score"] >= th) / len(ben) if ben else 0.0
    out = {
        "model_": s.model_, "split": "bank_calibration.py",
        "n_benign_prose": len(ben), "n_malicious_prose": len(bad),
        "benign_score_max": round(max_ben, 6), "benign_p95": round(p95, 6),
        "threshold_quarantine": round(threshold_c, 6), "threshold_indeterminate": round(threshold_i, 6),
        "detection_in_calibration_quarantine": round(det(threshold_c), 4),
        "detection_in_calibration_indeterminate": round(det(threshold_i), 4),
        "fp_in_calibration_quarantine": round(fp(threshold_c), 4),
        "fp_in_calibration_indeterminate": round(fp(threshold_i), 4),
        "segundos": round(time.perf_counter() - t0, 1),
    }
    (ROOT / "benchmark").mkdir(exist_ok=True)
    (ROOT / "benchmark" / "calibration.json").write_text(json.dumps(out, ensure_ascii=False, indent=1))
    print(json.dumps(out, ensure_ascii=False, indent=1))
    return 0

if __name__ == "__main__":
    sys.exit(main())
