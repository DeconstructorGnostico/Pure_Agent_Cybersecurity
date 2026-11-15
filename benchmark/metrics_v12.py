"""Metrics v1.2 from predictions_v12.json → RESULTS_v12.md, results_v12.json, comparative_v12.png."""
from __future__ import annotations
import json
from pathlib import Path
HERE = Path(__file__).resolve().parent
P = json.loads((HERE / "predictions_v12.json").read_text())
DATA = P["datasets"]

def metr(rows, get):
    tp = fn = fp = tn = 0; ms = 0.0; n_ms = 0
    for f in rows:
        d, t = get(f)
        if t is not None: ms += t; n_ms += 1
        if f["malicious"]: tp += d; fn += not d
        else: fp += d; tn += not d
    rec = tp / (tp + fn) if tp + fn else None
    fpr = fp / (fp + tn) if fp + tn else None
    prec = tp / (tp + fp) if tp + fp else None
    f1 = (2 * prec * rec / (prec + rec)) if (prec and rec) else (0.0 if (rec is not None and prec is not None) else None)
    return dict(n=len(rows), bad=tp + fn, ben=fp + tn, tp=tp, fn=fn, fp=fp, tn=tn,
                det=rec, fpr=fpr, prec=prec, f1=f1, ms=(ms / n_ms if n_ms else None))

def g_apc(key): return lambda f: (f[key]["detected"], f[key]["ms"]) if key in f else (False, None)
def g_db(f): return (f["deberta"]["detected"], f["deberta"]["ms"])
def g_lg(f): return (f["llmguard"]["flag"], f["llmguard"]["ms"])

pct = lambda x: "—" if x is None else f"{x*100:.1f}%"
num = lambda x: "—" if x is None else f"{x:.3f}"
NAMES = {
    "main": "Main bank (bank.py, used to adjust 1.1)",
    "heldout": "Held-out 1 (bank_heldout.py, contaminated by correcting 1.1)",
    "heldout2": "Held-out 2 clean (bank_heldout2.py, seed 20270101)",
    "deepset": "deepset/prompt-injections (train+test)",
    "safeguard": "xTRam1/safe-guard-prompt-injection (test)",
    "jackhhao_jailbreak": "jackhhao/jailbreak-classification (test)",
    "jasperls": "JasperLS/prompt-injections (test)",
    "gandalf_ignore": "Lakera/gandalf_ignore_instructions (test, malicious only)",
    "spml": "reshabhs/SPML_Chatbot_Prompt_Injection (balanced)",
    "jayavibhav": "jayavibhav/prompt-injection (test, balanceado)",
    "guardrails_jailbreak": "GuardrailsAI/detect-jailbreak (balanced)",
    "jailbreakhub": "walledai/JailbreakHub (balanced)",
}
APC_BANKS = ("main", "heldout", "heldout2")

res = {}; md = []
md.append("# Results Pure Agent Cybersecurity v1.2 (sensor ML ProtectAI due-v3}\n")
md.append(f"Package version: **{P['version']}**. "
          "APC v1.1 = the same agent with the sensor off (rules identical to 1.1). "
          "‘Detection’ = BLOCK or QUARANTINE; UNDETERMINED does not count as detection.\n")
md.append("Sensor frames: **INTENT** (user direct request; sensor only "
          "may lead to UNDETERMINED) and **DATA** (text as document/tool unreliable; "
          "the sensor can lead to QUARANTINE).\n")

def row_table(name_, cols):
    out = ["", f"### {NAMES.get(name_, name_)}", ""]
    rows = DATA[name_]
    out.append(f"Cases: {len(rows)} ({sum(f['malicious'] for f in rows)} malicious, {sum(not f['malicious'] for f in rows)} benign)")
    out.append("")
    out.append("Tool  Detection  False positive  Accuracy  F1  Latency")
    out.append("|---|---|---|---|---|---|")
    r = {}
    for etq, get in cols:
        m = metr(rows, get); r[etq] = m
        lat = "—" if m["ms"] is None else f"{m['ms']:.1f} ms"
        out.append(f"| {etq} | {pct(m['det'])} ({m['tp']}/{m['bad']}) | {pct(m['fpr'])} ({m['fp']}/{m['ben']}) | {num(m['prec'])} | {num(m['f1'])} | {lat} |")
    res[name_] = r
    return out

# columns by type of bank
for name_ in DATA:
    external = name_ not in APC_BANKS
    cols = [("APC v1.1 (INTENT)", g_apc("apc11")), ("APC v1.2 (INTENT)", g_apc("apc12"))]
    if external:
        cols += [("APC v1.1 (DATA)", g_apc("apc11_doc")), ("APC v1.2 (DATA)", g_apc("apc12_doc"))]
    cols += [("LLM Guard PromptInjection", g_lg), ("ProtectAI deberta-v2 (0.5)", g_db)]
    md += row_table(name_, cols)

(HERE / "results_v12.json").write_text(json.dumps(res, ensure_ascii=False, indent=1))
(HERE / "RESULTS_v12_tables.md").write_text("\n".join(md) + "\n")
print("\n".join(md))
