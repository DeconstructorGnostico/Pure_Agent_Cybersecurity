"""Comparative Chart v1.2 from results_v12.json."""
import json
from pathlib import Path
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
HERE = Path(__file__).resolve().parent
R = json.loads((HERE / "results_v12.json").read_text())

panels = [("safeguard", "safe-guard (2060)"), ("jackhhao_jailbreak", "jackhhao jailbreak (262)"),
           ("gandalf_ignore", "gandalf_ignore (112)"), ("spml", "SPML (500)"),
           ("deepset", "deepset (662)"), ("jailbreakhub", "JailbreakHub (500)")]
herr = ["APC v1.1 (DATA)", "APC v1.2 (DATA)", "LLM Guard PromptInjection", "ProtectAI deberta-v2 (0.5)"]
etq = ["APC v1.1\n(DATA)", "APC v1.2\n(DATA)", "LLM Guard", "deberta v2"]
fig, axs = plt.subplots(2, 3, figsize=(17, 9))
for ax, (ds, tit) in zip(axs.flat, panels):
    rr = R[ds]; x = np.arange(len(herr))
    det = [rr[h]["det"] * 100 if rr[h]["det"] is not None else 0 for h in herr]
    fp = [rr[h]["fpr"] * 100 if rr[h]["fpr"] is not None else 0 for h in herr]
    b1 = ax.bar(x - 0.2, det, 0.4, label="Detección (%)", color="#2e7d32")
    b2 = ax.bar(x + 0.2, fp, 0.4, label="False positive (%)", color="#c62828")
    ax.bar_label(b1, fmt="%.0f", fontsize=8); ax.bar_label(b2, fmt="%.0f", fontsize=8)
    ax.set_xticks(x); ax.set_xticklabels(etq, fontsize=8)
    ax.set_title(tit, fontsize=11); ax.set_ylim(0, 112); ax.grid(axis="y", alpha=.3)
axs[0, 0].set_ylabel("%"); axs[1, 0].set_ylabel("%")
axs[0, 0].legend(loc="upper left", fontsize=9)
fig.suptitle("APC v1.2 (sensor ML in channel DATA) vs v1.1 vs LLM Guard vs ProtectAI duty\n"
             "detection vs false positives — sensor raises detection in English by approaching duty, with less FP", fontsize=12)
fig.tight_layout(rect=[0, 0, 1, 0.95]); fig.savefig(HERE / "comparative_v12.png", dpi=130)
print("ok", HERE / "comparative_v12.png")
