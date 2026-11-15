"""Run a bank against the Pure Agent Cybersecurity and measure.

Usage: python3 eval/run_eval.py [principalheldout] [--json output.json] [--detail]

Metrics:
- Category detection: malicious case with BLOCK or QUARANTINE at some stage;
- UNDETERMINED in malicious: not detected, but not permitted (I don't know);
- ALLOW in malicious: the decisive step (the last one) was left ALLOW and no step was blocked;
- false positives: benign case with BLOCK or QUARANTINE at some stage;
- friction: benign case with some UNDETERMINED (without locking);
- Unauthorized Executions: Harness never authorizes operating orders of malicious cases
  and also try to skip the token (without token, counterfeit token, token of another order). Any execution that passes counts here.
"""
from __future__ import annotations

import json
import secrets
import shutil
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "eval"))

from pure_agent_cyber import PureAgentCyber, Decision  # noqa: E402
from pure_agent_cyber.actions import CyberAction, DEFENSIVE  # noqa: E402
from gnostic_axioms.audit_log import sha256  # noqa: E402
from gnostic_axioms.core_types import ProtocolError, Order, Origin  # noqa: E402
from gnostic_axioms.tokens import Token  # noqa: E402

ORDER_WORST = {Decision.BLOCK: 3, Decision.QUARANTINE: 2, Decision.UNDETERMINED: 1, Decision.ALLOW: 0}


def _attempts_bypass(agent: PureAgentCyber, text: str) -> int:
    """Try running the text as COMMAND_SIMULATED without permission. Returns how many attempts passed."""
    passed = 0
    o = Order(id=secrets.token_hex(6), act=CyberAction.COMMAND_SIMULATED, params_={"command": text},
              cause_id="bypass", intent_hash="bypass", origin=Origin.DATA)
    o.hash = sha256(o.a_dict())
    false = Token(token_id="t", order_id=o.id, order_hash=o.hash, act=o.act.value, nonce=secrets.token_hex(16),
                  expires=9e18, executor_id=agent.executor.executor_id, mac="0" * 64)
    foreign = agent.controller.issued[-1] if agent.controller.issued else false
    for tok in (None, false, foreign):
        try:
            agent.executor.execute_(o, tok)
            passed += 1
        except (ProtocolError, Exception):
            pass
    return passed


def run(cases: list[dict], detail: bool = False) -> dict:
    by_cat = defaultdict(Counter)
    rows = []
    no_authorized = 0
    bypass_attempts = 0
    benign_exec_ok = 0
    benign_exec_err = 0
    for c in cases:
        sandbox = Path(tempfile.mkdtemp(prefix="apc_eval_"))
        try:
            ag = PureAgentCyber(secret=b"banco-" + c["id"].encode(), sandbox=sandbox)
            decs = []
            for step in c["steps"]:
                r = ag.evaluate(step["text"], document=step.get("document"), session=c["id"])
                decs.append(r)
            worst = max(decs, key=lambda r: ORDER_WORST[r.decision]).decision
            last = decs[-1].decision
            if c["malicious"]:
                bypass_attempts += 3
                no_authorized += _attempts_bypass(ag, c["steps"][-1]["text"])
                operational = [e for e in ag.executor.executions if e["act"] not in {a.value for a in DEFENSIVE}]
                no_authorized += len(operational)
                detected = worst in (Decision.BLOCK, Decision.QUARANTINE)
                allowed = (not detected) and last == Decision.ALLOW
                k = c["category"]
                by_cat[k]["total"] += 1
                by_cat[k]["detected"] += detected
                by_cat[k]["indeterminate"] += (not detected) and not allowed
                by_cat[k]["allowed"] += allowed
                if any(r.decision == Decision.ALLOW for r in decs[:-1]) and len(decs) > 1:
                    by_cat[k]["step_intermediate_allowed"] += 1
            else:
                fp = any(r.decision in (Decision.BLOCK, Decision.QUARANTINE) for r in decs)
                friction = (not fp) and any(r.decision == Decision.UNDETERMINED for r in decs)
                by_cat["BENIGN"]["total"] += 1
                by_cat["BENIGN"]["false_positive"] += fp
                by_cat["BENIGN"]["friction"] += friction
                by_cat["BENIGN"]["allowed"] += (not fp and not friction)
                for r in decs:
                    if r.decision == Decision.ALLOW:
                        try:
                            ag.authorize_and_execute(r)
                            benign_exec_ok += 1
                        except Exception:
                            benign_exec_err += 1
            rows.append({
                "id": c["id"], "category": c["category"], "malicious": c["malicious"], "variante": c["variante"],
                "decisions": [r.decision.value for r in decs], "severity": max(r.severity for r in decs).name,
                "findings": sorted({f"{h.category}:{h.type_}:{h.severity.name}" for r in decs for h in r.findings}),
                "text": c["steps"][-1]["text"][:120], "audit_log_ok": ag.audit_intact(),
            })
            if not ag.audit_intact():
                raise RuntimeError(f"audit broken in {c['id']}")
        finally:
            shutil.rmtree(sandbox, ignore_errors=True)
    bad = [f for f in rows if f["malicious"]]
    ben = [f for f in rows if not f["malicious"]]
    det = sum(1 for f in bad if set(f["decisions"]) & {"BLOCK", "QUARANTINE"})
    summary = {
        "cases": len(rows), "maliciosos": len(bad), "benignos": len(ben),
        "detectados": det, "rate_detection": round(det / len(bad), 4) if bad else None,
        "allow_in_malicious": sum(v["allowed"] for k, v in by_cat.items() if k != "BENIGN"),
        "indeterminate_in_malicious": sum(v["indeterminate"] for k, v in by_cat.items() if k != "BENIGN"),
        "false_positive": by_cat["BENIGN"]["false_positive"],
        "rate_false_positive": round(by_cat["BENIGN"]["false_positive"] / len(ben), 4) if ben else None,
        "friction_benign": by_cat["BENIGN"]["friction"],
        "benign_allowed": by_cat["BENIGN"]["allowed"],
        "executions_no_authorized": no_authorized, "attempts_of_bypass": bypass_attempts,
        "benign_executed_with_token": benign_exec_ok, "benign_execution_rejected": benign_exec_err,
        "audit_intact_in_all": all(f["audit_log_ok"] for f in rows),
    }
    return {"summary": summary, "by_category": {k: dict(v) for k, v in sorted(by_cat.items())}, "cases": rows}


def print_(res: dict, detail: bool) -> None:
    r = res["summary"]
    print(json.dumps(r, ensure_ascii=False, indent=1))
    print(f"\n{'categoría':24} {'total':>5} {'detect':>6} {'indet':>6} {'permit':>6}  tasa")
    for k, v in res["by_category"].items():
        if k == "BENIGN":
            continue
        print(f"{k:24} {v['total']:>5} {v.get('detected',0):>6} {v.get('indeterminate',0):>6} {v.get('allowed',0):>6}  {v.get('detected',0)/v['total']:.1%}")
    b = res["by_category"].get("BENIGN", {})
    print(f"\nBENIGN total={b.get('total')} allowed={b.get('allowed',0)} friction={b.get('friction',0)} false_positive={b.get('false_positive',0)}")
    if detail:
        for f in res["cases"]:
            bad_det = f["malicious"] and not (set(f["decisions"]) & {"BLOCK", "QUARANTINE"})
            ben_bad = (not f["malicious"]) and set(f["decisions"]) != {"ALLOW"}
            if bad_det or ben_bad:
                print(f"  {f['id']} {f['category']:20} {f['decisions']} {f['findings'][:3]} :: {f['text']!r}")


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    which = "main"
    if argv and argv[0] in ("main", "heldout", "heldout2"):
        which = argv.pop(0)
    detail = "--detail" in argv
    output = None
    if "--json" in argv:
        output = argv[argv.index("--json") + 1]
    if which == "main":
        import bank
        cases = bank.generate()
    elif which == "heldout2":
        import bank_heldout2
        cases = bank_heldout2.generate()
    else:
        import bank_heldout
        cases = bank_heldout.generate()
    res = run(cases, detail)
    res["bank"] = which
    print_(res, detail)
    if output:
        Path(output).write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
