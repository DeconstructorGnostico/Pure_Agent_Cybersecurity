"""CLI: python3 -m gnostic_axioms --demo  --input '...' [--datum '...']"""
from __future__ import annotations

import argparse
import json
import sys

from .demo import run
from .system import PerfectedSystem


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="gnostic_axioms",
                                description="Perfected System (Axioms + Gnostic Deconstructor)")
    p.add_argument("--demo", action="store_true", help="run the 7 demonstration cases")
    p.add_argument("--input", dest="input_", default=None, help="request of the initiator")
    p.add_argument("--datum", dest="datum", default=None, help="document or context (channel DATA, does not give commands)")
    p.add_argument("--json", action="store_true", help="print the result in JSON")
    p.add_argument("--execute-", action="store_true",
                   help="authorizes and executes the proposed commands (only for local demo; by default no)")
    args = p.parse_args(argv)

    if args.demo:
        log = run(silent=False)
        return 0 if all(x["ok"] for x in log) else 1

    if not args.input_:
        p.print_help()
        return 2

    s = PerfectedSystem()
    r = s.request(args.input_, document=args.datum)
    if args.execute_ and r.orders and r.state.value == "PENDING_AUTHORIZATION":
        try:
            facts = s.authorize_and_execute(r)
            r.details["execution"] = facts
            r.state = type(r.state)("EXECUTED")
        except Exception as e:
            r.details["execution_error"] = f"{type(e).__name__}: {e}"
    if args.json:
        print(json.dumps(r.a_dict(), ensure_ascii=False, indent=2))
    else:
        print(f"estado: {r.state.value}")
        print(f"mensaje: {r.message}")
        if r.intent:
            print(f"intención: {r.intent.type_.value} — {r.intent.target}")
            if r.intent.missing_items:
                print(f"faltantes: {r.intent.missing_items}")
        if r.orders:
            print("proposed orders:")
            for o in r.orders:
                print(f"  - {o.act.value} {o.params_}  riesgo={o.risk}")
        print(f"peace_sustained: {r.peace_sustained} integrity_ok: {r.integrity_ok} cost_inherited: {r.cost_inherited}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
