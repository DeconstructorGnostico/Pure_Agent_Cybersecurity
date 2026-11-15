"""CLI: python3 -m pure_agent_cyber "text or command" [--document "..."] [--json]  --demo"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

from .agent import PureAgentCyber


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="pure_agent_cyber",
                                description="Pure Agent Cybersecurity: decides ALLOW, BLOCK, QUARANTINE or UNDETERMINED")
    p.add_argument("text", nargs="*", help="request or command to evaluate (INTENTION channel)")
    p.add_argument("--document", "--datum", dest="document", default=None,
                   help="document, tool result or web page (channel DATA: does not give commands)")
    p.add_argument("--origin", default="document", help="source of the data: document  tool  web")
    p.add_argument("--json", action="store_true", help="output in JSON")
    p.add_argument("--demo", action="store_true", help="runs the 8 demonstration scenarios")
    argv = list(sys.argv[1:] if argv is None else argv)
    if any(a in ("-h", "--help") for a in argv):
        p.print_help()
        return 0
    # All that is not an option ours is text, in its original order
    # (so ‘rm -rf /’ works even without quotation marks).
    own, text, i = [], [], 0
    while i < len(argv):
        a = argv[i]
        if a in ("--json", "--demo"):
            own.append(a)
        elif a in ("--document", "--datum", "--origin") and i + 1 < len(argv):
            own += [a, argv[i + 1]]
            i += 1
        else:
            text.append(a)
        i += 1
    args = p.parse_args(own)
    args.text = text
    if args.demo:
        from .demo import run
        log = run()
        return 0 if all(x["ok"] for x in log) else 1
    text = " ".join(args.text).strip()
    if not text:
        p.print_help()
        return 2
    with tempfile.TemporaryDirectory(prefix="apc_cli_") as tmp:
        ag = PureAgentCyber(sandbox=Path(tmp))
        r = ag.evaluate(text, document=args.document, origin_data=args.origin)
    return _print(r, args.json)


def _print(r, as_json: bool) -> int:
    if as_json:
        print(json.dumps(r.a_dict(), ensure_ascii=False, indent=2))
        return 0
    print(f"decisión:  {r.decision.value}")
    print(f"severidad: {r.severity.name}")
    print(f"motivo:    {r.reason}")
    for h in r.findings:
        print(f"  - {h.category}/{h.type_} {h.severity.name} verdad={h.truth.value}"
              + (f" evidencia={h.fact_id}" if h.fact_id else "") + f" :: {h.evidence[:80]!r}" + (f" ({h.note})" if h.note else ""))
    if r.orders:
        print("proposed commands (expect token; not executed from CLI):")
        for o in r.orders:
            print(f"  - {o.act.value} {o.params_}")
    if r.responses:
        print("defensive response (simulated in sandbox, with token):")
        for x in r.responses:
            print(f"  - {x['act']} ok={x['ok']}")
    if r.flag_list:
        print(f"detected obfuscation: {r.flag_list}")
    print(f"CVA: {r.cva.get('state')} · audit: {r.audit_hash}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
