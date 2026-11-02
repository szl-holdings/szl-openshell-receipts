import argparse
import hashlib
import json
import sys
import uuid

from .chain import ReceiptChain, verify_chain
from .controls import validate_ledger
from .openshell_log import parse_log
from .reach import delta, gate
from .workspace import Workspace


def _jsonl(files, path):
    return [json.loads(x) for x in files.read_text(path).splitlines() if x.strip()]


def main(argv=None):
    p = argparse.ArgumentParser(prog="szl-openshell-receipts")
    p.add_argument("--root", default=".", help="Trusted workspace directory (default: current directory)")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("ingest", "ingest-log"):
        s = sub.add_parser(name)
        s.add_argument("source")
        s.add_argument("--policy", required=True)
        s.add_argument("--commit", required=True)
        s.add_argument("--out", required=True)
        s.add_argument("--run-id", default=None)
    v = sub.add_parser("verify")
    v.add_argument("receipts")
    d = sub.add_parser("delta")
    d.add_argument("old")
    d.add_argument("new")
    d.add_argument("--prover-findings", default=None)
    d.add_argument("--fail-on-review", action="store_true")
    c = sub.add_parser("controls")
    c.add_argument("ledger")
    a = p.parse_args(argv)

    try:
        with Workspace(a.root) as files:
            fields = {"ingest": ("source", "policy", "out"), "ingest-log": ("source", "policy", "out"),
                      "verify": ("receipts",), "delta": ("old", "new"), "controls": ("ledger",)}
            for field in fields[a.cmd]:
                files.validate(getattr(a, field), output=field == "out")
            return _run(a, files)
    except (OSError, ValueError):
        print("Workspace path or input refused", file=sys.stderr)
        return 2


def _run(a, files):
    if a.cmd in ("ingest", "ingest-log"):
        policy_hash = hashlib.sha256(files.read_bytes(a.policy)).hexdigest()
        chain = ReceiptChain(a.run_id or str(uuid.uuid4()), policy_hash, a.commit)
        if a.cmd == "ingest":
            events, skipped = _jsonl(files, a.source), 0
        else:
            events, skipped = parse_log(files.read_text(a.source))
        for event in events:
            chain.append(event)
        files.write_text(a.out, "".join(json.dumps(r, sort_keys=True) + "\n" for r in chain.receipts))
        print(json.dumps({"receipts": len(chain.receipts), "skipped_lines": skipped,
                          "flagged": sum(1 for r in chain.receipts if r["flags"])}))
        return 0

    if a.cmd == "verify":
        ok, message = verify_chain(_jsonl(files, a.receipts))
        print(message)
        return 0 if ok else 1

    if a.cmd == "delta":
        old = json.loads(files.read_text(a.old))
        new = json.loads(files.read_text(a.new))
        result = delta(old, new)
        prover = None if a.prover_findings is None else [x for x in a.prover_findings.split(",") if x]
        result["gate"] = gate(result["findings"], prover)
        print(json.dumps(result, indent=2))
        return 2 if (a.fail_on_review and result["gate"]["decision"] != "ALLOW_ELIGIBLE") else 0

    ok, problems, info = validate_ledger(json.loads(files.read_text(a.ledger)))
    print(json.dumps({"ok": ok, "problems": problems, **info}, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
