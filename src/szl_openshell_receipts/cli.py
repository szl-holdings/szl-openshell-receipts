import argparse
import hashlib
import json
import sys
import uuid
from pathlib import Path

from .chain import ReceiptChain, verify_chain
from .controls import validate_ledger
from .openshell_log import parse_log
from .reach import delta, gate


def _jsonl(path):
    return [json.loads(x) for x in Path(path).read_text(encoding="utf-8").splitlines() if x.strip()]


def main(argv=None):
    p = argparse.ArgumentParser(prog="szl-openshell-receipts")
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

    if a.cmd in ("ingest", "ingest-log"):
        policy_hash = hashlib.sha256(Path(a.policy).read_bytes()).hexdigest()
        chain = ReceiptChain(a.run_id or str(uuid.uuid4()), policy_hash, a.commit)
        if a.cmd == "ingest":
            events, skipped = _jsonl(a.source), 0
        else:
            events, skipped = parse_log(Path(a.source).read_text(encoding="utf-8"))
        for event in events:
            chain.append(event)
        Path(a.out).write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in chain.receipts), encoding="utf-8")
        print(json.dumps({"receipts": len(chain.receipts), "skipped_lines": skipped,
                          "flagged": sum(1 for r in chain.receipts if r["flags"])}))
        return 0

    if a.cmd == "verify":
        ok, message = verify_chain(_jsonl(a.receipts))
        print(message)
        return 0 if ok else 1

    if a.cmd == "delta":
        old = json.loads(Path(a.old).read_text(encoding="utf-8"))
        new = json.loads(Path(a.new).read_text(encoding="utf-8"))
        result = delta(old, new)
        prover = None if a.prover_findings is None else [x for x in a.prover_findings.split(",") if x]
        result["gate"] = gate(result["findings"], prover)
        print(json.dumps(result, indent=2))
        return 2 if (a.fail_on_review and result["gate"]["decision"] != "ALLOW_ELIGIBLE") else 0

    ok, problems, info = validate_ledger(json.loads(Path(a.ledger).read_text(encoding="utf-8")))
    print(json.dumps({"ok": ok, "problems": problems, **info}, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
