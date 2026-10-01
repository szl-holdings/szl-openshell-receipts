# szl-openshell-receipts

[![PyPI](https://img.shields.io/pypi/v/szl-openshell-receipts)](https://pypi.org/project/szl-openshell-receipts/) [![Python](https://img.shields.io/pypi/pyversions/szl-openshell-receipts)](https://pypi.org/project/szl-openshell-receipts/)

Governed, hash-chained receipts and an independent policy reach-delta witness for sandboxed agent runtimes such as NVIDIA OpenShell.

## v0.2
- `ingest-log`: parses OpenShell-style audit tokens (HTTP:* DENIED/ALLOWED, CONFIG:PROPOSED/APPROVED/REJECTED/LOADED) into receipts. Only line digests and key=value fields are kept, never raw lines.
- `delta`: SZL reach-set witness. Computes what a policy change adds and flags the four categories OpenShell's prover reasons about, using an independent simplified model.
- Two-witness gate: `ALLOW_ELIGIBLE` only when this witness and the supplied prover result both report nothing.
- Approval receipts bind candidate hash and a digest of the review token.
- Controls ledger (`governance/controls.json`) with doctrine labels.
- Combined multimodal digest.

## Honest status
See `governance/controls.json`. Chain, gate, approvals and multimodal digest are MEASURED by tests. Live OpenShell field mapping and credential isolation are UNKNOWN. Signing is UNAVAILABLE; receipts are UNSIGNED_HONEST. Examples are SYNTHETIC. The reach model is not the OpenShell policy schema.

## Usage
    pip install .
    szl-openshell-receipts ingest-log examples/openshell.sample.log --policy examples/policy.readonly-audit.yaml --commit <sha> --out r.jsonl
    szl-openshell-receipts verify r.jsonl
    szl-openshell-receipts delta examples/policy.before.json examples/policy.after.json --prover-findings capability_expansion
    szl-openshell-receipts controls governance/controls.json

Study notes: `docs/STUDY.md`.
