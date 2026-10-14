# szl-openshell-receipts

<!-- szl:header v1 -->
<!-- Native identity: szl-brand@4309f6fce89179331b0b3ed8c99494e76c5be256; Orbit v2 icon. -->
<p>
  <a href="https://github.com/szl-holdings">
    <img src="https://raw.githubusercontent.com/szl-holdings/szl-brand/4309f6fce89179331b0b3ed8c99494e76c5be256/kit/logos/orbit-v2/suite/szl-icon-32.svg" alt="SZL Holdings — Orbit v2" width="32" height="32" />
  </a>
</p>

**Control before action. Evidence after.**

[Product](https://a-11-oy.com) · [Proof](https://a11oy.net) · [GitHub organization](https://github.com/szl-holdings)
<!-- /szl:header -->

[![PyPI](https://img.shields.io/pypi/v/szl-openshell-receipts)](https://pypi.org/project/szl-openshell-receipts/) [![Python](https://img.shields.io/pypi/pyversions/szl-openshell-receipts)](https://pypi.org/project/szl-openshell-receipts/) [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/szl-holdings/szl-openshell-receipts/badge)](https://scorecard.dev/viewer/?uri=github.com/szl-holdings/szl-openshell-receipts)

Governed, hash-chained receipts and an independent policy reach-delta witness for sandboxed agent runtimes such as NVIDIA OpenShell.

## v0.2
- `ingest-log`: parses OpenShell-style audit tokens (HTTP:* DENIED/ALLOWED, CONFIG:PROPOSED/APPROVED/REJECTED/LOADED) into receipts. Only line digests and key=value fields are kept, never raw lines.
- `delta`: SZL reach-set witness. Computes what a policy change adds and flags the four categories OpenShell's prover reasons about, using an independent simplified model.
- Two-witness gate: `ALLOW_ELIGIBLE` only when this witness and the supplied prover result both report nothing.
- Approval receipts bind candidate hash and a digest of the review token.
- Controls ledger (`governance/controls.json`) with doctrine labels.
- Combined multimodal digest.

## Honest status
See `governance/controls.json`. Chain, gate, approvals and multimodal digest are MEASURED by tests. Live OpenShell field mapping and credential isolation are UNKNOWN. Signing is UNAVAILABLE; receipts are UNSIGNED_HONEST. Examples are SYNTHETIC. The reach model is not the OpenShell policy schema. The observation-consistency checker below is MEASURED on synthetic fixtures only (C-08); a live export adapter is UNAVAILABLE (C-09).

## Reference: observation-consistency checker
`reference/observation_checker/` is a standalone, standard-library, zero-model checker. It reads one saved agent-run evidence bundle and reports what the records consistently support: schema validity, identity, lifecycle, attempt accounting, call budget, admission, durable acknowledgement, fresh-process restoration, separate support assessment, claim strength and current-runtime evidence. Each is a separate PASS, FAIL, UNKNOWN or NOT_APPLICABLE finding. There is no overall verdict, and a PASS grants no authority.

It is not part of the installed package. It does no network or model work, never repairs or signs anything, and does not authenticate the evidence it is given. Missing, stale or denied evidence never becomes PASS. A cancellation acknowledgement is never treated as stopped effects. The wall-clock bound is always UNKNOWN. The 20 canonical scenarios are disclosed, authored synthetic fixtures, not a benchmark. The checker contains no PentAGI or other third-party code. Read its `README.md`, `review.md` and `completion_receipt.md` for the full contract and limits.

    cd reference/observation_checker
    python -B -m unittest -v test_observation_checker.py
    python -B observation_checker.py example_bundle.json example_policy.json

`verify.py` and the `independent_review/` scripts rewrite the committed result files, so run them in a copy. CI does this on Python 3.10, 3.12 and 3.13 and requires byte-identical output. `SHA256SUMS` binds every file.

## Usage
    pip install .
    szl-openshell-receipts ingest-log examples/openshell.sample.log --policy examples/policy.readonly-audit.yaml --commit <sha> --out r.jsonl
    szl-openshell-receipts verify r.jsonl
    szl-openshell-receipts delta examples/policy.before.json examples/policy.after.json --prover-findings capability_expansion
    szl-openshell-receipts controls governance/controls.json

Study notes: `docs/STUDY.md`.
