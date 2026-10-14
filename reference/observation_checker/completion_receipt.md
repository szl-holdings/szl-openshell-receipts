# SZL observation-consistency checker completion receipt

14 October 2026. Original local reference only; no repository, external-service, credential, security or deployment effect.

## Result

- 20/20 disclosed canonical scenarios match the full 11-predicate expected matrix. Case 17 supplies four separately rejected malformed-input variants.
- 90 unittest methods pass on CPython 3.12.14 and CPython 3.13.5, with zero failures, errors or skips on each. The second interpreter repeats the same tests.
- Four deliberately defective implementations are detected: ignoring denied dispatch, ignoring acknowledgement/result binding, promoting synthetic evidence into runtime evidence, and refunding unknown attempts.
- Three CLI hash-seed runs return byte-identical output.
- Separate review: 25/25 adversarial/invariance assertions, 7/7 runtime-conflict scenarios, 475 shuffled-order comparisons and 475 JSON-route comparisons pass on the final checker hash.

Expected FAIL and UNKNOWN diagnoses are successful conformance results. There is no aggregate authorization, production readiness, answer correctness or exactly-once claim.

## Exact primary identities

- Checker SHA-256: `888e1ffc3b1ebdfe0239a64052e17d69beb691b93d1bfdd00c3f127f60888fb6`
- Fixture SHA-256: `d6f1578a043c8976729d3a9d7e7ea632ab8386490d3b258544a3003eb25bfb11`
- Full contents: `SHA256SUMS`

## Remaining boundaries

This is a finite synthetic checker, not an integrated observer, authoritative ledger, controller or live adapter. Evidence authenticity, real-world completeness, assessor independence, live source identity, operational durability and stopped real effects are not established. Wall-clock qualification is always UNKNOWN and no clock/deadline adapter is implemented. License/adoption review remains separate.

The separate review records one traceability caveat: conflicting runtime IDs remain in the report's global conflicting-record list, but a rule-specific evidence-ID list can omit those ambiguous IDs. This does not produce a reproduced false PASS; the runtime conflict predicate fails. Neither finite review nor the tests establish exhaustive correctness or a statistical failure rate.

All source/fixture/test/report artifacts are included for independent reproduction. Hashes bind saved bytes; they do not authenticate pre-run freezing or confer authority.
