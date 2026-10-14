# SZL zero-model observation-consistency reference

An original, standalone, standard-library Python checker for the 20 disclosed SZL observation-consistency cases. It reads saved synthetic evidence and reports what the records consistently support. It does not execute a journey, contact a service, repair anything, load a model, issue authority, sign a receipt, or change a repository.

## Verified result

- 20/20 canonical scenarios matched every expected predicate; case 17 includes four malformed-input variants.
- 90 standard-library unittest methods passed on CPython 3.12.14 and 3.13.5, with zero failures, errors or skips on either interpreter. These are the same 90 tests, not 180 distinct cases.
- All four deliberate negative-control mutations were detected by the fixed fixture oracles.
- The separate review passed 25 adversarial/invariance assertions, seven additional runtime-conflict checks, and 475 shuffled-order plus 475 JSON-route comparisons on the same checker bytes.
- Three fresh CLI processes with different hash seeds produced byte-identical reports.

These counts describe distinct checks, not independent statistical samples. Canonical scenarios intentionally contain FAIL and UNKNOWN findings; matching those expected findings is a passing conformance test.

## Run

Python 3.10 or newer, standard library only. No installation is needed. Unpack into a disposable directory outside a live repository, then:

```sh
python -B -m unittest -v test_observation_checker.py
python -B observation_checker.py example_bundle.json example_policy.json
python -B verify.py
```

`verify.py` reproduces the tests, all case reports, four deliberate implementation mutations, and identical example CLI outputs in three new Python processes with different hash seeds. Its only writes are local diagnostic files beside this README. Run in a copy if you want to preserve the original bundled output hashes; rerunning legitimately rewrites diagnostic files. The portable independent review can be reproduced with `python -B independent_review/verify.py`, `python -B independent_review/metamorphic.py`, and `python -B independent_review/runtime_review.py`. The checker’s `check_bundle(bundle, policy)` and `check_json(raw, policy_raw)` functions perform no file or network I/O and do not mutate inputs. The optional `advisory` argument is deliberately ignored, including malformed or hostile objects.

The CLI reads the specified local files and prints JSON. Exit 0 means parsing and diagnostic evaluation completed, even when findings are FAIL or UNKNOWN. Exit 2 means schema/input rejection. Neither exit code is a release or authorization decision.

## What is delivered

- `observation_checker.py`: pure parser/checker plus a bounded read-only CLI
- `fixtures.json`: the exact 20 disclosed scenario categories, explicit expectations for every predicate, and four malformed variants within case 17
- `build_fixtures.py`: reproducible, separate fixture/oracle authoring; never imports the checker
- `test_observation_checker.py`: canonical and adversarial tests
- `verify.py`, `verification_results.json`, `tests.log`: reproducible execution evidence
- `case_results.json`: complete diagnostic reports for 19 valid scenarios plus the four malformed variants
- `example_bundle.json`, `example_policy.json`, `example_report.json`: an independently runnable example
- `review.md`: separate adversarial review scope, findings and final disposition
- `SHA256SUMS`: exact file identities; no claim of authenticated pre-run fixture freezing
- `requirements_provenance.json`: identities of the saved requirement documents used for this build

These are conformance/development fixtures. They are not hidden test data, a statistical failure-rate estimate, an evaluation of a model, or proof of real SZL behavior. Fixture expectations were explicitly authored from the scenario requirements, then corrected where the initial expanded oracle omitted the declared complete accounting contract. They were not generated from checker outputs. All early defects discovered during implementation were corrected before the final reported run.

## Input contract and limits

The file is one JSON object with exact keys. Unsupported/extra fields are rejected, including `verified=true`, tool requests and arbitrary status extensions. Duplicate JSON object keys, nonfinite or floating-point numbers, booleans used as integers, malformed/non-UTC timestamps, invalid digests, unsupported versions, oversized arrays and excessive nesting fail schema before any other predicate is evaluated.

Limits: 128 KiB per input JSON document; 64 supplied records including duplicate copies; 8 distinct attempt identities; depth 12; identifiers at most 128 printable ASCII characters; source/artifact digests are lowercase SHA-256 or 40-character immutable revision identifiers. The limits are prototype design choices, not measured production capacities. Every core loop is over these bounded collections. No unbounded replay, recursive dependency traversal or external reference resolution exists.

Top-level fields:

- `schema`: exactly 1
- `ordering`: exactly `EXPLICIT_SEQUENCE`; the caller declares a logical total order through per-record `seq`. This is an exported-record convention, not authenticated happens-before proof. Physical array order is ignored. Sequence collisions are inconsistent.
- `evidence_class`: SYNTHETIC, HISTORICAL_EXECUTION, CURRENT_SOURCE_ONLY or OBSERVED_EXECUTION
- `interval`: inclusive UTC `start` and `end`; all record timestamps must lie inside it
- `max_age_seconds`: exact integer freshness window, inclusive at its boundary
- `source`: repository pseudonym, immutable revision/tree, exporter schema and Python identity
- `journey`: tenant/session/action/run/plan/step/stage/generation/policy-epoch bindings
- `records`: bounded immutable observations, described below
- `result`: optional terminal digest, terminal record ID and cited acknowledgement IDs
- `accounting`: optional contract ID, bound action, calls-unit limit, declared history completeness and optional charged summary
- `claims`: a narrow UI/evidence projection, including durable/restored/current-admission/runtime/deployed/budget assertions and an optional legacy final-projection reference

Each record carries an ID, kind, component, artifact digest, time, sequence, evidence class, method, complete binding (or null when unavailable), optional physical attempt ID and a closed kind-specific data object. See the example and `DATA_KEYS` for the complete supported vocabulary. Identity values are case-sensitive; no aliasing or normalization is invented. Raw source text, prompts, answer bodies, credentials and URLs are unnecessary and have no supported fields. Use only synthetic data in this prototype.

Kinds cover submission, admission/grant/hydration/generation, dispatch/non-invocation, terminal or unknown outcome, timeout, cancellation request/acknowledgement/stopped effects, durable acknowledgement, fresh-process readback, closure/cleanup, separate support assessment, attempt states, transport/local-contract/historical-test/planning/legacy observations, runtime identity and a separately supplied signature-integrity statement. Signature integrity is retained as an observation and never confers signer authority or admission. Digests are references; the checker does not fetch or authenticate the underlying bytes.

Current policy is a separate optional JSON input with an exact source/generation/epoch binding, observed/expiry timestamps and revoked grant IDs. It is not accepted from a bundle's claim flag. Offline separation cannot authenticate that the caller actually obtained independent/current policy or an independent support assessor. Those are explicit external assumptions.

## Independent findings

There is no overall success, readiness, authorization, correctness or exactly-once flag. Each finding has PASS, FAIL, UNKNOWN or NOT_APPLICABLE, exact reason codes and record references. Conflicting IDs are retained in the report’s `observations.conflicting_record_ids`; a rule-specific evidence list can omit those ambiguous IDs, as noted in the independent review:

1. Schema validity
2. Cross-record identity consistency
3. Lifecycle and terminal consistency
4. Attempt accounting consistency
5. Declared call-budget bound, including each observed prefix
6. Bound current admission evidence
7. Bound durable acknowledgement evidence
8. Bound fresh-process restoration evidence
9. Presence/binding of a separate support/abstention assessment
10. Claim strength versus supplied evidence
11. Matching current-runtime observation evidence

PASS means the named finite consistency rule has its required records in this supplied bundle. A forged but coherent bundle can pass. Even OBSERVED_EXECUTION labels and runtime observations are externally supplied, not independently probed by this checker. SYNTHETIC and historical records never become current-runtime evidence.

Missing, stale or unsuitable required evidence stays UNKNOWN. Explicit contradiction, denial, revocation and conflicting IDs produce FAIL in the relevant rule. Stale contradictory records are not silently erased. Exact duplicate exports are deduplicated; conflicting reuse preserves an explicit conflict rather than selecting a convenient variant. Different legitimate legacy FIRST_CYCLE and FINAL values are not compared as if they had the same meaning; a final projection must be explicitly bound.

Administrative Finished and failed cleanup can coexist with an unknown synthesis outcome. Transport success, handles, local `deployed=true`, planning readiness, a screenshot-like/local-memory acknowledgement, and a signature-valid flag do not substitute for stronger evidence. Cancellation acknowledgement only means acknowledged; a scoped stopped-effects observation must match the requested attempt and follow the request. An unrelated stop cannot cancel another attempt. Neither signal proves termination of all unobserved work.

## Accounting and evidence boundaries

- Charges/reservations are reconstructed by unique physical attempt ID and explicit sequence. ACTIVE, UNKNOWN and SETTLED attempts remain charged.
- RESERVED_UNSENT may become ABANDONED_UNSENT only through the permitted transition. Invalid refund transitions retain the previous state/cost and produce FAIL.
- Each dispatch needs a prior positive reservation/charge. Multiple distinct dispatch observations cannot silently reuse one charged attempt.
- Final and prefix costs are checked. A later unsent abandonment cannot erase an earlier budget breach.
- Missing attempt records, missing contracts or declared incomplete history prevent budget PASS. Contradictions can still be reported on an incomplete trace.
- A complete-history declaration is an assumption about the exported record set, not proof that all real effects were observed.
- Wall-clock boundedness is always reported UNKNOWN. This version does not implement a clock/deadline evidence adapter or a time-budget qualification; finite calls do not imply termination.
- Restore evidence requires the same result, acknowledgement and attempt, a distinct recorded process identity, the fresh-process-readback method, and later sequence. These are consistency requirements on supplied records, not a real restart test.
- Support-assessment presence can pass while the assessor's verdict is CONTRADICTED or UNRESOLVED. The separate verdict is preserved. This is not a truth oracle. Contradictory assessments for the same immutable result remain conflicts, including stale contradictions.

## Source and scope

Canonical requirements: the saved 12 October 2026 SZL/PentAGI study, `szl-fit.md`, “Read-only observation-consistency checker” through its 20-case table and prototype acceptance; `math-model-evaluation.md`, its finite evidence-state assumptions and shared conformance contract. The 14 October v26 SZL builder handoff retains this bounded backlog item.

The earlier study was pinned to PentAGI commit `843dfeb4bfc809c09d1bc5022e567c602d8fc9dd`. This checker contains no copied PentAGI implementation, operational agent, prompt, tool wiring or wrapper. No third-party runtime code is included. Component, service and data license decisions remain separate before any integration or redistribution; this reference does not clear those decisions.

No repository, external service, credential, security setting or deployment was changed. No packages, models or source repositories were installed/downloaded. No production data were used. There is no export adapter, authoritative journal, scheduler, recovery controller, network test, formal proof, trust root, provenance verification, service-recovery evidence, measured speedup or full-ecosystem integration claim. A later read-only adapter would require its own scoped review and source-owner agreement.
