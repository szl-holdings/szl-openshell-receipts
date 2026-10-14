# Independent bounded SZL checker review

Inspected checker: observation_checker.py (bundle root)
SHA-256: 888e1ffc3b1ebdfe0239a64052e17d69beb691b93d1bfdd00c3f127f60888fb6

## Result

No remaining reproduced false-PASS or crash blockers in this bounded review. All 25 adversarial and invariance assertions and all seven additional runtime-conflict scenarios matched their specified expectations on the inspected revision. One diagnostic traceability limitation is noted below.

The review confirmed corrections for cross-attempt cancellation promotion, terminal/denial/support conflicts hidden by duplicated IDs, stale contradictory support assessments, absent attempt-accounting observations, mismatched cited acknowledgements, record-order-dependent conflict handling, wrong-kind terminal references, oversized JSON integers, missing UI projection evidence, and synthetic provenance concealed by conflicted records.

## Final runtime-conflict inspection

The runtime_errors change inspects all observation variants. A same-bound-journey tree or Python payload mismatch fails current_runtime_evidence. Conflicting reuse of a runtime record ID also fails that predicate. A requested current-runtime claim fails with those contradictions.

Seven independent scenarios passed: matching runtime only; matching plus conflicting tree; matching plus conflicting Python; conflicted runtime ID with differing payload; conflicted runtime ID with differing component metadata; exact duplicate runtime copy; and conflicting runtime ID without an additional unconflicted matching record. All scenarios also preserved input objects and produced identical reports with reversed record order.

Diagnostic traceability limitation: when a runtime record ID is conflicted, current_runtime_evidence.evidence_ids may omit that conflicting ID, or be empty. The exact ID remains reported in observations.conflicting_record_ids. The tested status and reason still fail conservatively; no false-PASS resulted.

## Additional deterministic checks

- 475 shuffled record/reference orderings across the 19 structured canonical fixture bundles produced identical reports.
- The same 475 orderings produced identical reports through serialized JSON parsing.
- The malformed raw-JSON canonical case was excluded from ordering permutations.
- Input immutability and six advisory inputs, including malformed/nonfinite values and an unevaluated callable, preserved deterministic results.
- The inspected source hash was stable during the permutation and runtime-review runs and matched the assertion-run result.

## Artifacts

Portable scripts and saved results are in independent_review/.

- probe.py: independent synthetic reproductions and saved input/report pairs.
- verify.py and verification.json: 25/25 asserted review outcomes.
- metamorphic.py and metamorphic-results.json: 475 ordering, JSON-route and input-immutability checks.
- runtime_review.py and runtime-review-results.json: seven final runtime-conflict scenarios, explicitly pinned to the inspected checker hash.

## Portability and final rerun

The initial independent scripts were adapted only for portable paths: checker/fixtures resolve from the parent directory and generated results are written beside the scripts. Their test logic and expected results were preserved. The seven final runtime-conflict scenarios are a separately labeled, bounded addition requested after the checker changed.

Portable verify.py, metamorphic.py and runtime_review.py were rerun against the exact hash above. No checker implementation edits were made by this reviewer.

## Scope and limitations

Read-only implementation inspection and local standard-library execution only. No installs, network, repositories, live adapters, models, credentials, external effects or integration work. Initial artifacts were written to the review's temporary directory; portable artifacts and rerun results are in the requested bundle's independent_review/ directory.

These checks establish results for the exercised inputs. They do not establish exhaustive correctness, evidence authenticity, semantic truth, real-world completeness, live-runtime qualification, authority, exactly-once effects, or a statistical failure rate. Permutation checks compare against each bundle's existing checker report; they are not independent semantic-oracle tests.
