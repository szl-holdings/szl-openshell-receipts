# STUDY-03: containment witness vs openshell-prover 0.1.2

| Stage | Record |
|---|---|
| Archive | openshell-prover studied only through `check --output json`. No OpenShell source copied. |
| Silhouette | Contained when every (access, path) requested is covered by a boundary grant; read_write also grants read; coverage is path-component prefix. |
| Material | Python standard library only. |
| Atelier | Lists every violation (the prover reports one counterexample) and proposes a minimal repair: drop, or downgrade write to read. |
| Runway | 51 cases: 11 hypothesis probes + 40 seeded random (seed 20260928), each run through both engines. |

## Measured results

- Valid prover responses: 31/51
- Agreement: 31/31 (100.0%)
- Prover counterexample found in witness violations: 16/16
- Witness repairs accepted by the real prover: 29/33
- Probe evidence sha256: 3e00efe8a732892c2bbdd4ddca7eacb6f4f3fc389154972b6baad0565174282b
- CLI study sha256: e87970d652e03dcae38091c75920c2143d1eecf351b4a6c1ce023dc7f97c848a (gateway NOT_CONNECTED; text kept locally)

## Disagreements

None on this suite.

## Does not prove

- Equivalence outside this suite or for other prover versions.
- Network, process and Landlock domains; the witness models filesystem only.
- Live sandbox enforcement; C-05 and C-06 stay open until real sandbox events are captured.
