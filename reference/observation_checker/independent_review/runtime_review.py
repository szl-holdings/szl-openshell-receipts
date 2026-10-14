"""Bounded independent checks of the final runtime-conflict change."""
import contextlib
import copy
import hashlib
import io
import json
import pathlib
import runpy

HERE = pathlib.Path(__file__).resolve().parent
SOURCE = HERE.parent / 'observation_checker.py'
EXPECTED_HASH = '888e1ffc3b1ebdfe0239a64052e17d69beb691b93d1bfdd00c3f127f60888fb6'
source_hash = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
assert source_hash == EXPECTED_HASH
with contextlib.redirect_stdout(io.StringIO()):
    helpers = runpy.run_path(str(HERE / 'probe.py'))
m, base, record, revision = (helpers[k] for k in ('m', 'base', 'r', 'R'))

def runtime(rid, seq, *, tree=revision, python='3', component='runtime-observer'):
    value = record(rid, 'runtime_observation', seq, attempt=None, tree=tree, python=python)
    value.update(evidence_class='OBSERVED_EXECUTION', method='HTTP', component=component)
    return value

good = runtime('matching-runtime', 1)
cases = [
    ('matching_only', [good], 'PASS', None),
    ('conflicting_tree', [good, runtime('other-runtime', 2, tree='c' * 40)], 'FAIL', 'runtime_source_or_python_mismatch'),
    ('conflicting_python', [good, runtime('other-runtime', 2, python='other-python')], 'FAIL', 'runtime_source_or_python_mismatch'),
    ('conflicted_runtime_id_payload', [good, runtime('conflicted-runtime', 2), runtime('conflicted-runtime', 3, tree='c' * 40)], 'FAIL', 'conflicting_runtime_record'),
    ('conflicted_runtime_id_metadata', [good, runtime('conflicted-runtime', 2), runtime('conflicted-runtime', 2, component='other-component')], 'FAIL', 'conflicting_runtime_record'),
    ('exact_duplicate_runtime_copy', [good, copy.deepcopy(good)], 'PASS', None),
    ('conflicted_runtime_id_without_matching_record', [runtime('conflicted-runtime', 2), runtime('conflicted-runtime', 3, python='other-python')], 'FAIL', 'conflicting_runtime_record'),
]
results = []
for name, records, expected, reason in cases:
    bundle = base()
    bundle['evidence_class'] = 'OBSERVED_EXECUTION'
    bundle['claims']['current_runtime'] = True
    bundle['records'] = copy.deepcopy(records)
    before = copy.deepcopy(bundle)
    report = m.check_bundle(bundle)
    finding = report['findings']['current_runtime_evidence']
    assert finding['status'] == expected, (name, finding)
    assert report['findings']['claim_strength']['status'] == expected, (name, report['findings']['claim_strength'])
    assert reason is None or reason in finding['reasons'], (name, finding)
    assert bundle == before, (name, 'input mutation')
    bundle['records'].reverse()
    assert m.check_bundle(bundle) == report, (name, 'order dependence')
    results.append({'case': name, 'expected_status': expected, 'actual_status': finding['status'], 'claim_status': report['findings']['claim_strength']['status'], 'reasons': finding['reasons'], 'evidence_ids': finding['evidence_ids'], 'reported_conflicting_ids': report['observations']['conflicting_record_ids'], 'input_unchanged': True, 'reverse_order_identical': True})
assert hashlib.sha256(SOURCE.read_bytes()).hexdigest() == source_hash
output = {'source_sha256': source_hash, 'source_unchanged_during_run': True, 'passed': len(results), 'total': len(cases), 'results': results}
(HERE / 'runtime-review-results.json').write_text(json.dumps(output, indent=2))
print(json.dumps(output, indent=2))
