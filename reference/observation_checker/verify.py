"""Reproduce the local conformance evidence with only Python's standard library."""
from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import unittest

import observation_checker as checker
import test_observation_checker as tests
from build_fixtures import add, base

HERE = Path(__file__).resolve().parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def outcomes(module):
    rows = []
    for c in tests.FIXTURES:
        if 'invalid_variants' in c:
            for v in c['invalid_variants']:
                r = module.check_json(v['raw'])
                rows.append({'case_id': c['case_id'], 'variant': v['name'], 'report': r})
        else:
            r = module.check_bundle(c['bundle'], c['policy'])
            rows.append({'case_id': c['case_id'], 'report': r})
    return rows


def mutant_checks():
    source = (HERE / 'observation_checker.py').read_text()
    mutations = {
        'ignore_denied_dispatch': ('denial_dispatch = bool(denial and any(r["binding"] == expected for r in dispatch))', 'denial_dispatch = False'),
        'ignore_ack_result_identity': ('elif ack["data"]["result_digest"] != result["digest"] or (terminal and ack["attempt_id"] != terminal["attempt_id"]):', 'elif False:'),
        'promote_synthetic_to_runtime': ('runtime_ok = bool(runtime) and bundle["evidence_class"] == "OBSERVED_EXECUTION" and "observed_execution_class_overstated" not in claim_errors and not runtime_errors', 'runtime_ok = True'),
        'refund_unknown_attempt': ('if a["state"] != "ABANDONED_UNSENT" or any(d["attempt_id"] == a["id"] for d in dispatch) or "invalid_attempt_state_transition" in accounting_errors', 'if a["state"] not in {"ABANDONED_UNSENT", "UNKNOWN"}'),
    }
    results = []
    for name, (old, new) in mutations.items():
        if source.count(old) != 1:
            raise AssertionError('Mutation anchor changed: ' + name)
        namespace = {'__name__': '__bounded_negative_control__'}
        exec(compile(source.replace(old, new), '<negative-control:' + name + '>', 'exec'), namespace)
        detected = []
        for c in tests.FIXTURES:
            if 'bundle' not in c:
                continue
            r = namespace['check_bundle'](deepcopy(c['bundle']), deepcopy(c['policy']))
            wrong = {k: v['status'] for k, v in r['findings'].items()} != c['expected_findings']
            wrong |= any(r['observations'][k] != v for k, v in c['expected_observations'].items())
            if wrong:
                detected.append(c['case_id'])
        if not detected:
            raise AssertionError('Negative control escaped: ' + name)
        results.append({'name': name, 'detected_by_cases': detected, 'detected': True})
    return results


def main():
    suite = unittest.defaultTestLoader.loadTestsFromModule(tests)
    log = io.StringIO()
    run = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
    (HERE / 'tests.log').write_text(log.getvalue())
    if not run.wasSuccessful():
        print(log.getvalue())
        return 1
    rows = outcomes(checker)
    serialized = checker.canonical(rows)
    (HERE / 'case_results.json').write_text(json.dumps(rows, sort_keys=True, indent=2) + '\n')
    outputs = []
    for seed in ('0', '1', '123456'):
        command = [sys.executable, '-B', str(HERE / 'observation_checker.py'), str(HERE / 'example_bundle.json'), str(HERE / 'example_policy.json')]
        result = subprocess.run(command, env=dict(os.environ, PYTHONHASHSEED=seed, PYTHONDONTWRITEBYTECODE='1'), capture_output=True, check=True, timeout=15)
        outputs.append(result.stdout)
    if len(set(outputs)) != 1:
        raise AssertionError('CLI report varies across hash seeds')
    (HERE / 'example_report.json').write_bytes(outputs[0])
    negative = mutant_checks()
    source_paths = ['observation_checker.py', 'build_fixtures.py', 'fixtures.json', 'test_observation_checker.py', 'verify.py', 'example_bundle.json', 'example_policy.json']
    report = {
        'scope': 'Local synthetic reference only; no ecosystem integration or live qualification',
        'python': platform.python_version(), 'implementation': platform.python_implementation(), 'platform': sys.platform,
        'unittest': {'methods': run.testsRun, 'failures': len(run.failures), 'errors': len(run.errors), 'skips': len(run.skipped)},
        'canonical_scenarios': 20, 'malformed_variants_in_case_17': 4,
        'case_reports': len(rows), 'full_predicate_oracles': True,
        'record_permutation_checks': 190,
        'cli_hash_seed_values': ['0', '1', '123456'], 'cli_outputs_identical': True,
        'negative_controls': negative,
        'normalized_case_report_sha256': hashlib.sha256(serialized.encode()).hexdigest(),
        'inputs_and_implementation_sha256': {name: digest(HERE / name) for name in source_paths},
        'evidence_limits': [
            'Conformance/development data are disclosed, authored synthetic fixtures, not an independent held-out benchmark.',
            'Separate adversarial review is finite and does not constitute formal verification.',
            'No authentication, provenance, trust-root, model, network, real process cancellation, storage durability, deployment or integration qualification is established.',
            'Hashes identify bytes and do not independently authenticate pre-run freeze timing.',
        ],
    }
    (HERE / 'verification_results.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'tests': run.testsRun, 'canonical_scenarios': 20, 'negative_controls_detected': len(negative), 'cli_hash_seeds_identical': True}, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
