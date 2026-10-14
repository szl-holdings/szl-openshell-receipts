"""Conformance oracles and adversarial, deterministic, malformed-input controls."""
import ast
from copy import deepcopy
import json
from pathlib import Path
import random
import unittest

import observation_checker as checker
from build_fixtures import add, accounting, base, full, policy, DIGEST, OTHER

HERE = Path(__file__).resolve().parent
FIXTURES = json.loads((HERE / 'fixtures.json').read_text())['cases']


def check_case(test, case, function=checker.check_bundle):
    if 'invalid_variants' in case:
        for variant in case['invalid_variants']:
            with test.subTest(variant=variant['name']):
                report = checker.check_json(variant['raw'])
                test.assertEqual(report['findings']['schema']['reasons'], [variant['reason']])
                test.assertEqual({k: v['status'] for k, v in report['findings'].items()}, case['expected_findings'])
        return
    report = function(case['bundle'], case['policy'])
    test.assertEqual({k: v['status'] for k, v in report['findings'].items()}, case['expected_findings'])
    for key, value in case['expected_observations'].items():
        test.assertEqual(report['observations'][key], value, key)
    for key, reasons in case['expected_reasons'].items():
        test.assertTrue(set(reasons) <= set(report['findings'][key]['reasons']))


class ConformanceTests(unittest.TestCase):
    pass


for case in FIXTURES:
    def test(self, case=case):
        check_case(self, case)
    setattr(ConformanceTests, 'test_case_' + case['case_id'], test)


class AdversarialTests(unittest.TestCase):
    def setUp(self):
        self.bundle, self.policy = full(), policy()

    def record(self, rid):
        return next(r for r in self.bundle['records'] if r['id'] == rid)

    def run_check(self):
        return checker.check_bundle(self.bundle, self.policy)

    def status(self, rule):
        return self.run_check()['findings'][rule]['status']

    def test_all_input_permutations_sampled_are_deterministic(self):
        for c in FIXTURES:
            if 'bundle' not in c:
                continue
            expected = checker.canonical(checker.check_bundle(c['bundle'], c['policy']))
            for seed in range(10):
                b = deepcopy(c['bundle']); random.Random(seed).shuffle(b['records'])
                with self.subTest(case=c['case_id'], seed=seed):
                    self.assertEqual(checker.canonical(checker.check_bundle(b, c['policy'])), expected)

    def test_input_not_mutated(self):
        before = deepcopy((self.bundle, self.policy))
        self.run_check()
        self.assertEqual((self.bundle, self.policy), before)

    def test_advisory_boundary_never_inspected(self):
        class Poison:
            def __getattribute__(self, name):
                raise AssertionError('advisory inspected')
        expected = self.run_check()
        for advisory in (None, True, {'authorized': True, 'score': float('nan')}, 'retry now', Poison()):
            self.assertEqual(checker.check_bundle(self.bundle, self.policy, advisory=advisory), expected)

    def test_no_authority_or_execution_output(self):
        forbidden = {'authorized', 'ready_for_production', 'execute', 'tool_call', 'retry', 'overall', 'answer_correct', 'exactly_once'}
        def visit(value):
            if type(value) is dict:
                self.assertFalse(forbidden & value.keys())
                for v in value.values(): visit(v)
            elif type(value) is list:
                for v in value: visit(v)
        for c in FIXTURES:
            if 'bundle' in c: visit(checker.check_bundle(c['bundle'], c['policy']))

    def test_core_imports_are_standard_library_only(self):
        tree = ast.parse((HERE / 'observation_checker.py').read_text())
        modules = {n.module.split('.')[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
        modules |= {alias.name.split('.')[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for alias in n.names}
        self.assertEqual(modules, {'__future__', 'json', 're', 'sys', 'datetime', 'typing'})

    def test_no_policy_is_unknown(self):
        self.policy = None
        self.assertEqual(self.status('admission'), 'UNKNOWN')

    def test_stale_policy_is_unknown(self):
        self.policy['at'] = '2026-10-14T09:00:00Z'
        self.policy['expires'] = '2026-10-14T09:10:00Z'
        self.assertEqual(self.status('admission'), 'UNKNOWN')

    def test_future_policy_is_unknown(self):
        self.policy['at'] = '2026-10-14T10:01:00Z'
        self.assertEqual(self.status('admission'), 'UNKNOWN')

    def test_policy_epoch_mismatch_fails(self):
        self.policy['policy_epoch'] = 'epoch-wrong'
        self.assertEqual(self.status('admission'), 'FAIL')

    def test_stale_grant_is_unknown(self):
        self.record('grant')['at'] = '2026-10-14T09:00:00Z'
        self.assertEqual(self.status('admission'), 'UNKNOWN')

    def test_exact_freshness_boundary_included(self):
        self.record('grant')['at'] = '2026-10-14T09:50:00Z'
        self.assertEqual(self.status('admission'), 'PASS')

    def test_one_second_outside_freshness_is_unknown(self):
        self.record('grant')['at'] = '2026-10-14T09:49:59Z'
        self.assertEqual(self.status('admission'), 'UNKNOWN')

    def test_each_binding_dimension_on_ack_is_rejected(self):
        for key in sorted(self.record('ack')['binding']):
            b = deepcopy(self.bundle)
            ack = next(r for r in b['records'] if r['id'] == 'ack')
            ack['binding'][key] = 'e' * 64 if key == 'plan' else 'e' * 40 if key.startswith('source_') else 'unrelated'
            r = checker.check_bundle(b, self.policy)
            with self.subTest(key=key):
                self.assertEqual(r['findings']['identity']['status'], 'FAIL')
                self.assertEqual(r['findings']['durability']['status'], 'FAIL')

    def test_missing_ack_binding_is_unknown(self):
        self.record('ack')['binding'] = None
        self.assertEqual(self.status('durability'), 'UNKNOWN')

    def test_valid_ack_cannot_hide_wrong_run_cited_ack(self):
        other = deepcopy(self.record('ack')); other.update(id='other-ack', seq=13)
        other['binding']['run'] = 'other-run'; self.bundle['records'].append(other)
        self.bundle['result']['receipt_refs'].append('other-ack')
        self.assertEqual(self.status('durability'), 'FAIL')

    def test_valid_ack_cannot_hide_missing_cited_ack(self):
        self.bundle['result']['receipt_refs'].append('missing-ack')
        self.assertEqual(self.status('durability'), 'UNKNOWN')
        self.assertIn('missing-ack', self.run_check()['unresolved_references'])

    def test_ack_matching_hash_wrong_attempt_fails(self):
        self.record('ack')['attempt_id'] = 'different-attempt'
        self.assertEqual(self.status('durability'), 'FAIL')

    def test_local_memory_ack_is_unknown(self):
        self.record('ack')['method'] = 'LOCAL_MEMORY'
        self.assertEqual(self.status('durability'), 'UNKNOWN')

    def test_same_process_restore_fails(self):
        self.record('restore')['data']['process_id'] = 'origin-process'
        self.assertEqual(self.status('restoration'), 'FAIL')

    def test_restore_wrong_attempt_fails(self):
        self.record('restore')['attempt_id'] = 'different-attempt'
        self.assertEqual(self.status('restoration'), 'FAIL')

    def test_restore_missing_ack_is_unknown(self):
        self.record('restore')['data']['ack_id'] = 'missing-ack'
        self.assertEqual(self.status('restoration'), 'UNKNOWN')
        self.assertIn('missing-ack', self.run_check()['unresolved_references'])

    def test_self_authored_assessment_not_independent(self):
        self.record('assessment')['component'] = 'answer-producer'
        self.assertEqual(self.status('support_assessment'), 'UNKNOWN')
        self.assertEqual(self.status('claim_strength'), 'UNKNOWN')

    def test_model_score_cannot_replace_assessment(self):
        self.bundle['records'] = [r for r in self.bundle['records'] if r['id'] != 'assessment']
        r = checker.check_bundle(self.bundle, self.policy, advisory={'confidence': 1, 'verified': True})
        self.assertEqual(r['findings']['support_assessment']['status'], 'UNKNOWN')

    def test_unknown_verified_flag_is_schema_rejected(self):
        self.bundle['verified'] = True
        self.assertEqual(self.status('schema'), 'FAIL')

    def test_denied_admission_not_rescued_by_signature(self):
        self.record('admission')['data']['decision'] = 'DENIED'
        add(self.bundle, 'signature_integrity', {'valid': True}, method='VERIFIER')
        self.assertEqual(self.status('admission'), 'FAIL')

    def test_conflicting_terminal_id_never_promotes_outcome(self):
        a = deepcopy(self.record('terminal')); a.update(id='reused', seq=13)
        b = deepcopy(a); b['data']['outcome'] = 'FAILURE'
        self.bundle['records'] += [a, b]
        self.assertEqual(self.status('lifecycle'), 'FAIL')
        self.assertEqual(self.run_check()['observations']['outcome'], 'CONFLICT')

    def test_conflicting_terminal_id_is_order_invariant(self):
        x = deepcopy(self.record('terminal')); x['attempt_id'] = 'different-attempt'
        self.bundle['records'].append(x)
        first = self.run_check()
        self.bundle['records'].reverse()
        self.assertEqual(self.run_check(), first)

    def test_conflicting_admission_id_cannot_hide_denial(self):
        a = deepcopy(self.record('admission')); a.update(id='reused', seq=13)
        b = deepcopy(a); b['data']['decision'] = 'DENIED'
        self.bundle['records'] += [a, b]
        self.assertEqual(self.status('admission'), 'FAIL')

    def test_conflicting_ack_id_cannot_hide_bad_evidence(self):
        a = deepcopy(self.record('ack')); a.update(id='reused', seq=13)
        b = deepcopy(a); b['data']['result_digest'] = OTHER
        self.bundle['records'] += [a, b]
        self.assertEqual(self.status('durability'), 'FAIL')

    def test_wrong_kind_terminal_never_crashes(self):
        self.record('terminal')['kind'] = 'closure'
        self.record('terminal')['data'] = {'status': 'Finished'}
        self.assertEqual(self.status('lifecycle'), 'FAIL')
        self.assertNotEqual(self.status('durability'), 'PASS')

    def test_acknowledged_cancel_does_not_stop_effects(self):
        self.bundle = base(); accounting(self.bundle)
        add(self.bundle, 'attempt', {'state': 'ACTIVE', 'cost': 1})
        add(self.bundle, 'cancel_request'); add(self.bundle, 'cancel_ack')
        self.bundle['claims']['ui_status'] = 'cancelled'
        r = self.run_check()
        self.assertEqual(r['observations']['cancellation'], 'ACKNOWLEDGED_EFFECTS_UNKNOWN')
        self.assertEqual(r['findings']['claim_strength']['status'], 'UNKNOWN')
        self.assertEqual(r['observations']['charged_or_reserved_cost'], 1)

    def test_unrelated_stopped_attempt_does_not_cancel_requested_attempt(self):
        self.bundle = base(); accounting(self.bundle)
        add(self.bundle, 'attempt', {'state': 'ACTIVE', 'cost': 1})
        add(self.bundle, 'cancel_request'); add(self.bundle, 'effects_stopped', attempt='attempt-2')
        self.bundle['claims']['ui_status'] = 'cancelled'
        self.assertEqual(self.status('claim_strength'), 'UNKNOWN')
        self.assertEqual(self.run_check()['observations']['cancellation'], 'REQUESTED_EFFECTS_UNKNOWN')

    def test_stopped_before_cancel_request_does_not_prove_cancel(self):
        self.bundle = base(); add(self.bundle, 'effects_stopped'); add(self.bundle, 'cancel_request')
        self.bundle['claims']['ui_status'] = 'cancelled'
        self.assertEqual(self.status('claim_strength'), 'UNKNOWN')

    def test_dispatch_after_stop_is_conflict(self):
        self.bundle = base(); add(self.bundle, 'cancel_request'); add(self.bundle, 'effects_stopped'); add(self.bundle, 'dispatch')
        self.assertEqual(self.status('lifecycle'), 'FAIL')

    def test_valid_scoped_stop_remains_synthetic(self):
        self.bundle = base(); add(self.bundle, 'cancel_request'); add(self.bundle, 'cancel_ack'); add(self.bundle, 'effects_stopped')
        self.bundle['claims']['ui_status'] = 'cancelled'
        self.assertEqual(self.status('claim_strength'), 'PASS')
        self.assertEqual(self.status('current_runtime_evidence'), 'UNKNOWN')

    def test_prefix_budget_breach_survives_abandonment(self):
        self.bundle = base(); accounting(self.bundle, summary=1)
        add(self.bundle, 'attempt', {'state': 'RESERVED_UNSENT', 'cost': 1}, attempt='attempt-1')
        add(self.bundle, 'attempt', {'state': 'RESERVED_UNSENT', 'cost': 1}, attempt='attempt-2')
        add(self.bundle, 'attempt', {'state': 'ABANDONED_UNSENT', 'cost': 1}, attempt='attempt-2')
        r = self.run_check()
        self.assertEqual(r['observations']['charged_or_reserved_cost'], 1)
        self.assertEqual(r['observations']['peak_prefix_cost'], 2)
        self.assertEqual(r['findings']['budget']['status'], 'FAIL')

    def test_missing_attempt_ledger_prevents_zero_budget_pass(self):
        self.bundle = base(); accounting(self.bundle, limit=0, summary=0)
        add(self.bundle, 'outcome', {'outcome': 'ANSWER', 'result_digest': DIGEST, 'process_id': 'process-1'})
        self.assertEqual(self.status('accounting'), 'UNKNOWN')
        self.assertEqual(self.status('budget'), 'UNKNOWN')
        self.assertEqual(self.run_check()['observations']['unaccounted_attempt_ids'], ['attempt-1'])

    def test_incomplete_history_never_budget_pass(self):
        self.bundle['accounting']['history_complete'] = False
        self.assertEqual(self.status('budget'), 'UNKNOWN')

    def test_dispatch_without_prior_charge_fails(self):
        self.bundle['records'] = [r for r in self.bundle['records'] if r['id'] != 'reserved']
        self.assertEqual(self.status('accounting'), 'FAIL')

    def test_unknown_attempt_cannot_transition_to_refunded(self):
        self.bundle = base(); accounting(self.bundle, summary=0)
        add(self.bundle, 'attempt', {'state': 'ACTIVE', 'cost': 1})
        add(self.bundle, 'attempt', {'state': 'UNKNOWN', 'cost': 1})
        add(self.bundle, 'attempt', {'state': 'ABANDONED_UNSENT', 'cost': 1})
        r = self.run_check()
        self.assertEqual(r['findings']['accounting']['status'], 'FAIL')
        self.assertEqual(r['observations']['unknown_attempt_ids'], ['attempt-1'])
        self.assertEqual(r['observations']['charged_or_reserved_cost'], 1)

    def test_attempt_cost_cannot_decrease(self):
        self.record('settled')['data']['cost'] = 0
        self.assertEqual(self.status('accounting'), 'FAIL')
        self.assertEqual(self.run_check()['observations']['charged_or_reserved_cost'], 1)

    def test_empty_ledger_not_evidence_of_absent_dispatch(self):
        self.bundle = base()
        self.assertEqual(self.status('lifecycle'), 'UNKNOWN')
        self.assertEqual(self.status('accounting'), 'UNKNOWN')

    def test_sequence_collision_prevents_pass(self):
        self.record('ack')['seq'] = self.record('terminal')['seq']
        self.assertEqual(self.status('identity'), 'FAIL')
        self.assertNotEqual(self.status('durability'), 'PASS')

    def test_stale_terminal_cannot_support_durability(self):
        self.record('terminal')['at'] = '2026-10-14T09:00:00Z'
        self.assertEqual(self.status('lifecycle'), 'UNKNOWN')
        self.assertEqual(self.status('durability'), 'UNKNOWN')

    def test_finished_requires_closure_evidence(self):
        self.bundle = base(); self.bundle['claims']['ui_status'] = 'finished'
        self.assertEqual(self.status('claim_strength'), 'UNKNOWN')

    def test_ready_requires_plan_evidence(self):
        self.bundle = base(); self.bundle['claims']['ui_status'] = 'ready_to_orchestrate'
        self.assertEqual(self.status('claim_strength'), 'UNKNOWN')

    def test_first_cycle_is_not_final_projection(self):
        self.bundle = base(); add(self.bundle, 'legacy_snapshot', {'phase': 'FIRST_CYCLE', 'value_digest': DIGEST}, rid='first')
        self.bundle['claims']['projection_record'] = 'first'
        self.assertEqual(self.status('claim_strength'), 'FAIL')

    def test_matching_current_runtime_records_are_scoped_only(self):
        self.bundle = base(); self.bundle['evidence_class'] = 'OBSERVED_EXECUTION'
        add(self.bundle, 'runtime_observation', {'tree': self.bundle['source']['tree'], 'python': self.bundle['source']['python']}, method='HTTP', evidence_class='OBSERVED_EXECUTION')
        self.assertEqual(self.status('current_runtime_evidence'), 'PASS')
        self.assertEqual(self.status('admission'), 'UNKNOWN')

    def test_cancelled_projection_cannot_replace_existing_answer(self):
        add(self.bundle, 'cancel_request'); add(self.bundle, 'effects_stopped')
        self.bundle['claims']['ui_status'] = 'cancelled'
        self.assertEqual(self.status('claim_strength'), 'FAIL')

    def test_hidden_denial_keeps_dispatch_contradiction(self):
        a = deepcopy(self.record('admission')); a.update(id='reused', seq=13)
        b = deepcopy(a); b['data']['decision'] = 'DENIED'
        self.bundle['records'] += [a, b]
        self.assertEqual(self.status('lifecycle'), 'FAIL')
        self.assertEqual(self.status('claim_strength'), 'FAIL')

    def test_hidden_contradictory_assessment_cannot_promote_success(self):
        a = deepcopy(self.record('assessment')); a.update(id='reused', seq=13)
        b = deepcopy(a); b['data']['verdict'] = 'CONTRADICTED'
        self.bundle['records'] += [a, b]
        self.assertEqual(self.status('support_assessment'), 'FAIL')
        self.assertEqual(self.status('claim_strength'), 'FAIL')

    def test_conflicted_synthetic_evidence_cannot_disappear_from_runtime_class(self):
        self.bundle = base(); self.bundle['evidence_class'] = 'OBSERVED_EXECUTION'
        add(self.bundle, 'runtime_observation', {'tree': self.bundle['source']['tree'], 'python': self.bundle['source']['python']}, method='HTTP', evidence_class='OBSERVED_EXECUTION')
        a = add(self.bundle, 'local_contract', {'deployed': True}, rid='reused', method='LOCAL_SPY')
        b = deepcopy(a); b['data']['deployed'] = False; self.bundle['records'].append(b)
        self.assertEqual(self.status('current_runtime_evidence'), 'UNKNOWN')
        self.assertEqual(self.status('claim_strength'), 'FAIL')

    def test_two_dispatches_cannot_reuse_one_charge(self):
        duplicate = deepcopy(self.record('dispatch')); duplicate.update(id='second-dispatch', seq=13)
        self.bundle['records'].append(duplicate)
        self.assertEqual(self.status('accounting'), 'FAIL')

    def test_finite_attempt_budget_never_implies_wall_clock_bound(self):
        self.assertEqual(self.run_check()['observations']['wall_clock_bound'], 'UNKNOWN')

    def test_stale_contradiction_cannot_be_discarded_for_success(self):
        a = deepcopy(self.record('assessment')); a.update(id='old-assessment', seq=13, at='2026-10-14T09:00:00Z')
        a['data']['verdict'] = 'CONTRADICTED'; self.bundle['records'].append(a)
        self.assertEqual(self.status('support_assessment'), 'FAIL')
        self.assertEqual(self.status('claim_strength'), 'FAIL')
        self.assertEqual(self.run_check()['observations']['all_bound_assessment_verdicts'], ['CONTRADICTED', 'SUPPORTED'])

    def test_matching_runtime_cannot_hide_conflicting_runtime_payload(self):
        self.bundle = base(); self.bundle['evidence_class'] = 'OBSERVED_EXECUTION'
        add(self.bundle, 'runtime_observation', {'tree': self.bundle['source']['tree'], 'python': self.bundle['source']['python']}, method='HTTP', evidence_class='OBSERVED_EXECUTION')
        add(self.bundle, 'runtime_observation', {'tree': '9' * 40, 'python': 'other-python'}, method='HTTP', evidence_class='OBSERVED_EXECUTION')
        self.bundle['claims']['current_runtime'] = True
        self.assertEqual(self.status('current_runtime_evidence'), 'FAIL')
        self.assertEqual(self.status('claim_strength'), 'FAIL')

    def test_matching_runtime_cannot_hide_conflicted_runtime_id(self):
        self.bundle = base(); self.bundle['evidence_class'] = 'OBSERVED_EXECUTION'
        add(self.bundle, 'runtime_observation', {'tree': self.bundle['source']['tree'], 'python': self.bundle['source']['python']}, method='HTTP', evidence_class='OBSERVED_EXECUTION')
        a = add(self.bundle, 'runtime_observation', {'tree': self.bundle['source']['tree'], 'python': self.bundle['source']['python']}, rid='reused', method='HTTP', evidence_class='OBSERVED_EXECUTION')
        b = deepcopy(a); b['component'] = 'other-component'; self.bundle['records'].append(b)
        self.assertEqual(self.status('current_runtime_evidence'), 'FAIL')

    def test_negative_control_all_pass_is_detected(self):
        caught = 0
        for c in FIXTURES:
            if 'bundle' not in c: continue
            r = checker.check_bundle(c['bundle'], c['policy'])
            for value in r['findings'].values(): value['status'] = 'PASS'
            caught += {k: v['status'] for k, v in r['findings'].items()} != c['expected_findings']
        self.assertEqual(caught, 19)


class MalformedTests(unittest.TestCase):
    def reject(self, raw):
        r = checker.check_json(raw)
        self.assertEqual(r['findings']['schema']['status'], 'FAIL')
        self.assertTrue(all(v['status'] == 'NOT_APPLICABLE' for k, v in r['findings'].items() if k != 'schema'))
        self.assertIsNone(r['observations'])

    def test_duplicate_nested_keys(self):
        self.reject('{"schema":1,"nested":{"a":1,"a":2}}')

    def test_nonfinite_and_floating_numbers(self):
        for value in ('NaN', 'Infinity', '-Infinity', '1e999', '1.5'):
            with self.subTest(value=value): self.reject('{"x":' + value + '}')

    def test_huge_integer(self):
        self.reject('{"x":' + '1' * 5000 + '}')

    def test_invalid_utf8(self):
        self.reject(b'\xff')

    def test_oversized_document(self):
        self.reject(b' ' * (checker.MAX_BYTES + 1))

    def test_excessive_nesting(self):
        self.reject('[' * 2000 + '0' + ']' * 2000)

    def test_truncated_json(self):
        self.reject('{"schema":')

    def test_malformed_timestamp(self):
        for stamp in ('2026-02-30T10:00:00Z', '2026-10-14T10:00:00', '2026-10-14T10:00:00+00:00'):
            b = base(); b['interval']['end'] = stamp
            with self.subTest(stamp=stamp): self.reject(json.dumps(b))

    def test_bool_is_not_integer(self):
        b = full(); b['accounting']['limit'] = True
        self.reject(json.dumps(b))

    def test_missing_and_unknown_fields(self):
        b = base(); del b['ordering']; self.reject(json.dumps(b))
        b = base(); b['execute'] = 'something'; self.reject(json.dumps(b))

    def test_policy_malformed_rejects_whole_evaluation(self):
        r = checker.check_json(json.dumps(full()), '{"verified":true}')
        self.assertEqual(r['findings']['schema']['status'], 'FAIL')

    def test_malformed_shape_never_raises(self):
        for field, value in [('result', {'digest': DIGEST, 'terminal_id': 'x', 'receipt_refs': [{}]}), ('claims', []), ('records', {}), ('schema', True)]:
            b = base(); b[field] = value
            with self.subTest(field=field): self.reject(json.dumps(b))


if __name__ == '__main__':
    unittest.main()
