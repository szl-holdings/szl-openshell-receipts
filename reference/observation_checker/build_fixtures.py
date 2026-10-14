"""Generate disclosed synthetic conformance inputs and hand-specified oracles.

No checker import: expectations are explicit scenario contracts, not calculated
from implementation output. This file is original fixture authoring, not hidden
held-out data or an independent real-world oracle.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
DIGEST = 'a' * 64
OTHER = 'b' * 64
REV = '1' * 40
TREE = '2' * 40
TIME = '2026-10-14T10:00:00Z'


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n'


def base():
    return {
        'schema': 1, 'ordering': 'EXPLICIT_SEQUENCE', 'evidence_class': 'SYNTHETIC',
        'interval': {'start': '2026-10-14T09:00:00Z', 'end': TIME},
        'max_age_seconds': 600,
        'source': {'repository': 'synthetic/szl-reference', 'revision': REV, 'tree': TREE, 'exporter_schema': 'fixture-export/1', 'python': '3.12'},
        'journey': {'tenant': 'tenant-fictional', 'session': 'session-1', 'action': 'action-1', 'run': 'run-1', 'plan': 'c' * 64, 'step': 'step-1', 'stage': 'synthesis', 'generation': 'generation-1', 'policy_epoch': 'epoch-1'},
        'records': [], 'result': None, 'accounting': None,
        'claims': {'ui_status': 'unknown', 'durable': False, 'restored': False, 'current_admission': False, 'current_runtime': False, 'deployed': False, 'budget_compliant': None, 'projection_record': None},
    }


def policy():
    return {'schema': 1, 'generation': 'generation-1', 'policy_epoch': 'epoch-1', 'source_revision': REV, 'source_tree': TREE, 'at': TIME, 'expires': '2026-10-14T10:10:00Z', 'revoked_grants': []}


def add(b, kind, data=None, *, rid=None, attempt='attempt-1', method='FIXTURE', component='fixture-exporter', evidence_class='SYNTHETIC'):
    seq = len(b['records']) + 1
    record = {'id': rid or kind + '-' + str(seq), 'kind': kind, 'component': component, 'artifact_digest': hashlib.sha256(canon(data or {}).encode()).hexdigest(), 'at': TIME, 'seq': seq, 'evidence_class': evidence_class, 'method': method, 'binding': dict(b['journey'], source_revision=b['source']['revision'], source_tree=b['source']['tree']), 'attempt_id': attempt, 'data': data or {}}
    b['records'].append(record)
    return record


def accounting(b, *, limit=1, summary=1, complete=True):
    b['accounting'] = {'contract_id': 'fixed-root-budget-1', 'action': 'action-1', 'unit': 'calls', 'limit': limit, 'history_complete': complete, 'summary_charged': summary}


def full():
    b = base()
    accounting(b)
    add(b, 'attempt', {'state': 'RESERVED_UNSENT', 'cost': 1}, rid='reserved')
    add(b, 'admission', {'decision': 'ADMITTED'}, rid='admission')
    add(b, 'source_grant', {'grant_id': 'grant-1', 'decision': 'ADMITTED'}, rid='grant')
    add(b, 'hydration', {'source_digest': 'd' * 64}, rid='hydration')
    add(b, 'generation', {'generation': 'generation-1'}, rid='generation')
    add(b, 'dispatch', rid='dispatch')
    add(b, 'attempt', {'state': 'ACTIVE', 'cost': 1}, rid='active')
    add(b, 'outcome', {'outcome': 'ANSWER', 'result_digest': DIGEST, 'process_id': 'origin-process'}, rid='terminal', component='answer-producer')
    add(b, 'attempt', {'state': 'SETTLED', 'cost': 1}, rid='settled')
    add(b, 'durable_ack', {'result_digest': DIGEST, 'storage_ref': 'synthetic-storage-1'}, rid='ack', method='DURABLE_STORE_READBACK')
    add(b, 'restore', {'result_digest': DIGEST, 'ack_id': 'ack', 'process_id': 'fresh-process'}, rid='restore', method='FRESH_PROCESS_READBACK')
    add(b, 'support_assessment', {'result_digest': DIGEST, 'verdict': 'SUPPORTED'}, rid='assessment', method='INDEPENDENT_ASSESSMENT', component='fixture-assessor')
    b['result'] = {'digest': DIGEST, 'terminal_id': 'terminal', 'receipt_refs': ['ack']}
    b['claims'].update(ui_status='success', durable=True, restored=True, current_admission=True, budget_compliant=True)
    return b


def fixture(case_id, title, b, expected, observed=None, p=None, reasons=None):
    return {'case_id': case_id, 'title': title, 'bundle': b, 'policy': p, 'expected_findings': expected, 'expected_observations': observed or {}, 'expected_reasons': reasons or {}}


def build():
    out = []
    all_pass = {k: 'PASS' for k in ('schema', 'identity', 'lifecycle', 'accounting', 'budget', 'admission', 'durability', 'restoration', 'support_assessment', 'claim_strength')}
    all_pass['current_runtime_evidence'] = 'UNKNOWN'
    out.append(fixture('01', 'Bound result, durable acknowledgement and fresh restoration', full(), all_pass, {'outcome': 'ANSWER', 'charged_or_reserved_cost': 1, 'evidence_class': 'SYNTHETIC'}, policy()))
    b = base(); accounting(b)
    add(b, 'attempt', {'state': 'ACTIVE', 'cost': 1}, rid='active')
    add(b, 'attempt', {'state': 'UNKNOWN', 'cost': 1}, rid='unknown')
    add(b, 'closure', {'status': 'Finished'})
    add(b, 'cleanup', {'status': 'FAILED'})
    b['claims']['ui_status'] = 'finished'
    out.append(fixture('02', 'Administrative closure with failed cleanup and unknown outcome', b, {'lifecycle': 'UNKNOWN', 'claim_strength': 'PASS', 'accounting': 'PASS'}, {'outcome': 'UNKNOWN', 'unknown_attempt_ids': ['attempt-1'], 'cleanup': ['FAILED']}))
    b = base(); add(b, 'transport', {'status': 200, 'handles_only': True}, rid='wire', method='HTTP')
    out.append(fixture('03', 'Wire success without hydrated content or grant', b, {'identity': 'PASS', 'admission': 'UNKNOWN', 'lifecycle': 'UNKNOWN'}, {'outcome': 'UNKNOWN', 'transport_observations': [{'id': 'wire', 'status': 200, 'handles_only': True}]}))
    b = base(); add(b, 'local_contract', {'deployed': True}, rid='local', method='LOCAL_SPY'); b['claims']['deployed'] = True
    out.append(fixture('04', 'Controller-local deployed flag is not live deployment', b, {'current_runtime_evidence': 'UNKNOWN', 'claim_strength': 'UNKNOWN'}, {'local_contract_observations': [{'id': 'local', 'deployed': True}]}))
    b = base(); accounting(b, summary=0)
    add(b, 'attempt', {'state': 'RESERVED_UNSENT', 'cost': 1})
    add(b, 'admission', {'decision': 'DENIED'})
    add(b, 'not_invoked')
    add(b, 'attempt', {'state': 'ABANDONED_UNSENT', 'cost': 1})
    add(b, 'outcome', {'outcome': 'ABSTAINED', 'result_digest': None, 'process_id': 'origin-process'})
    b['claims']['ui_status'] = 'abstained'
    out.append(fixture('05', 'Denied admission with explicit non-invocation and abstention', b, {'lifecycle': 'PASS', 'admission': 'FAIL', 'claim_strength': 'PASS', 'budget': 'PASS'}, {'outcome': 'ABSTAINED', 'charged_or_reserved_cost': 0}))
    b = base(); accounting(b)
    add(b, 'attempt', {'state': 'RESERVED_UNSENT', 'cost': 1})
    add(b, 'admission', {'decision': 'DENIED'})
    add(b, 'dispatch')
    out.append(fixture('06', 'Denied stage nevertheless dispatched', b, {'lifecycle': 'FAIL', 'admission': 'FAIL'}, reasons={'lifecycle': ['denied_stage_dispatched']}))
    b = base(); accounting(b)
    add(b, 'submission', {'status': 'PENDING'})
    add(b, 'attempt', {'state': 'ACTIVE', 'cost': 1})
    add(b, 'timeout')
    add(b, 'attempt', {'state': 'UNKNOWN', 'cost': 1})
    out.append(fixture('07', 'Pending submission times out without reconciliation', b, {'lifecycle': 'UNKNOWN', 'accounting': 'PASS'}, {'outcome': 'UNKNOWN', 'unknown_attempt_ids': ['attempt-1'], 'charged_or_reserved_cost': 1}))
    b = full(); add(b, 'outcome', {'outcome': 'ANSWER', 'result_digest': OTHER, 'process_id': 'origin-process'}, rid='conflicting-terminal')
    out.append(fixture('08', 'Conflicting terminal digests on one attempt', b, {'lifecycle': 'FAIL', 'durability': 'UNKNOWN', 'claim_strength': 'FAIL'}, {'outcome': 'CONFLICT'}, policy(), {'lifecycle': ['conflicting_terminal_results']}))
    b = full(); b['records'].append(deepcopy(b['records'][0]))
    out.append(fixture('09', 'Exact duplicate observation is counted once', b, all_pass, {'duplicate_export_count': 1, 'unique_record_count': 12, 'charged_or_reserved_cost': 1}, policy()))
    b = full(); next(r for r in b['records'] if r['id'] == 'ack')['data']['result_digest'] = OTHER
    out.append(fixture('10', 'Acknowledgement digest does not match result', b, {'durability': 'FAIL', 'restoration': 'UNKNOWN', 'claim_strength': 'FAIL'}, p=policy(), reasons={'durability': ['ack_result_or_attempt_mismatch']}))
    b = full(); b['records'] = [r for r in b['records'] if r['id'] != 'restore']; b['claims']['restored'] = False
    out.append(fixture('11', 'Durable acknowledgement without fresh restoration', b, {'durability': 'PASS', 'restoration': 'UNKNOWN', 'claim_strength': 'PASS'}, p=policy()))
    b = base(); accounting(b)
    add(b, 'attempt', {'state': 'ACTIVE', 'cost': 1})
    add(b, 'cancel_request')
    out.append(fixture('12', 'Cancellation requested without acknowledgement', b, {'lifecycle': 'UNKNOWN'}, {'cancellation': 'REQUESTED_EFFECTS_UNKNOWN', 'charged_or_reserved_cost': 1, 'outcome': 'UNKNOWN'}))
    b = base(); b['evidence_class'] = 'HISTORICAL_EXECUTION'
    add(b, 'historical_test', {'tested_tree': '9' * 40, 'python': '3.9', 'passed': True}, evidence_class='HISTORICAL_EXECUTION', method='SOURCE_REVIEW')
    b['claims']['current_runtime'] = True
    out.append(fixture('13', 'Historical green test belongs to another tree and runtime', b, {'identity': 'PASS', 'current_runtime_evidence': 'UNKNOWN', 'claim_strength': 'UNKNOWN'}))
    b = base(); add(b, 'plan', {'mode': 'PLAN_ONLY', 'status': 'READY_TO_ORCHESTRATE'}); b['claims']['ui_status'] = 'ready_to_orchestrate'
    out.append(fixture('14', 'Plan-only readiness without execution', b, {'identity': 'PASS', 'lifecycle': 'UNKNOWN', 'current_runtime_evidence': 'UNKNOWN', 'claim_strength': 'PASS'}, {'dispatch_record_ids': [], 'outcome': 'UNKNOWN'}))
    b = base(); add(b, 'legacy_snapshot', {'phase': 'FIRST_CYCLE', 'value_digest': DIGEST}, rid='first'); add(b, 'legacy_snapshot', {'phase': 'FINAL', 'value_digest': OTHER}, rid='final'); b['claims']['projection_record'] = 'final'
    out.append(fixture('15', 'Legacy first-cycle and final trace are separate projections', b, {'identity': 'PASS', 'claim_strength': 'PASS'}, {'legacy_projections': [{'id': 'first', 'phase': 'FIRST_CYCLE', 'value_digest': DIGEST}, {'id': 'final', 'phase': 'FINAL', 'value_digest': OTHER}]}))
    b = full(); p = policy(); p['revoked_grants'] = ['grant-1']
    out.append(fixture('16', 'Stable source bytes with revoked current grant', b, {'identity': 'PASS', 'admission': 'FAIL', 'claim_strength': 'FAIL'}, p=p, reasons={'admission': ['source_grant_revoked']}))
    b = base(); malformed = []
    raw = canon(b); malformed.append({'name': 'duplicate_json_key', 'raw': raw.replace('"schema":1', '"schema":1,"schema":1'), 'reason': 'json:duplicate_key'})
    malformed.append({'name': 'nonfinite_json', 'raw': raw.replace('"max_age_seconds":600', '"max_age_seconds":NaN'), 'reason': 'json:nonfinite'})
    bad = deepcopy(b); bad['schema'] = 2; malformed.append({'name': 'unsupported_schema', 'raw': canon(bad), 'reason': 'schema:version'})
    bad = full(); bad['records'] = [deepcopy(bad['records'][0]) for _ in range(65)]; malformed.append({'name': 'oversized_array', 'raw': canon(bad), 'reason': 'array:size'})
    out.append({'case_id': '17', 'title': 'Ambiguous, nonfinite, unsupported and oversized inputs', 'invalid_variants': malformed, 'expected_findings': {'schema': 'FAIL'}})
    b = full(); b['evidence_class'] = 'OBSERVED_EXECUTION'
    out.append(fixture('18', 'Synthetic linked observations relabeled observed execution', b, {'claim_strength': 'FAIL', 'current_runtime_evidence': 'UNKNOWN'}, p=policy(), reasons={'claim_strength': ['observed_execution_class_overstated']}))
    b = base(); accounting(b, limit=1, summary=1)
    add(b, 'attempt', {'state': 'ACTIVE', 'cost': 1}, attempt='attempt-1')
    add(b, 'attempt', {'state': 'ACTIVE', 'cost': 1}, attempt='attempt-2')
    b['claims']['budget_compliant'] = True
    out.append(fixture('19', 'Summary conceals a second charged attempt', b, {'accounting': 'FAIL', 'budget': 'FAIL', 'claim_strength': 'FAIL'}, {'charged_or_reserved_cost': 2}, reasons={'accounting': ['charged_summary_mismatch'], 'budget': ['observed_budget_exceeded']}))
    b = base(); accounting(b, limit=1, summary=1)
    add(b, 'attempt', {'state': 'ACTIVE', 'cost': 1}, attempt='attempt-1')
    add(b, 'timeout', attempt='attempt-1')
    add(b, 'attempt', {'state': 'UNKNOWN', 'cost': 1}, attempt='attempt-1')
    add(b, 'attempt', {'state': 'RESERVED_UNSENT', 'cost': 1}, attempt='attempt-2')
    b['claims']['budget_compliant'] = True
    out.append(fixture('20', 'Timed-out unknown attempt cannot be refunded for another attempt', b, {'accounting': 'FAIL', 'budget': 'FAIL', 'lifecycle': 'UNKNOWN'}, {'charged_or_reserved_cost': 2, 'unknown_attempt_ids': ['attempt-1'], 'outcome': 'UNKNOWN'}, reasons={'accounting': ['charged_summary_mismatch']}))
    # Full predicate oracle for every case, authored from the scenario contract.
    default = {k: 'UNKNOWN' for k in all_pass}
    default.update(schema='PASS', identity='PASS', claim_strength='PASS')
    full_based = {'01', '08', '09', '10', '11', '16', '18'}
    extra = {'02': {'budget': 'PASS'}, '05': {'accounting': 'PASS'}, '06': {'accounting': 'PASS', 'budget': 'PASS'}, '07': {'budget': 'PASS'}, '12': {'accounting': 'PASS', 'budget': 'PASS'}, '08': {'support_assessment': 'UNKNOWN', 'restoration': 'UNKNOWN'},
             '20': {'claim_strength': 'FAIL'}}
    for case in out:
        if case['case_id'] == '17':
            case['expected_findings'] = {k: 'NOT_APPLICABLE' for k in all_pass}
            case['expected_findings']['schema'] = 'FAIL'
        else:
            fixed = dict(all_pass if case['case_id'] in full_based else default)
            fixed.update(case['expected_findings'])
            fixed.update(extra.get(case['case_id'], {}))
            case['expected_findings'] = fixed
    return {'fixture_schema': 1, 'scope': '20 disclosed synthetic conformance/development scenarios; not a held-out benchmark', 'cases': out}


if __name__ == '__main__':
    fixtures = build()
    (HERE / 'fixtures.json').write_text(json.dumps(fixtures, sort_keys=True, indent=2) + '\n', encoding='utf-8')
    (HERE / 'example_bundle.json').write_text(json.dumps(fixtures['cases'][0]['bundle'], sort_keys=True, indent=2) + '\n', encoding='utf-8')
    (HERE / 'example_policy.json').write_text(json.dumps(fixtures['cases'][0]['policy'], sort_keys=True, indent=2) + '\n', encoding='utf-8')
