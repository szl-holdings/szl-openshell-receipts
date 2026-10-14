import contextlib,copy,hashlib,io,json,pathlib,runpy
root=pathlib.Path(__file__).resolve().parent
with contextlib.redirect_stdout(io.StringIO()): ns=runpy.run_path(str(root/'probe.py'))
m=ns['m']; base=ns['base']; r=ns['r']; D=ns['D']; R=ns['R']
cases=[('cancel_other_attempt','claim_strength',{'UNKNOWN','FAIL'}),('hidden_terminal_conflict','lifecycle',{'FAIL'}),('unaccounted_terminal_attempt','budget',{'UNKNOWN','FAIL'}),('mismatched_cited_ack','durability',{'FAIL'}),('hidden_admission_denial','admission',{'FAIL'}),('wrong_kind_terminal_restore_crash','lifecycle',{'FAIL'}),('missing_ready_plan','claim_strength',{'UNKNOWN','FAIL'}),('missing_finished_closure','claim_strength',{'UNKNOWN','FAIL'}),('cancel_after_answer_terminal','claim_strength',{'FAIL'}),('hidden_denial_dispatch_success','lifecycle',{'FAIL'}),('hidden_contradicted_support','support_assessment',{'FAIL'}),('hidden_contradicted_support','claim_strength',{'FAIL'}),('hidden_synthetic_runtime_evidence','claim_strength',{'FAIL'}),('hidden_synthetic_runtime_evidence','current_runtime_evidence',{'UNKNOWN','FAIL'}),('stale_negative_assessment','support_assessment',{'FAIL'}),('stale_negative_assessment','claim_strength',{'FAIL'})]
results=[]
for case,key,expected in cases:
 data=json.loads((root/(case+'-report.json')).read_text()); observed=data['findings'][key]['status']; results.append(dict(case=case,finding=key,expected=sorted(expected),observed=observed,matched=observed in expected))
a=json.loads((root/'conflicting_terminal_order_a-report.json').read_text());b=json.loads((root/'conflicting_terminal_order_b-report.json').read_text());results.append(dict(case='order_invariance',matched=a==b))
b=base();before=copy.deepcopy(b);baseline=m.check_bundle(b);results.append(dict(case='input_immutability',matched=b==before))
for index,advisory in enumerate((None,{'authorized':True},float('nan'),object(),{'scores':[-1,200]},lambda: (_ for _ in ()).throw(Exception('must not run')))):
 results.append(dict(case='advisory_noninterference_'+str(index),matched=m.check_bundle(b,advisory=advisory)==baseline))
results.append(dict(case='oversized_json_integer_rejected',matched=m.check_json('{"n":'+('1'*5000)+'}')['findings']['schema']['status']=='FAIL'))
source=pathlib.Path(ns['P']);report=dict(source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),results=results,passed=sum(x['matched'] for x in results),total=len(results));(root/'verification.json').write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2))
