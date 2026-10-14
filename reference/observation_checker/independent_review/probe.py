import copy, importlib.util, json, pathlib
REVIEW_DIR=pathlib.Path(__file__).resolve().parent
P=str(REVIEW_DIR.parent/'observation_checker.py')
s=importlib.util.spec_from_file_location('observation_checker',P); m=importlib.util.module_from_spec(s); s.loader.exec_module(m)
D='a'*64; R='b'*40
J=dict(tenant='tenant',session='session',action='action',run='run',plan=D,step='step',stage='stage',generation='generation',policy_epoch='epoch')
B=dict(J,source_revision=R,source_tree=R)
def r(i,k,seq,attempt='A',**data):
 return dict(id=i,kind=k,component='component',artifact_digest=D,at='2026-10-14T10:00:00Z',seq=seq,evidence_class='SYNTHETIC',method='FIXTURE',binding=copy.deepcopy(B),attempt_id=attempt,data=data)
def base():
 return dict(schema=1,ordering="EXPLICIT_SEQUENCE",evidence_class='SYNTHETIC',interval=dict(start='2026-10-14T10:00:00Z',end='2026-10-14T10:00:10Z'),max_age_seconds=60,source=dict(repository='synthetic',revision=R,tree=R,exporter_schema='1',python='3'),journey=copy.deepcopy(J),records=[],result=None,accounting=dict(contract_id='c',action='action',unit='calls',limit=2,history_complete=True,summary_charged=None),claims=dict(ui_status='unknown',durable=False,restored=False,current_admission=False,current_runtime=False,deployed=False,budget_compliant=None,projection_record=None))
def show(name,b,p=None):
 (REVIEW_DIR/(name+'.json')).write_text(json.dumps(b,indent=2)); out=m.check_bundle(b,p); (REVIEW_DIR/(name+'-report.json')).write_text(json.dumps(out,indent=2)); print(name,json.dumps({'findings':{k:v for k,v in out['findings'].items() if k in ('schema','identity','lifecycle','accounting','budget','admission','claim_strength')},'observations':out['observations']}))
 return out
b=base(); b['records']=[r('req','cancel_request',1),r('active','attempt',2,state='ACTIVE',cost=1),r('other_stop','effects_stopped',3,attempt='B')]; b['claims']['ui_status']='cancelled'; show('cancel_other_attempt',b)
b=base(); b['records']=[r('term','outcome',1,outcome='ANSWER',result_digest=D,process_id='p'),r('collision','outcome',2,outcome='ANSWER',result_digest=D,process_id='p'),r('collision','outcome',3,outcome='FAILURE',result_digest=D,process_id='p')]; b['result']=dict(digest=D,terminal_id='term',receipt_refs=[]); show('hidden_terminal_conflict',b)
b=base(); b['records']=[r('term','outcome',1,outcome='ANSWER',result_digest=D,process_id='p')]; b['result']=dict(digest=D,terminal_id='term',receipt_refs=[]); b['accounting']['limit']=0; b['claims']['budget_compliant']=True; show('unaccounted_terminal_attempt',b)
b=base(); b['records']=[r('term','outcome',1,outcome='ANSWER',result_digest=D,process_id='p'),r('ack1','durable_ack',2,result_digest=D,storage_ref='s1'),r('ack2','durable_ack',3,result_digest=D,storage_ref='s2')]; b['records'][1]['method']='DURABLE_STORE_READBACK'; b['records'][2]['method']='DURABLE_STORE_READBACK'; b['records'][2]['binding']['run']='other-run'; b['result']=dict(digest=D,terminal_id='term',receipt_refs=['ack1','ack2']); b['claims']['durable']=True; show('mismatched_cited_ack',b)
p=dict(schema=1,generation='generation',policy_epoch='epoch',source_revision=R,source_tree=R,at='2026-10-14T10:00:00Z',expires='2026-10-14T10:00:30Z',revoked_grants=[])
b=base(); b['records']=[r('admitted','admission',1,decision='ADMITTED'),r('grant','source_grant',2,grant_id='g',decision='ADMITTED'),r('hydration','hydration',3,source_digest=D),r('collision','admission',4,decision='ADMITTED'),r('collision','admission',5,decision='DENIED')]; b['claims']['current_admission']=True; show('hidden_admission_denial',b,p)
b=base(); b['records']=[r('restore','restore',3,result_digest=D,ack_id='weird',process_id='p2'),r('weird','closure',1,status='Finished')]; b['result']=dict(digest=D,terminal_id='weird',receipt_refs=[])
try: show('wrong_kind_terminal_restore',b)
except Exception as e: print('wrong_kind_terminal_restore uncaught',type(e).__name__,str(e))
b=base(); b['records']=[r('restore','restore',3,result_digest=D,ack_id='ack',process_id='p2'),r('weird','closure',1,status='Finished'),r('ack','durable_ack',2,result_digest=D,storage_ref='s')]; b['result']=dict(digest=D,terminal_id='weird',receipt_refs=['ack'])
try: show('wrong_kind_terminal_restore_crash',b)
except Exception as e: print('wrong_kind_terminal_restore_crash uncaught',type(e).__name__,str(e)); (REVIEW_DIR/'wrong_kind_terminal_restore_crash.json').write_text(json.dumps(b,indent=2))
b=base(); b['records']=[r('term','outcome',1,outcome='ANSWER',result_digest=D,process_id='p'),r('term','outcome',2,attempt='B',outcome='ANSWER',result_digest=D,process_id='p'),r('ack','durable_ack',3,result_digest=D,storage_ref='s')]; b['result']=dict(digest=D,terminal_id='term',receipt_refs=['ack']); b['records'][2]['method']='DURABLE_STORE_READBACK'
x=show('conflicting_terminal_order_a',b); b['records'].reverse(); y=show('conflicting_terminal_order_b',b); print('conflicting_terminal_order equivalent',x==y,'durability',x['findings']['durability'],y['findings']['durability'])
try: print('big_integer_result',m.check_json('{"n":'+('1'*5000)+'}'))
except Exception as e: print('big_integer uncaught',type(e).__name__,str(e)[:100])
b=base(); b['records']=[r('generation','generation',1,generation='different-generation')]; show('generation_payload_mismatch',b)
b=base(); b['claims']['ui_status']='ready_to_orchestrate'; show('missing_ready_plan',b)
b=base(); b['claims']['ui_status']='finished'; show('missing_finished_closure',b)
b=base(); b['records']=[r('term','outcome',1,outcome='ANSWER',result_digest=D,process_id='p'),r('stopped','effects_stopped',2)]; b['result']=dict(digest=D,terminal_id='term',receipt_refs=[]); b['claims']['ui_status']='cancelled'; show('cancelled_claim_answer_terminal',b)
b=base(); b['records']=[r('a','attempt',1,state='ACTIVE',cost=1),r('term','outcome',2,outcome='ANSWER',result_digest=D,process_id='p'),r('cancel','cancel_request',3),r('stopped','effects_stopped',4)]; b['result']=dict(digest=D,terminal_id='term',receipt_refs=[]); b['claims']['ui_status']='cancelled'; show('cancel_after_answer_terminal',b)
b=base(); b['records']=[r('a','attempt',1,state='ACTIVE',cost=1),r('collision','admission',2,decision='ADMITTED'),r('collision','admission',3,decision='DENIED'),r('dispatch','dispatch',4),r('term','outcome',5,outcome='ANSWER',result_digest=D,process_id='p'),r('assessment','support_assessment',6,result_digest=D,verdict='SUPPORTED')]; b['records'][-1]['component']='independent'; b['records'][-1]['method']='INDEPENDENT_ASSESSMENT'; b['result']=dict(digest=D,terminal_id='term',receipt_refs=[]); b['claims']['ui_status']='success'; show('hidden_denial_dispatch_success',b)
b=base(); b['records']=[r('term','outcome',1,outcome='ANSWER',result_digest=D,process_id='p'),r('assessment','support_assessment',2,result_digest=D,verdict='SUPPORTED'),r('collision','support_assessment',3,result_digest=D,verdict='SUPPORTED'),r('collision','support_assessment',4,result_digest=D,verdict='CONTRADICTED')];
for x in b['records'][1:]: x['component']='independent';x['method']='INDEPENDENT_ASSESSMENT'
b['result']=dict(digest=D,terminal_id='term',receipt_refs=[]);b['claims']['ui_status']='success';show('hidden_contradicted_support',b)
b=base(); b['evidence_class']='OBSERVED_EXECUTION'; b['records']=[r('runtime','runtime_observation',1,attempt=None,tree=R,python='3'),r('collision','local_contract',2,attempt=None,deployed=True),r('collision','local_contract',3,attempt=None,deployed=False)]; b['records'][0]['evidence_class']='OBSERVED_EXECUTION';b['records'][0]['method']='HTTP';b['claims']['current_runtime']=True;show('hidden_synthetic_runtime_evidence',b)
b=base(); b['max_age_seconds']=5; b['records']=[r('old_contradiction','support_assessment',1,result_digest=D,verdict='CONTRADICTED'),r('term','outcome',2,outcome='ANSWER',result_digest=D,process_id='p'),r('support','support_assessment',3,result_digest=D,verdict='SUPPORTED')];b['records'][1]['at']='2026-10-14T10:00:09Z';b['records'][2]['at']='2026-10-14T10:00:10Z'
for x in (b['records'][0],b['records'][2]): x['component']='independent';x['method']='INDEPENDENT_ASSESSMENT'
b['result']=dict(digest=D,terminal_id='term',receipt_refs=[]);b['claims']['ui_status']='success';show('stale_negative_assessment',b)
