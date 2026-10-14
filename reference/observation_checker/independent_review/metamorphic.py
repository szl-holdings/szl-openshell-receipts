import copy,hashlib,importlib.util,json,pathlib,random
root=pathlib.Path(__file__).resolve().parent.parent; source=root/'observation_checker.py'; digest=hashlib.sha256(source.read_bytes()).hexdigest(); s=importlib.util.spec_from_file_location('review_checker',source);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
fixtures=json.loads((root/'fixtures.json').read_text())['cases'];rng=random.Random(20261014);results=[]
for c in fixtures:
 if 'bundle' not in c:
  results.append({'case':c['case_id'],'permutations':0,'json_roundtrips':0,'input_unchanged':True,'note':'Raw malformed JSON case excluded from order permutations'})
  continue
 b=c['bundle'];p=c['policy'];before=copy.deepcopy((b,p));expected=m.check_bundle(b,p);count=0
 for i in range(25):
  perm=copy.deepcopy(b); rng.shuffle(perm['records'])
  if perm['result']: rng.shuffle(perm['result']['receipt_refs'])
  actual=m.check_bundle(perm,p)
  assert actual==expected, (c['case_id'],'order variant',i)
  assert m.check_json(m.canonical(perm),m.canonical(p) if p else None)==expected,(c['case_id'],'json route')
  count+=1
 assert (b,p)==before,(c['case_id'],'mutated input')
 results.append({'case':c['case_id'],'permutations':count,'json_roundtrips':count,'input_unchanged':True})
report={'source_sha256':digest,'source_unchanged_during_run':digest==hashlib.sha256(source.read_bytes()).hexdigest(),'results':results,'total_orderings':sum(x['permutations'] for x in results)};(pathlib.Path(__file__).resolve().parent/'metamorphic-results.json').write_text(json.dumps(report,indent=2));print(json.dumps({k:v for k,v in report.items() if k!='results'}))
