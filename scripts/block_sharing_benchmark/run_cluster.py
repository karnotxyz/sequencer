import os,json,subprocess,time,concurrent.futures
from pathlib import Path
repo=Path(__file__).resolve().parents[2]
h=Path('/data/harness')
out=h/'evidence';out.mkdir(exist_ok=True)
results=[]
def execute(arm,name,args,extra=None,expected_failure=False):
 folder=out/name;folder.mkdir(exist_ok=True)
 env=dict(os.environ,CD_SHARING_HARNESS=str(h),CD_SHARING_VARIANT=name,**(extra or {}))
 started=time.time()
 try:
  with (folder/'run.log').open('w') as log:
   result=subprocess.run([str(repo/'benchmark-bin'/f'{arm}-flow-tests'),*args,'--nocapture','--test-threads=1'],cwd=repo,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=1200)
  passed=(result.returncode!=0 if expected_failure else result.returncode==0)
  if expected_failure:
   # A crash, missing fixture or host error is not evidence of constrained rejection.
   text=(folder/'run.log').read_text()
   passed=passed and any(x in text for x in ['An ASSERT_EQ instruction failed','assertion failed:','DiffAssertValues','OutOfBounds','Failed to run OS'])
  row=dict(arm=arm,name=name,returncode=result.returncode,expected_failure=expected_failure,passed=passed,seconds=round(time.time()-started,2))
 except subprocess.TimeoutExpired:
  row=dict(arm=arm,name=name,passed=False,timeout=True)
 print(json.dumps(row),flush=True)
 return row
for test in ['batch_verifier_','block_sharing_roots_and_callers','block_sharing_two_blocks','committed_data_batches_match_os_and_bound_resources','committed_data_bad_witness_fails_inside_os','committed_data_invalid_requests_produce_provable_reverts_without_witnesses']:
 results.append(execute('prototype','regression-'+test,[test]))
for tamper in ['unaligned','future','wrong-preimage']:
 results.append(execute('prototype','tamper-'+tamper,['block_sharing_roots_and_callers'],{'CD_CACHE_TAMPER':tamper},True))
cases=[(238,False),(239,False),(238,True),(231,True),(224,True),(217,True),(266,True),(259,True)]
def trade(case):
 arm,block,pair=case
 name=f'{arm}-'+('pair' if pair else 'single')+f'-{block}'
 extra={'CD_SHARING_BLOCK':str(block)}
 if pair:extra['CD_SHARING_PAIR']='1'
 return execute(arm,name,['paired_full_trade_snapshot'],extra)
with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
 results.extend(pool.map(trade,[(arm,b,p)for arm in ['current','prototype']for b,p in cases]))
(out/'execution-summary.json').write_text(json.dumps(results,indent=2))
# Archive first; an accounting regression must remain visible and must not lower fees.
raise SystemExit(int(not all(r['passed']for r in results)))
