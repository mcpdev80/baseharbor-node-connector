#!/usr/bin/env python3
"""Bind complete native and normal operator HTTP journeys to an Actions origin."""
import hashlib,json,os,pathlib,re,subprocess,urllib.request

root=pathlib.Path(os.environ['BASEHARBOR_BROWSER_FIXTURE'])
output=root/'manifest.json'
output.unlink(missing_ok=True)
def require(value,message):
    if not value: raise ValueError(message)
def revision(directory):
    return subprocess.check_output(['git','-C',str(directory),'rev-parse','HEAD'],text=True).strip()
repository='mcpdev80/baseharbor-node-connector'
gate=os.environ['RELEASE_GATE']
require(os.environ['GITHUB_REPOSITORY']==repository,'repository differs')
source=revision(os.environ['GITHUB_WORKSPACE'])
core=revision(os.environ['BASEHARBOR_BROWSER_CORE_SOURCE'])
console=revision('.')
demo=revision('.release-demo-source')
require(source==os.environ['GITHUB_SHA'] and core==os.environ['BASEHARBOR_BROWSER_CORE_COMMIT'] and demo==os.environ['BASEHARBOR_BROWSER_DEMO_COMMIT'],'exact checkout differs')
require(all(re.fullmatch('[0-9a-f]{40}',value) for value in [source,core,console,demo]),'exact source required')
require(pathlib.Path('.browser-core-source/docs/releases/v0.4.23.demo-ref').read_text().strip()==demo,'candidate demo differs')
native=json.loads((root/'browser-receipt.json').read_text())
http=json.loads((root/'remote-http-receipt.json').read_text())
require(native['schema']=='baseharbor.private-browser-receipt/v1' and native['repository']==repository and native['commit']==console and native['core_commit']==core and native['demo_commit']==demo,'browser source binding differs')
require(native['result']=='success' and native['cleanup']=='success','browser result or cleanup failed')
for flag in ['core_bootstrap_evidence','application_lifecycle_evidence','terminal_runtime_evidence','logs_runtime_evidence','production_rotation_evidence']:
    require(native.get(flag) is True,'required browser qualification missing')
steps=set(native['steps'])
required={
 'oidc-origin-role':['real-keycloak-code-S256-login','actual-Core-binds-browser-origin-to-one-installation','actual-Core-viewer-read-allowed-mutation-and-destruction-denied','real-token-expiry-ends-Console-session-and-Core-admission','actual-Core-rejects-real-issuer-token-with-wrong-audience'],
 'plan-apply-result-events':['actual-Core-POST-SSE-GET-and-empty-read-model','actual-browser-first-apply-Core-required-explicit-bootstrap-SQL-Secrets-Identity-READY-and-same-application-continuation'],
 'logs-follow-cancel':['actual-browser-Core-owned-container-logs-read-follow-new-output-cancel-without-replay'],
 'terminal-resize-close':['actual-browser-Core-owned-container-PTY-input-output-resize-exit-and-foreign-actor-denial'],
 'core-setup':['actual-browser-first-apply-Core-required-explicit-bootstrap-SQL-Secrets-Identity-READY-and-same-application-continuation'],
 'application-lifecycle':['actual-browser-Core-application-plan-status-doctor-repair-explicit-destroy-and-foreign-issuer-preservation','actual-browser-authoritative-status-ready-doctor-healthy-before-and-after-rotation'],
 'production-rotation':['actual-browser-approved-production-credential-CA-rotation-changed-native-CA-and-post-rotation-application-status-doctor'],
}
for journey in required.values(): require(set(journey)<=steps,'complete browser steps missing')
require('actual-operator-HTTP-production-enrollment-outbound-Connector-application-plan-apply-status-doctor-immutable-repair-destroy-and-owned-cleanup' in steps,'normal remote HTTP journey missing')
binary=pathlib.Path(os.environ['BASEHARBOR_TEST_CONNECTOR_BIN'])
build=hashlib.sha256(binary.read_bytes()).hexdigest()
require(http['schema']=='baseharbor.remote-http-journey/v1' and http['core_commit']==core and http['connector_binary_sha256']==build and http['runtime']==os.environ['BASEHARBOR_CONNECTOR_RUNTIME_KIND'],'HTTP source binding differs')
require(http['result']=='success' and http['cleanup_result']=='success' and http['production_authority'] is True,'normal HTTP qualification failed')
require({row['operation'] for row in http['observations']}=={'plan','apply','status','doctor','repair','destroy'} and all(row['state']=='succeeded' for row in http['observations']),'complete HTTP lifecycle not observed')
log=pathlib.Path(os.environ['RUNNER_TEMP'],'enrollment.log').read_text()
for marker in [
 'actual Keycloak operator authorization/denials, Connector managed enrollment, local-key renewal, CA overlap/retirement, native typed exec and persisted revocation passed',
 'managed generated SQL project preserved protected TLS material, native UID 70, verified TLS SELECT 1 and immutable repair',
 'actual enrolled remote Application engine published provider and prebuilt repository workload together, verified TLS SQL before workload activation, detected lost workload, restored immutable source for repair without restarting provider, verified status and owned reset/cleanup with foreign preservation',
 '--- PASS: TestNativeOpenBaoManagedCoreAndNodeCSRRotation',
]: require(marker in log,'production enrollment/runtime qualification missing')
require('--- FAIL:' not in log and '--- SKIP:' not in log,'native qualification failed or skipped')
if gate=='integration/static/live-console': qualifications={name:True for name in required}
else:
    require(gate=='integration/'+os.environ['BASEHARBOR_CONNECTOR_RUNTIME_KIND']+'/remote-target','gate runtime differs')
    qualifications={name:True for name in ['production-enrollment','ca-overlap-renewal-revocation','outbound-mtls','application-plan-apply-status-doctor-repair-destroy','secret-tls','foreign-preservation']}
qualifications['owned-cleanup']=True
run=os.environ['GITHUB_RUN_ID']; attempt=int(os.environ['GITHUB_RUN_ATTEMPT'])
require(str(native['run_id'])==run and int(native['run_attempt'])==attempt and attempt>0,'native origin differs')
request=urllib.request.Request(f'https://api.github.com/repos/{repository}/actions/runs/{run}/jobs?per_page=100&filter=latest',headers={'Authorization':'Bearer '+os.environ['GH_TOKEN'],'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'})
with urllib.request.urlopen(request,timeout=15) as response: jobs=json.load(response)['jobs']
matching=[job for job in jobs if job['name']=='Integration · '+gate and job['head_sha']==source and job['run_attempt']==attempt]
require(len(matching)==1,'one exact Actions qualification origin required')
receipt={'schema':'baseharbor.private-integration-evidence/v1','repository':repository,'consumer_commit':source,'core_commit':core,'demo_commit':demo,'console_commit':console,'role':'connector','gate':gate,'workflow_run_id':run,'workflow_run_attempt':attempt,'job_id':matching[0]['id'],'build_sha256':build,'result':'success','cleanup_result':'success','release_eligible':True,'production_authority':True,'qualifications':qualifications}
output.write_text(json.dumps(receipt,indent=2)+'\n');output.chmod(0o600)
