import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { root } from './helpers.mjs';

const code = `
import datetime,hashlib,importlib.util,json,pathlib,sys,tempfile
root=pathlib.Path(sys.argv[1]);case=sys.argv[2]
spec=importlib.util.spec_from_file_location('security',root/'tools/check-hysteria-security.py')
s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def write(p,value):p.write_text(json.dumps(value,sort_keys=True)+'\\n');return sha(p)
with tempfile.TemporaryDirectory() as temporary:
 base=pathlib.Path(temporary);evidence=base/'evidence';shipping=base/'shipping';scan=base/'scan'
 for p in (evidence,shipping,scan):p.mkdir()
 now=datetime.datetime(2026,10,13,4,20,tzinfo=datetime.timezone.utc)
 affected=['github.com/klauspost/compress/s2','golang.org/x/crypto/openpgp']
 entries=[];queries=[];response=[]
 for i,(id,module,version) in enumerate((('GO-2026-5841','github.com/klauspost/compress','v1.17.9'),('GO-2026-5932','golang.org/x/crypto','v0.57.0'))):
  advisory={'id':id,'affected':[{'package':{'ecosystem':'Go','name':module},'ecosystem_specific':{'imports':[{'path':affected[i]}]}}]}
  advisorySha=write(scan/(id+'.json'),advisory)
  entries.append({'ecosystem':'Go','package':module,'version':version,'advisory':id,'advisorySha256':advisorySha,'expires':'2026-11-12','affectedPackages':[affected[i]],'reason':'Synthetic non-imported fixture'})
  queries.append({'package':{'ecosystem':'Go','name':module},'version':version});response.append({'vulns':[{'id':id}]})
 if case=='different-version':queries[0]['version']='v1.18.0'
 if case=='unknown-finding':response[0]['vulns'].append({'id':'GO-2099-9999'})
 policy={'schema':1,'scope':'CGO0 Linux Hysteria incoming server','runtimeVersion':'go1.26.9','moduleManifestSha256':'b'*64,'sourceReceiptSha256':'a'*64,'maxScanAgeHours':24,'exceptions':entries,'targets':[],'queryCount':2}
 for arch in ('amd64','arm64'):
  target=shipping/('linux-'+arch);target.mkdir();binary=target/'hysteria';binary.write_bytes(('synthetic binary '+arch).encode())
  modules=target/'go-modules.json';moduleSha=write(modules,{'synthetic':'module'});policy['moduleManifestSha256']=moduleSha
  producer={'target':'linux-'+arch,'binaryRuntimeVersion':'go1.26.9','binarySha256':sha(binary),'filesSha256':{'go-modules.json':moduleSha},'testSuite':{'sourceReceiptSha256':'a'*64},'buildInfo':['build\\tCGO_ENABLED=0','build\\tGOOS=linux','build\\tGOARCH='+arch,'dep\\tgithub.com/klauspost/compress\\tv1.17.9\\th1:fixture','dep\\tgolang.org/x/crypto\\tv0.57.0\\th1:fixture']}
  producerSha=write(target/'hysteria-producer.json',producer)
  packages=[{'ImportPath':'github.com/klauspost/compress/zstd','Module':{'Path':'github.com/klauspost/compress','Version':'v1.17.9'},'GoFiles':['zstd.go'],'Dir':'/synthetic/zstd'}, {'ImportPath':'golang.org/x/crypto/hkdf','Module':{'Path':'golang.org/x/crypto','Version':'v0.57.0'},'GoFiles':['hkdf.go'],'Dir':'/synthetic/hkdf'}, {'ImportPath':'fixture/app','Name':'main','Imports':['github.com/klauspost/compress/zstd','golang.org/x/crypto/hkdf'],'GoFiles':['main.go'],'Dir':'/synthetic/app'}]
  if case=='affected-package' and arch=='amd64':packages.insert(0,{'ImportPath':affected[0],'Module':{'Path':'github.com/klauspost/compress','Version':'v1.17.9'},'GoFiles':['dict.go'],'Dir':'/synthetic/s2'})
  if case=='incomplete-graph' and arch=='amd64':packages[0]['Incomplete']=True
  if case=='replacement' and arch=='amd64':packages[0]['Module']['Replace']={'Path':'other/module'}
  graph=evidence/(arch+'-packages.json');graph.write_text(''.join(json.dumps(x)+'\\n' for x in packages))
  files={p['ImportPath']:{f:'c'*64 for f in p['GoFiles']} for p in packages}
  filesSha=write(evidence/(arch+'-selected-files.json'),files)
  policy['targets'].append({'architecture':arch,'producerSha256':producerSha,'binarySha256':sha(binary),'graphSha256':sha(graph),'selectedFilesSha256':filesSha,'packageCount':len(packages)})
  if case=='changed-binary' and arch=='amd64':binary.write_bytes(b'changed binary')
  if case=='changed-producer' and arch=='amd64':write(target/'hysteria-producer.json',dict(producer,binaryRuntimeVersion='go1.26.8'))
 if case.startswith('alias-'):
  canonical=scan/'GO-2026-5841.json';value=json.loads(canonical.read_text());value['aliases']=['GHSA-259r-337f-4rfw','CVE-2026-63209']
  if case=='alias-missing-primary-proof':value['aliases']=['CVE-2026-63209']
  policy['exceptions'][0]['advisorySha256']=write(canonical,value)
  alias={'id':'GHSA-259r-337f-4rfw','aliases':['CVE-2026-63209'],'affected':[{'package':{'ecosystem':'Go','name':'github.com/klauspost/compress'},'ranges':[{'type':'SEMVER','events':[{'introduced':'0'},{'fixed':'1.18.7'}]}]}]}
  if case=='alias-different-module':alias['affected'][0]['package']['name']='unreviewed/module'
  aliasSha=write(scan/'GHSA-259r-337f-4rfw.json',alias)
  policy['advisoryAliasPairs']=[{'advisory':'GHSA-259r-337f-4rfw','canonical':'GO-2026-5841','advisorySha256':aliasSha}]
  if case=='alias-changed-body':write(scan/'GHSA-259r-337f-4rfw.json',dict(alias,changed=True))
  response[1 if case=='alias-wrong-coordinate'else 0]['vulns'].append({'id':'GHSA-259r-337f-4rfw'})
  if case=='alias-unreviewed-extra':response[0]['vulns'].append({'id':'GHSA-unknown-unknown'})
  if case=='alias-duplicate-id':response[0]['vulns'].append({'id':'GHSA-259r-337f-4rfw'})
 if case=='expired':policy['exceptions'][0]['expires']='2026-10-12'
 if case=='missing-target':policy['targets'].pop()
 if case=='boolean-count':policy['queryCount']=True
 policy['queryPayloadSha256']=write(scan/'query-payload.json',{'queries':queries})
 policy['responseSha256']=write(scan/'querybatch-response.json',{'results':response})
 request={'schema':1,'endpoint':'https://api.osv.dev/v1/querybatch','exitCode':0,'publicQueries':2,'queryPayloadSha256':policy['queryPayloadSha256'],'responseSha256':policy['responseSha256'],'httpMetadata':'200 https://api.osv.dev/v1/querybatch','finished':now.isoformat()}
 if case=='stale-scan':request['finished']=(now-datetime.timedelta(days=2)).isoformat()
 if case=='future-scan':request['finished']=(now+datetime.timedelta(days=2)).isoformat()
 write(scan/'request-receipt.json',request)
 if case=='changed-advisory':write(scan/'GO-2026-5841.json',{'id':'GO-2026-5841','changed':True})
 if case=='symlink-graph':
  p=evidence/'amd64-packages.json';p.rename(evidence/'foreign.json');p.symlink_to(evidence/'foreign.json')
 result=s.check_evidence(policy,evidence,shipping,scan,now)
 assert result['findings']==(3 if case=='alias-qualified'else 2) and result['qualifiedExceptions']==2 and result['blockingFindings']==0
 if case=='alias-qualified':assert result['canonicalAdvisories']==2 and result['reviewedAliasDuplicates']==1
`;

const refused = {
  'affected-package': 'Affected advisory package became reachable',
  'changed-binary': 'Security evidence digest differs',
  'changed-producer': 'Security evidence digest differs',
  'different-version': 'Unqualified public vulnerability finding',
  expired: 'Security exception expired',
  'changed-advisory': 'Security evidence digest differs',
  'unknown-finding': 'Unqualified public vulnerability finding',
  'missing-target': 'Both reviewed Linux architectures required',
  'incomplete-graph': 'Incomplete selected package evidence',
  replacement: 'Replacement changes compiled scope',
  'boolean-count': 'Bounded scan freshness and coordinate count required',
  'stale-scan': 'Public scan is stale or in the future',
  'future-scan': 'Public scan is stale or in the future',
  'symlink-graph': 'Regular security evidence file required',
  'alias-missing-primary-proof': 'Primary canonical and duplicate advisory identity differ',
  'alias-different-module': 'Duplicate advisory package or fixed version differs',
  'alias-changed-body': 'Security evidence digest differs',
  'alias-wrong-coordinate': 'Unqualified public vulnerability finding',
  'alias-unreviewed-extra': 'Unqualified public vulnerability finding',
  'alias-duplicate-id': 'Unqualified public vulnerability finding'
};

for (const scenario of ['synthetic-qualified', 'alias-qualified', ...Object.keys(refused)]) {
  test('Hysteria security boundary: ' + scenario, () => {
    const result = spawnSync('python3', ['-B', '-c', code, root, scenario], {
      encoding: 'utf8', timeout: 10000
    });
    assert.ifError(result.error);
    if (scenario === 'synthetic-qualified' || scenario === 'alias-qualified') assert.equal(result.status, 0, result.stderr);
    else {
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /ValueError/);
      assert.ok(result.stderr.includes(refused[scenario]), result.stderr);
    }
  });
}
