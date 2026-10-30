import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { root } from './helpers.mjs';

const code = `
import hashlib,importlib.util,json,pathlib,shutil,sys,tempfile
root=pathlib.Path(sys.argv[1]);case=sys.argv[2]
spec=importlib.util.spec_from_file_location('prepare',root/'tools/prepare-install-bundle.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
v=p.catalog.budgets.provenance
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
with tempfile.TemporaryDirectory() as temporary:
 source=pathlib.Path(temporary)
 shutil.copyfile(root/'package/hysteria'/v.SOURCE_PATCH_FILE,source/v.PROVENANCE_FILES[0])
 shutil.copyfile(root/'package/hysteria/security-source.json',source/v.PROVENANCE_FILES[1])
 evidence=v.source_evidence(source/v.PROVENANCE_FILES[0],source/v.PROVENANCE_FILES[1])
 for name in v.LICENSES:(source/name).write_text('Synthetic original legal fixture: '+name)
 record={'schema':1,'sourceSha256':v.SOURCE_SHA,'sourceCommit':v.SOURCE_COMMIT,'sourcePatch':v.patch_record(evidence),'toolchain':'go version go1.26.10 linux/amd64','binaryRuntimeVersion':'go1.26.10','buildInfo':['dep\\tgolang.org/x/net\\tv0.60.0\\th1:synthetic'],'filesSha256':{n:sha(source/n) for n in v.LICENSES+v.PROVENANCE_FILES},'testSuite':{'schema':1,'sourceReceiptSha256':v.SUITE_SOURCE_SHA,'freshCompleteReceiptSha256':'f66db45fa33d2895c9ca8945ef6c668d0db8910748a063bbed638788004a506e','casePass':510,'caseFail':0,'caseSkip':0,'packagePass':29,'packageSkip':15,'oldCasesRetained':0,'actualSuiteExitCode':0}}
 record['sourceTestScope']={'kind':'retained-exact-source-tests','compilerVersion':'go1.26.9','currentCompilerTestsExecuted':False,'freshCompleteReceiptSha256':'f66db45fa33d2895c9ca8945ef6c668d0db8910748a063bbed638788004a506e'}
 record['currentCompilerQualification']={'schema':1,'runtimeReceiptSha256':'3b39d555cb1fedecefcde92f72da72abdd0a26abbf769b0e220992a88c6bf2fd','archiveSha256':'ccfe7ae822d2c2f41f4fe7c956199967a4dac22d0ee0d2b2bfdb440aab3b20c5','ordinaryTlsControlReceiptSha256':'9bd8a66cdc799c7df449640469ecb8986de2e1e2b9588baa3c8a126a15e16f50','ordinaryTlsControlScope':'Linux/amd64 existing TestGoVerify ordinary chain control; not Hysteria target runtime or denylist regression','ordinaryTlsControlReused':True,'currentTargetRuntimeAcceptance':None}
 (source/'hysteria-producer.json').write_text(json.dumps(record))
 catalog={'schema':1,'development':True,'variants':[{'coreProducerFile':'core-producer.json','capabilitiesFile':'capabilities.json','serverProducerFile':'hysteria-producer.json','modes':{'flash':{'budgetFile':'budget.json'}}}]}
 (source/'package-catalog.json').write_text(json.dumps(catalog))
 (source/'budget.json').write_text(json.dumps({'schema':1,'filesSha256':{},'memoryEvidence':{'provisional':True,'acceptedForRelease':False}}))
 if case=='changed-original':(source/'LICENSE.md').write_text('changed notice fixture')
 if case=='missing-original':(source/'LICENSE.md').unlink()
 selected=p.selected_assets(source,True)
 assert set(record['filesSha256'])<=selected
 copied=source/'copied';copied.mkdir()
 for name,digest in record['filesSha256'].items():
  shutil.copyfile(source/name,copied/name);assert sha(copied/name)==digest
`;

for (const scenario of ['preserve-originals', 'changed-original', 'missing-original']) {
  test('Install bundle original producer assets: ' + scenario, () => {
    const result = spawnSync('python3', ['-B', '-c', code, root, scenario], {
      encoding: 'utf8', timeout: 10000
    });
    assert.ifError(result.error);
    if (scenario === 'preserve-originals') assert.equal(result.status, 0, result.stderr);
    else {
      assert.notEqual(result.status, 0);
      const expected = scenario === 'changed-original'
        ? 'Hysteria legal or repair provenance digest differs'
        : 'Regular Hysteria provenance input required';
      assert.ok(result.stderr.includes(expected), result.stderr);
    }
  });
}
