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
 record={'schema':1,'sourceSha256':v.SOURCE_SHA,'sourceCommit':v.SOURCE_COMMIT,'sourcePatch':v.patch_record(evidence),'toolchain':'go version go1.26.11 linux/amd64','binaryRuntimeVersion':'go1.26.11','buildInfo':['dep\\t'+name+'\\t'+version+'\\th1:synthetic' for name,version in {'golang.org/x/net':'v0.62.0','golang.org/x/crypto':'v0.59.0','golang.org/x/sys':'v0.50.0','github.com/andybalholm/brotli':'v1.2.7','github.com/klauspost/compress':'v1.20.2'}.items()],'filesSha256':{n:sha(source/n) for n in v.LICENSES+v.PROVENANCE_FILES},'testSuite':{'schema':1,'sourceReceiptSha256':v.SUITE_SOURCE_SHA,'freshCompleteReceiptSha256':'f66db45fa33d2895c9ca8945ef6c668d0db8910748a063bbed638788004a506e','casePass':510,'caseFail':0,'caseSkip':0,'packagePass':29,'packageSkip':15,'oldCasesRetained':0,'actualSuiteExitCode':0}}
 record['sourceTestScope']={'kind':'fresh-current-compiler-tests','compilerVersion':'go1.26.11','currentCompilerTestsExecuted':True,'freshCompleteReceiptSha256':'f66db45fa33d2895c9ca8945ef6c668d0db8910748a063bbed638788004a506e'}
 record['currentCompilerQualification']={'schema':2,'origin':'source-built-Go-toolchain','version':'go1.26.11','sourceCommit':'26b4433366fce47e480679e0b5a30222b63996e0','sourceArchiveSha256':'d44101b0ff27ed2a4c75ad46c17b9c74359209e2eb2ca7c9df6cb4fdb68e1969','binGoSha256':'26ee101a4b1aa25cc4fcf0f7d1934779eedffe6297b721284167723693852b06','binGoBytes':15548742,'compilerComponentReceiptSha256':'289bce83337162a9e7d0e8825a8329c4789d8d28f2c4781408e8417f12925dfd','runtimeManifestSha256':'c4b52158ad3392089146c65ec2ce01240e97632f93591c2c15e391b1af0513c7','runtimeFileCount':15048,'sourceCompilerBuildReplayedInGo8Job':False,'runtimeFencesPassed':True,'currentTargetRuntimeAcceptance':None}
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
