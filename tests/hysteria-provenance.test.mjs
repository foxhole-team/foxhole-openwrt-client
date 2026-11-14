import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { root } from './helpers.mjs';

const code = `
import copy,hashlib,importlib.util,json,pathlib,shutil,sys,tempfile
root=pathlib.Path(sys.argv[1]);case=sys.argv[2]
spec=importlib.util.spec_from_file_location('provenance',root/'tools/hysteria_provenance.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
with tempfile.TemporaryDirectory() as directory:
 out=pathlib.Path(directory)
 shutil.copyfile(root/'package/hysteria'/p.SOURCE_PATCH_FILE,out/p.PROVENANCE_FILES[0])
 shutil.copyfile(root/'package/hysteria/security-source.json',out/p.PROVENANCE_FILES[1])
 evidence=p.source_evidence(out/p.PROVENANCE_FILES[0],out/p.PROVENANCE_FILES[1])
 for name in p.LICENSES:(out/name).write_text('synthetic legal fixture: '+name)
 record={'sourceSha256':p.SOURCE_SHA,'sourceCommit':p.SOURCE_COMMIT,'sourcePatch':p.patch_record(evidence),
  'toolchain':'go version go1.26.11 linux/amd64','binaryRuntimeVersion':'go1.26.11','buildInfo':['dep\\t'+name+'\\t'+version+'\\th1:synthetic' for name,version in {'golang.org/x/net':'v0.62.0','golang.org/x/crypto':'v0.59.0','golang.org/x/sys':'v0.50.0','github.com/andybalholm/brotli':'v1.2.7','github.com/klauspost/compress':'v1.20.2'}.items()],
  'filesSha256':{name:hashlib.sha256((out/name).read_bytes()).hexdigest() for name in p.LICENSES+p.PROVENANCE_FILES}}
 record['testSuite']={'schema':1,'sourceReceiptSha256':'6e3995f198b93654ea2b6cb5f780191ab22c10acc496447c419e7d44bd7cc7f0','freshCompleteReceiptSha256':'f66db45fa33d2895c9ca8945ef6c668d0db8910748a063bbed638788004a506e','casePass':510,'caseFail':0,'caseSkip':0,'packagePass':29,'packageSkip':15,'oldCasesRetained':0,'actualSuiteExitCode':0}
 record['sourceTestScope']={'kind':'fresh-current-compiler-tests','compilerVersion':'go1.26.11','currentCompilerTestsExecuted':True,'freshCompleteReceiptSha256':'f66db45fa33d2895c9ca8945ef6c668d0db8910748a063bbed638788004a506e'}
 record['currentCompilerQualification']={'schema':2,'origin':'source-built-Go-toolchain','version':'go1.26.11','sourceCommit':'26b4433366fce47e480679e0b5a30222b63996e0','sourceArchiveSha256':'d44101b0ff27ed2a4c75ad46c17b9c74359209e2eb2ca7c9df6cb4fdb68e1969','binGoSha256':'26ee101a4b1aa25cc4fcf0f7d1934779eedffe6297b721284167723693852b06','binGoBytes':15548742,'compilerComponentReceiptSha256':'289bce83337162a9e7d0e8825a8329c4789d8d28f2c4781408e8417f12925dfd','runtimeManifestSha256':'c4b52158ad3392089146c65ec2ce01240e97632f93591c2c15e391b1af0513c7','runtimeFileCount':15048,'sourceCompilerBuildReplayedInGo8Job':False,'runtimeFencesPassed':True,'currentTargetRuntimeAcceptance':None}
 if case=='missing-compiler-qualification':record.pop('currentCompilerQualification')
 if case=='wrong-compiler-runtime':record['currentCompilerQualification']['compilerComponentReceiptSha256']='a'*64
 if case=='invented-current-acceptance':record['currentCompilerQualification']['currentTargetRuntimeAcceptance']=True
 if case=='retagged-source-suite':record['sourceTestScope']['compilerVersion']='go1.26.10'
 if case=='invented-current-tests':record['sourceTestScope']['currentCompilerTestsExecuted']=False
 if case=='missing-suite':record.pop('testSuite')
 if case=='boolean-suite-schema':record['testSuite']['schema']=True
 if case=='old-suite-source':record['testSuite']['sourceReceiptSha256']='59f1f3a0ff584073e23dc1bb80da1ef9584c82b07c101a74d58d00110e2df2e7'
 if case=='malformed-suite-digest':record['testSuite']['freshCompleteReceiptSha256']='not-an-actual-digest'
 if case=='empty-suite':record['testSuite']['casePass']=0
 if case=='partial-suite':record['testSuite']['packagePass']=28
 if case=='old-retained-cases':record['testSuite']['oldCasesRetained']=473
 if case=='failed-suite':record['testSuite']['actualSuiteExitCode']=1
 if case=='old-toolchain':record['toolchain']='go version go1.26.8 linux/amd64'
 if case=='old-binary-runtime':record['binaryRuntimeVersion']='go1.26.8'
 if case=='old-network':record['buildInfo']=['dep\\tgolang.org/x/net\\tv0.57.0\\th1:synthetic']
 if case=='old-compression':record['buildInfo']=[x.replace('v1.20.2','v1.18.7') for x in record['buildInfo']]
 if case=='old-brotli':record['buildInfo']=[x.replace('v1.2.7','v1.1.0') for x in record['buildInfo']]
 if case=='wrong-go-binary':record['currentCompilerQualification']['binGoSha256']='a'*64
 if case=='boolean-runtime-count':record['currentCompilerQualification']['runtimeFileCount']=True
 if case=='unfenced-runtime':record['currentCompilerQualification']['runtimeFencesPassed']=False
 if case=='false-unmodified':record['sourcePatch']['sourceUnmodified']=True
 if case=='integer-unmodified':record['sourcePatch']['sourceUnmodified']=0
 if case=='boolean-schema':record['sourcePatch']['schema']=True
 if case=='missing-patch':record['filesSha256'].pop(p.PROVENANCE_FILES[0])
 if case=='tampered-patch':(out/p.PROVENANCE_FILES[0]).write_text('changed repair')
 if case=='tampered-notice':(out/p.LICENSES[0]).write_text('changed legal file')
 p.verify(record,out)
`;

for (const scenario of ['synthetic-complete', 'missing-compiler-qualification', 'wrong-compiler-runtime', 'invented-current-acceptance', 'retagged-source-suite', 'invented-current-tests', 'old-toolchain', 'old-binary-runtime', 'old-network', 'false-unmodified',
  'integer-unmodified', 'boolean-schema', 'missing-patch', 'tampered-patch', 'tampered-notice',
  'old-compression', 'old-brotli', 'wrong-go-binary', 'boolean-runtime-count', 'unfenced-runtime',
  'missing-suite', 'boolean-suite-schema', 'old-suite-source', 'malformed-suite-digest',
  'empty-suite', 'partial-suite', 'old-retained-cases', 'failed-suite']) {
  test('Hysteria repair evidence admission: ' + scenario, () => {
    const result = spawnSync('python3', ['-B', '-c', code, root, scenario], { encoding: 'utf8', timeout: 10000 });
    assert.ifError(result.error);
    if (scenario === 'synthetic-complete') assert.equal(result.status, 0, result.stderr);
    else {
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /ValueError/);
    }
  });
}
