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
  'toolchain':'go version go1.26.10 linux/amd64','binaryRuntimeVersion':'go1.26.10','buildInfo':['dep\\tgolang.org/x/net\\tv0.60.0\\th1:synthetic'],
  'filesSha256':{name:hashlib.sha256((out/name).read_bytes()).hexdigest() for name in p.LICENSES+p.PROVENANCE_FILES}}
 record['testSuite']={'schema':1,'sourceReceiptSha256':'4384fa5b283cde9a33ac2147756a4ce61e31708b9b1271e8c0929a330296181b','freshCompleteReceiptSha256':'f66db45fa33d2895c9ca8945ef6c668d0db8910748a063bbed638788004a506e','casePass':510,'caseFail':0,'caseSkip':0,'packagePass':29,'packageSkip':15,'oldCasesRetained':0,'actualSuiteExitCode':0}
 record['sourceTestScope']={'kind':'retained-exact-source-tests','compilerVersion':'go1.26.9','currentCompilerTestsExecuted':False,'freshCompleteReceiptSha256':'f66db45fa33d2895c9ca8945ef6c668d0db8910748a063bbed638788004a506e'}
 record['currentCompilerQualification']={'schema':1,'runtimeReceiptSha256':'3b39d555cb1fedecefcde92f72da72abdd0a26abbf769b0e220992a88c6bf2fd','archiveSha256':'ccfe7ae822d2c2f41f4fe7c956199967a4dac22d0ee0d2b2bfdb440aab3b20c5','ordinaryTlsControlReceiptSha256':'9bd8a66cdc799c7df449640469ecb8986de2e1e2b9588baa3c8a126a15e16f50','ordinaryTlsControlScope':'Linux/amd64 existing TestGoVerify ordinary chain control; not Hysteria target runtime or denylist regression','ordinaryTlsControlReused':True,'currentTargetRuntimeAcceptance':None}
 if case=='missing-compiler-qualification':record.pop('currentCompilerQualification')
 if case=='wrong-compiler-runtime':record['currentCompilerQualification']['runtimeReceiptSha256']='a'*64
 if case=='invented-current-acceptance':record['currentCompilerQualification']['currentTargetRuntimeAcceptance']=True
 if case=='retagged-source-suite':record['sourceTestScope']['compilerVersion']='go1.26.10'
 if case=='invented-current-tests':record['sourceTestScope']['currentCompilerTestsExecuted']=True
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
