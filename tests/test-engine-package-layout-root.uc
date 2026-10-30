import * as fs from 'fs';
import * as policy from '../tools/engine-package-layout.uc';

const ORIGINAL=json("{\n  \"info\": {\n    \"name\": \"foxcore-engine-hysteria2-flash-5febba87ef05e6ea9fdf9fcb012d05a7efbc888dc2c4903caedc46a0258ba26d\",\n    \"version\": \"1.0.0-r1\",\n    \"hashes\": \"c51512efbed414ff7a3dcc972ed6be18b34190bf\",\n    \"description\": \"One verified protocol producer in a versioned immutable slot. It has no init scripts, service hooks or replacement of another engine.\",\n    \"arch\": \"x86_64\",\n    \"license\": \"GPL-3.0-or-later\",\n    \"origin\": \"/source/package/foxcore-engine\",\n    \"maintainer\": \"FoxHole Team\",\n    \"installed-size\": 12525362,\n    \"depends\": [\n      \"libc\"\n    ]\n  },\n  \"paths\": [\n    {\n      \"acl\": {\n        \"mode\": 493,\n        \"user\": \"root\",\n        \"group\": \"root\"\n      }\n    },\n    {\n      \"name\": \"lib\",\n      \"acl\": {\n        \"mode\": 493,\n        \"user\": \"root\",\n        \"group\": \"root\"\n      }\n    },\n    {\n      \"name\": \"lib/apk\",\n      \"acl\": {\n        \"mode\": 493,\n        \"user\": \"root\",\n        \"group\": \"root\"\n      }\n    },\n    {\n      \"name\": \"lib/apk/packages\",\n      \"acl\": {\n        \"mode\": 493,\n        \"user\": \"root\",\n        \"group\": \"root\"\n      },\n      \"files\": [\n        {\n          \"name\": \"foxcore-engine-hysteria2-flash-5febba87ef05e6ea9fdf9fcb012d05a7efbc888dc2c4903caedc46a0258ba26d.list\",\n          \"acl\": {\n            \"mode\": 420,\n            \"user\": \"root\",\n            \"group\": \"root\"\n          },\n          \"size\": 1152,\n          \"mtime\": 1792120747,\n          \"hash\": \"3df17b5572a37575b496c14610dfdfd1b8ff2ba1680f2c6dcd8f59330a52325b\"\n        }\n      ]\n    },\n    {\n      \"name\": \"usr\",\n      \"acl\": {\n        \"mode\": 493,\n        \"user\": \"root\",\n        \"group\": \"root\"\n      }\n    },\n    {\n      \"name\": \"usr/libexec\",\n      \"acl\": {\n        \"mode\": 493,\n        \"user\": \"root\",\n        \"group\": \"root\"\n      }\n    },\n    {\n      \"name\": \"usr/libexec/foxhole\",\n      \"acl\": {\n        \"mode\": 493,\n        \"user\": \"root\",\n        \"group\": \"root\"\n      }\n    },\n    {\n      \"name\": \"usr/libexec/foxhole/engines\",\n      \"acl\": {\n        \"mode\": 493,\n        \"user\": \"root\",\n        \"group\": \"root\"\n      }\n    },\n    {\n      \"name\": \"usr/libexec/foxhole/engines/hysteria2\",\n      \"acl\": {\n        \"mode\": 493,\n        \"user\": \"root\",\n        \"group\": \"root\"\n      }\n    },\n    {\n      \"name\": \"usr/libexec/foxhole/engines/hysteria2/5febba87ef05e6ea9fdf9fcb012d05a7efbc888dc2c4903caedc46a0258ba26d\",\n      \"acl\": {\n        \"mode\": 493,\n        \"user\": \"root\",\n        \"group\": \"root\"\n      },\n      \"files\": [\n        {\n          \"name\": \"capabilities.json\",\n          \"acl\": {\n            \"mode\": 420,\n            \"user\": \"root\",\n            \"group\": \"root\"\n          },\n          \"size\": 189,\n          \"mtime\": 1792120747,\n          \"hash\": \"a955f47d39794f3a5a0e4f7b2442656c8996ba3b2544e23f8ea17307c47f601d\"\n        },\n        {\n          \"name\": \"core-producer.json\",\n          \"acl\": {\n            \"mode\": 420,\n            \"user\": \"root\",\n            \"group\": \"root\"\n          },\n          \"size\": 1974,\n          \"mtime\": 1792120747,\n          \"hash\": \"afcb5623671da76bcb47ba1becdb60d044715cf431622f7ebbe3c21b27d1a403\"\n        },\n        {\n          \"name\": \"foxcore-cli\",\n          \"acl\": {\n            \"mode\": 493,\n            \"user\": \"root\",\n            \"group\": \"root\"\n          },\n          \"size\": 9794976,\n          \"mtime\": 1792120747,\n          \"hash\": \"a89ede004e6d8419aa98264ff4d4c9099d0f94f6280b1dd4c62e537807b5a072\"\n        },\n        {\n          \"name\": \"slot.json\",\n          \"acl\": {\n            \"mode\": 420,\n            \"user\": \"root\",\n            \"group\": \"root\"\n          },\n          \"size\": 655,\n          \"mtime\": 1792120747,\n          \"hash\": \"5febba87ef05e6ea9fdf9fcb012d05a7efbc888dc2c4903caedc46a0258ba26d\"\n        }\n      ]\n    },\n    {\n      \"name\": \"usr/share\",\n      \"acl\": {\n        \"mode\": 493,\n        \"user\": \"root\",\n        \"group\": \"root\"\n      }\n    },\n    {\n      \"name\": \"usr/share/licenses\",\n      \"acl\": {\n        \"mode\": 493,\n        \"user\": \"root\",\n        \"group\": \"root\"\n      }\n    },\n    {\n      \"name\": \"usr/share/licenses/foxcore-engine-hysteria2-flash-5febba87ef05e6ea9fdf9fcb012d05a7efbc888dc2c4903caedc46a0258ba26d\",\n      \"acl\": {\n        \"mode\": 493,\n        \"user\": \"root\",\n        \"group\": \"root\"\n      },\n      \"files\": [\n        {\n          \"name\": \"DEPENDENCY-LICENSES.txt\",\n          \"acl\": {\n            \"mode\": 420,\n            \"user\": \"root\",\n            \"group\": \"root\"\n          },\n          \"size\": 2307017,\n          \"mtime\": 1792120747,\n          \"hash\": \"393f635beb2a346f6874e1cd66f57bdd92c2031c91c82701f1b24dc68afb8c27\"\n        },\n        {\n          \"name\": \"LEGAL-PROVENANCE.json\",\n          \"acl\": {\n            \"mode\": 420,\n            \"user\": \"root\",\n            \"group\": \"root\"\n          },\n          \"size\": 1582,\n          \"mtime\": 1792120747,\n          \"hash\": \"6401e4b878b98c1b5adb73956f676e8fae3815a100e60b07662ef23603eb7791\"\n        },\n        {\n          \"name\": \"LICENSE\",\n          \"acl\": {\n            \"mode\": 420,\n            \"user\": \"root\",\n            \"group\": \"root\"\n          },\n          \"size\": 35149,\n          \"mtime\": 1792120747,\n          \"hash\": \"3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986\"\n        },\n        {\n          \"name\": \"RUNTIME-NOTICES.txt\",\n          \"acl\": {\n            \"mode\": 420,\n            \"user\": \"root\",\n            \"group\": \"root\"\n          },\n          \"size\": 377356,\n          \"mtime\": 1792120747,\n          \"hash\": \"6cb9a034659984a13fc6f3128202d638f18e58ad3489267a93f8dab8871b6631\"\n        },\n        {\n          \"name\": \"THIRD_PARTY_NOTICES.md\",\n          \"acl\": {\n            \"mode\": 420,\n            \"user\": \"root\",\n            \"group\": \"root\"\n          },\n          \"size\": 5312,\n          \"mtime\": 1792120747,\n          \"hash\": \"5ccccc073f313a4c71db9c086f4eef407254db0ddd868595809b1ab7e460df00\"\n        }\n      ]\n    }\n  ]\n}\n");
const EXPECTED=json("{\"id\":\"hysteria2\",\"manifestSha256\":\"5febba87ef05e6ea9fdf9fcb012d05a7efbc888dc2c4903caedc46a0258ba26d\",\"packageName\":\"foxcore-engine-hysteria2-flash-5febba87ef05e6ea9fdf9fcb012d05a7efbc888dc2c4903caedc46a0258ba26d\",\"packageVersion\":\"1.0.0-r1\",\"architecture\":\"x86_64\",\"installedBytes\":12525362}");

let passed=0, failed=0;
function copy(value) { return json(sprintf('%J',value)); };
function equal(value,wanted) { if (sprintf('%J',value)!=sprintf('%J',wanted)) die('layout_assertion_failed'); };
function refuses(value) {
 let caught=null;
 try { policy.layout(value,EXPECTED); } catch(error) { caught=type(error)=='string'?error:error.message; }
 equal(caught,'engine_package_verification_failed');
};
function test(name,fn) {
 try { fn(); passed++; print('ok ',name,'\n'); }
 catch(error) { failed++; print('not ok ',name,': ',type(error)=='string'?error:error.message,'\n'); }
};


test('actual native unnamed root with finite children is accepted',()=>{
 equal(policy.layout(copy(ORIGINAL),EXPECTED),true);
});
test('native explicit empty-string root is accepted',()=>{
 let value=copy(ORIGINAL);value.paths[0].name='';equal(policy.layout(value,EXPECTED),true);
});
test('explicit null root name is refused',()=>{let value=copy(ORIGINAL);value.paths[0].name=null;refuses(value);});
test('duplicate native root is refused',()=>{let value=copy(ORIGINAL);push(value.paths,copy(value.paths[0]));refuses(value);});
test('native root cannot carry a payload file',()=>{let value=copy(ORIGINAL);value.paths[0].files=[copy(value.paths[3].files[0])];refuses(value);});
test('native root must be 0755 root-root',()=>{
 for(let patch in [{mode:0o777},{mode:0o700},{user:'nobody'},{group:'nobody'}]) {
  let value=copy(ORIGINAL);for(let key,item in patch)value.paths[0].acl[key]=item;refuses(value);
 }
});
test('native root cannot be a symlink or have unknown metadata',()=>{
 for(let key in ['target','unknown']){let value=copy(ORIGINAL);value.paths[0][key]='/tmp/other';refuses(value);}
});
test('native root cannot carry even empty xattrs',()=>{let value=copy(ORIGINAL);value.paths[0].acl.xattrs=[];refuses(value);});
test('dot absolute and unknown directory paths do not become roots',()=>{
 for(let name in ['.','/','/usr','unknown','../usr']){let value=copy(ORIGINAL);value.paths[0].name=name;refuses(value);}
});
test('child world-write and duplicate directory remain refused',()=>{
 let value=copy(ORIGINAL);value.paths[1].acl.mode=0o777;refuses(value);
 value=copy(ORIGINAL);push(value.paths,copy(value.paths[1]));refuses(value);
});
test('child symlink and missing finite payload remain refused',()=>{
 let value=copy(ORIGINAL);value.paths[3].files[0].target='/tmp/other';refuses(value);
 value=copy(ORIGINAL);value.paths[3].files=[];refuses(value);
});
print('Native layout cases: ',passed,' passed, ',failed,' failed\n');
exit(failed?1:0);
