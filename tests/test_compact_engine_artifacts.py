import ast,hashlib,json,re,tempfile,unittest
from pathlib import Path

SOURCE=Path(__file__).resolve().parents[1]/'tools/compact-install-bundle.py'
TREE=ast.parse(SOURCE.read_bytes())
NAMES={'sha','asset','document','assets','engine_artifact_rows','catalog_release_version'}
FUNCTIONS=[v for v in TREE.body if isinstance(v,ast.FunctionDef)and v.name in NAMES]
NS={'Path':Path,'hashlib':hashlib,'json':json,'re':re,'NAME':re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,159}')}
NS['INSTALLERS']=dict.fromkeys(('install.sh','install-core.sh','install-compact.sh','install-plan.uc','install-plan-model.uc','install-compact-plan.uc','engine-package-layout.uc','register-compact-engines.uc','indexed-install.uc'))
exec(compile(ast.Module(body=FUNCTIONS,type_ignores=[]),'actual-public-compact-asset-functions','exec'),NS)

def fixture(root):
    def file(name,body):
        (root/name).write_bytes(body);return hashlib.sha256(body).hexdigest()
    def document(name,value):return file(name,(json.dumps(value)+'\n').encode())
    def entry(arch,token):
        package='foxcore-engine-hysteria2-flash-'+token*64;name=package+'-1.0.0-r1.apk';body=arch.encode()
        digest=file(name,body)
        return {'id':'hysteria2','storage':'FLASH','architecture':arch,'packageName':package,'packageVersion':'1.0.0-r1',
            'packageUrl':'https://github.com/foxhole-team/foxhole-openwrt-client/releases/download/v1.0.0/'+name,
            'packageSha256':digest,'archiveBytes':len(body)},name
    x86,xname=entry('x86_64','a');arm,aname=entry('aarch64_generic','b')
    entries=[x86,arm];ec={'schema':1,'entries':entries}
    eh=document('engine-catalog.json',ec);uh=document('universe.json',{'filesSha256':{xname:x86['packageSha256']}})
    pointers={key:{'file':key+'.json','sha256':document(key+'.json',{'synthetic':True})}for key in('producer','capabilities','slotManifest')}
    catalog={'schema':2,'kind':'compact-client-engines-v1','platforms':[{'engineCatalog':{'file':'engine-catalog.json','sha256':eh},
       'packageUniverse':{'file':'universe.json','sha256':uh},'clients':[{'id':'hysteria2','storage':'flash','entry':x86,**pointers}],'server':None}]}
    document('package-catalog.json',catalog);file('foxhole-openwrt-apk.pem',b'SYNTHETIC-ROLE-UNIT-NOT-A-KEY')
    return catalog,ec,xname,aname

class EngineArtifactUniverseTests(unittest.TestCase):
    def test_global_catalog_requires_all_artifacts_without_inventing_arm_platform(self):
        with tempfile.TemporaryDirectory()as tmp:
            root=Path(tmp);catalog,ec,xname,aname=fixture(root)
            names=NS['assets'](root,catalog)
            self.assertIn(xname,names);self.assertIn(aname,names)
            self.assertEqual(len(catalog['platforms']),1);self.assertEqual(len(catalog['platforms'][0]['clients']),1)

    def test_missing_unselected_architecture_archive_is_refused(self):
        with tempfile.TemporaryDirectory()as tmp:
            root=Path(tmp);catalog,ec,xname,aname=fixture(root);(root/aname).unlink()
            with self.assertRaises(ValueError):NS['assets'](root,catalog)

    def test_changed_unselected_archive_bytes_are_refused(self):
        with tempfile.TemporaryDirectory()as tmp:
            root=Path(tmp);catalog,ec,xname,aname=fixture(root);(root/aname).write_bytes(b'changed')
            with self.assertRaises(ValueError):NS['assets'](root,catalog)

    def test_duplicate_global_artifact_identity_is_refused(self):
        with tempfile.TemporaryDirectory()as tmp:
            root=Path(tmp);catalog,ec,xname,aname=fixture(root);ec['entries'].append(dict(ec['entries'][1]))
            raw=(json.dumps(ec)+'\n').encode();(root/'engine-catalog.json').write_bytes(raw)
            catalog['platforms'][0]['engineCatalog']['sha256']=hashlib.sha256(raw).hexdigest()
            with self.assertRaises(ValueError):NS['assets'](root,catalog)


class EngineCatalogReleaseTests(unittest.TestCase):
    def entry(self,release='1.0.3'):
        base='https://github.com/foxhole-team/foxhole-openwrt-client/releases/download/v'+release+'/'
        return {'packageName':'foxcore-engine-hysteria2-flash-'+'a'*64,'packageVersion':'1.0.2-r1',
            'packageUrl':base+'foxcore-engine-hysteria2-flash-'+'a'*64+'-1.0.2-r1.apk','indexUrl':base+'engines.adb'}

    def test_existing_router_and_core_release_match(self):
        self.assertEqual(NS['catalog_release_version']({'old':self.entry('1.0.2')}),'1.0.2')

    def test_new_router_release_reuses_exact_older_core_package(self):
        self.assertEqual(NS['catalog_release_version']({'current':self.entry()}),'1.0.3')

    def test_mixed_router_release_references_are_rejected(self):
        with self.assertRaises(ValueError):NS['catalog_release_version']({'old':self.entry('1.0.2'),'current':self.entry()})

    def test_foreign_or_inconsistent_asset_references_are_rejected(self):
        for field,value in [('indexUrl','https://example.test/v1.0.3/engines.adb'),
                ('indexUrl',self.entry()['indexUrl']+'?token=ignored'),
                ('indexUrl',self.entry()['indexUrl'].replace('/v1.0.3/','/v01.0.3/')),
                ('packageUrl',self.entry('1.0.2')['packageUrl']),
                ('packageUrl',self.entry()['packageUrl'].replace('-1.0.2-r1.apk','-1.0.3-r1.apk'))]:
            entry=self.entry();entry[field]=value
            with self.subTest(field=field,value=value),self.assertRaises(ValueError):NS['catalog_release_version']({'entry':entry})

    def test_missing_or_invalid_catalog_entries_are_rejected(self):
        for entries in [{},[],{'entry':{}},{'entry':{'indexUrl':1}}]:
            with self.subTest(entries=entries),self.assertRaises(ValueError):NS['catalog_release_version'](entries)

if __name__=='__main__':unittest.main()
