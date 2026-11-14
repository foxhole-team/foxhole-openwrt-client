"""Catalog role admission; no filesystem artifacts or signature fixtures."""
from pathlib import Path
import importlib.util
import unittest

spec = importlib.util.spec_from_file_location('server_catalog', Path(__file__).resolve().parents[1]/'tools/build-server-install-catalog.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class CatalogRoleTests(unittest.TestCase):
    def pair(self, role='server-components-v1', budget='server-component-budget-v1'):
        return ({'schema':2,'kind':role,'development':False},
                {'schema':2,'kind':budget,'includeServer':True,'architecture':'x86_64'})
    def test_separate_server_role_has_no_base_package_hash_dependency(self):
        module.validate_role(*self.pair(), 'x86_64')
    def test_existing_compact_role_remains_strict(self):
        module.validate_role(*self.pair('compact-client-engines-v1','compact-selected-budget-v1'),'x86_64')
    def test_roles_cannot_be_mixed_or_unknown(self):
        for a,b in [('server-components-v1','compact-selected-budget-v1'),('unknown','server-component-budget-v1')]:
            with self.assertRaises(ValueError):module.validate_role(*self.pair(a,b),'x86_64')
    def test_untrusted_or_incomplete_metadata_is_rejected(self):
        for key,value,target in [('development',True,0),('includeServer',False,1),('architecture','aarch64_cortex-a53',1)]:
            pair=list(self.pair());pair[target][key]=value
            with self.assertRaises(ValueError):module.validate_role(*pair,'x86_64')

if __name__=='__main__':unittest.main()
