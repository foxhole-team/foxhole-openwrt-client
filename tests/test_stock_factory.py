import hashlib
import importlib.util
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "tools" / "stock-factory.py"
spec = importlib.util.spec_from_file_location("stock_factory", TOOL)
factory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(factory)


class StockFactoryTest(unittest.TestCase):
    def test_checksum_binds_exact_board_and_release(self):
        name = "openwrt-25.12.6-mediatek-filogic-cudy_wr3000s-v1-squashfs-sysupgrade.bin"
        digest = hashlib.sha256(b"image").hexdigest()
        line = (digest + " *" + name + "\n").encode()
        self.assertEqual(factory.image_hash(line, name), digest)
        with self.assertRaises(ValueError):
            factory.image_hash(line + line, name)
        with self.assertRaises(ValueError):
            factory.image_hash(line, name.replace("wr3000s", "wr3000"))

    def test_regular_bytes_symlink_and_unexpected_metadata(self):
        content = b"data"
        metadata = b"/ D 1 755 0 0\nbin D 1 755 0 0\nbin/tool R 1 755 0 0 4 0 0\nbin/link S 1 777 0 0 tool"
        entries, body = factory.parse_pseudo(metadata + factory.DATA_MARKER + content)
        self.assertEqual(factory.file_bytes(entries["bin/tool"], body), content)
        self.assertEqual(entries["bin/link"]["target"], "tool")
        for extra in [b"bin/tool R 1 755 0 0 4 0 0", b"../oops D 1 755 0 0",
                      b"bin/extra R 1 755 0 0 1 4 0", b"bin/tool x security.capability=0sAQ=="]:
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                factory.parse_pseudo(metadata + b"\n" + extra + factory.DATA_MARKER + content)

    def test_package_db_binds_identity_and_ownership(self):
        db = b"C:Q1AAAAAAAAAAAAAAAAAAAAAAAAAAA=\nP:test\nV:1-r1\nA:noarch\nf:S\nF:etc\nR:sample\n\n"
        packages = factory.owned_files(db)
        self.assertEqual(packages["test"]["cid"], "00" * 20)
        self.assertEqual(packages["test"]["files"], ["etc/sample"])
        with self.assertRaises(ValueError):
            factory.owned_files(db + db)
        with self.assertRaises(ValueError):
            factory.owned_files(db.replace(b"R:sample", b"R:../unowned"))

    def test_observed_configuration_changes_and_immutable_file_changes(self):
        expected = dict(type="R", mode=0o644, uid=0, gid=0, bytes=3,
                        sha256=hashlib.sha256(b"old").hexdigest(), policy="immutable")
        altered = dict(type="R", mode=0o644, uid=0, gid=0, bytes=3,
                       sha256=hashlib.sha256(b"new").hexdigest())
        with self.assertRaises(ValueError):
            factory.match_entry("etc/tool", expected, altered)
        factory.match_entry("etc/config/dhcp", {**expected, "policy": "configuration"}, altered)
        with self.assertRaises(ValueError):
            factory.match_entry("etc/config/dhcp", {**expected, "policy": "configuration"},
                                {**altered, "mode": 0o666})
        factory.match_entry("etc/uci-defaults/example", {**expected, "policy": "first-boot-script"}, None)
        with self.assertRaises(ValueError):
            factory.match_entry("etc/tool", expected, None)


if __name__ == "__main__":
    unittest.main()
