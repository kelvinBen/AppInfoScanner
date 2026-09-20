#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen (微信/WeChat: bromomo )
# Github: https://github.com/kelvinBen/AppInfoScanner
# Gitee: https://gitee.com/kelvin_ben/AppInfoScanner
import os
import struct
import tempfile
import unittest

from libs.core import fix_magic


def build_axml(broken=False):
    sp = b"\x01\x00\x1c\x00" + struct.pack("<I", 160) + b"A" * 152
    good = b"\x03\x00\x08\x00" + struct.pack("<I", 8 + len(sp)) + sp
    if not broken:
        return good
    bad = bytearray(good)
    bad[0:4] = b"\x00\x00\x00\x00"
    bad[4:8] = struct.pack("<I", 9999)
    return bytes(bad)


class TestFixMagic(unittest.TestCase):
    def test_axml_detect_and_fix(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "AndroidManifest.xml")
            with open(path, "wb") as f:
                f.write(build_axml(broken=True))
            status = fix_magic.detect_axml(path)
            self.assertIsNotNone(status)
            self.assertFalse(status["magic_ok"])
            import contextlib
            import io
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertTrue(fix_magic.fix_axml(path))
            status = fix_magic.detect_axml(path)
            self.assertTrue(status["magic_ok"] and status["size_ok"])
            with open(path, "rb") as f:
                self.assertEqual(f.read(), build_axml(broken=False))

    def test_dex_detect_and_fix(self):
        body = b"B" * 400
        dex = (b"dex\n035\x00" + b"\x00" * 4 + b"\x00" * 20 + b"\x00" * 4 +
               struct.pack("<I", 112 + len(body)) + struct.pack("<I", 0x70) +
               struct.pack("<I", 0x12345678) + b"\x00" * 64 + body)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "demo.dex")
            with open(path, "wb") as f:
                f.write(dex)
            self.assertIsNotNone(fix_magic.detect_dex(path))
            import contextlib
            import io
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertTrue(fix_magic.fix_dex(path))
            status = fix_magic.detect_dex(path)
            self.assertTrue(all((status["magic_ok"], status["size_ok"],
                                 status["checksum_ok"], status["signature_ok"])))

    def test_zip_magic_fix(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "demo.zip")
            with open(path, "wb") as f:
                f.write(b"\x00\x00\x00\x00" + b"PK\x05\x06" + b"\x00" * 14)
            import contextlib
            import io
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertTrue(fix_magic.fix_zip(path))
            with open(path, "rb") as f:
                self.assertEqual(f.read(4), b"PK\x03\x04")

    def test_detect_chain_order(self):
        # 完好 AXML(>112B) 不被误判为损坏的 dex
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "m.xml")
            with open(path, "wb") as f:
                f.write(build_axml(broken=False))
            status = fix_magic.detect_axml(path)
            self.assertTrue(status["magic_ok"] and status["size_ok"])

    def test_resolve_path_rejects_traversal(self):
        self.assertIsNone(fix_magic.resolve_path("../evil.dex"))
        self.assertIsNone(fix_magic.resolve_path("a/../../evil.dex"))


if __name__ == "__main__":
    unittest.main()
