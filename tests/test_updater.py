#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen (微信/WeChat: bromomo )
# Github: https://github.com/kelvinBen/AppInfoScanner
# Gitee: https://gitee.com/kelvin_ben/AppInfoScanner
import os
import sys
import hashlib
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from libs.core import updater


class TestVersionLt(unittest.TestCase):
    def test_basic(self):
        self.assertTrue(updater.version_lt("1.0.10", "1.0.11"))
        self.assertFalse(updater.version_lt("1.0.11", "1.0.11"))
        self.assertFalse(updater.version_lt("1.0.12", "1.0.11"))
        self.assertTrue(updater.version_lt("1.0.9", "1.0.10"))

    def test_release_tags(self):
        self.assertTrue(updater.version_lt("1.0.10", "V1.0.11_Releases"))
        self.assertFalse(updater.version_lt("V1.0.11_Releases", "1.0.11"))


class TestMD5(unittest.TestCase):
    def test_verify(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"hello world")
            path = f.name
        try:
            md5 = hashlib.md5(b"hello world").hexdigest()
            self.assertTrue(updater.verify_md5(path, md5))
            self.assertFalse(updater.verify_md5(path, "0" * 32))
            self.assertTrue(updater.verify_md5(path, None))  # 无期望值跳过
        finally:
            os.unlink(path)


class TestExtractMD5(unittest.TestCase):
    def test_extract(self):
        valid_md5 = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"  # 32位纯hex
        self.assertEqual(updater._extract_md5("MD5: " + valid_md5), valid_md5)
        self.assertEqual(updater._extract_md5("md5: " + valid_md5), valid_md5)
        self.assertIsNone(updater._extract_md5("no md5 here"))
        self.assertIsNone(updater._extract_md5(None))


class TestFetchRelease(unittest.TestCase):
    def test_returns_none_on_network_error(self):
        with mock.patch.object(updater.urllib.request, "urlopen",
                               side_effect=urllib.error.URLError("timeout")):
            self.assertIsNone(updater.fetch_latest_release())

    def test_parses_release_json(self):
        fake = mock.MagicMock()
        fake.__enter__.return_value.read.return_value = json.dumps({
            "tag_name": "V1.0.12_Releases",
            "html_url": "https://github.com/test",
            "body": "MD5: " + "a" * 32,
            "assets": [{"name": "test.zip", "browser_download_url": "https://...", "size": 100, "body": ""}],
        }).encode()
        with mock.patch.object(updater.urllib.request, "urlopen", return_value=fake):
            release = updater.fetch_latest_release()
        self.assertEqual(release["tag"], "V1.0.12_Releases")
        self.assertEqual(len(release["assets"]), 1)


import json
import urllib.error


class TestJarVersion(unittest.TestCase):
    def test_reads_jar_manifest(self):
        import zipfile
        with tempfile.NamedTemporaryFile(delete=False, suffix=".jar") as f:
            with zipfile.ZipFile(f, "w") as zf:
                zf.writestr("META-INF/MANIFEST.MF",
                            "Manifest-Version: 1.0\nImplementation-Version: 3.0.3\n")
            path = f.name
        try:
            self.assertEqual(updater._jar_version(path), "3.0.3")
        finally:
            os.unlink(path)

    def test_returns_none_on_bad_jar(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".jar") as f:
            f.write(b"not a jar")
            path = f.name
        try:
            self.assertIsNone(updater._jar_version(path))
        finally:
            os.unlink(path)


class TestCheckCache(unittest.TestCase):
    def test_should_check_no_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertTrue(updater._should_check(tmp))

    def test_should_check_expired(self):
        with tempfile.TemporaryDirectory() as tmp:
            updater._touch_cache(tmp)
            # 刚写入, 不应检测
            self.assertFalse(updater._should_check(tmp))
            # 修改 mtime 为 2 小时前
            cache = os.path.join(tmp, updater._CACHE_FILE)
            old = os.path.getmtime(cache) - 7200
            os.utime(cache, (old, old))
            self.assertTrue(updater._should_check(tmp))


if __name__ == "__main__":
    unittest.main()
