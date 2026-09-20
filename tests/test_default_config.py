#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen (微信/WeChat: bromomo )
# Github: https://github.com/kelvinBen/AppInfoScanner
# Gitee: https://gitee.com/kelvin_ben/AppInfoScanner
import unittest
import tomllib

from libs.core import default_config as dc


class TestConfigRoundtrip(unittest.TestCase):
    def test_dump_roundtrip(self):
        merged = dc.merge_over_defaults(tomllib.loads(dc.dump_config(dc.DEFAULTS)))
        self.assertEqual(merged, dc.DEFAULTS)

    def test_template_roundtrip(self):
        merged = dc.merge_over_defaults(tomllib.loads(dc.generate_default_toml()))
        self.assertEqual(merged, dc.DEFAULTS)

    def test_detection_packs_present(self):
        # 关键检测包规模回归：防止误删条目
        self.assertEqual(len(dc.DEFAULTS["shell_vendors"]), 39)
        self.assertEqual(len(dc.DEFAULTS["apk_permissions"]), 49)
        self.assertEqual(len(dc.DEFAULTS["ios_permissions"]), 22)
        self.assertEqual(len(dc.DEFAULTS["filter_components"]), 20)
        self.assertEqual(len(dc.DEFAULTS["ios_components"]), 22)
        self.assertGreaterEqual(len(dc.DEFAULTS["filter_no_domains"]), 120)
        self.assertEqual(len(dc.DEFAULTS["filter_ak_map"]), 24)
        self.assertEqual(len(dc.DEFAULTS["filter_pii_map"]), 9)

    def test_flutter_not_shell_class(self):
        # Flutter 标准 Application 不是壳，不得回归
        for info in dc.DEFAULTS["shell_vendors"].values():
            self.assertNotIn("io.flutter.app.FlutterApplication", info.get("classes", []))

    def test_mogosec_vendor_mapping(self):
        self.assertIn("com.mogosec.AppMgr", dc.DEFAULTS["shell_vendors"]["中国移动加固"]["classes"])


if __name__ == "__main__":
    unittest.main()
