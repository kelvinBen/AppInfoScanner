#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen (微信/WeChat: bromomo )
# Github: https://github.com/kelvinBen/AppInfoScanner
# Gitee: https://gitee.com/kelvin_ben/AppInfoScanner
import os
import unittest

from libs.core import i18n


class TestI18n(unittest.TestCase):
    def tearDown(self):
        i18n.set_lang("zh")
        os.environ.pop("APPINFO_LANG", None)

    def test_env_override_detection(self):
        os.environ["APPINFO_LANG"] = "en_US"
        i18n._LANG = None
        self.assertEqual(i18n.detect_lang(), "en")
        os.environ["APPINFO_LANG"] = "zh"
        i18n._LANG = None
        self.assertEqual(i18n.detect_lang(), "zh")

    def test_t_dynamic_template(self):
        i18n.set_lang("zh")
        self.assertEqual(i18n.t("[*] Result directory: {}", "/tmp/x"),
                         "[*] 结果目录: /tmp/x")
        i18n.set_lang("en")
        self.assertEqual(i18n.t("[*] Result directory: {}", "/tmp/x"),
                         "[*] Result directory: /tmp/x")

    def test_ts_static(self):
        i18n.set_lang("zh")
        self.assertEqual(i18n.ts("[*] ========= Summary: ==============="),
                         "[*] =========  摘要:  ===============")

    def test_unknown_message_passthrough(self):
        i18n.set_lang("zh")
        self.assertEqual(i18n.ts("[*] not in catalog"), "[*] not in catalog")


if __name__ == "__main__":
    unittest.main()
