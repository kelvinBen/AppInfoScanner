#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen (微信/WeChat: bromomo )
# Github: https://github.com/kelvinBen/AppInfoScanner
# Gitee: https://gitee.com/kelvin_ben/AppInfoScanner
import os
import tempfile
import tomllib
import unittest

from tests import load_runtime_config
load_runtime_config()
from libs.core import default_config as dc


class TestSplitConfig(unittest.TestCase):
    # P-4: 规则键/个人配置键划分完备且不重叠
    def test_partition_covers_defaults(self):
        rules, personal = dc.split_config(dc.DEFAULTS)
        self.assertEqual(set(rules) | set(personal), set(dc.DEFAULTS))
        self.assertEqual(set(rules) & set(personal), set())

    def test_rule_keys_content(self):
        for k in ("filter_ak_map", "filter_pii_map", "shell_vendors",
                  "pii_test_vectors", "component_hosts", "email_tlds"):
            self.assertIn(k, dc.RULE_KEYS)
        for k in ("method", "headers", "data", "ai_verify", "dex_strings_direct",
                  "config_version"):
            self.assertNotIn(k, dc.RULE_KEYS)

    def test_generators_roundtrip(self):
        for gen, keys in ((dc.generate_config_toml, lambda k: k not in dc.RULE_KEYS),
                          (dc.generate_rules_toml, lambda k: k in dc.RULE_KEYS)):
            parsed = tomllib.loads(gen())
            self.assertEqual(set(parsed), {k for k in dc.DEFAULTS if keys(k)})


class TestWorkspaceDualFile(unittest.TestCase):
    # P-4: 旧单文件拆分迁移 + 双文件加载优先级
    def test_split_legacy(self):
        import libs.core as cores
        from libs.core import Bootstrapper
        tmp = tempfile.mkdtemp()
        # 模拟旧版单文件: 规则键 + 个人键混杂
        legacy = os.path.join(tmp, "config.toml")
        with open(legacy, "w", encoding="utf-8") as f:
            f.write(dc.dump_config({
                "method": "POST",
                "pii_test_vectors": ["15258229321"],
                "filter_no": ["^0\\."],
            }))
        b = Bootstrapper(__file__, os.path.join(tmp, "out"), False, False, "/tmp/x.apk")
        b.__split_legacy_rules__(legacy, os.path.join(tmp, "rules.toml"))
        # config.toml 只剩个人键; rules.toml 拿到规则键; 备份存在
        with open(legacy, "rb") as f:
            personal = tomllib.load(f)
        self.assertEqual(set(personal), {"method"})
        self.assertEqual(personal["method"], "POST")
        with open(os.path.join(tmp, "rules.toml"), "rb") as f:
            rules = tomllib.load(f)
        self.assertEqual(rules["pii_test_vectors"], ["15258229321"])
        self.assertTrue(any(".bak." in n for n in os.listdir(tmp)))

    def test_deploy_creates_both(self):
        import libs.core as cores
        from libs.core import Bootstrapper
        tmp = tempfile.mkdtemp()
        b = Bootstrapper(__file__, os.path.join(tmp, "out"), False, False, "/tmp/x.apk")
        b.__deploy_workspace__("/nonexistent-script-dir", tmp)   # 直接指定工作区根
        self.assertTrue(os.path.exists(os.path.join(tmp, "config.toml")))
        rules_path = os.path.join(tmp, "rules.toml")
        self.assertTrue(os.path.exists(rules_path))
        with open(rules_path, "rb") as f:
            rules = tomllib.load(f)
        self.assertIn("filter_ak_map", rules)
        self.assertIn("shell_vendors", rules)
        with open(os.path.join(tmp, "config.toml"), "rb") as f:
            personal = tomllib.load(f)
        self.assertNotIn("filter_ak_map", personal)
        self.assertIn("ai_verify", personal)
        # 运行时配置合并完整
        self.assertTrue(hasattr(cores.config, "filter_ak_map"))
        self.assertTrue(hasattr(cores.config, "ai_verify"))


class TestRulesPrecedence(unittest.TestCase):
    # P-4: rules.toml 允许手改, 同键个人配置优先
    def test_config_overrides_rules(self):
        import libs.core as cores
        from libs.core import Bootstrapper
        tmp = tempfile.mkdtemp()
        b = Bootstrapper(__file__, os.path.join(tmp, "out"), False, False, "/tmp/x.apk")
        b.__deploy_workspace__("/nonexistent-script-dir", tmp)
        # rules.toml 手改追加自定义规则; 重载后生效
        rp = os.path.join(tmp, "rules.toml")
        with open(rp, "a", encoding="utf-8") as f:
            f.write("\n[filter_pii_map.My_Custom_Rule]\nrules = ['\\d{11}']\n")
        b2 = Bootstrapper(__file__, os.path.join(tmp, "out"), False, False, "/tmp/x.apk")
        b2.__deploy_workspace__("/nonexistent-script-dir", tmp)
        self.assertIn("My_Custom_Rule", cores.config.filter_pii_map)
        self.assertIn("Phone_CN", cores.config.filter_pii_map)   # 默认规则仍完整


if __name__ == "__main__":
    unittest.main()
