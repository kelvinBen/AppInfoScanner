#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen (微信/WeChat: bromomo )
# Github: https://github.com/kelvinBen/AppInfoScanner
# Gitee: https://gitee.com/kelvin_ben/AppInfoScanner
import os
import tempfile
import tomllib
import unittest
from unittest import mock

from tests import load_runtime_config
load_runtime_config()
import libs.core as cores
from libs.core import wizard
from libs.core import default_config as dc


class ScriptedAsk:
    # 应答序列注入: 依次弹出任 q 触发取消
    def __init__(self, answers):
        self.answers = list(answers)
        self.calls = []

    def __call__(self, prompt, default=None):
        self.calls.append(prompt)
        return self.answers.pop(0)


class TestWizard(unittest.TestCase):
    def setup_config(self):
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "config.toml")
        with open(path, "w", encoding="utf-8") as f:
            f.write(dc.dump_config(dc.DEFAULTS))
        return path

    def test_download_section_write_and_backup(self):
        path = self.setup_config()
        ask = ScriptedAsk(["post", "", "", "y"])   # method->post, headers/data 跳过, 确认
        changed = wizard.run("download", config_path=path, ask=ask)
        self.assertIn("method = 'post'", changed)
        with open(path, "rb") as f:
            cfg = tomllib.load(f)
        self.assertEqual(cfg["method"], "post")
        backups = [n for n in os.listdir(os.path.dirname(path)) if ".bak." in n]
        self.assertEqual(len(backups), 1)

    def test_enter_keeps_value(self):
        path = self.setup_config()
        ask = ScriptedAsk(["", "", "", "y"])
        changed = wizard.run("download", config_path=path, ask=ask)
        self.assertEqual(changed, [])
        with open(path, "rb") as f:
            self.assertEqual(tomllib.load(f)["method"], "GET")

    def test_q_cancel_no_write(self):
        path = self.setup_config()
        before = open(path).read()
        ask = ScriptedAsk(["q"])
        with self.assertRaises(wizard.Cancel):
            wizard.run("download", config_path=path, ask=ask)
        self.assertEqual(open(path).read(), before)

    def test_confirm_n_no_write(self):
        path = self.setup_config()
        before = open(path).read()
        ask = ScriptedAsk(["post", "", "", "n"])
        with self.assertRaises(wizard.Cancel):
            wizard.run("download", config_path=path, ask=ask)
        self.assertEqual(open(path).read(), before)

    def test_ai_provider_wizard_local(self):
        path = self.setup_config()
        ask = ScriptedAsk([
            "true", "60", "5", "method", "6000",   # ai 五项: enabled/timeout/batch/granularity/max
            "1", "", "1", "y",                      # provider: 本地序号1, key 空, model 序号1, 确认
        ])
        with mock.patch.object(wizard, "_probe_local_ollama", return_value=True), \
                mock.patch.object(wizard, "_fetch_models",
                                  return_value=["qwen2.5-coder:7b", "qwen2.5:14b"]), \
                mock.patch.object(wizard, "_connect_ok", create=True), \
                mock.patch("libs.core.ai_verify.healthy", return_value=True):
            changed = wizard.run("ai", config_path=path, ask=ask)
        self.assertTrue(any("ai_verify.provider.local-ollama" in c for c in changed))
        with open(path, "rb") as f:
            cfg = tomllib.load(f)
        prov = cfg["ai_verify"]["provider"]["local-ollama"]
        self.assertEqual(prov["model_text"], "qwen2.5-coder:7b")
        self.assertEqual(prov["base_url"], "http://127.0.0.1:11434/v1")
        self.assertTrue(cfg["ai_verify"]["enabled"])

    def test_space_section_graceful(self):
        path = self.setup_config()
        ask = ScriptedAsk(["y"])
        changed = wizard.run("space", config_path=path, ask=ask)
        self.assertEqual(changed, [])

    def test_registry_keys_exist_in_defaults(self):
        for _, _, items in wizard.REGISTRY:
            for key_path, _, _ in (items or []):
                root = key_path.split(".")[0]
                self.assertIn(root, dc.DEFAULTS, key_path)


if __name__ == "__main__":
    unittest.main()
