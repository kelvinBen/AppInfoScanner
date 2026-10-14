#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen (微信/WeChat: bromomo )
# Github: https://github.com/kelvinBen/AppInfoScanner
# Gitee: https://gitee.com/kelvin_ben/AppInfoScanner
import unittest

from tests import load_runtime_config
load_runtime_config()
import libs.core as cores
from libs.task.base_task import BaseTask
from libs.core import report


class TestExitCodes(unittest.TestCase):
    # 13-3: 语义化退出码 0/1/2/3/4
    def test_codes(self):
        self.assertEqual(cores.TaskError("x").exit_code, 1)
        self.assertEqual(cores.ShellDetected("x").exit_code, 2)
        self.assertEqual(cores.TaskTimeout("x").exit_code, 3)
        self.assertEqual(cores.EnvMissing("x").exit_code, 4)
        self.assertTrue(issubclass(cores.ShellDetected, cores.TaskError))


class TestAgentMode(unittest.TestCase):
    # 13-3: agent 安全默认——强制关嗅探、拒绝 --unpack、meta 标记
    def test_agent_forces_sniffer_off(self):
        task = BaseTask("Android", "/tmp/x.apk", sniffer=True, agent=True)
        self.assertFalse(task.sniffer)
        self.assertTrue(task.agent_mode)

    def test_normal_mode_keeps_sniffer(self):
        self.assertTrue(BaseTask("Android", "/tmp/x.apk", sniffer=True).sniffer)

    def test_agent_bans_unpack(self):
        with self.assertRaises(cores.TaskError):
            BaseTask("Android", "/tmp/x.apk", unpack=True, agent=True)

    def test_report_meta_agent_flag(self):
        meta = report.build_report_meta("t.apk", "Android", agent=True)
        self.assertTrue(meta["agent_mode"])
        self.assertFalse(report.build_report_meta("t.apk", "Android")["agent_mode"])

    def test_cli_agent_flag_registered(self):
        import io, contextlib
        from click.testing import CliRunner
        import app
        runner = CliRunner()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            result = runner.invoke(app.cli, ["android", "--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("--agent", result.output)


if __name__ == "__main__":
    unittest.main()
