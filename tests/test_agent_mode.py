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


class TestRedact(unittest.TestCase):
    # 13-3 第二批: 三级脱敏 none/hash/full
    def test_redact_levels(self):
        import libs.core as cores
        old = cores.redact_mode
        try:
            cores.redact_mode = "none"
            self.assertEqual(cores.redact("AKIAIOSFODNN7EXAMPLE"), "AKIAIOSFODNN7EXAMPLE")
            cores.redact_mode = "hash"
            r = cores.redact("AKIAIOSFODNN7EXAMPLE")
            self.assertTrue(r.startswith("AKIAIOSF") and "#" in r)
            self.assertEqual(r, "AKIAIOSF...#" + __import__("hashlib").sha256(
                b"AKIAIOSFODNN7EXAMPLE").hexdigest()[:8])
            cores.redact_mode = "full"
            self.assertEqual(cores.redact("AKIAIOSFODNN7EXAMPLE"), "<redacted>")
        finally:
            cores.redact_mode = old

    def test_txt_redacted_in_hash_mode(self):
        import tempfile, os, contextlib, io as _io
        import libs.core as cores
        from libs.core import report
        old = cores.redact_mode
        try:
            cores.redact_mode = "hash"
            data = report.classify_results(
                {"/a.js": ["[Authorization_Header]-->: Bearer secret123"]}, set(), set())
            meta = report.build_report_meta("t.apk", "Android")
            extra = {"components": [], "permissions": [], "shell": [], "sniffer": [],
                     "details": {"/a.js": ["[Authorization_Header]-->: Bearer secret123"]}}
            tp = os.path.join(tempfile.mkdtemp(), "r.txt")
            report.write_txt_report(tp, meta, data, extra)
            txt = open(tp).read()
            self.assertNotIn("secret123", txt)
            self.assertIn("Bearer s", txt)   # 前8位保留
        finally:
            cores.redact_mode = old

    def test_json_full_mode_redacted(self):
        import tempfile, os, json
        import libs.core as cores
        from libs.core import report
        old = cores.redact_mode
        try:
            cores.redact_mode = "full"
            data = report.classify_results(
                {"/a.js": ["[Authorization_Header]-->: Bearer secret123"]}, set(), set())
            meta = report.build_report_meta("t.apk", "Android")
            extra = {"components": [], "permissions": [], "shell": [], "sniffer": [],
                     "details": {"/a.js": ["[Authorization_Header]-->: Bearer secret123"]}}
            jp = os.path.join(tempfile.mkdtemp(), "r.json")
            report.write_json_report(jp, meta, data, extra)
            payload = json.load(open(jp))
            blob = json.dumps(payload, ensure_ascii=False)
            self.assertNotIn("secret123", blob)
        finally:
            cores.redact_mode = old

    def test_cli_redact_flag_registered(self):
        from click.testing import CliRunner
        import app
        result = CliRunner().invoke(app.cli, ["android", "--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("--redact", result.output)


class TestJsonOnlyAndTimeout(unittest.TestCase):
    # 13-3 第二批: json-only(stdout 纯 JSON/过程输出走 stderr) 与总超时
    def test_run_with_timeout_pass(self):
        import app
        ran = []
        app._run_with_timeout(lambda: ran.append(1), 5)
        self.assertEqual(ran, [1])
        app._run_with_timeout(lambda: None, None)   # 无超时直跑

    def test_run_with_timeout_expires(self):
        import time, app
        t0 = time.time()
        with self.assertRaises(TimeoutError):
            app._run_with_timeout(lambda: time.sleep(3), 0.2)
        self.assertLess(time.time() - t0, 2)

    def test_json_only_routes_progress_to_stderr(self):
        import io as _io, contextlib
        import libs.core as cores
        old = cores.json_only
        try:
            cores.json_only = True
            cores._progress_is_tty = None
            cores._progress_tick = 0
            err, out = _io.StringIO(), _io.StringIO()
            with contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
                cores.progress("working")
            self.assertIn("working", err.getvalue())
            self.assertEqual(out.getvalue(), "")
        finally:
            cores.json_only = old
            cores._progress_is_tty = None
            cores._progress_tick = 0

    def test_build_report_payload_reusable(self):
        from libs.core import report
        data = report.classify_results({}, set(), set())
        meta = report.build_report_meta("t", "Android")
        payload = report.build_report_payload(meta, data, {"components": []})
        self.assertIn("meta", payload)
        self.assertIn("components", payload)

    def test_cli_flags_registered(self):
        from click.testing import CliRunner
        import app
        result = CliRunner().invoke(app.cli, ["web", "--help"])
        self.assertEqual(result.exit_code, 0)
        for flag in ("--format", "--timeout", "--redact", "--agent"):
            self.assertIn(flag, result.output)


if __name__ == "__main__":
    unittest.main()
