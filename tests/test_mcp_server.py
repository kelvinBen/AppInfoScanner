#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen (微信/WeChat: bromomo )
# Github: https://github.com/kelvinBen/AppInfoScanner
# Gitee: https://gitee.com/kelvin_ben/AppInfoScanner
import io
import json
import unittest
from unittest import mock

from tests import load_runtime_config
load_runtime_config()
from libs.core import mcp_server


class TestMcpProtocol(unittest.TestCase):
    # 13-3 第二批: stdio JSON-RPC 协议
    def test_initialize(self):
        resp = mcp_server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        self.assertEqual(resp["id"], 1)
        self.assertEqual(resp["result"]["serverInfo"]["name"], "appinfoscanner")
        self.assertIn("tools", resp["result"]["capabilities"])

    def test_tools_list(self):
        resp = mcp_server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        names = [t["name"] for t in resp["result"]["tools"]]
        self.assertEqual(names, ["scan_app", "scan_web"])
        self.assertEqual(resp["result"]["tools"][0]["inputSchema"]["required"], ["target"])

    def test_notification_no_response(self):
        self.assertIsNone(mcp_server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}))

    def test_unknown_method_error(self):
        resp = mcp_server.handle({"jsonrpc": "2.0", "id": 3, "method": "nope"})
        self.assertEqual(resp["error"]["code"], -32601)

    def test_serve_loop(self):
        reqs = "\n".join([
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
            "not-json",
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        ]) + "\n"
        out = io.StringIO()
        mcp_server.serve(stdin=io.StringIO(reqs), stdout=out)
        lines = [l for l in out.getvalue().splitlines() if l.strip()]
        self.assertEqual(len(lines), 1)   # 通知与坏行不产生响应
        self.assertEqual(json.loads(lines[0])["id"], 1)


class TestMcpToolCall(unittest.TestCase):
    def _fake_proc(self, stdout="", stderr="", returncode=0):
        proc = mock.MagicMock()
        proc.stdout, proc.stderr, proc.returncode = stdout, stderr, returncode
        return proc

    def test_scan_app_parses_stdout_json(self):
        payload = {"meta": {"sample": "x.apk"}, "urls": []}
        with mock.patch.object(mcp_server.subprocess, "run",
                               return_value=self._fake_proc(stdout=json.dumps(payload) + "\n")) as run:
            result = mcp_server.call_tool("scan_app", {"target": "/tmp/x.apk"})
        self.assertNotIn("isError", result)
        self.assertEqual(json.loads(result["content"][0]["text"])["meta"]["sample"], "x.apk")
        cmd = run.call_args[0][0]
        self.assertIn("--agent", cmd)
        self.assertIn("json-only", cmd)
        self.assertIn("/tmp/x.apk", cmd)

    def test_missing_target(self):
        result = mcp_server.call_tool("scan_app", {})
        self.assertTrue(result["isError"])

    def test_nonzero_exit_reports_tail(self):
        with mock.patch.object(mcp_server.subprocess, "run",
                               return_value=self._fake_proc(stdout="", stderr="boom\ntrace", returncode=2)):
            result = mcp_server.call_tool("scan_app", {"target": "/tmp/x.apk"})
        self.assertTrue(result["isError"])
        self.assertIn("exit 2", result["content"][0]["text"])


if __name__ == "__main__":
    unittest.main()
