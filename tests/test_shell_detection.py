#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen (微信/WeChat: bromomo )
# Github: https://github.com/kelvinBen/AppInfoScanner
# Gitee: https://gitee.com/kelvin_ben/AppInfoScanner
import os
import tempfile
import unittest

from tests import load_runtime_config
load_runtime_config()
from libs.task.android_task import AndroidTask


def fake_apk(tmp, manifest, dirs=(), files=()):
    with open(os.path.join(tmp, "AndroidManifest.xml"), "w") as f:
        f.write(manifest)
    for d in dirs:
        os.makedirs(os.path.join(tmp, d), exist_ok=True)
        open(os.path.join(tmp, d, "A.smali"), "w").write("x")
    for name in files:
        path = os.path.join(tmp, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        open(path, "w").write("x")


class TestShellDetection(unittest.TestCase):
    def setUp(self):
        self.unpack_called = []

    def new_task(self):
        task = AndroidTask("/tmp/x.apk", "")
        task.__android_unpack__ = lambda: self.unpack_called.append(1)
        return task

    def manifest(self, app_cls, package="com.demo.app"):
        return ('<manifest package="%s"><application android:name="%s"/>'
                '</manifest>' % (package, app_cls))

    def test_normal_app_not_flagged(self):
        tmp = tempfile.mkdtemp()
        fake_apk(tmp, self.manifest("com.demo.App"), ["smali/com/demo/app"])
        task = self.new_task()
        task.__shell_test__(tmp)
        self.assertFalse(task.shell_flag)
        self.assertEqual(self.unpack_called, [])

    def test_class_gate_with_signature_confirm(self):
        tmp = tempfile.mkdtemp()
        fake_apk(tmp, self.manifest("com.stub.StubApp"),
                 ["smali/com/stub"], ["lib/arm64-v8a/libjiagu.so", "assets/.appkey"])
        task = self.new_task()
        task.__shell_test__(tmp)
        self.assertTrue(task.shell_flag)
        self.assertTrue(task.shell_confirmed)  # 签名已确认
        self.assertEqual(self.unpack_called, [])  # 不再自动脱壳
        self.assertTrue(any("360加固" in line for line in task.shell_report))

    def test_class_gate_without_signature(self):
        tmp = tempfile.mkdtemp()
        fake_apk(tmp, self.manifest("com.stub.StubApp"), ["smali/com/stub"])
        task = self.new_task()
        task.__shell_test__(tmp)
        self.assertTrue(task.shell_flag)
        self.assertEqual(self.unpack_called, [])

    def test_package_missing_gate(self):
        # 不换 application 类名的壳：包名缺失门控 + 跨厂商签名定位
        tmp = tempfile.mkdtemp()
        fake_apk(tmp, self.manifest("com.demo.App"),
                 ["smali/com/stub"], ["lib/arm64-v8a/libjiagu.so"])
        task = self.new_task()
        task.__shell_test__(tmp)
        self.assertTrue(task.shell_flag)
        self.assertEqual(self.unpack_called, [])  # 不再自动脱壳

    def test_package_missing_confirmed_no_suspected_line(self):
        # 12-4: 厂商签名确认后不再输出 Suspected 启发式行(消矛盾三连)
        tmp = tempfile.mkdtemp()
        fake_apk(tmp, self.manifest("com.demo.App"),
                 ["smali/com/stub"], ["lib/arm64-v8a/libjiagu.so"])
        task = self.new_task()
        task.__shell_test__(tmp)
        self.assertTrue(task.shell_confirmed)
        self.assertTrue(any("360加固" in l for l in task.shell_report))
        self.assertFalse(any("Suspected" in l for l in task.shell_report))

    def test_multidex_package_found(self):
        tmp = tempfile.mkdtemp()
        fake_apk(tmp, self.manifest("com.demo.App"),
                 ["smali/com/other", "smali_classes3/com/demo/app"])
        task = self.new_task()
        task.__shell_test__(tmp)
        self.assertFalse(task.shell_flag)

    def test_flutter_application_not_shell(self):
        tmp = tempfile.mkdtemp()
        fake_apk(tmp, self.manifest("io.flutter.app.FlutterApplication"),
                 ["smali/com/demo/app"])
        task = self.new_task()
        task.__shell_test__(tmp)
        self.assertFalse(task.shell_flag)


class TestShellGatePolicy(unittest.TestCase):
    # 门控契约: 仅"已确认壳且未处置"才中止; 处置过(prefer-dump/unpack成功或失败降级)
    # 与疑似未确认都放行扫描(base_task 的遗留闸门不该拦这些路径)
    def gated(self, shell_flag, shell_confirmed, handled):
        task = AndroidTask("/tmp/g.apk", "")
        task.shell_flag = shell_flag
        task.shell_confirmed = shell_confirmed
        task.__gate_shell_flag__(handled)
        return task

    def test_prefer_dump_clears_flag(self):
        task = self.gated(True, True, True)
        self.assertFalse(task.shell_flag)

    def test_unpack_failure_fallback_clears_flag(self):
        # unpack 失败降级静态扫描: handled=True, 同样必须放行
        task = self.gated(True, True, True)
        self.assertFalse(task.shell_flag)

    def test_unconfirmed_suspicion_clears_flag(self):
        # 包名缺失启发式命中但无厂商签名: 疑似不等于确认, 不中止
        task = self.gated(True, False, False)
        self.assertFalse(task.shell_flag)

    def test_confirmed_unhandled_still_blocks(self):
        # 唯一保留中止的路径: 已确认壳且未做任何处置
        task = self.gated(True, True, False)
        self.assertTrue(task.shell_flag)

    def test_no_shell_untouched(self):
        task = self.gated(False, False, False)
        self.assertFalse(task.shell_flag)
        task2 = self.gated(False, True, False)
        self.assertFalse(task2.shell_flag)


class TestPermissions(unittest.TestCase):
    def test_manifest_permissions_with_notes(self):
        tmp = tempfile.mkdtemp()
        manifest = ('<manifest package="com.d">'
                    '<uses-permission android:name="android.permission.CAMERA"/>'
                    '<uses-permission android:name="android.permission.ACCESS_BACKGROUND_LOCATION"/>'
                    '<uses-permission android:name="android.permission.WAKE_LOCK"/>'
                    '<application android:name=".App"/></manifest>')
        fake_apk(tmp, manifest, ["smali/com/d"])
        task = AndroidTask("/tmp/p.apk", "")
        task.__android_unpack__ = lambda: None
        task.__shell_test__(tmp)
        self.assertEqual(len(task.permissions), 2)  # WAKE_LOCK 非敏感被忽略
        self.assertTrue(any("精确定位" in p or "后台持续定位" in p for p in task.permissions))


if __name__ == "__main__":
    unittest.main()
