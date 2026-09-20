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
        self.assertEqual(self.unpack_called, [1])
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
        self.assertEqual(self.unpack_called, [1])

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
