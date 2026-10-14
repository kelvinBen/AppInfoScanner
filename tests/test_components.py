#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen (微信/WeChat: bromomo )
# Github: https://github.com/kelvinBen/AppInfoScanner
# Gitee: https://gitee.com/kelvin_ben/AppInfoScanner
import json
import os
from unittest import mock
import tempfile
import unittest

from tests import load_runtime_config
load_runtime_config()
from libs.task.android_task import AndroidTask
from libs.core import report


def write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)


class TestVersionValidation(unittest.TestCase):
    # 12-2: OID 伪版本一律拒绝, 合理版本放行
    def test_oid_rejected(self):
        for oid in ("1.2.840.113549.1.9.16.3.8", "2.5.29.32.0", "1.3.101",
                    "1.3.6.1.4.1", "2.5.4.3"):
            self.assertFalse(AndroidTask.__version_valid__(oid), oid)

    def test_valid_versions(self):
        for v in ("1.69", "1.46", "1.2.83", "2.17.0", "3.5.2", "20.0.0"):
            self.assertTrue(AndroidTask.__version_valid__(v), v)

    def test_unreasonable_rejected(self):
        for v in ("21.0.0", "1.2.3.4.5", "1.2.9999", "1.x.2", ""):
            self.assertFalse(AndroidTask.__version_valid__(v), v)


class TestHostAttribution(unittest.TestCase):
    # 12-9: 组件包路径之前的包段命中宿主映射, 多命中取最长
    def test_networkbench_prefix(self):
        p = "/tmp/out/smali/com/networkbench/lbs/org/bouncycastle/Version.smali"
        self.assertEqual(AndroidTask.__match_component_host__(p, "org/bouncycastle"),
                         "听云SDK(networkbench)")

    def test_direct_dependency(self):
        p = "/tmp/out/smali/org/bouncycastle/Version.smali"
        self.assertEqual(AndroidTask.__match_component_host__(p, "org/bouncycastle"),
                         "应用本体")

    def test_longest_prefix_wins(self):
        p = "/tmp/out/smali/com/tencent/mm/org/bouncycastle/X.smali"
        self.assertEqual(AndroidTask.__match_component_host__(p, "org/bouncycastle"),
                         "微信SDK(WeChat)")


class TestComponentAggregation(unittest.TestCase):
    # 12-3/12-9: 同组件多副本按宿主归组去重, 无版本标注人工核
    def build(self):
        task = AndroidTask("/tmp/x.apk", "")
        tmp = tempfile.mkdtemp()
        # BC@听云 v1.69(同宿主同版本两份 → 去重) + 文件内 OID 常量干扰
        write(os.path.join(tmp, "smali/com/networkbench/lbs/org/bouncycastle/Version.smali"),
              '"1.2.840.113549.1.9.16.3.8"\nconst-string v0, "bouncycastle 1.69"')
        write(os.path.join(tmp, "smali/com/networkbench/lbs/org/bouncycastle/Other.smali"),
              'const-string v0, "bouncycastle 1.69"')
        # BC@银联 与 BC@应用本体 同为 v1.46
        write(os.path.join(tmp, "smali/org/bouncycastle/Core.smali"),
              'const-string v0, "bouncycastle 1.46"')
        write(os.path.join(tmp, "smali/com/unionpay/org/bouncycastle/Core.smali"),
              'const-string v0, "bouncycastle 1.46"')
        # fastjson@应用本体 v1.2.83(安全) + fastjson@听云 仅 OID(人工核)
        write(os.path.join(tmp, "smali/com/alibaba/fastjson/JSON.smali"),
              'const-string v0, "VERSION"; const-string v1, "1.2.83"')
        write(os.path.join(tmp, "smali/com/networkbench/com/alibaba/fastjson/Fake.smali"),
              'const-string v0, "1.3.101"')
        task.__get_scanner_file__(tmp, ["smali"])
        task.__render_components__()
        return task

    def test_dedup_single_line_per_component(self):
        task = self.build()
        bc_lines = [l for l in task.comp_list if "bouncycastle" in l]
        fj_lines = [l for l in task.comp_list if "fastjson" in l]
        self.assertEqual(len(bc_lines), 1, bc_lines)   # 原 18 行重复 → 1 行
        self.assertEqual(len(fj_lines), 1, fj_lines)

    def test_host_and_version_in_line(self):
        line = [l for l in self.build().comp_list if "bouncycastle" in l][0]
        for expect in ("听云SDK(networkbench)", "银联SDK(UnionPay)", "应用本体",
                       "1.69", "1.46", "CVE-2023-33201"):
            self.assertIn(expect, line, expect)

    def test_detail_rows(self):
        detail = self.build().comp_detail
        bc = [d for d in detail if d["component"] == "org.bouncycastle"]
        fj = [d for d in detail if d["component"] == "com.alibaba.fastjson"]
        self.assertEqual(len(bc), 3)   # 听云/银联/应用本体 三个宿主各一行
        hosts = {d["host"] for d in bc}
        self.assertEqual(hosts, {"听云SDK(networkbench)", "银联SDK(UnionPay)", "应用本体"})
        fj_hosts = {d["host"]: d for d in fj}
        self.assertEqual(fj_hosts["应用本体"]["version"], "1.2.83")
        self.assertEqual(fj_hosts["应用本体"]["verdict"], "安全")
        # 12-3: 有版本规则但未提取到 → 人工核口径, 不按风险口径显示
        self.assertEqual(fj_hosts["听云SDK(networkbench)"]["verdict"], "人工核")
        self.assertEqual(fj_hosts["听云SDK(networkbench)"]["version"], "")


class TestComponentReport(unittest.TestCase):
    # 12-9: xlsx 四列结构 + json 明细字段
    def test_xlsx_json_carry_detail(self):
        tmp = tempfile.mkdtemp()
        detail = [{"component": "org.bouncycastle", "desc": "加密库", "host": "听云SDK(networkbench)",
                   "version": "1.69", "verdict": "CVE-2023-33201 (LDAP injection)"}]
        data = report.classify_results({}, set(), set())
        meta = report.build_report_meta("t.apk", "Android")
        extra = {"components": ["line"], "components_detail": detail, "permissions": [],
                 "shell": [], "sniffer": [], "details": {}}
        xp = os.path.join(tmp, "r.xlsx")
        jp = os.path.join(tmp, "r.json")
        report.write_xlsx_report(xp, meta, data, extra)
        report.write_json_report(jp, meta, data, extra)
        from openpyxl import load_workbook
        ws = load_workbook(xp)["Components"]
        header = [c.value for c in ws[1]]
        self.assertEqual(header, ["Component", "Host SDK", "Version", "Verdict"])
        row2 = [c.value for c in ws[2]]
        self.assertIn("听云SDK(networkbench)", row2)
        with open(jp) as f:
            payload = json.load(f)
        self.assertEqual(payload["components_detail"], detail)


class TestDexDirectStrings(unittest.TestCase):
    # 12-12: dex 二进制字符串直提(分块+入队+组件包名标记匹配)
    def make_dex(self, tmp, blob):
        import hashlib
        path = os.path.join(tmp, "fake.dex")
        with open(path, "wb") as f:
            f.write(blob)
        return path

    def test_extract_queue_and_components(self):
        task = AndroidTask("/tmp/x.apk", "")
        tmp = tempfile.mkdtemp()
        blob = (b"https://api.foo.cn/v1/login\x00" * 50 +
                b"Lorg/bouncycastle/crypto/Engine;\x00" +
                b"AKIAIOSFODNN7EXAMPLE\x00")
        dex = self.make_dex(tmp, blob)
        out = os.path.join(tmp, "out")
        os.makedirs(out)
        task.__strings_from_dex__(dex, out)
        queued = []
        while not task.file_queue.empty():
            queued.append(task.file_queue.get())
        self.assertGreaterEqual(len(queued), 1)
        text = "".join(open(q).read() for q in queued)
        self.assertIn("https://api.foo.cn/v1/login", text)
        self.assertIn("AKIAIOSFODNN7EXAMPLE", text)
        # 组件包名标记命中(dex 字符串池含类型描述符), 标注直提模式
        self.assertTrue(any("org.bouncycastle" in c and "直提模式" in c for c in task.comp_list))

    def test_chunk_splitting(self):
        task = AndroidTask("/tmp/x.apk", "")
        tmp = tempfile.mkdtemp()
        with mock.patch.object(AndroidTask, "_STRINGS_CHUNK_LIMIT", 256):
            dex = self.make_dex(tmp, b"abcdefgh1234" * 100)  # 12字符/条 * 100
            out = os.path.join(tmp, "out")
            os.makedirs(out)
            task.__strings_from_dex__(dex, out)
        files = [f for f in os.listdir(out) if f.startswith("strings_")]
        self.assertGreater(len(files), 1)  # 超限分块
        queued = []
        while not task.file_queue.empty():
            queued.append(task.file_queue.get())
        self.assertEqual(len(queued), len(files))

    def test_decode_file_dex_default_direct(self):
        # 配置开启直提时: __decode_file__ 不再调 baksmali
        # (默认值已回退 False——直提 URL 覆盖回归未修, 见开发计划 P-5)
        import libs.core as cores
        task = AndroidTask("/tmp/x.apk", "")
        tmp = tempfile.mkdtemp()
        dex = self.make_dex(tmp, b"https://x.cn/a\x00" * 10)
        # 开启直提 + 输出目录重定向临时目录, 防止产物落进仓库根
        with mock.patch.object(cores.config, "dex_strings_direct", True), \
                mock.patch.object(cores, "output_path", tmp):
            task.__decode_dex__ = lambda *a, **k: self.fail("baksmali 不应被调用")
            task.__decode_file__(dex)
        self.assertFalse(task.file_queue.empty())


if __name__ == "__main__":
    unittest.main()
