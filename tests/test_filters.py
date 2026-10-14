#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen (微信/WeChat: bromomo )
# Github: https://github.com/kelvinBen/AppInfoScanner
# Gitee: https://gitee.com/kelvin_ben/AppInfoScanner
import io
import os
import re
import contextlib
import tempfile
import threading
import unittest
from queue import Queue

from tests import load_runtime_config
load_runtime_config()
import libs.core as cores
from libs.core.parses import ParsesThreads
from libs.task.base_task import BaseTask


def scan_content(content, types="Android"):
    tmp = tempfile.mkdtemp()
    path = os.path.join(tmp, "config.js")
    with open(path, "w") as f:
        f.write(content)
    q = Queue(); q.put(path)
    pt = ParsesThreads(1, "t", q, {}, types)
    pt.threadLock = threading.Lock()
    with contextlib.redirect_stdout(io.StringIO()):
        pt.__regular_parse__()
    return list(pt.result_list)


class TestExtractionRules(unittest.TestCase):
    def extract(self, s):
        out = []
        for pattern in [re.compile(p) for p in cores.config.filter_strs]:
            m = pattern.findall(s)
            if m:
                self.assertNotIsInstance(m[0], tuple, "多捕获组会破坏管线")
                out.append(m[0])
        return out

    def test_protocols_and_ips(self):
        cases = {
            "https://api.target.cn/v1": ["https://api.target.cn/v1"],
            "redis://10.0.0.2:6379": ["redis://10.0.0.2:6379", "10.0.0.2"],
            "jdbc:oracle:thin:@//dbz:1521/orcl": ["jdbc:oracle:thin:@//dbz:1521/orcl"],
            "10.20.30.40:8080": ["10.20.30.40:8080"],  # 独立IP规则带端口捕获
            "2001:db8::99": ["2001:db8::99"],
            "[fe80::1]:5353": ["fe80::1"],
        }
        for value, expect in cases.items():
            got = self.extract(value)
            for item in expect:
                self.assertIn(item, got, value)

    def test_noise_rejected(self):
        for value in ("1.02.3.4", "2023.09.20.1", "10.20.300.40", "999.1.1.1",
                      "1.2.3", "1.2.3.4.5", "aa:bb:cc:dd:ee:ff", "context://weird"):
            self.assertEqual(self.extract(value), [], value)


class TestTwoTierFilter(unittest.TestCase):
    def setUp(self):
        cores._compiled = None
        tmp = tempfile.mkdtemp()
        self.pt = ParsesThreads(1, "t", Queue(), {}, "Android")
        self.pt.threadLock = threading.Lock()

    def keep(self, s):
        return self.pt.__filter__(s) == 1

    def test_domain_suffix_filtering(self):
        self.assertFalse(self.keep("https://www.w3.org/XML"))
        self.assertFalse(self.keep("bugly.qq.com"))
        self.assertFalse(self.keep("sdk.open.uc.cn"))
        self.assertTrue(self.keep("mail.qq.com"))          # 不连坐 qq.com
        self.assertTrue(self.keep("notw3.organization.cn"))  # 旧子串误杀修复

    def test_reserved_address_filtering(self):
        # 127.x 不再作噪声过滤(本地服务通讯情报, 由报告层归入 loopback 桶)
        for s in ("0.1.2.3", "255.255.255.255", "192.0.2.1", "::1", "::"):
            self.assertFalse(self.keep(s), s)
        self.assertTrue(self.keep("127.0.0.1:8080"))
        self.assertTrue(self.keep("127.0.0.5"))

    def test_private_kept(self):
        for s in ("10.0.0.1", "192.168.1.1", "169.254.169.254", "172.16.5.5"):
            self.assertTrue(self.keep(s), s)


class TestSensitiveDetection(unittest.TestCase):
    def test_credentials(self):
        import itertools

        def cyc(n):
            pool = itertools.cycle("a1B2c3D4e5F6g7H8i9J0kLmN5oP6qR7")
            return "".join(next(pool) for _ in range(n))

        sendgrid = "SG.%s.%s" % (cyc(22), cyc(43))  # 真实格式 22/43 位
        for content, marker in (
                ('aws: AKIAIOSFODNN7EXAMPLE', "Amazon_AWS"),
                ('t: LTAI4G7e8f9g0h1i2j3k4l', "Aliyun"),
                ('tok: ghp_1234567890abcdefghijklmnopqrstuvwxyz1234', "GitHub"),
                ('sg: %s' % sendgrid, "SendGrid"),
                ('-----BEGIN RSA PRIVATE KEY-----', "Private_Key"),
                ('d: mysql://root:secret123@db', "Password_In_URL")):
            results = scan_content(content)
            self.assertTrue(any(marker in r for r in results), content)

    def test_pii_with_checksum(self):
        results = scan_content('id: 11010519491231002X  tel: 13812345678')
        self.assertTrue(any("IDCard" in r for r in results))
        self.assertTrue(any("Phone_CN" in r for r in results))
        # 校验位错误被拒
        self.assertFalse(any("IDCard" in r for r in scan_content('id: 110105194912310021')))

    def test_pii_email_public_domain_filtered(self):
        self.assertFalse(any("apache.org" in r for r in scan_content('dev <user@apache.org>')))

    def test_clean_content_no_hits(self):
        self.assertEqual(scan_content('var x = compute(a, b); console.log("done");'), [])


if __name__ == "__main__":
    unittest.main()


class TestPIITestVectors(unittest.TestCase):
    def test_known_vector_filtered(self):
        results = scan_content('bc: 6272217099150286, tl: 15258229321')
        self.assertFalse(any("BankCard" in r for r in results))
        self.assertFalse(any("Phone_CN" in r for r in results))

    def test_real_phone_not_filtered(self):
        results = scan_content('tel: 13912345678')
        self.assertTrue(any("Phone_CN" in r for r in results))


class TestUSCCFormat(unittest.TestCase):
    def test_hex_rejected(self):
        # 纯 hex 串不是合法信用代码(首位 7 对应工商但次位 0 不在合法集)
        self.assertFalse(scan_content('uscc: 704313664479786E81')
                         and any("USCC" in r for r in scan_content('uscc: 704313664479786E81')))


class TestPIIStandalone(unittest.TestCase):
    # 12-5: 数字/证件类完全匹配——内嵌于 hex/base64 blob 的片段整类消灭
    BLOB = ("b259d2d6e627a768c94be36164c2d9fc79d97aab9253140e5bf17751197731d6f7540d2509"
            "e7b9ffee0a70a6e26d56e92d2edd7f85aba85600b69089f35f6bdbf3c298e05842535d9f06"
            "4e6b0391cb7d306e0a2d20c4dfb4e7b49a9640bdea26c10ad69c3f05007ce2513cee44cfe0"
            "1998e62b6c3637d3fc0391079b26ee36d5")

    def test_hex_blob_embeds_nothing(self):
        results = scan_content(self.BLOB)
        for name in ("Phone_CN", "BankCard_CN", "IDCard_CN_18", "USCC_CN"):
            self.assertFalse(any("[%s]" % name in r for r in results), name)

    def test_standalone_phone_still_hits(self):
        self.assertTrue(any("Phone_CN" in r for r in scan_content("tel: 13912345678,")))

    def test_vector_17751197731_dropped(self):
        self.assertFalse(any("Phone_CN" in r for r in scan_content("id: 17751197731,")))


class TestBankCardLuhn(unittest.TestCase):
    # 12-5: 银行卡/信用卡合桶 + Luhn 后验
    def test_unionpay_valid(self):
        self.assertTrue(any("BankCard_CN" in r for r in scan_content("卡号: 6212345678901232")))

    def test_brand_prefixes(self):
        for pan in ("4111111111111111", "5500005555555559", "378282246310005", "3530111333300000"):
            self.assertTrue(any("BankCard_CN" in r for r in scan_content("pan: " + pan)), pan)

    def test_luhn_fail_rejected(self):
        self.assertFalse(any("BankCard_CN" in r for r in scan_content("pan: 4111111111111112")))

    def test_embedded_card_rejected(self):
        self.assertFalse(any("BankCard_CN" in r for r in scan_content("x6212345678901232x")))


class TestNewDocumentRules(unittest.TestCase):
    # 12-5: 港澳通行证(裸字母+锚定)与驾驶证(仅锚定)
    def test_permit_bare_letter_form(self):
        self.assertTrue(any("HK_Macau_Permit" in r for r in scan_content("code C12345678 end")))

    def test_permit_anchored_9digit(self):
        self.assertTrue(any("HK_Macau_Permit" in r for r in scan_content("港澳通行证：123456789")))

    def test_permit_c9_rejected(self):
        self.assertFalse(any("HK_Macau_Permit" in r for r in scan_content("code C123456789 end")))

    def test_driving_license_anchored(self):
        self.assertTrue(any("Driving_License" in r for r in scan_content("驾驶证号:330227199303025415")))

    def test_driving_license_archive_no(self):
        self.assertTrue(any("Driving_License" in r for r in scan_content("档案编号: 330224123456")))

    def test_driving_license_bare_rejected(self):
        self.assertFalse(any("Driving_License" in r for r in scan_content("no 330224123456 here")))


class TestEmailTLD(unittest.TestCase):
    # 12-5: Email 顶级域白名单
    def test_common_tld_hits(self):
        self.assertTrue(any("Email" in r for r in scan_content("mail: admin@mycompany.cn")))

    def test_png_template_rejected(self):
        self.assertFalse(any("Email" in r for r in scan_content("img: %s@2x.png")))

    def test_new_gtld_hits(self):
        self.assertTrue(any("Email" in r for r in scan_content("dev mail: ops@team.dev")))


class TestProgressTty(unittest.TestCase):
    # 12-7: 非 tty 降级为按块打印, tty 保持 \r 单行刷新
    def _reset(self):
        import libs.core as cores
        cores._progress_is_tty = None
        cores._progress_tick = 0
        cores._progress_last = ""

    def test_non_tty_block_printing(self):
        import io as _io
        import contextlib
        import libs.core as cores
        self._reset()
        buf = _io.StringIO()   # StringIO 无 isatty -> 非 tty 分支
        with contextlib.redirect_stdout(buf):
            for i in range(120):
                cores.progress("scan %d" % i)
        lines = [l for l in buf.getvalue().splitlines() if l.strip()]
        self.assertEqual(len(lines), 3)  # 首条 + 50/100 两条
        self.assertNotIn("\r", lines[0])

    def test_tty_single_line_refresh(self):
        import contextlib
        import libs.core as cores
        self._reset()

        class FakeTty:
            def write(self, s):
                self.chunks.append(s)

            def flush(self):
                pass

            @staticmethod
            def isatty():
                return True

        fake = FakeTty()
        fake.chunks = []
        with contextlib.redirect_stdout(fake):
            cores.progress("aaa")
            cores.progress("b")
        self.assertTrue(all(c.startswith("\r") for c in fake.chunks))


class TestSampleName(unittest.TestCase):
    # 12-8: 目录名含点不剥扩展名, 文件名照常剥
    def test_directory_name_kept(self):
        import tempfile, os
        import libs.core as cores
        d = os.path.join(tempfile.mkdtemp(), "com.nbbank_dex")
        os.makedirs(d, exist_ok=True)
        self.assertEqual(cores.__sanitize_sample_name__(d), "com.nbbank_dex")

    def test_file_extension_stripped(self):
        import libs.core as cores
        self.assertEqual(cores.__sanitize_sample_name__("/tmp/app.apk"), "app")

    def test_url_input(self):
        import libs.core as cores
        self.assertEqual(cores.__sanitize_sample_name__("https://x.cn/a/app.apk?t=1"), "app")


class TestSuspectedSecretKey(unittest.TestCase):
    # 12-10: SecretKeySpec 紧邻 16/24/32 字节可打印常量 -> 疑似对称密钥(低置信)
    def test_smali_const_string_key(self):
        content = ('invoke-static {}, Ljavax/crypto/spec/SecretKeySpec;-><init>'
                   'const-string v0, "0123456789abcdef"')
        self.assertTrue(any("Suspected_SecretKey" in r for r in scan_content(content)))

    def test_java_literal_key(self):
        content = 'new SecretKeySpec("0123456789abcdef01234567".getBytes(), "AES")'
        results = scan_content(content)
        self.assertTrue(any("Suspected_SecretKey]-->: 0123456789abcdef01234567" in r for r in results))

    def test_odd_length_rejected(self):
        content = 'SecretKeySpec "0123456789abcdef0" x'   # 17 位
        self.assertFalse(any("Suspected_SecretKey" in r for r in scan_content(content)))

    def test_no_secretkeyspec_no_hit(self):
        content = 'const-string v0, "0123456789abcdef"'
        self.assertFalse(any("Suspected_SecretKey" in r for r in scan_content(content)))


class TestPIIDepthDefense(unittest.TestCase):
    # 12-13: 路径降权 config 化 + 邻域启发式
    def scan_at(self, rel_dir, content):
        import tempfile, os
        from queue import Queue
        from threading import Lock
        from libs.core.parses import ParsesThreads
        tmp = tempfile.mkdtemp()
        d = os.path.join(tmp, rel_dir)
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, "x.js")
        open(path, "w").write(content)
        q = Queue(); q.put(path)
        pt = ParsesThreads(1, "t", q, {}, "Android")
        pt.threadLock = Lock()
        import contextlib, io as _io
        with contextlib.redirect_stdout(_io.StringIO()):
            pt.__regular_parse__()
        return list(pt.result_list)

    def test_path_downweight_configured(self):
        results = self.scan_at("smali/org/bouncycastle", "tel: 13912345678,")
        self.assertTrue(any("13912345678 (疑似测试向量, 来源: 测试数据路径)" in r for r in results))

    def test_plain_path_not_downweighted(self):
        results = self.scan_at("assets/js", "tel: 13912345678,")
        self.assertTrue(any("Phone_CN" in r for r in results))
        self.assertFalse(any("疑似测试向量" in r for r in results))

    def test_neighborhood_hex_downweight(self):
        # 命中值附近存在长 hex(测试数据成组特征) -> 上下文降权
        content = "phone 13912345678 hash 5bdcc146bf60754e6a042426089575c7f1"
        results = self.scan_at("assets/js", content)
        self.assertTrue(any("(疑似测试向量, 来源: 上下文特征)" in r for r in results))

    def test_neighborhood_negative(self):
        results = self.scan_at("assets/js", "tel: 13912345678,")
        self.assertFalse(any("疑似测试向量" in r for r in results))


class TestFieldFeedbackBatch2(unittest.TestCase):
    # 2026-10-14 实战反馈第二批: 五项修复的回归
    def test_tool_version_from_program(self):
        from libs.core import report
        from libs.core import updater
        meta = report.build_report_meta("t.apk", "Android")
        self.assertEqual(meta["tool_version"], "v" + updater.APP_VERSION)
        self.assertNotEqual(meta["tool_version"], "v1.0.10")

    def test_authorization_no_crossline(self):
        # \s 含换行曾把行尾 Basic 与下一行拼成假凭据
        content = "header Basic\nnext_line_token_abcdef123456"
        self.assertFalse(any("Authorization_Header" in r for r in scan_content(content)))
        self.assertTrue(any("Authorization_Header" in r
                            for r in scan_content("header Basic abcdef1234567890123")))

    def test_permit_lowercase_hex_rejected(self):
        # ARM 立即数 c80000000 是小写 hex, 不再当通行证
        self.assertFalse(any("HK_Macau_Permit" in r for r in scan_content("const c80000000 c73222735")))
        self.assertTrue(any("HK_Macau_Permit" in r for r in scan_content("code C12345678 end")))

    def test_uscc_allhex_rejected(self):
        # 全 hex 18 位串(...E71)即使过校验位也拒绝
        self.assertFalse(any("USCC" in r for r in scan_content("uscc: 704313664479786E81")))

    def test_pii_annotation_dedup(self):
        # 同值"带标注/不带标注"归并为一个键
        from libs.core import report
        data = report.classify_results({
            "/a.js": ["[Phone_CN]-->: 13912345678"],
            "/b.js": ["[Phone_CN]-->: 13912345678 (疑似测试向量, 来源: 上下文特征)"],
        }, set(), set(cores.config.filter_pii_map))
        keys = list(data["pii"].keys())
        self.assertEqual(len(keys), 1, keys)
        self.assertEqual(len(data["pii"][keys[0]]), 2)   # 两个文件都归到该键


class TestScopeFileLoading(unittest.TestCase):
    def make_task(self, scope_arg):
        return BaseTask("Android", "/tmp/x.apk", scope=scope_arg)

    def test_scope_file_loaded(self):
        fd, path = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(fd, "w") as f:
            f.write("Example.com\n# comment\napi.foo.cn\n")
        task = self.make_task(path)
        self.assertEqual(task.scope_domains, {"example.com", "api.foo.cn"})
        os.unlink(path)

    def test_scope_missing_file_denies_all(self):
        # 清单读失败必须 deny-all(空集合), 不能回退成不限量嗅探
        task = self.make_task("/tmp/__no_such_scope__.txt")
        self.assertEqual(task.scope_domains, set())

    def test_scope_empty_file_denies_all(self):
        fd, path = tempfile.mkstemp(suffix=".txt")
        os.fdopen(fd, "w").close()
        task = self.make_task(path)
        self.assertEqual(task.scope_domains, set())
        os.unlink(path)
