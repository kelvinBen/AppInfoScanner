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
