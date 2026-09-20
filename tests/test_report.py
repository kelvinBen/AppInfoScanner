#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen (微信/WeChat: bromomo )
# Github: https://github.com/kelvinBen/AppInfoScanner
# Gitee: https://gitee.com/kelvin_ben/AppInfoScanner
import unittest

from libs.core.report import (classify_results, extract_host, extract_port,
                              is_private_ip4, sniff_allowed)


class TestClassifyResults(unittest.TestCase):
    def setUp(self):
        self.rd = {
            "/a/Mos": {"https://ms.test.cqcbank.com:9070/gateway", "172.16.30.36",
                       "2001:db8::99", "[Amazon_AWS_AccessKeyID]-->:AKIAIOSFODNN7EXAMPLE",
                       "[Phone_CN]-->: 13812345678", "https://%@:%hu/x"},
            "/a/Mos2": {"https://ms.test.cqcbank.com:9070/gw2", "172.16.30.36",
                        "8.8.8.8", "jdbc:mysql://intranet-db:3306/x"},
        }
        self.data = classify_results(
            self.rd, {"Amazon_AWS_AccessKeyID"}, {"Phone_CN"})

    def test_url_classification(self):
        self.assertEqual(set(self.data["urls"]), {
            "https://ms.test.cqcbank.com:9070/gateway",
            "https://ms.test.cqcbank.com:9070/gw2", "https://%@:%hu/x",
            "jdbc:mysql://intranet-db:3306/x"})

    def test_host_aggregation_across_files(self):
        self.assertEqual(self.data["hosts"]["ms.test.cqcbank.com"], ["/a/Mos", "/a/Mos2"])
        self.assertEqual(self.data["hosts"]["intranet-db"], ["/a/Mos2"])

    def test_ip_classification(self):
        self.assertEqual(self.data["ip_private"], {"172.16.30.36": ["/a/Mos", "/a/Mos2"]})
        self.assertEqual(self.data["ip_public"], {"8.8.8.8": ["/a/Mos2"]})
        self.assertEqual(self.data["ip_v6"], {"2001:db8::99": ["/a/Mos"]})

    def test_sensitive_split(self):
        self.assertEqual(list(self.data["credentials"]),
                         ["Amazon_AWS_AccessKeyID|AKIAIOSFODNN7EXAMPLE"])
        self.assertEqual(list(self.data["pii"]), ["Phone_CN|13812345678"])


class TestHostExtraction(unittest.TestCase):
    def test_variants(self):
        self.assertEqual(extract_host("https://a.b:8443/x"), "a.b")
        self.assertEqual(extract_host("jdbc:oracle:thin:@//dbz:1521/orcl"), "dbz")
        self.assertEqual(extract_host("https://user:pw@h.cn/x"), "h.cn")


class TestPrivateIP(unittest.TestCase):
    def test_private(self):
        for ip in ("10.0.0.1", "192.168.1.1", "172.16.5.5", "169.254.169.254"):
            self.assertTrue(is_private_ip4(ip), ip)

    def test_public(self):
        for ip in ("8.8.8.8", "172.32.1.1", "100.100.100.200"):
            self.assertFalse(is_private_ip4(ip), ip)


class TestExtractPort(unittest.TestCase):
    def test_port_variants(self):
        self.assertEqual(extract_port("http://127.0.0.1:8080/api"), "8080")
        self.assertEqual(extract_port("127.0.0.1:6379"), "6379")
        self.assertEqual(extract_port("http://localhost:3000/dev"), "3000")
        self.assertEqual(extract_port("127.0.0.1"), None)
        self.assertEqual(extract_port("http://[::1]:8080/x"), None)


class TestLoopbackClassification(unittest.TestCase):
    def test_loopback_bucket(self):
        rd = {"/f": {"http://127.0.0.1:8080/api", "127.0.0.1:6379",
                     "http://localhost:3000/dev", "10.0.0.1:6379", "https://api.x.cn/v1"}}
        data = classify_results(rd, set(), set())
        self.assertEqual(set(data["loopback"]), {
            "http://127.0.0.1:8080/api", "127.0.0.1:6379", "http://localhost:3000/dev"})
        # 端口保留的私网地址 + 常规 URL 不受影响
        self.assertEqual(list(data["ip_private"]), ["10.0.0.1:6379"])
        self.assertEqual(list(data["urls"]), ["https://api.x.cn/v1"])


class TestSniffAllowed(unittest.TestCase):
    def test_internal_not_sniffed(self):
        for host in ("10.1.2.3", "192.168.0.1", "172.31.255.1", "127.0.0.1", "localhost",
                     "169.254.169.254", "0.0.0.1", "::1", "fe80::1", "fd00::1",
                     "2001:db8::1"):
            self.assertFalse(sniff_allowed(host), host)

    def test_domain_and_public_sniffed(self):
        for host in ("api.target.cn", "8.8.8.8", "1.2.3.4", "localhost.bad.example"):
            self.assertTrue(sniff_allowed(host), host)


if __name__ == "__main__":
    unittest.main()
