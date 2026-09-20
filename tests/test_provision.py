#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen (微信/WeChat: bromomo )
# Github: https://github.com/kelvinBen/AppInfoScanner
# Gitee: https://gitee.com/kelvin_ben/AppInfoScanner
import shutil
import unittest
from unittest import mock

from libs.core import provision


class TestDetectPackageManager(unittest.TestCase):
    def test_brew_preferred(self):
        with mock.patch.object(shutil, "which", side_effect=lambda name: "/bin/brew" if name == "brew" else None):
            self.assertEqual(provision.detect_pkg_manager(), "brew")

    def test_apt_mapping(self):
        with mock.patch.object(shutil, "which", side_effect=lambda name: "/usr/bin/apt-get" if name == "apt-get" else None):
            self.assertEqual(provision.detect_pkg_manager(), "apt")

    def test_none(self):
        with mock.patch.object(shutil, "which", return_value=None):
            self.assertIsNone(provision.detect_pkg_manager())


class TestEnsureShortCircuit(unittest.TestCase):
    """已安装场景必须零副作用直接返回，绝不触发安装。"""

    def test_java_present_no_install(self):
        with mock.patch.object(shutil, "which", return_value="/usr/bin/java"), \
                mock.patch.object(provision, "_run_install") as run:
            self.assertTrue(provision.ensure_java())
            run.assert_not_called()

    def test_adb_present_returns_path(self):
        with mock.patch.object(shutil, "which", return_value="/opt/adb"), \
                mock.patch.object(provision, "_run_install") as run:
            self.assertEqual(provision.ensure_adb(), "/opt/adb")
            run.assert_not_called()

    def test_frida_present_no_pip(self):
        with mock.patch.object(shutil, "which", return_value="/usr/local/bin/frida"), \
                mock.patch.object(provision, "subprocess") as sp:
            self.assertTrue(provision.ensure_frida())
            sp.call.assert_not_called()

    def test_frida_missing_pip_fail_returns_false(self):
        import contextlib, io
        with mock.patch.object(shutil, "which", return_value=None), \
                mock.patch.object(provision.subprocess, "call", return_value=1), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(provision.ensure_frida())

    def test_frida_only_cli_dexdump_missing_reinstalls(self):
        """只装了 frida 而 frida-dexdump 缺失时不得短路，必须走安装。"""
        import contextlib, io
        which_calls = {"frida": "/bin/frida", "frida-dexdump": None}
        with mock.patch.object(shutil, "which", side_effect=lambda n: which_calls.get(n)), \
                mock.patch.object(provision.subprocess, "call", return_value=1), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(provision.ensure_frida())


class TestMissingWithoutManager(unittest.TestCase):
    """无包管理器时返回 False/None 且给出指引，不抛异常。"""

    def test_java_missing_no_manager(self):
        import contextlib
        import io
        with mock.patch.object(shutil, "which", return_value=None), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(provision.ensure_java())

    def test_adb_missing_no_manager(self):
        import contextlib
        import io
        with mock.patch.object(shutil, "which", return_value=None), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertIsNone(provision.ensure_adb())


if __name__ == "__main__":
    unittest.main()


class TestFridaVersionConsistency(unittest.TestCase):
    def test_server_matches(self):
        import tempfile, os
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "server")
            open(p, "wb").write(b"....frida-server 17.18.0 stuff....17.18.0...")
            self.assertTrue(provision.server_matches(p, "17.18.0"))
            self.assertFalse(provision.server_matches(p, "16.5.9"))

    def test_server_version_guess_filters_noise(self):
        import tempfile, os
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "server")
            open(p, "wb").write(b"17.18.0 " * 3 + b"16.840.1 " * 114 + b"10.200046.1")
            with mock.patch.object(provision, "frida_core_version", return_value="17.18.0"):
                self.assertEqual(provision.server_version_guess(p), "17.18.0")

    def test_ensure_server_uses_matching_bundled(self):
        import tempfile, os, contextlib, io
        with tempfile.TemporaryDirectory() as tmp:
            bundled = os.path.join(tmp, "tools", "unpacker", "hexl-server-arm64")
            os.makedirs(os.path.dirname(bundled), exist_ok=True)
            open(bundled, "wb").write(b"x 17.18.0 y")
            import libs.core as cores
            with mock.patch.object(provision, "frida_core_version", return_value="17.18.0"), \
                    mock.patch.object(cores, "default_out_root", tmp, create=True), \
                    mock.patch.object(provision.urllib.request, "urlopen") as urlopen, \
                    contextlib.redirect_stdout(io.StringIO()):
                path = provision.ensure_frida_server("arm64-v8a")
            self.assertEqual(path, bundled)
            urlopen.assert_not_called()  # 匹配自带版本时绝不联网

    def test_ensure_server_downloads_on_mismatch(self):
        import tempfile, os, contextlib, io, lzma
        payload = b"frida-server 16.5.9 binary"
        with tempfile.TemporaryDirectory() as tmp:
            bundled = os.path.join(tmp, "tools", "unpacker", "hexl-server-arm64")
            os.makedirs(os.path.dirname(bundled), exist_ok=True)
            open(bundled, "wb").write(b"old 15.0.0")  # 自带版本不匹配
            import libs.core as cores
            fake_resp = mock.MagicMock()
            fake_resp.__enter__.return_value.read.return_value = lzma.compress(payload)
            with mock.patch.object(provision, "frida_core_version", return_value="16.5.9"), \
                    mock.patch.object(cores, "default_out_root", tmp, create=True), \
                    mock.patch.object(provision.urllib.request, "urlopen", return_value=fake_resp) as urlopen, \
                    contextlib.redirect_stdout(io.StringIO()):
                path = provision.ensure_frida_server("arm64-v8a")
            self.assertTrue(path.endswith("frida-server-16.5.9-android-arm64"))
            self.assertEqual(open(path, "rb").read(), payload)
            urlopen.assert_called_once()
            self.assertIn("releases/download/16.5.9", urlopen.call_args[0][0])

    def test_ensure_server_unsupported_abi(self):
        import contextlib, io
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertIsNone(provision.ensure_frida_server("mips"))


class TestPinnedRequirements(unittest.TestCase):
    def test_parse_pins_from_requirements(self):
        import tempfile, os
        import libs.core as cores
        with tempfile.TemporaryDirectory() as tmp:
            req = os.path.join(tmp, "requirements.txt")
            open(req, "w").write("requests\nfrida==17.18.0\nfrida-tools==14.10.4\nfrida-dexdump==2.0.1\n")
            with mock.patch.object(cores, "script_root_dir", tmp, create=True):
                self.assertEqual(provision.pinned_frida_requirements(),
                                 ["frida==17.18.0", "frida-tools==14.10.4", "frida-dexdump==2.0.1"])

    def test_fallback_unpinned_when_missing(self):
        import tempfile, os
        import libs.core as cores
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(cores, "script_root_dir", tmp, create=True):
                self.assertEqual(provision.pinned_frida_requirements(),
                                 ["frida", "frida-tools", "frida-dexdump"])

    def test_ensure_frida_installs_pinned_versions(self):
        import contextlib, io
        with mock.patch.object(shutil, "which", return_value=None), \
                mock.patch.object(provision, "pinned_frida_requirements",
                                  return_value=["frida==17.18.0", "frida-tools==14.10.4",
                                                "frida-dexdump==2.0.1"]) as pins, \
                mock.patch.object(provision.subprocess, "call", return_value=1) as call, \
                contextlib.redirect_stdout(io.StringIO()):
            provision.ensure_frida()
        first_cmd = call.call_args_list[0][0][0]
        for pinned in ("frida==17.18.0", "frida-tools==14.10.4", "frida-dexdump==2.0.1"):
            self.assertIn(pinned, first_cmd, first_cmd)
        pins.assert_called_once()
