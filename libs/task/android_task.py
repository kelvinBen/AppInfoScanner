#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen (微信/WeChat: bromomo )
# Github: https://github.com/kelvinBen/AppInfoScanner
# Gitee: https://gitee.com/kelvin_ben/AppInfoScanner
import os
import re
import shutil
import tempfile
import subprocess

import hashlib
import zipfile
from queue import Queue
import libs.core as cores
from libs.core import fix_magic
from libs.core import provision


class AndroidTask(object):

    def __init__(self, path, package, unpack=False, prefer_dump=None):
        self.path = path
        self.package = package
        self.unpack_enabled = unpack
        self.prefer_dump = prefer_dump
        self._quiet_shell_logs = bool(prefer_dump)  # prefer-dump 场景静默壳过程日志
        self.file_queue = Queue()
        self.shell_flag = False
        self.shell_confirmed = False  # 厂商签名已确认(脱壳前置条件)
        self.packagename = ""
        self.comp_list = []
        self.shell_report = []
        self.file_identifier = []
        self.permissions = []
        self.files = []
        self.comp_detail = []   # 结构化组件明细(报告用)
        self._comp_index = {}   # 聚合索引: 组件 -> {desc, hosts: {宿主: [(版本,结论)]}}

    def start(self):
        # 环境检查 + 自动供给: mac/Linux 缺失时经包管理器/pip 自动安装(provision)
        cores.logf("[CMD] java -version")
        if shutil.which("java") is None:
            if not provision.ensure_java():
                raise cores.EnvMissing(cores.i18n.t("Please install the Java environment!"))
        if subprocess.call(["java", "-version"], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL) != 0:
            raise cores.EnvMissing(cores.i18n.t("Please install the Java environment!"))
        input_file_path = self.path
        if os.path.isdir(input_file_path):
            self.__decode_dir__(input_file_path)
        else:
            if self.__decode_file__(input_file_path) == "error":
                raise cores.TaskError(cores.i18n.t(
                    "Retrieval of this file type is not supported. Select APK file or DEX file."))

        # 脱壳决策: --prefer-dump 直接扫描已有dump; --unpack 才走脱壳流程;
        # 壳确认但未指定 --unpack 时仅提示不动设备(防止破坏渗透现场)
        shell_handled = False
        if getattr(self, "prefer_dump", None):
            cores.logp(cores.i18n.t("[*] Scanning pre-dumped DEX from: {}", self.prefer_dump))
            self.__decode_dir__(self.prefer_dump)
            shell_handled = True
        elif self.shell_confirmed and getattr(self, "unpack_enabled", False):
            # frida 仅是显式脱壳的前置条件, 缺失时降级静态扫描而不阻断任务
            cores.logf("[CMD] frida --version")
            if shutil.which("frida") is None and not provision.ensure_frida():
                cores.logp("[-] Frida environment missing; unpack skipped, continuing with static scan")
            elif not self.__android_unpack__():
                cores.logp(cores.i18n.t(
                    "[*] Unpack failed, continuing with static scan of decoded artifacts"))
            shell_handled = True
        elif self.shell_confirmed:
            cores.logp("[!] Shell confirmed but --unpack not specified; skipping device interaction")
            cores.logp("[*] Tip: rerun with --unpack to unpack, or --prefer-dump <dir> to scan existing DEX dumps")

        self.__gate_shell_flag__(shell_handled)

        self.__render_components__()

        return {"comp_list": self.comp_list, "comp_detail": self.comp_detail, "shell_flag": self.shell_flag, "file_queue": self.file_queue,
                "packagename": self.packagename, "file_identifier": self.file_identifier,
                "permissions": self.permissions, "shell_report": self.shell_report}

    # 壳门控裁决: 已处置(prefer-dump/脱壳或降级)或仅疑似未确认时放行扫描,
    # 仅"已确认壳且未处置"保留中止(base_task 的遗留闸门只应拦这一种)
    def __gate_shell_flag__(self, shell_handled):
        if self.shell_flag and not self.shell_confirmed:
            cores.logp("[!] Shell suspected but unconfirmed; continuing scan, results may be incomplete")
            self.shell_flag = False
        elif self.shell_flag and shell_handled:
            self.shell_flag = False

    UNPACK_TIMEOUT = 120  # 各阶段超时(秒), 反调试拦截时避免无限等待

    # 脱壳入口: 失败不终止任务, 降级到壳payload静态扫描(payload明文区有真实资产)
    def __android_unpack__(self):
        cores.logp(cores.i18n.t("[*] unpacking"))
        try:
            return self.__unpack_pipeline__()
        except subprocess.TimeoutExpired as e:
            cores.logp(cores.i18n.t(
                "[-] Unpack stage timed out after {}s (suspected anti-debug or device issue)", 
                e.timeout or self.UNPACK_TIMEOUT))
            cores.logp(cores.i18n.t("[*] Falling back to static scan of shell payload"))
            return False
        except FileNotFoundError as e:
            cores.logp("[-] Unpack tool missing: {}".format(e))
            cores.logp(cores.i18n.t("[*] Falling back to static scan of shell payload"))
            return False
        except Exception as e:
            cores.logp("[-] Unpack failed: {}".format(e))
            cores.logp(cores.i18n.t("[*] Falling back to static scan of shell payload"))
            return False

    # 脱壳各阶段: 安装 -> 推送server -> 启动 -> dexdump, 每阶段带超时
    def __unpack_pipeline__(self):
        adb_path = provision.ensure_adb()
        if not adb_path:
            cores.logp("[-] adb not available, cannot unpack")
            return False
        timeout = self.UNPACK_TIMEOUT
        device_tmp_dir = "/data/local/tmp"

        cores.logp(cores.i18n.t("[*] Install the APK"))
        cores.logf("[CMD] {} install {}".format(adb_path, self.path))
        if subprocess.call([adb_path, "install", self.path], timeout=timeout) != 0:
            cores.logp(cores.i18n.t("[-] We can't install the APP"))
            return False

        # 版本一致性: 以本地 frida core 为基准获取匹配的 frida-server(自带/下载)
        cores.logp(cores.i18n.t("Push Frida Server"))
        abi = subprocess.run([adb_path, "shell", "getprop", "ro.product.cpu.abi"],
                             capture_output=True, text=True, timeout=30).stdout.strip()
        server_path = provision.ensure_frida_server(abi, adb_path)
        if not server_path:
            return False
        server_name = os.path.basename(server_path)

        cores.logp(cores.i18n.t("[*] Running Frida Server"))
        cores.logf("[CMD] {} push {} {}".format(adb_path, server_path, device_tmp_dir))
        if subprocess.call([adb_path, "push", server_path, device_tmp_dir],
                           timeout=timeout) != 0:
            cores.logp(cores.i18n.t("[-] Failed to push frida-server"))
            return False
        for cmd_desc, cmd in [
            ("chmod", [adb_path, "shell", "su", "-c",
                       "chmod 755 {0}/{1}".format(device_tmp_dir, server_name)]),
            ("setenforce", [adb_path, "shell", "su", "-c", "setenforce 0"]),
            ("start", [adb_path, "shell", "su", "-c",
                       "{0}/{1} &".format(device_tmp_dir, server_name)]),
        ]:
            cores.logf("[CMD] " + " ".join(cmd))
            if subprocess.call(cmd, timeout=timeout) != 0:
                cores.logp(cores.i18n.t(
                    "[-] Frida server {} failed (possible anti-debug kill)", cmd_desc))
                return False
        cores.logp(cores.i18n.t("[*] Frida Server started"))

        # aapt 优先 PATH，缺位时回退用 manifest 已解析的包名
        package_name = self.packagename
        aapt = shutil.which("aapt") or shutil.which("aapt2")
        if aapt:
            cores.logf("[CMD] {} dump badging {}".format(aapt, self.path))
            result = subprocess.run([aapt, "dump", "badging", self.path],
                                    capture_output=True, text=True, timeout=30)
            match = re.compile(r"package: name='(\S+)'").match(result.stdout or "")
            if match:
                package_name = match.group(1)
        if not package_name:
            cores.logp("[-] Cannot determine package name for frida-dexdump")
            return False
        cores.logp(package_name)

        cores.logf("[CMD] frida-dexdump -U -f {}".format(package_name))
        if subprocess.call(["frida-dexdump", "-U", "-f", package_name],
                           timeout=timeout * 2) != 0:
            cores.logp(cores.i18n.t(
                "[-] frida-dexdump failed (target process may be killed by anti-debug)"))
            return False
        return True

    def __decode_file__(self, file_path):
        apktool_path = str(cores.apktool_path)
        backsmali_path = str(cores.backsmali_path)
        base_out_path = str(cores.output_path)
        filename = os.path.basename(file_path)
        suffix_name = filename.split(".")[-1]


        if suffix_name == "apk" or suffix_name == "hpk":
            name = filename.split(".")[0]
            output_path = os.path.join(base_out_path, name)
            self.__decode_apk__(file_path, apktool_path, output_path)
        elif suffix_name == "dex":
            f = open(file_path, 'rb')
            md5_obj = hashlib.md5()
            while True:
                r = f.read(1024)
                if not r:
                    break
                md5_obj.update(r)
            dex_md5 = md5_obj.hexdigest().lower()
            self.file_identifier.append(dex_md5)
            output_path = os.path.join(base_out_path, dex_md5)
            if not os.path.exists(output_path):
                os.makedirs(output_path)
            # dex 默认二进制字符串直提(秒级); 需要组件路径上下文时可关掉回退 baksmali
            if getattr(cores.config, "dex_strings_direct", True):
                self.__strings_from_dex__(file_path, output_path)
            else:
                self.__decode_dex__(file_path, backsmali_path, output_path)
        else:
            return "error"

    def __decode_dir__(self, root_dir):
        dir_or_files = os.listdir(root_dir)
        for dir_or_file in dir_or_files:
            dir_or_file_path = os.path.join(root_dir, dir_or_file)
            if os.path.isdir(dir_or_file_path):
                self.__decode_dir__(dir_or_file_path)
            else:
                if self.__decode_file__(dir_or_file_path) == "error":
                    continue

    # 分解apk
    def __decode_apk__(self, file_path, apktool_path, output_path):
        # 失败时先经 fix_magic 修复(zip魔数/内部dex/manifest)再重试一次；
        # 无可修复项则不重试，避免空转
        attempts = 0
        while True:
            cores.logf("[CMD] java -jar {} d -f {} -o {}".format(apktool_path, file_path, output_path))
            result = subprocess.run(
                ["java", "-jar", apktool_path, "d", "-f", file_path, "-o", output_path],
                capture_output=True, text=True)
            if result.returncode == 0:
                self.__shell_test__(output_path)
                self.__scanner_file_by_apktool__(output_path)
                return
            attempts += 1
            if attempts >= 2:
                break
            cores.logp(cores.i18n.t("[*] Decompilation failed, trying fix_magic repair..."))
            if not self.__repair_apk__(file_path):
                break
            cores.logp(cores.i18n.t("[*] Repair applied, retrying decompilation"))
        output_tail = "\n".join(
            (result.stdout or "").splitlines()[-3:] + (result.stderr or "").splitlines()[-3:])
        if output_tail:
            cores.logp("[-] apktool output: {}".format(output_tail))
        cores.logp("[-] Decompilation failed, please submit error information at https://github.com/kelvinBen/AppInfoScanner/issues")
        raise Exception("{}: {}".format(file_path, cores.i18n.t("Decompilation failed")))

    def __repair_apk__(self, file_path):
        """apktool 失败后用 fix_magic 检测并修复可修复的损坏，修复了返回 True。

        覆盖三类: APK 自身 zip 魔数、内部 classes*.dex 头、AndroidManifest.xml(AXML) 头；
        修复前原文件备份为 .bak(fix_magic 内置)；检测不出的损坏不做任何动作。
        """
        repaired = False
        file_size = os.path.getsize(file_path)
        with open(file_path, "rb") as f:
            head = f.read(4)
            f.seek(max(0, file_size - 65536))
            tail = f.read()
        # 仅当尾部存在 zip 目录结束记录(EOCD)时才认定是"魔数损坏的 zip"，
        # 任意垃圾文件不修、不污染
        if head != b"PK\x03\x04" and b"PK\x05\x06" in tail:
            fix_magic.fix_zip(file_path)
            cores.logf("[REPAIR] zip magic fixed: " + file_path)
            repaired = True
        try:
            with zipfile.ZipFile(file_path) as zf:
                members = [name for name in zf.namelist()
                           if name == "AndroidManifest.xml" or re.match(r"classes\d*\.dex$", name)]
        except zipfile.BadZipFile:
            # 非 zip 结构(且无 EOCD 可修)，不做任何动作
            return repaired
        for name in members:
            with zipfile.ZipFile(file_path) as zf:
                data = zf.read(name)
            with tempfile.TemporaryDirectory() as tmp_dir:
                tmp_path = os.path.join(tmp_dir, os.path.basename(name))
                with open(tmp_path, "wb") as f:
                    f.write(data)
                if name.endswith(".dex"):
                    status = fix_magic.detect_dex(tmp_path)
                    if status and not all((status["magic_ok"], status["size_ok"],
                                           status["checksum_ok"], status["signature_ok"])):
                        fix_magic.fix_dex(tmp_path)
                        self.__rewrite_zip_member__(file_path, name, open(tmp_path, "rb").read())
                        cores.logf("[REPAIR] dex header fixed: " + name)
                        repaired = True
                else:
                    status = fix_magic.detect_axml(tmp_path)
                    if status and not (status["magic_ok"] and status["size_ok"]):
                        fix_magic.fix_axml(tmp_path)
                        self.__rewrite_zip_member__(file_path, name, open(tmp_path, "rb").read())
                        cores.logf("[REPAIR] manifest (axml) header fixed")
                        repaired = True
        return repaired

    def __rewrite_zip_member__(self, apk_path, member_name, new_bytes):
        """以新内容重写 zip 内单个成员(整包重写后原子替换)。"""
        fix_magic.backup(apk_path)
        temp_path = apk_path + ".repaired"
        with zipfile.ZipFile(apk_path, "r") as zin, \
                zipfile.ZipFile(temp_path, "w", zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                data = new_bytes if item.filename == member_name else zin.read(item.filename)
                zout.writestr(item, data)
        os.replace(temp_path, apk_path)

    # dex 二进制字符串直提: 跳过全量 baksmali(中间产物大/耗时分钟级), 秒级提取;
    # 无 smali 路径上下文, 组件按包名标记匹配且不标注版本与宿主
    _STRINGS_CHUNK_LIMIT = 8 * 1024 * 1024  # 单文件上限(扫描线程有 10MB 文件门限)

    def __strings_from_dex__(self, file_path, output_path):
        total = written = chunk_id = 0
        fout = open(os.path.join(output_path, "strings_%02d.txt" % (chunk_id + 1)),
                    "w", encoding="utf-8", errors="ignore")
        with open(file_path, "rb") as fin:
            for line in fin:
                for m in re.finditer(rb"[ -~]{4,}", line):
                    text = m.group().decode("ascii", "ignore")
                    fout.write(text + "\n")
                    written += len(text) + 1
                    total += 1
                    if written >= self._STRINGS_CHUNK_LIMIT:
                        fout.close()
                        chunk_id += 1
                        written = 0
                        fout = open(os.path.join(output_path, "strings_%02d.txt" % (chunk_id + 1)),
                                    "w", encoding="utf-8", errors="ignore")
        fout.close()
        chunk_count = chunk_id + 1
        cores.logp(cores.i18n.t(
            "[*] dex direct strings: {} ({} strings, {} files)",
            os.path.basename(file_path), total, chunk_count))
        # 入队扫描 + 组件包名标记匹配(直提模式无路径上下文)
        components = cores.config.filter_components.items() if isinstance(
            cores.config.filter_components, dict) else (
            (component, None) for component in cores.config.filter_components)
        for i in range(1, chunk_count + 1):
            txt = os.path.join(output_path, "strings_%02d.txt" % i)
            self.file_queue.put(txt)
            with open(txt, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            for component, desc in components:
                if component.replace(".", "/") in content:
                    base = "{} ({})".format(component, desc) if desc else component
                    entry = base + " [直提模式, 无路径归属]"
                    if entry not in self.comp_list:
                        self.comp_list.append(entry)

    # 分解dex: baksmali返回非零不等于无产物(依赖错误只影响部分类), 有smali就继续扫
    def __decode_dex__(self, file_path, backsmali_path, output_path):
        cores.logf("[CMD] java -jar {} d {} -o {}".format(backsmali_path, file_path, output_path))
        result = subprocess.call(["java", "-jar", backsmali_path, "d", file_path, "-o", output_path])
        if result == 0:
            self.__get_scanner_file__(output_path)
            return
        # 失败: 先尝试 fix_magic 修复 dex 头(脱壳产物常见 CheckSum 损坏)
        cores.logp(cores.i18n.t("[*] Decompilation failed, trying fix_magic repair..."))
        if self.__repair_dex_file__(file_path):
            cores.logp(cores.i18n.t("[*] Repair applied, retrying decompilation"))
            result = subprocess.call(["java", "-jar", backsmali_path, "d", file_path, "-o", output_path])
            if result == 0:
                self.__get_scanner_file__(output_path)
                return
        # 修复无效或重试仍失败: 检查是否有部分产物(依赖错误只影响部分类)
        if os.path.isdir(output_path) and any(
                name.endswith(".smali") for _, _, files in os.walk(output_path) for name in files):
            cores.logp("[!] Partial decompilation succeeded (some classes may have dependency errors)")
            self.__get_scanner_file__(output_path)
        else:
            cores.logp(
                "[-] Decompilation failed, please submit error information at https://github.com/kelvinBen/AppInfoScanner/issues")
            raise cores.TaskError("{}: {}".format(file_path, cores.i18n.t("Decompilation failed")))

    # 修复独立dex文件的头部(魔数/大小/校验和), 脱壳产物常见损坏
    def __repair_dex_file__(self, file_path):
        from libs.core import fix_magic
        status = fix_magic.detect_dex(file_path)
        if status and not all((status["magic_ok"], status["size_ok"],
                               status["checksum_ok"], status["signature_ok"])):
            fix_magic.fix_dex(file_path)
            cores.logf("[REPAIR] dex header fixed: " + file_path)
            return True
        return False

    # 初始化检测文件信息
    def __scanner_file_by_apktool__(self, output_path):
        file_names = os.listdir(output_path)
        for file_name in file_names:
            file_path = os.path.join(output_path, file_name)
            if not os.path.isdir(file_path):
                continue

            if "smali" in file_name or "assets" in file_name:
                scanner_file_suffixs = ["smali", "js", "xml"]
                if cores.resource_flag:
                    scanner_file_suffixs = ["smali"]
                self.__get_scanner_file__(file_path, scanner_file_suffixs)

    def __get_scanner_file__(self, scanner_dir, scanner_file_suffixs=None):
        if scanner_file_suffixs is None:
            scanner_file_suffixs = ["smali"]
        dir_or_files = os.listdir(scanner_dir)
        for dir_or_file in dir_or_files:
            dir_file_path = os.path.join(scanner_dir, dir_or_file)

            if os.path.isdir(dir_file_path):
                self.__get_scanner_file__(dir_file_path, scanner_file_suffixs)
            else:
                if ("." not in dir_or_file) or (len(dir_or_file.split(".")) < 1) or (
                        dir_or_file.split(".")[-1] not in scanner_file_suffixs):
                    continue
                self.file_queue.put(dir_file_path)
                # 组件表为 {包名: 说明} 映射；兼容旧版纯包名数组
                components = cores.config.filter_components.items() if isinstance(
                    cores.config.filter_components, dict) else (
                    (component, None) for component in cores.config.filter_components)
                for component, desc in components:
                    comp = component.replace(".", "/")
                    if comp in dir_file_path:
                        # 聚合索引: 同组件多副本按宿主归组, 渲染统一在 start() 末尾
                        host = self.__match_component_host__(dir_file_path, comp)
                        ver = self.__extract_component_version__(component, dir_file_path)
                        info = self._comp_index.setdefault(component, {"desc": desc, "hosts": {}})
                        host_vers = info["hosts"].setdefault(host, [])
                        if ver and ver not in host_vers:
                            host_vers.append(ver)

    # 从smali提取组件版本号, 对照CVE影响范围表给出(版本, 结论)二元组;
    # OID 伪版本(RSA/证书策略/密钥算法等)一律视为未提取到, 不做影响判定
    def __extract_component_version__(self, component, smali_path):
        version_rules = getattr(cores.config, "component_versions", {})
        rule = version_rules.get(component)
        if not rule:
            return None
        try:
            with open(smali_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(512 * 1024)  # 只读前 512KB
            candidates = []
            # 方式1: version_field (如 fastjson 的 Version.VERSION)
            if rule.get("version_field"):
                m = re.compile(
                    r'const-string.*"' + re.escape(rule["version_field"]) + r'".*?"([\d.]+)"').search(content)
                if m:
                    candidates.append(m.group(1))
            # 方式2: version_pattern (如 bcprov 的版本串)
            if rule.get("version_pattern"):
                m = re.compile(rule["version_pattern"]).search(content)
                if m:
                    candidates.append(m.group(1))
            # 方式3 兜底: 文件前 8KB 的第一个 x.y.z 串
            m = re.compile(r'"(\d+\.\d+\.\d+)"').search(content[:8192])
            if m:
                candidates.append(m.group(1))
            for ver in candidates:
                if not self.__version_valid__(ver):
                    continue
                safe = rule.get("safe_above", "")
                if safe and self.__version_lt__(ver, safe):
                    return (ver, rule.get("cve", "受影响"))
                return (ver, "安全")
            return None
        except Exception:
            return None

    # 版本号语义校验: 拒绝 OID 形态(1.2.840.*/2.5.*/1.3.6.1.*/1.3.101*)与
    # 不合理段值(超过4段/major>20/段值>999), 防止把加密库常量当版本做判定
    @staticmethod
    def __version_valid__(ver):
        oid_prefixes = ("1.2.840.", "2.5.", "1.3.6.1.", "1.3.101")
        if any(ver.startswith(p) for p in oid_prefixes):
            return False
        segs = ver.split(".")
        if not segs or len(segs) > 4:
            return False
        for s in segs:
            if not s.isdigit() or len(s) > 3 or int(s) > 999:
                return False
        return int(segs[0]) <= 20

    # 从 smali 路径推断宿主 SDK: 组件包路径之前的包段命中宿主映射则归属,
    # 多命中取最长前缀; 未命中归属"应用本体"
    @staticmethod
    def __match_component_host__(file_path, comp_path):
        hosts = getattr(cores.config, "component_hosts", {})
        pos = file_path.find(comp_path)
        prefix = file_path[:pos] if pos > 0 else ""
        best, best_name = "", "应用本体"
        for pkg, name in hosts.items():
            seg = pkg.replace(".", "/") + "/"
            if seg in prefix and len(pkg) > len(best):
                best, best_name = pkg, name
        return best_name

    # 聚合渲染组件条目: 同组件多副本按宿主归组去重; 有版本规则的组件未提取
    # 到版本时标注人工核; 输出行式条目(comp_list)与结构化明细(comp_detail)双形态
    def __render_components__(self):
        has_rule = lambda c: c in getattr(cores.config, "component_versions", {})
        for component, info in self._comp_index.items():
            base = "{} ({})".format(component, info["desc"]) if info["desc"] else component
            parts = []
            for host, versions in info["hosts"].items():
                if versions:
                    vers_note = " ".join("[v{}, {}]".format(v, d) for v, d in versions)
                    row_version = ", ".join(v for v, _ in versions)
                    row_verdict = "; ".join(d for _, d in versions)
                elif has_rule(component):
                    vers_note = "[版本未提取到, 人工核]"
                    row_version, row_verdict = "", "人工核"
                else:
                    vers_note, row_version, row_verdict = "", "", ""
                parts.append((host, vers_note))
                self.comp_detail.append({
                    "component": component, "desc": info["desc"] or "",
                    "host": host, "version": row_version, "verdict": row_verdict})
            host_notes = "; ".join(
                (note + " @" + host) if note else ("@" + host) for host, note in parts)
            self.comp_list.append("{} {}".format(base, host_notes).rstrip())

    # 语义化版本比较: a < b 返回 True
    @staticmethod
    def __version_lt__(a, b):
        pa = [int(x) for x in a.split(".") if x.isdigit()]
        pb = [int(x) for x in b.split(".") if x.isdigit()]
        for i in range(max(len(pa), len(pb))):
            va = pa[i] if i < len(pa) else 0
            vb = pb[i] if i < len(pb) else 0
            if va < vb:
                return True
            if va > vb:
                return False
        return False

    # 壳检测过程日志: prefer-dump 场景静默(shell_report 仍完整记录)
    def __shell_log__(self, msg):
        if not self._quiet_shell_logs:
            cores.logp(msg)

    # 按application类名定位加固厂商
    def __match_shell_vendor__(self, app_class):
        for vendor, info in cores.config.shell_vendors.items():
            if app_class in info.get("classes", []):
                return vendor
        return None

    # 经验规则: 壳加密业务dex后, 原始包名在dex包结构中缺失即疑似加固
    def __package_in_dex__(self, output, package_name):
        pkg_dir = package_name.replace(".", "/")
        for entry in os.listdir(output):
            if entry.startswith("smali") and os.path.isdir(os.path.join(output, entry)):
                if os.path.isdir(os.path.join(output, entry, pkg_dir)):
                    return True
        return False

    # 壳文件特征确认; vendor=None 时跨厂商定位(包名缺失门控)
    def __confirm_shell__(self, output, vendor=None):
        if vendor:
            candidates = {vendor: cores.config.shell_vendors.get(vendor, {})}
        else:
            candidates = cores.config.shell_vendors
        all_signatures = set()
        for info in candidates.values():
            all_signatures.update(info.get("so", []))
            all_signatures.update(info.get("assets", []))
        if not all_signatures:
            self.__shell_log__("[*] Shell confirmed by manifest only (无文件特征记录)")
            return
        hits = []
        for root, _, files in os.walk(output):
            for file_name in files:
                rel = os.path.relpath(os.path.join(root, file_name), output).replace(os.sep, "/")
                for sig in all_signatures:
                    if sig in rel and sig not in hits:
                        hits.append(sig)
        if hits:
            matched = [name for name, info in candidates.items()
                       if any(sig in (info.get("so", []) + info.get("assets", [])) for sig in hits)]
            msg = "Shell file signatures confirmed ({}): {}".format(", ".join(matched), ", ".join(hits))
            self.__shell_log__("[*] " + msg)
            self.shell_report.append(msg)
            # 不再直接调 __android_unpack__: 由 BaseTask 根据 --unpack 决定
            self.shell_confirmed = True
        else:
            msg = "Shell suspected but no vendor signature found in decoded output"
            self.__shell_log__("[*] " + msg)
            self.shell_report.append(msg)

    def __shell_test__(self, output):
        am_path = os.path.join(output, "AndroidManifest.xml")

        with open(am_path, "r", encoding='utf-8', errors='ignore') as f:
            am_str = f.read()

            am_package = re.compile(r'<manifest.*package=\"(.*?)\".*')
            apackage = am_package.findall(am_str)
            if len(apackage) >= 1:
                self.packagename = apackage[0]
                self.file_identifier.append(apackage[0])

            am_name = re.compile(r'<application.*android:name=\"(.*?)\".*>')
            aname = am_name.findall(am_str)
            if aname and len(aname) >= 1:
                # 统一特征库门控入口: manifest application 类名先行判断，
                # 命中厂商后才用该厂商的 so/assets 文件特征确认，不做无差别全量签名扫描
                vendor = self.__match_shell_vendor__(aname[0])
                if vendor:
                    self.shell_flag = True
                    msg = "Detect shell by manifest: {} (加固厂商: {})".format(aname[0], vendor)
                    self.__shell_log__("[*] " + msg)
                    self.shell_report.append(msg)
                    self.__confirm_shell__(output, vendor)

            # 非贪婪捕获：贪婪的 (.*) 在单行(压缩过的) manifest 里会跨标签匹配到最后一个 "/>
            am_permission = re.compile(r'<uses-permission android:name="(.*?)"/>')
            ampermissions = am_permission.findall(am_str)
            for ampermission in ampermissions:
                if ampermission in cores.config.apk_permissions:
                    # 权限表为 {权限: 中文说明} 映射；兼容旧版纯权限数组
                    desc = cores.config.apk_permissions[ampermission] if isinstance(
                        cores.config.apk_permissions, dict) else None
                    self.permissions.append(
                        "{} ({})".format(ampermission, desc) if desc else ampermission)

            # 经验规则门控：壳加密业务 dex 后，应用包名在 dex 包结构中缺失。
            # 类名门控未命中时启用，命中后跨厂商扫签名定位加固厂商;
            # 厂商签名确认成功则只报厂商结论, 未确认才输出 Suspected 启发式行
            if not self.shell_flag and self.packagename:
                if not self.__package_in_dex__(output, self.packagename):
                    self.shell_flag = True
                    self.__confirm_shell__(output, None)
                    if not self.shell_confirmed:
                        msg = "Suspected shell: package {} not found in any dex (业务dex被壳加密的典型特征)".format(
                            self.packagename)
                        self.__shell_log__("[*] " + msg)
                        self.shell_report.append(msg)
