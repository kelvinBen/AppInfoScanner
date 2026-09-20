#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen (微信/WeChat: bromomo )
# Github: https://github.com/kelvinBen/AppInfoScanner
# Gitee: https://gitee.com/kelvin_ben/AppInfoScanner

import re
import os
import subprocess
import platform
import threading
from queue import Empty
import libs.core as cores

class ParsesThreads(threading.Thread):

    # 单文件扫描大小上限：超过该大小的 js/html 等文件直接跳过，
    # 避免非贪婪 findall 在超大文件上耗时失控阻塞整个扫描队列 (issue #27)
    MAX_SCAN_SIZE = 10 * 1024 * 1024
    # 单条提取字符串的最大长度，超长结果截断保存
    MAX_STRING_LENGTH = 512

    def __init__(self, threadID, name, file_queue, result_dict, types, comp_list=None):
        threading.Thread.__init__(self)
        self.file_queue = file_queue
        self.name = name
        self.threadID = threadID
        self.result_list = []
        self.result_dict = result_dict
        self.types = types
        self.comp_list = comp_list if comp_list is not None else []
        # 预编译过滤规则，避免对每条字符串重复编译
        self._compiled_filter_strs = [re.compile(p) for p in cores.config.filter_strs]
        # 忽略规则两级化：公共域名走后缀 set（每条结果 O(标签数) 次 set 查找），
        # 正则单独预编译 —— 域名清单再大也不会退化成 O(结果数×规则数) 的正则循环
        self._compiled_filter_no = [re.compile(p) for p in cores.config.filter_no]
        self._filter_no_domains = set(
            domain.lower() for domain in getattr(cores.config, "filter_no_domains", []))
        # iOS 组件特征：标记串 -> 说明；对整个 strings 输出做一次全文匹配
        self._ios_components = getattr(cores.config, "ios_components", {})
        # 个人/企业敏感信息规则：预编译；模式均为有界线性扫描，无需触发词门槛
        self._compiled_pii = [(name, re.compile(rule))
                              for name, rules in getattr(cores.config, "filter_pii_map", {}).items()
                              for rule in rules]

    def __regular_parse__(self):
        # 直接依赖 get 超时退出：empty()+get 的组合在多线程抢最后一件时会抛 Empty
        while True:
            try:
                file_path = self.file_queue.get(timeout=5)
            except Empty:
                break
            if self.types == "iOS":
                self.__get_string_by_iOS__(file_path)
            else:
                self.__get_string_by_file__(file_path)

            result_set = set(self.result_list)
            if len(result_set) != 0:
                self.result_dict[file_path] = result_set
            with cores._progress_lock:
                cores.scan_files += 1
                cores.scan_hits += len(result_set)
            if cores.all_flag:
                cores.progress(cores.i18n.t("[*] Progress: {} files scanned, {} hits", cores.scan_files, cores.scan_hits))

    def __get_string_by_iOS__(self, file_path):
        strings_path = cores.strings_path
        # 直接捕获 strings 工具输出，替代临时文件中转与 shell 重定向。
        # macOS/Linux 的 cdtolls strings 对文件参数是 Mach-O 节感知输出，会漏掉
        # __DATA/__OBJC 节(ObjC 类名/框架名，实测约90%字符串)，经 "-" 走 stdin
        # 触发全文件扫描；Windows 的 strings.exe 按文件全量扫描，不受影响
        try:
            if platform.system() == "Windows":
                cores.logf("[CMD] strings {}".format(file_path))
                result = subprocess.run([str(strings_path), str(file_path)],
                                        capture_output=True)
            else:
                cores.logf("[CMD] strings - <{}>".format(file_path))
                with open(file_path, "rb") as fin:
                    result = subprocess.run([str(strings_path), "-"], stdin=fin,
                                            capture_output=True)
        except FileNotFoundError:
            cores.logp("[-] strings tool not found, skip: {}".format(file_path))
            return
        if result.returncode == 0:
            lines = result.stdout.decode('utf-8', 'ignore').splitlines()
            # 组件特征对全量内容做一次匹配，避免逐行 × 特征数量级的比较
            if self._ios_components and lines:
                content = "\n".join(lines)
                for marker, desc in self._ios_components.items():
                    if marker in content:
                        entry = "{} ({})".format(marker, desc)
                        self.threadLock.acquire()
                        if entry not in self.comp_list:
                            self.comp_list.append(entry)
                        self.threadLock.release()
            for line in lines:
                self.__parse_string__(line)

    def __get_string_by_file__(self, file_path):
        # 大文件跳过：非贪婪正则在超大 js/html 上耗时失控，是扫描卡死的主要来源
        try:
            if os.path.getsize(file_path) > self.MAX_SCAN_SIZE:
                cores.logp(cores.i18n.t("[-] Skip large file (>{}MB): {}", self.MAX_SCAN_SIZE // (1024 * 1024), file_path))
                return
        except OSError:
            return
        with open(file_path, "r", encoding="utf8", errors='ignore') as f:
            file_content = f.read()
            # 获取到所有的字符串（finditer 惰性迭代 + 截断超长结果，替代一次性 findall）
            pattern = re.compile(r'\"(.*?)\"')
            results = [match.group(1)[:self.MAX_STRING_LENGTH]
                       for match in pattern.finditer(file_content)]

            # 搜素AK和SK信息,由于iOS的逻辑处理效率过慢暂时忽略对iOS的AK检测
            if not (".js" == file_path[-3:] and self.types == "iOS"):
                # 触发预过滤：大文件(>=512KB)需命中规则集特征词才进入匹配；
                # 小文件直接全量匹配，规避前缀型密钥(如 AKIA/ghp_/xoxb)无关键词可依的漏报
                lowered = file_content.lower()
                gate_hit = len(file_content) < 512 * 1024 or any(trigger in lowered for trigger in (
                    "access", "secret", "akia", "ltai", "akid", "token", "apikey", "api_key",
                    "password", "passwd", "bearer", "private key", "eyj", "ghp_", "gho_", "ghu_",
                    "ghs_", "glpat-", "aiza", "xox", "sq0", "sg.", "key-", "sk_live", "rk_live",
                    "cloudinary", "basic ", "eAACEdEose0c".lower()))
                if gate_hit:
                    for key, values in cores.config.filter_ak_map.items():
                        if isinstance(values, list):
                            for value in values:
                                self.__ak_and_sk__(key, value, file_content)
                        else:
                            self.__ak_and_sk__(key, values, file_content)

            # 个人/企业敏感信息：身份证与统一社会信用代码做校验位验证(压低误报)，
            # 邮箱按公共域名表过滤开源许可类来信(参考 HaE 的 Validator 思路)
            for name, pattern in self._compiled_pii:
                for match in pattern.findall(file_content):
                    value = match
                    if isinstance(match, tuple):
                        value = next((group for group in match if group), "")
                    if not value:
                        continue
                    if name == "IDCard_CN_18" and not self.__valid_idcard__(value):
                        continue
                    if name == "USCC_CN" and not self.__valid_uscc__(value):
                        continue
                    if name == "Email" and self.__is_public_host__(self.__extract_host__("mailto:" + value)):
                        continue
                    entry = ("[%s]-->: %s") % (name, value)
                    if entry not in self.result_list:
                        self.threadLock.acquire()
                        if entry not in self.result_list:
                            self.result_list.append(entry)
                            cores.notice("[!][%s] %s" % (name, value))
                        self.threadLock.release()

            # 遍历所有的字符串
            for result in set(results):
                if ("http://" == result) or ("https://" == result) or result.startswith("https://.") or result.startswith("http://.") :
                    continue
                self.__parse_string__(result)

    def __ak_and_sk__(self, name, ak_rule, content):
        akAndSkList = re.compile(ak_rule).findall(content)
        for akAndSk in akAndSkList:
            # 当规则包含分组时 findall 返回元组，取第一个非空分组作为匹配结果
            if isinstance(akAndSk, tuple):
                akAndSk = next((group for group in akAndSk if group), "")
            ak = ("[%s]-->:%s") % (name, akAndSk.strip())
            self.result_list.append(ak)
            cores.notice("[!][%s] %s" % (name, akAndSk.strip()))

    # 身份证校验位(GB 11643-1999, ISO 7064 MOD 11-2)：17位加权求和模11映射校验字符
    _IDCARD_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
    _IDCARD_CHECKS = "10X98765432"
    # 统一社会信用代码校验位(GB 32100-2015, MOD 31)：31字符集，权重为 3^(i) mod 31
    _USCC_CHARS = "0123456789ABCDEFGHJKLMNPQRTUWXY"
    _USCC_WEIGHTS = (1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28)

    def __valid_idcard__(self, value):
        """18位身份证号校验位验证，正则形态命中后再过此关压低误报。"""
        digits = value.upper()
        total = sum(int(digits[i]) * w for i, w in enumerate(self._IDCARD_WEIGHTS))
        return self._IDCARD_CHECKS[total % 11] == digits[17]

    def __valid_uscc__(self, value):
        """统一社会信用代码校验位验证。"""
        total = sum(self._USCC_CHARS.index(value[i]) * w
                    for i, w in enumerate(self._USCC_WEIGHTS))
        return self._USCC_CHARS[(31 - total % 31) % 31] == value[17]

    def __parse_string__(self, result):
        # 通过预编译的规则筛选需要过滤的字符串
        for filter_str_pat in self._compiled_filter_strs:
            filter_resl = filter_str_pat.findall(result)
            # 过滤掉未搜索到的内容
            if len(filter_resl) != 0:
                # 提取第一个结果
                resl_str = filter_resl[0]
                # 过滤
                if self.__filter__(resl_str) == 0:
                    continue

                self.threadLock.acquire()
                # 控制台降噪：逐条命中仅在 -a(verbose) 时输出；默认模式走单行进度统计
                if not cores.all_flag:
                    cores.logp(("[+] The string searched for matching rule is: %s") % (resl_str))
                self.result_list.append(resl_str)
                self.threadLock.release()
            continue

    def __filter__(self, resl_str):
        resl_str = resl_str.replace("\r", "").replace("\n", "").replace(" ", "")
        if len(resl_str) == 0:
            return 0
        if self.__is_public_host__(self.__extract_host__(resl_str)):
            return 0
        for filter_no_pat in self._compiled_filter_no:
            if filter_no_pat.match(resl_str):
                return 0
        return 1

    def __extract_host__(self, value):
        """从提取结果中取 host：scheme://(userinfo@)host(:port)/path 或裸 host。"""
        rest = value
        if "://" in rest:
            rest = rest.split("://", 1)[1]
        rest = rest.split("/", 1)[0]
        if "@" in rest:
            rest = rest.rsplit("@", 1)[1]
        if rest.startswith("["):
            # IPv6 字面量带端口的形式，如 [2001:db8::1]:8080
            return rest[1:rest.index("]")] if "]" in rest else rest
        return rest.rsplit(":", 1)[0]

    def __is_public_host__(self, host):
        """host 自身或任意父域后缀命中公共域名表即视为噪声。"""
        labels = host.lower().rstrip(".").split(".")
        for i in range(len(labels)):
            if ".".join(labels[i:]) in self._filter_no_domains:
                return True
        return False

    def run(self):
        self.threadLock = threading.Lock()
        try:
            self.__regular_parse__()
        except Exception:
            # 线程异常不会进入 app.py 的捕获，这里兜底记录并置失败标记
            cores.thread_failed = True
            cores.logexc("[!] ParsesThread %s aborted" % self.name)
