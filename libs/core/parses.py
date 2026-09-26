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
        # 忽略规则两级化: 公共域名走后缀set, 正则单独预编译
        self._compiled_filter_no = [re.compile(p) for p in cores.config.filter_no]
        self._filter_no_domains = set(
            domain.lower() for domain in getattr(cores.config, "filter_no_domains", []))
        # iOS组件特征: 标记串->说明, 对strings全量内容一次匹配
        self._ios_components = getattr(cores.config, "ios_components", {})
        # PII规则预编译 + 触发预判(必要条件不满足则跳过正则)
        self._compiled_pii = [(name, re.compile(rule))
                              for name, rules in getattr(cores.config, "filter_pii_map", {}).items()
                              for rule in rules]
        self._pii_triggers = self.__build_pii_triggers__()
        # AK/SK 前缀分桶(值前缀型规则按前缀存在性跳过)
        self._ak_buckets, self._ak_always = self.__build_ak_buckets__()

    # PII触发预判: 每类规则的必要条件(不满足则跳过该类正则)
    @staticmethod
    def __build_pii_triggers__():
        province_chars = "京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼使领"
        return {
            "Phone_CN": lambda c: re.search(r"\d{11}", c) is not None,
            "IDCard_CN_18": lambda c: re.search(r"\d{17}[\dXx]", c) is not None,
            "Email": lambda c: "@" in c,
            "BankCard_CN": lambda c: "62" in c,
            "Plate_CN": lambda c: any(ch in c for ch in province_chars),
            "Person_Name_CN": lambda c: any(kw in c for kw in ("姓名", "联系人", "收货人", "经办人")),
            "QQ_Number": lambda c: "qq" in c.lower() or "扣扣" in c,
            "USCC_CN": lambda c: re.search(r"[1-9][0-9A-HJ-NPQRTUWXY]\d{6}", c) is not None,
            "MAC_Address": lambda c: re.search(r"[0-9A-Fa-f]{2}:", c) is not None,
            "Passport_CN": lambda c: "护照" in c or "passport" in c.lower(),
            "VIN": lambda c: "vin" in c.lower() or "车架" in c,
            "IMEI": lambda c: "imei" in c.lower() or "device" in c.lower(),
            "Phone_Intl": lambda c: "+" in c and any(kw in c.lower() for kw in ("tel", "phone", "mobile")),
            "Address_CN": lambda c: any(kw in c for kw in ("地址", "住址", "收货")),
        }

    # AK/SK前缀分桶: 从正则中提取字面前缀, 按前缀存在性快速跳过
    def __build_ak_buckets__(self):
        """把 filter_ak_map 的规则分为"值前缀型"和"上下文型"两组。

        值前缀型(sk-/AKIA/LTAI/ghp_/eyJ等): 先做一次合并前缀扫描，
        前缀不存在则跳过该规则；上下文型(Generic/Map_SDK): 走关键词门控。
        """
        prefix_map = {}  # {前缀串: [(rule_set, regex_str), ...]}
        always = []      # 无明确前缀的规则(上下文型)
        for set_name, rules in cores.config.filter_ak_map.items():
            for rule in (rules if isinstance(rules, list) else [rules]):
                # 提取正则开头的字面量前缀(如 sk-/AKIA/LTAI)
                m = re.match(r"^(?:\(\?i\))?\(?['\"]?([a-zA-Z0-9_-]{3,12})", rule)
                if m:
                    prefix = m.group(1).lower()
                    # 前缀太短或太常见(如 the/and)不分桶
                    if len(prefix) >= 3 and prefix not in ("the", "and", "var", "let", "con", "func"):
                        prefix_map.setdefault(prefix, []).append((set_name, rule))
                        continue
                always.append((set_name, rule))
        return prefix_map, always

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

    # macOS strings对文件参数只输出__TEXT节(漏90%), 走stdin触发全文件扫描
    def __get_string_by_iOS__(self, file_path):
        strings_path = cores.strings_path
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

            # AK/SK 检测: 前缀分桶优化 + 触发词门控
            if not (".js" == file_path[-3:] and self.types == "iOS"):
                lowered = file_content.lower()
                # 大文件需命中触发词; 小文件直接全量
                gate_hit = len(file_content) < 512 * 1024 or any(trigger in lowered for trigger in (
                    "access", "secret", "akia", "ltai", "akid", "token", "apikey", "api_key",
                    "password", "passwd", "bearer", "private key", "eyj", "ghp_", "gho_", "ghu_",
                    "ghs_", "glpat-", "aiza", "xox", "sq0", "sg.", "key-", "sk_live", "rk_live",
                    "cloudinary", "basic ", "eaacedeose0c"))
                if gate_hit:
                    # 前缀分桶: 一次合并扫描找出内容中存在的所有前缀
                    if self._ak_buckets:
                        found_prefixes = set()
                        for prefix in self._ak_buckets:
                            if prefix in lowered:
                                found_prefixes.add(prefix)
                        # 只执行前缀存在的规则
                        for prefix in found_prefixes:
                            for set_name, rule in self._ak_buckets[prefix]:
                                self.__ak_and_sk__(set_name, rule, file_content)
                    # 上下文型规则(无明确值前缀)始终执行
                    for set_name, rule in self._ak_always:
                        self.__ak_and_sk__(set_name, rule, file_content)

            # PII 检测: 触发预判(必要条件不满足则跳过正则)
            test_vectors = set(getattr(cores.config, "pii_test_vectors", []))
            is_digest_path = "digest" in file_path.lower() or "crypto" in file_path.lower()

            for name, pattern in self._compiled_pii:
                # 快速必要条件检查
                trigger = self._pii_triggers.get(name)
                if trigger and not trigger(file_content):
                    continue
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
                    # 已知测试向量直接丢弃
                    if value in test_vectors:
                        cores.logf("[PII-SKIP] known test vector: " + value)
                        continue
                    # 可疑来源降权标注, 留给人工判断
                    if is_digest_path and name in ("BankCard_CN", "Phone_CN"):
                        value = value + " (疑似测试向量, 来源: crypto/digest 路径)"
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

    # 18位身份证校验位验证
    def __valid_idcard__(self, value):
        digits = value.upper()
        total = sum(int(digits[i]) * w for i, w in enumerate(self._IDCARD_WEIGHTS))
        return self._IDCARD_CHECKS[total % 11] == digits[17]

    # USCC三重校验: 长度+格式(首位部门码/次位机构类别码)+校验位
    def __valid_uscc__(self, value):
        if len(value) != 18:
            return False
        v = value.upper()
        # 格式校验: 首位登记管理部门码 + 次位机构类别码
        valid_dept = getattr(cores.config, "uscc_valid_codes", {}).get("dept", "123456789Y")
        valid_type = getattr(cores.config, "uscc_valid_codes", {}).get("type", "1239")
        if v[0] not in valid_dept or v[1] not in valid_type:
            return False
        # 中间 6 位(登记管理机关)必须是数字
        if not v[2:8].isdigit():
            return False
        # 校验位
        total = sum(self._USCC_CHARS.index(v[i]) * w
                    for i, w in enumerate(self._USCC_WEIGHTS))
        return self._USCC_CHARS[(31 - total % 31) % 31] == v[17]

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

    # 内容过滤: 公共域名后缀 + 正则
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

    # 从结果串中取host(scheme://user:pass@host:port/path)
    def __extract_host__(self, value):
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

    # host或其父域命中公共域名表即视为噪声
    def __is_public_host__(self, host):
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
