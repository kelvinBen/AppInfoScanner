#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen
# Github: https://github.com/kelvinBen/AppInfoScanner

import re
import os
import subprocess
import config
import threading
import libs.core as cores

class ParsesThreads(threading.Thread):

    # 单文件扫描大小上限：超过该大小的 js/html 等文件直接跳过，
    # 避免非贪婪 findall 在超大文件上耗时失控阻塞整个扫描队列 (issue #27)
    MAX_SCAN_SIZE = 10 * 1024 * 1024
    # 单条提取字符串的最大长度，超长结果截断保存
    MAX_STRING_LENGTH = 512

    def __init__(self, threadID, name, file_queue, result_dict, types):
        threading.Thread.__init__(self)
        self.file_queue = file_queue
        self.name = name
        self.threadID = threadID
        self.result_list = []
        self.result_dict = result_dict
        self.types = types
        # 预编译过滤规则，避免对每条字符串重复编译
        self._compiled_filter_strs = [re.compile(p) for p in config.filter_strs]

    def __regular_parse__(self):
        while True:
            if self.file_queue.empty():
                break

            file_path = self.file_queue.get(timeout=5)
            scan_str = ("[+] Scan file : %s" % file_path)
            if self.types == "iOS":
                self.__get_string_by_iOS__(file_path)
            else:
                self.__get_string_by_file__(file_path)

            result_set = set(self.result_list)
            if len(result_set) != 0:
                self.result_dict[file_path] = result_set

    def __get_string_by_iOS__(self, file_path):
        strings_path = cores.strings_path
        # 直接捕获 strings 工具输出，替代临时文件中转与 shell 重定向
        result = subprocess.run([str(strings_path), str(file_path)],
                                capture_output=True)
        if result.returncode == 0:
            lines = result.stdout.decode('utf-8', 'ignore').splitlines()
            for line in lines:
                self.__parse_string__(line)

    def __get_string_by_file__(self, file_path):
        # 大文件跳过：非贪婪正则在超大 js/html 上耗时失控，是扫描卡死的主要来源
        try:
            if os.path.getsize(file_path) > self.MAX_SCAN_SIZE:
                print("[-] Skip large file (>{}MB): {}".format(
                    self.MAX_SCAN_SIZE // (1024 * 1024), file_path))
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
                # 未包含相关字段不进行ak或者sk信息采集
                if "access" in file_content or "secret" in file_content:
                    for key, values in config.filter_ak_map.items():
                        if isinstance(values, list):
                            for value in values:
                                self.__ak_and_sk__(key, value, file_content)
                        else:
                            self.__ak_and_sk__(key, values, file_content)

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
            print(("[+] [%s] AK or SK in %s:") % (name, akAndSk.strip()))

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
                if cores.all_flag:
                    print(
                        ("[+] The string searched for matching rule is: %s") % (resl_str))
                self.result_list.append(resl_str)
                self.threadLock.release()
            continue

    def __filter__(self, resl_str):
        return_flag = 1
        resl_str = resl_str.replace("\r", "").replace(
            "\n", "").replace(" ", "")

        if len(resl_str) == 0:
            return 0

        for filte in set(config.filter_no):
            resl_str = resl_str.replace(filte, "")
            if len(resl_str) == 0:
                return_flag = 0
                continue

            if re.match(filte, resl_str):
                return_flag = 0
                continue

        return return_flag

    def run(self):
        self.threadLock = threading.Lock()
        self.__regular_parse__()
