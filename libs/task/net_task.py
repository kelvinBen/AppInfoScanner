#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen (微信/WeChat: bromomo )
# Github: https://github.com/kelvinBen/AppInfoScanner
# Gitee: https://gitee.com/kelvin_ben/AppInfoScanner

from queue import Queue
import libs.core as cores
from libs.core.net import NetThreads
from libs.core.report import extract_host, sniff_allowed


class NetTask(object):
    value_list = []
    domain_list = []

    def __init__(self, result_dict, app_history_list, domain_history_list, file_identifier, threads, scope_domains=None):
        self.result_dict = result_dict
        self.app_history_list = app_history_list
        self.file_identifier = file_identifier
        self.domain_queue = Queue()
        self.threads = int(threads)
        self.thread_list = []
        self.domain_history_list = domain_history_list
        # 授权域名清单(None=不限制, set=仅清单内嗅探)
        self.scope_domains = scope_domains

    # 执行嗅探并返回行数据
    def start(self):
        self.sniff_rows = []
        self.skipped_sniff = 0  # 被嗅探策略跳过的内网地址数
        self.__write_result_to_txt__()
        self.__start_threads__(self.sniff_rows)
        for thread in self.thread_list:
            thread.join()
        cores.progress_end()
        if self.skipped_sniff:
            cores.logp(cores.i18n.t("[*] Skipped sniffing {} internal addresses (kept in reports)", self.skipped_sniff))
        return self.sniff_rows

    def __write_result_to_txt__(self):
        append_file_flag = True
        # 后缀表转 set：逐条结果判断为 O(1)
        sniffer_filter_suffix = set(cores.config.sniffer_filter)

        for key, value in self.result_dict.items():
            for result in value:
                if result in self.value_list:
                    continue
                self.value_list.append(result)

                if (("http://" in result) or ("https://" in result)) and ("." in result):
                    if "{" in result or "}" in result or "[" in result or "]" in result or "\\" in result or "!" in result or "," in result:
                        continue

                    domain = result.replace(
                        "https://", "").replace("http://", "")
                    if "/" in domain:
                        domain = domain[:domain.index("/")]

                    if "|" in result:
                        result = result[:result.index("|")]
                    # 目前流通的域名中加上协议头最短长度为11位
                    if len(result) <= 10:
                        continue

                    url_suffix = result[result.rindex(".")+1:].lower()
                    sniffable = sniff_allowed(extract_host(result))
                    if not sniffable:
                        self.skipped_sniff += 1
                        cores.logf("[SNIFF-SKIP] internal address: " + result)
                    elif self.scope_domains is not None:
                        # 授权 scope 过滤: 域名或其父域必须在清单内
                        host = extract_host(result).lower()
                        host_labels = host.split(".")
                        in_scope = any(
                            ".".join(host_labels[i:]) in self.scope_domains
                            for i in range(len(host_labels)))
                        if not in_scope:
                            sniffable = False
                            self.skipped_sniff += 1
                            cores.logf("[SNIFF-SKIP] out of scope: " + result)
                    if sniffable and not(cores.resource_flag and url_suffix in sniffer_filter_suffix):
                        self.domain_queue.put(
                            {"domain": domain, "url_ip": result})

                    for identifier in self.file_identifier:
                        if identifier in self.app_history_list:
                            if not(domain in self.domain_history_list):
                                self.domain_list.append(domain)
                                self.__write_content_in_file__(
                                    cores.domain_history_path, domain)
                            continue

                        if not(domain in self.domain_list):
                            self.domain_list.append(domain)
                            self.__write_content_in_file__(
                                cores.domain_history_path, domain)

                        if append_file_flag:
                            self.__write_content_in_file__(
                                cores.app_history_path, identifier)
                            append_file_flag = False

    def __start_threads__(self, rows):
        for threadID in range(0, self.threads):
            name = "Thread - " + str(threadID)
            thread = NetThreads(threadID, name, self.domain_queue, rows)
            thread.start()
            self.thread_list.append(thread)

    def __write_content_in_file__(self, file_path, content):
        with open(file_path, "a+", encoding='utf-8', errors='ignore') as f:
            f.write(content+"\r")
            f.close()
