#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen (微信/WeChat: bromomo )
# Github: https://github.com/kelvinBen/AppInfoScanner
# Gitee: https://gitee.com/kelvin_ben/AppInfoScanner
import os
import re
from queue import Queue
import libs.core as cores
from libs.core import report
from libs.task.ios_task import iOSTask
from libs.task.web_task import WebTask
from libs.task.net_task import NetTask
from libs.core.parses import ParsesThreads
from libs.task.android_task import AndroidTask
from libs.task.download_task import DownloadTask


class BaseTask(object):
    # 统一初始化入口

    def __init__(self, types="Android", inputs="", rules="", sniffer=True, threads=10, package=""):
        # 实例级可变状态: 类级定义会在同进程多次任务间累积泄漏
        self.thread_list = []
        self.result_dict = {}
        self.app_history_list = []
        self.domain_history_list = []
        self.types = types
        self.path = inputs
        if rules:
            cores.config.filter_strs.append(r'.*'+str(rules)+'.*')
        self.sniffer = not sniffer
        self.threads = threads
        self.package = package
        self.file_queue = Queue()

    # 统一调度平台

    def start(self):

        cores.logp(cores.i18n.t("[*] AI is analyzing filtering rules......"))

        # 获取历史记录
        self.__history_handle__()

        cores.logp(cores.i18n.t("[*] The filtering rules obtained by AI are as follows: {}", set(cores.config.filter_no)))

        # 任务控制中心
        task_info = self.__tast_control__()
        if len(task_info) < 1:
            return

        file_queue = task_info["file_queue"]
        shell_flag = task_info["shell_flag"]
        comp_list = task_info["comp_list"]
        packagename = task_info["packagename"]
        file_identifier = task_info["file_identifier"]
        permissions = task_info["permissions"]
        shell_report = task_info.get("shell_report", [])

        if shell_flag:
            cores.logp('[-] \033[3;31m Error: This application has shell, the retrieval results may not be accurate, Please remove the shell and try again!')
            return

        # 线程控制中心
        cores.logp(
            "[*] =========  Searching for strings that match the rules ===============")
        self.__threads_control__(file_queue, comp_list)

        # 等待线程结束
        for thread in self.thread_list:
            thread.join()
        cores.progress_end()
        if cores.thread_failed:
            cores.logp(cores.i18n.t("[-] Some worker threads aborted, results may be incomplete (see log file)"))

        # 结果输出中心
        self.__print_control__(packagename, comp_list,
                               file_identifier, permissions, shell_report)

    def __tast_control__(self):
        task_info = {}
        # 自动根据文件后缀名称进行修正
        cache_info = DownloadTask().start(self.path, self.types)
        cacar_path = cache_info["path"]
        types = cache_info["type"]

        if (not os.path.exists(cacar_path) and cores.download_flag):
            cores.logp(
                "[-] File download failed! Please download the file manually and try again.")
            return task_info

        # 调用Android 相关处理逻辑
        if types == "Android":
            task_info = AndroidTask(cacar_path, self.package).start()
        # 调用iOS 相关处理逻辑
        elif types == "iOS":
            task_info = iOSTask(cacar_path).start()
        # 调用Web 相关处理逻辑
        else:
            task_info = WebTask(cacar_path).start()
        return task_info

    def __threads_control__(self, file_queue, comp_list):
        for threadID in range(self.threads):
            name = "Thread - " + str(int(threadID))
            thread = ParsesThreads(
                threadID, name, file_queue, self.result_dict, self.types, comp_list)
            thread.start()
            self.thread_list.append(thread)

    def __print_control__(self, packagename, comp_list, file_identifier, permissions, shell_report):
        # 网络嗅探(可选)：返回行数据，xlsx 由 report 统一编排
        sniff_rows = []
        if self.sniffer:
            cores.logp("[*] ========= Sniffing the URL address of the search ===============")
            sniff_rows = NetTask(self.result_dict, self.app_history_list,
                                 self.domain_history_list, file_identifier, self.threads).start()

        # 控制台分区汇总
        if packagename:
            cores.logp("[*] ========= The package name of this APP is: ===============")
            cores.logp(packagename)
        if shell_report:
            cores.logp("[*] ========= Shell detection: ===============")
            for line in shell_report:
                cores.logp("  " + line)
        if len(comp_list) != 0:
            cores.logp("[*] ========= Component information is as follows: ===============")
            for component in comp_list:
                cores.logp("  " + component)
        if len(permissions) != 0:
            cores.logp("[*] ========= Sensitive permission information is as follows: ===============")
            for permission in permissions:
                cores.logp("  " + permission)

        # 分类聚合并落盘三格式报告
        data = report.classify_results(
            self.result_dict,
            set(cores.config.filter_ak_map),
            set(cores.config.filter_pii_map))
        meta = report.build_report_meta(
            os.path.basename(str(self.path)) or "task", self.types)
        extra = {
            "components": list(comp_list),
            "permissions": list(permissions),
            "shell": list(shell_report),
            "sniffer": sniff_rows,
            "details": {fp: sorted(values) for fp, values in self.result_dict.items()},
        }
        for name, writer, path in (("json", report.write_json_report, cores.json_result_path),
                                    ("txt", report.write_txt_report, cores.txt_result_path),
                                    ("xlsx", report.write_xlsx_report, cores.xls_result_path)):
            try:
                writer(path, meta, data, extra)
            except Exception as e:
                cores.logp(cores.i18n.t("[-] Write {} report failed: {}", name, e))

        cores.logp("[*] ========= Summary: ===============")
        cores.logp("  URL: %d    Domain: %d    Private IP: %d    Public IP: %d    IPv6: %d    Loopback: %d" % (
            len(data["urls"]), len(data["hosts"]), len(data["ip_private"]),
            len(data["ip_public"]), len(data["ip_v6"]), len(data["loopback"])))
        cores.logp("  Credentials: %d    PII: %d    Other: %d" % (
            len(data["credentials"]), len(data["pii"]), len(data["other"])))
        cores.logp(cores.i18n.t("[*] Reports saved to: {}", cores.result_dir))

    def __history_handle__(self):
        domain_history_path = cores.domain_history_path
        app_history_path = cores.app_history_path
        # 两个历史文件独立判存：历史上 domain 存在而 app 不存在时直接崩
        app_size = 0
        if os.path.exists(app_history_path):
            with open(app_history_path, "r", encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                app_size = len(lines)
                for line in lines:
                    self.app_history_list.append(
                        line.replace("\r", "").replace("\n", ""))
                f.close()
        if os.path.exists(domain_history_path):

            with open(domain_history_path, "r", encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                cout = 3
                if (app_size > 3) and (app_size % 3 == 0):
                    cout = cout + 1
                for line in lines:
                    domain = line.replace("\r", "").replace("\n", "")
                    self.domain_history_list.append(domain)
                    domain_count = lines.count(line)
                    if domain_count >= cout:
                        cores.config.filter_no.append(".*" + re.escape(domain))
                f.close()
