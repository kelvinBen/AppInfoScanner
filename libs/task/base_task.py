#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen (微信/WeChat: bromomo )
# Github: https://github.com/kelvinBen/AppInfoScanner
# Gitee: https://gitee.com/kelvin_ben/AppInfoScanner
import os
import re
import sys as _sys
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

    def __init__(self, types="Android", inputs="", rules="", sniffer=False, threads=10, package="",
                 unpack=False, prefer_dump=None, scope=None, agent=False, output_format="all"):
        # 统一初始化入口
        # 实例级可变状态(不用类属性: 同进程多次任务会累积泄漏)
        self.thread_list = []
        self.result_dict = {}
        self.app_history_list = []
        self.domain_history_list = []
        self.types = types
        self.path = inputs
        if rules:
            cores.config.filter_strs.append(r'.*'+str(rules)+'.*')
        # Agent 模式安全默认: 强制关嗅探(越权交互)、禁止 --unpack(不动设备)、
        # 英文输出、结果目录隔离(agent- 前缀)
        self.agent_mode = bool(agent)
        self.output_format = output_format
        cores.json_only = (output_format == "json-only")
        if self.agent_mode:
            sniffer = False
            if unpack:
                raise cores.TaskError("--unpack is not allowed in agent mode")
        self.sniffer = sniffer  # --sniffer 显式开启, 默认关闭
        self.threads = threads
        self.package = package
        self.unpack_enabled = unpack
        self.prefer_dump = prefer_dump
        self.scope_file = scope
        self.scope_domains = self.__load_scope__() if scope else None
        self.file_queue = Queue()

    # Agent 断点续扫: 已处理文件 MD5 缓存, 重试时跳过;
    # 锚定输出根(out_dir 全局): out/ 下按运行实例建子目录且会被裁剪, 缓存不能落那里
    def __agent_cache_path__(self):
        base = str(getattr(cores, "out_dir", "")) or os.path.dirname(str(cores.output_path))
        return os.path.join(base, "agent-cache.json")

    @staticmethod
    def __file_md5__(path):
        import hashlib
        try:
            h = hashlib.md5()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except OSError:
            return None

    def __filter_queue_by_cache__(self, scan_queue):
        # 过滤的是任务实际队列(任务侧新建的 Queue), 不是 self.file_queue
        if not self.agent_mode:
            return
        done = {}
        try:
            import json
            with open(self.__agent_cache_path__(), "r", encoding="utf-8") as f:
                done = json.load(f).get("files", {})
        except (OSError, ValueError):
            pass
        keep, skipped = [], 0
        while not scan_queue.empty():
            item = scan_queue.get()
            digest = self.__file_md5__(item)
            if digest and digest in done:
                skipped += 1
                continue
            keep.append(item)
        for item in keep:
            scan_queue.put(item)
        self._scanned_md5 = [d for d in (self.__file_md5__(x) for x in keep) if d]
        if skipped:
            cores.logp(cores.i18n.t(
                "[*] Agent resume: skipped {} cached files", skipped))

    def __record_agent_cache__(self):
        if not self.agent_mode or not getattr(self, "_scanned_md5", None):
            return
        import json
        import time
        cache_path = self.__agent_cache_path__()
        done = {}
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                done = json.load(f).get("files", {})
        except (OSError, ValueError):
            pass
        for digest in self._scanned_md5:
            done[digest] = {"ts": time.strftime("%Y-%m-%d %H:%M:%S")}
        try:
            os.makedirs(os.path.dirname(cache_path), exist_ok=True)
            # 原子写(tmp+rename): 并行实例同时记录时不损坏, 最多丢一次合并
            tmp_path = cache_path + ".tmp." + str(os.getpid())
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump({"files": done}, f, ensure_ascii=False, indent=2)
            os.replace(tmp_path, cache_path)
        except OSError as e:
            cores.logf("[AGENT] write cache failed: {}".format(e))

    # 加载授权域名清单(每行一个域名或后缀)，仅名单内的域名参与嗅探
    def __load_scope__(self):
        try:
            with open(self.scope_file, "r", encoding="utf-8") as f:
                domains = [line.strip().lower() for line in f
                           if line.strip() and not line.startswith("#")]
            if domains:
                cores.logp(cores.i18n.t("[*] Scope file loaded: {} domains", len(domains)))
            return set(domains)
        except OSError as e:
            # 授权边界读失败必须拒止(deny-all): 空集合会让所有域名都出名单, 不回退到不限量嗅探
            cores.logp("[-] Failed to read scope file: {} — sniffing disabled".format(e))
            return set()

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
        # iOS/web 的组件为行式条目, 统一包装为结构化明细(报告用)
        comp_detail = task_info.get("comp_detail") or [
            {"component": c, "desc": "", "host": "应用本体", "version": "", "verdict": ""}
            for c in comp_list]
        packagename = task_info["packagename"]
        file_identifier = task_info["file_identifier"]
        permissions = task_info["permissions"]
        shell_report = task_info.get("shell_report", [])

        if shell_flag:
            cores.logp('[-] \033[3;31m Error: This application has shell, the retrieval results may not be accurate, Please remove the shell and try again!')
            for line in shell_report:
                cores.logp("  " + line)
            raise cores.ShellDetected("shell detected: " + "; ".join(shell_report[:2]))

        # 线程控制中心(agent 模式先按 MD5 缓存过滤, 重试跳过已处理文件)
        self.__filter_queue_by_cache__(file_queue)
        cores.logp(
            "[*] =========  Searching for strings that match the rules ===============")
        self.__threads_control__(file_queue, comp_list)

        # 等待线程结束
        for thread in self.thread_list:
            thread.join()
        self.__record_agent_cache__()
        cores.progress_end()
        if cores.thread_failed:
            cores.logp(cores.i18n.t("[-] Some worker threads aborted, results may be incomplete (see log file)"))

        # 结果输出中心
        self.__print_control__(packagename, comp_list,
                               file_identifier, permissions, shell_report, comp_detail)

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
            task_info = AndroidTask(cacar_path, self.package,
                                    unpack=self.unpack_enabled,
                                    prefer_dump=self.prefer_dump).start()
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

    def __print_control__(self, packagename, comp_list, file_identifier, permissions, shell_report, comp_detail=None):
        # 网络嗅探(可选)：返回行数据，xlsx 由 report 统一编排
        sniff_rows = []
        if self.sniffer:
            cores.logp("[*] ========= Sniffing the URL address of the search ===============")
            sniff_rows = NetTask(self.result_dict, self.app_history_list,
                                 self.domain_history_list, file_identifier, self.threads,
                                 scope_domains=self.scope_domains).start()

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

        # AI 语义复核(默认关闭): pii/credentials 命中送 LLM 结构化判定
        # + 多模态资产理解(解码产物下的图片/音频)
        from libs.core import ai_verify
        ai_verdicts = ai_verify.run_verify(self.result_dict)
        ai_assets = ai_verify.run_asset_review(str(cores.output_path))
        if ai_verdicts:
            confirm = sum(1 for v in ai_verdicts if v["verdict"] == "confirm")
            cores.logp(cores.i18n.t(
                "[*] ========= AI verdict summary: {} total / {} confirm ===============",
                len(ai_verdicts), confirm))

        # 分类聚合并落盘三格式报告
        data = report.classify_results(
            self.result_dict,
            set(cores.config.filter_ak_map),
            set(cores.config.filter_pii_map))
        meta = report.build_report_meta(
            os.path.basename(str(self.path)) or "task", self.types, agent=self.agent_mode)
        extra = {
            "components": list(comp_list),
            "components_detail": list(comp_detail or []),
            "permissions": list(permissions),
            "shell": list(shell_report),
            "sniffer": sniff_rows,
            "ai_verdict": list(ai_verdicts),
            "ai_assets": list(ai_assets),
            "details": {fp: sorted(values) for fp, values in self.result_dict.items()},
        }
        for name, writer, path in (("json", report.write_json_report, cores.json_result_path),
                                    ("txt", report.write_txt_report, cores.txt_result_path),
                                    ("xlsx", report.write_xlsx_report, cores.xls_result_path)):
            if self.output_format == "json-only" and name != "json":
                continue
            try:
                writer(path, meta, data, extra)
            except Exception as e:
                cores.logp(cores.i18n.t("[-] Write {} report failed: {}", name, e))
        if self.output_format == "json-only":
            import json as _json
            _sys.stdout.write(_json.dumps(
                report.build_report_payload(meta, data, extra), ensure_ascii=False) + "\n")
            _sys.stdout.flush()

        cores.logp("[*] ========= Summary: ===============")
        cores.logp("  URL: %d    Domain: %d    Private IP: %d    Public IP: %d    IPv6: %d    Loopback: %d" % (
            len(data["urls"]), len(data["hosts"]), len(data["ip_private"]),
            len(data["ip_public"]), len(data["ip_v6"]), len(data["loopback"])))
        cores.logp("  Credentials: %d    PII: %d    Other: %d" % (
            len(data["credentials"]), len(data["pii"]), len(data["other"])))
        # 中间产物占用报告
        out_size = self.__dir_size__(cores.output_path)
        if out_size > 1024 * 1024:
            cores.logp(cores.i18n.t(
                "[*] Intermediate artifacts in out/: {:.1f} MB, clean with: rm -rf {}",
                out_size / 1048576, cores.output_path))
        cores.logp(cores.i18n.t("[*] Reports saved to: {}", cores.result_dir))

    # 递归计算目录占用
    @staticmethod
    def __dir_size__(path):
        total = 0
        try:
            for root, _, files in os.walk(path):
                for name in files:
                    try:
                        total += os.path.getsize(os.path.join(root, name))
                    except OSError:
                        pass
        except OSError:
            pass
        return total

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
