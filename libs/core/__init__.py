#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen (微信/WeChat: bromomo )
# Github: https://github.com/kelvinBen/AppInfoScanner
# Gitee: https://gitee.com/kelvin_ben/AppInfoScanner
import os
import time
import shutil
import types
import tomllib
import platform
import subprocess
from libs.core import default_config
from libs.core import i18n

# smali 所在路径
smali_path = ""

# backsmli 所在路径
backsmali_path = ""

# apktool 所在路径
apktool_path = ""

# adb 所在路径
adb_path = ""

# frida server 所在路径
frida32_path = ""
frida64_path = ""

# aapt 所在路径
aapt_apth = ""

# 系统类型
os_type = ""

# 输出路径
output_path = ""

# 运行时配置：由 Bootstrapper 以「内置默认值 + 工作区 config.toml」合并填充，
# 消费方统一通过 cores.config.<键> 访问
config = None

# 下载完成标记
download_flag = False

# excel 起始行号
excel_row = 1

# 结果目录、结构化输出路径与集中日志
result_dir = ""
json_result_path = ""
logs_path = ""
log_file_path = ""


def __prune_logs__(logs_dir, keep=20):
    """按修改时间只保留最新 keep 个任务日志，防止 logs/ 无限膨胀。"""
    try:
        log_files = [os.path.join(logs_dir, name) for name in os.listdir(logs_dir)
                     if name.endswith(".log")]
        log_files.sort(key=lambda p: os.path.getmtime(p), reverse=True)
        removed = 0
        for stale in log_files[keep:]:
            os.remove(stale)
            removed += 1
        if removed:
            logp(i18n.t("[*] Pruned {} old log files, kept {}", removed, keep))
    except OSError:
        pass


def __sanitize_sample_name__(inputs):
    """从输入样本路径/URL 提取安全的结果目录名。"""
    import re as _re
    raw = os.path.basename(str(inputs).strip()) if inputs else ""
    raw = raw.rsplit(".", 1)[0] if "." in raw else raw
    raw = _re.sub(r"[^\w\u4e00-\u9fa5.-]", "_", raw).strip("._") or "task"
    return raw[:60]

# 扫描进度计数(线程安全)与单行进度输出：过程信息复用同一行刷新，避免刷屏
import sys as _sys
import logging as _logging
import threading as _threading
_progress_lock = _threading.Lock()
_progress_last = ""
scan_files = 0
scan_hits = 0
sniff_done = 0
# 任一工作线程异常置位：主流程在 join 后提示结果可能不完整
thread_failed = False


# 运行日志：控制台之外，全过程镜像写入结果目录 run.log（排障用）
logger = None
_LEVEL_BY_PREFIX = (("[!]", "WARNING"), ("[-]", "WARNING"), ("[+]", "DEBUG"))


def init_logger(log_path):
    """在结果目录建立 run.log(DEBUG 全量)，控制台输出不受影响。"""
    global logger
    logger = _logging.getLogger("AppInfoScanner")
    logger.setLevel(_logging.DEBUG)
    logger.propagate = False
    handler = _logging.FileHandler(log_path, mode="w", encoding="utf-8")
    handler.setLevel(_logging.DEBUG)
    handler.setFormatter(_logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S"))
    logger.addHandler(handler)
    return logger


# 只写日志文件
def logf(msg):
    msg = i18n.ts(msg)
    if logger:
        level = _logging.INFO
        for prefix, lv in _LEVEL_BY_PREFIX:
            if msg.startswith(prefix):
                level = getattr(_logging, lv)
                break
        logger.log(level, msg)


# 控台+日志双写, flush保证管道场景实时可见
def logp(msg):
    print(i18n.ts(msg), flush=True)
    logf(msg)


# 异常堆栈写入日志
def logexc(tag):
    if logger:
        logger.exception(tag)


# 过程信息单行刷新
def progress(msg):
    global _progress_last
    msg = i18n.ts(msg)
    logf(msg)
    with _progress_lock:
        pad = " " * max(0, len(_progress_last) - len(msg))
        _sys.stdout.write("\r" + msg + pad)
        _sys.stdout.flush()
        _progress_last = msg


# 进度行上方插入完整输出
def notice(msg):
    global _progress_last
    logf(msg)
    with _progress_lock:
        pad = " " * max(0, len(_progress_last) - len(msg))
        _sys.stdout.write("\r" + msg + pad + "\n")
        _sys.stdout.flush()
        _progress_last = ""


# 结束进度行
def progress_end():
    global _progress_last
    with _progress_lock:
        if _progress_last:
            _sys.stdout.write("\n")
            _sys.stdout.flush()
            _progress_last = ""


class Bootstrapper(object):

    def __init__(self, path, out_path, all=False, no_resource=False, inputs=""):
        global smali_path
        global backsmali_path
        global apktool_path
        global adb_path
        global frida32_path
        global frida64_path
        global aapt_apth
        global os_type
        global output_path
        global script_root_dir
        global txt_result_path
        global xls_result_path
        global strings_path
        global history_path
        global app_history_path
        global domain_history_path
        global default_out_root
        global excel_row
        global download_path
        global download_flag
        global out_dir
        global all_flag
        global resource_flag
        global result_dir
        global json_result_path
        global logs_path
        global log_file_path

        all_flag = not all
        resource_flag = no_resource

        create_time = time.strftime("%Y%m%d%H%M%S", time.localtime())
        script_root_dir = os.path.dirname(os.path.abspath(path))
        # 所有输出物默认落在用户文档目录下的 AppInfoScanner 目录；
        # ~/Documents 不存在的环境（部分精简 Linux）回退到用户主目录下的
        # AppInfoScanner（Linux 下即 /home/<用户名>/AppInfoScanner）
        home_dir = os.path.expanduser("~")
        docs_dir = os.path.join(home_dir, "Documents")
        default_out_root = os.path.join(
            docs_dir if os.path.isdir(docs_dir) else home_dir, "AppInfoScanner")
        if out_path:
            out_dir = out_path
        else:
            out_dir = default_out_root
        # 配置与三方工具随用户工作区落盘：首次运行从内置默认值/脚本目录部署到默认根目录，
        # 之后优先使用工作区副本 —— 用户可直接编辑工作区 config.toml、按平台替换工具
        tools_dir = os.path.join(default_out_root, "tools")
        output_path = os.path.join(out_dir, "out")
        # history 为跨运行的累积状态，始终跟随默认输出根目录，不随 -o 变动
        history_path = os.path.join(default_out_root, "history")

        if platform.system() == "Windows":
            machine2bits = {'AMD64': 64, 'x86_64': 64, 'i386': 32, 'x86': 32}
            machine2bits.get(platform.machine())

            if platform.machine() == 'i386' or platform.machine() == 'x86':
                strings_path = os.path.join(tools_dir, "strings.exe")
            else:
                strings_path = os.path.join(tools_dir, "strings64.exe")
        else:
            strings_path = "strings"

        backsmali_path = os.path.join(tools_dir, "baksmali.jar")
        apktool_path = os.path.join(tools_dir, "apktool.jar")
        unpacker_dir = os.path.join(tools_dir, "unpacker")
        adb_path = os.path.join(unpacker_dir, "adb.exe")
        frida32_path = os.path.join(unpacker_dir, "hexl-server-arm32")
        frida64_path = os.path.join(unpacker_dir, "hexl-server-arm64")
        aapt_apth = os.path.join(unpacker_dir, "aapt.exe")
        download_path = os.path.join(out_dir, "download")
        # 结果产物集中到 result/<样本名>_<时间戳>/ 子目录，多任务互不覆盖
        sample_name = __sanitize_sample_name__(inputs)
        result_dir = os.path.join(out_dir, "result",
                                  "%s_%s" % (sample_name, create_time))
        # 日志跟随 -o 输出目录: 排障时用户只需要看一处, 不用翻工作区和 -o 两处
        # 无 -o 时回退到工作区 ~/Documents/AppInfoScanner/logs/, 仅保留最新 20 个
        logs_path = os.path.join(out_dir, "logs")
        log_file_path = os.path.join(logs_path,
                                     "%s_%s.log" % (sample_name, create_time))
        txt_result_path = os.path.join(result_dir, "report.txt")
        xls_result_path = os.path.join(result_dir, "report.xlsx")
        json_result_path = os.path.join(result_dir, "report.json")
        app_history_path = os.path.join(history_path, "app_history.txt")
        domain_history_path = os.path.join(history_path, "domain_history.txt")

    def init(self):
        logp(i18n.t("[*] Output root: {}", out_dir))
        if not os.path.exists(out_dir):
            os.makedirs(out_dir)
            logp(i18n.t("[*] Create directory {}", out_dir))

        if os.path.exists(output_path):
            try:
                shutil.rmtree(output_path)
            except Exception as e:
                # 解决windows超长文件名删除问题
                if not (platform.system() == "Windows"):
                    raise e
                self.__removed_dirs_cmd__(output_path)

        os.makedirs(output_path)
        logp(i18n.t("[*] Create directory {}", output_path))

        if not os.path.exists(download_path):
            os.makedirs(download_path)
            logp(i18n.t("[*] Create directory {}", download_path))

        if not os.path.exists(history_path):
            os.makedirs(history_path)
            logp(i18n.t("[*] Create directory {}", history_path))

        os.makedirs(result_dir, exist_ok=True)
        os.makedirs(logs_path, exist_ok=True)
        init_logger(log_file_path)
        __prune_logs__(logs_path, keep=20)
        logp(i18n.t("[*] Result directory: {}", result_dir))
        logp(i18n.t("[*] Log file: {}", log_file_path))
        from libs.core import updater
        logf("[*] AppInfoScanner v{} start: {} {}".format(
            updater.APP_VERSION, platform.system(), _sys.version.split()[0]))

        self.__deploy_workspace__(script_root_dir, default_out_root)

        # 启动时非阻塞检测新版本(1小时冷却, 不影响正常使用)
        try:
            updater.check_for_update(default_out_root, silent=True)
        except Exception:
            pass  # 更新检测失败不影响正常使用


    # 部署工作区config.toml与tools, 加载合并运行时配置
    def __deploy_workspace__(self, script_root_dir, workspace_root):
        global config
        workspace_toml = os.path.join(workspace_root, "config.toml")
        legacy_py = os.path.join(workspace_root, "config.py")
        if not os.path.exists(workspace_toml):
            if os.path.exists(legacy_py):
                try:
                    legacy = default_config.load_legacy_config(legacy_py)
                    with open(workspace_toml, "w", encoding="utf-8") as f:
                        f.write("# 由旧版工作区 config.py 迁移生成，原文件保留为 config.py.bak\n")
                        f.write(default_config.dump_config(legacy))
                    os.rename(legacy_py, legacy_py + ".bak")
                    logp("[*] Migrated workspace config: config.py -> {} (原文件保留为 config.py.bak)".format(workspace_toml))
                except Exception as e:
                    logp("[-] Migrate legacy config failed ({}), deploy default config.toml".format(e))
                    self.__write_default_toml__(workspace_toml)
            else:
                self.__write_default_toml__(workspace_toml)

        workspace_tools = os.path.join(workspace_root, "tools")
        if not os.path.exists(workspace_tools):
            script_tools = os.path.join(script_root_dir, "tools")
            if os.path.isdir(script_tools):
                ignore = shutil.ignore_patterns(
                    "unpacker", ".DS_Store", "*.bak") if platform.system() != "Windows" else None
                shutil.copytree(script_tools, workspace_tools, ignore=ignore)
                logp(i18n.t("[*] Deploy tools to workspace: {}", workspace_tools))

        try:
            with open(workspace_toml, "rb") as f:
                parsed = tomllib.load(f)
            # 版本检查与自动迁移
            cfg_ver = parsed.get("config_version", "1.0.10")  # 无版本字段视为早期版本
            if default_config.version_lt(cfg_ver, default_config.CONFIG_VERSION):
                logp(i18n.t("[*] Config v{} -> v{} migrating...", cfg_ver, default_config.CONFIG_VERSION))
                parsed, changed = default_config.migrate_config(parsed, cfg_ver)
                if changed:
                    # 有迁移变更时回写 config.toml(保留用户自定义 + 更新版本号)
                    parsed.pop("config_version", None)  # dump_config 会自动写
                    with open(workspace_toml, "w", encoding="utf-8") as f:
                        f.write(default_config.dump_config(parsed))
                    logp("[+] Config migrated to v{}".format(default_config.CONFIG_VERSION))
                else:
                    # 无迁移函数也更新版本号(仅深合并, 不回写文件)
                    logp("[*] Config is compatible, no migration needed")
            merged = default_config.merge_over_defaults(parsed)
        except Exception as e:
            logp("[-] Load workspace config failed ({}), fallback to built-in config".format(e))
            merged = default_config.merge_over_defaults({})
        config = types.SimpleNamespace(**merged)

    def __write_default_toml__(self, workspace_toml):
        with open(workspace_toml, "w", encoding="utf-8") as f:
            f.write(default_config.generate_default_toml())
        logp(i18n.t("[*] Deploy config to workspace: {}", workspace_toml))

    def __removed_dirs_cmd__(self, output_path):
        files = os.listdir(output_path)
        for file in files:
            new_dir = os.path.join(output_path, "newdir")
            old_dir = os.path.join(output_path, file)
            if not os.path.exists(new_dir):
                os.makedirs(new_dir)
            os.chdir(output_path)
            # 使用参数列表调用 robocopy，避免路径含空格时破坏命令；
            # robocopy 的返回码为位掩码，< 8 均表示清理成功
            subprocess.run(["robocopy", new_dir, old_dir, "/purge"])
            os.removedirs(new_dir)
            os.removedirs(old_dir)
