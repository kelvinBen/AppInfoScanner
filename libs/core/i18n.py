#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen (微信/WeChat: bromomo )
# Github: https://github.com/kelvinBen/AppInfoScanner
# Gitee: https://gitee.com/kelvin_ben/AppInfoScanner
# AppInfoScanner i18n：按系统语言输出提示。
#
# 语言判定优先级: APPINFO_LANG 环境变量 > LC_ALL/LC_MESSAGES/LANG > locale 探测，
# 均无法判定时默认 zh(现有主要用户群)。
# 边界约定：仅翻译 UI 提示(标题/错误/进度/摘要)；config.toml 中的描述性内容
# (CVE/权限/厂商说明等)是用户数据，保持原文不做翻译。
import os
import locale

_LANG = None

# key 为代码中的消息模板(静态串或带 {} 的动态模板)，值为各语言译文
_CATALOG = {
    # ---- 启动/目录 ----
    "[*] Output root: {}": {"zh": "[*] 输出根目录: {}", "en": "[*] Output root: {}"},
    "[*] Create directory {}": {"zh": "[*] 创建目录 {}", "en": "[*] Create directory {}"},
    "[*] Result directory: {}": {"zh": "[*] 结果目录: {}", "en": "[*] Result directory: {}"},
    "[*] AppInfoScanner v1.0.10 start: {} {}": {"zh": "[*] AppInfoScanner v1.0.10 启动: {} {}", "en": "[*] AppInfoScanner v1.0.10 start: {} {}"},
    # ---- 工作区/配置 ----
    "[*] Deploy config to workspace: {}": {"zh": "[*] 部署配置到工作区: {}", "en": "[*] Deploy config to workspace: {}"},
    "[*] Deploy tools to workspace: {}": {"zh": "[*] 部署工具到工作区: {}", "en": "[*] Deploy tools to workspace: {}"},
    "[*] Migrated workspace config: config.py -> {} (原文件保留为 config.py.bak)": {"zh": "[*] 旧版配置已迁移: config.py -> {} (原文件保留为 config.py.bak)", "en": "[*] Migrated legacy config: config.py -> {} (backup kept as config.py.bak)"},
    "[-] Migrate legacy config failed ({}), deploy default config.toml": {"zh": "[-] 旧配置迁移失败 ({})，改为部署默认 config.toml", "en": "[-] Migrate legacy config failed ({}), deploy default config.toml"},
    "[-] Load workspace config failed ({}), fallback to built-in config": {"zh": "[-] 工作区配置加载失败 ({})，回退内置默认配置", "en": "[-] Load workspace config failed ({}), fallback to built-in config"},
    # ---- 环境/命令 ----
    "[*] Java not found, auto-installing via {}...": {"zh": "[*] 未找到 Java，正在通过 {} 自动安装...", "en": "[*] Java not found, auto-installing via {}..."},
    "[+] Java installed successfully": {"zh": "[+] Java 安装成功", "en": "[+] Java installed successfully"},
    "[-] Java auto-install failed, please install JDK 11+ manually": {"zh": "[-] Java 自动安装失败，请手动安装 JDK 11+", "en": "[-] Java auto-install failed, please install JDK 11+ manually"},
    "[*] adb not found, auto-installing via {}...": {"zh": "[*] 未找到 adb，正在通过 {} 自动安装...", "en": "[*] adb not found, auto-installing via {}..."},
    "[+] adb installed successfully": {"zh": "[+] adb 安装成功", "en": "[+] adb installed successfully"},
    "[-] adb auto-install failed, please install android platform-tools manually": {"zh": "[-] adb 自动安装失败，请手动安装 android platform-tools", "en": "[-] adb auto-install failed, please install android platform-tools manually"},
    "[*] frida not found, auto-installing via pip...": {"zh": "[*] 未找到 frida，正在通过 pip 自动安装...", "en": "[*] frida not found, auto-installing via pip..."},
    "[+] frida installed successfully": {"zh": "[+] frida 安装成功", "en": "[+] frida installed successfully"},
    "[-] frida auto-install failed, run: python3 -m pip install frida-tools": {"zh": "[-] frida 自动安装失败，请执行: python3 -m pip install frida-tools", "en": "[-] frida auto-install failed, run: python3 -m pip install frida-tools"},
    "[*] frida core {} <-> frida-server {} aligned ({})": {"zh": "[*] frida core {} 与 frida-server {} 版本一致 ({})", "en": "[*] frida core {} <-> frida-server {} aligned ({})"},
    "[-] frida-server version mismatch: bundled {} vs core {}, downloading matching release...": {"zh": "[-] frida-server 版本不匹配: 自带 {} 与 core {} 不一致，正在下载匹配版本...", "en": "[-] frida-server version mismatch: bundled {} vs core {}, downloading matching release..."},
    "[+] frida-server {} downloaded for {}": {"zh": "[+] frida-server {} 已下载 ({})", "en": "[+] frida-server {} downloaded for {}"},
    "[-] frida-server download failed ({}); ensure a matching frida-server {} manually": {"zh": "[-] frida-server 下载失败 ({}); 请手动准备版本匹配的 frida-server {}", "en": "[-] frida-server download failed ({}); ensure a matching frida-server {} manually"},
    "Please install the Java environment!": {"zh": "请先安装 Java 环境!", "en": "Please install the Java environment!"},
    "Please install the Frida environment!": {"zh": "请先安装 Frida 环境!", "en": "Please install the Frida environment!"},
    "[-] strings tool not found, skip: {}": {"zh": "[-] 未找到 strings 工具，跳过: {}", "en": "[-] strings tool not found, skip: {}"},
    "[-] Skip large file (>{}MB): {}": {"zh": "[-] 跳过大文件 (>{}MB): {}", "en": "[-] Skip large file (>{}MB): {}"},
    # ---- 文件类型/下载 ----
    "Retrieval of this file type is not supported. Select APK file or DEX file.": {"zh": "不支持的文件类型，请提供 APK 或 DEX 文件。", "en": "Retrieval of this file type is not supported. Select APK file or DEX file."},
    "Retrieval of this file type is not supported. Select IPA file or Mach-o file.": {"zh": "不支持的文件类型，请提供 IPA 或 Mach-O 文件。", "en": "Retrieval of this file type is not supported. Select IPA file or Mach-o file."},
    "[-] Invalid APK file: {}": {"zh": "[-] 无效的 APK 文件: {}", "en": "[-] Invalid APK file: {}"},
    "[-] Invalid IPA file: {}": {"zh": "[-] 无效的 IPA 文件: {}", "en": "[-] Invalid IPA file: {}"},
    "File download failed! Please check the URL/network or configure headers, data and method in config.toml, then download manually.": {"zh": "文件下载失败！请检查 URL/网络，或在 config.toml 中配置 headers、data、method 后重试，也可手动下载。", "en": "File download failed! Please check the URL/network or configure headers, data and method in config.toml, then download manually."},
    "[-] Download failed ({}): {}": {"zh": "[-] 下载失败 ({}): {}", "en": "[-] Download failed ({}): {}"},
    "[*] Download progress: {}% {}": {"zh": "[*] 下载进度: {}% {}", "en": "[*] Download progress: {}% {}"},
    # ---- 反编译/壳 ----
    "[*] Decompilation failed, trying fix_magic repair...": {"zh": "[*] 反编译失败，尝试 fix_magic 修复...", "en": "[*] Decompilation failed, trying fix_magic repair..."},
    "[*] Repair applied, retrying decompilation": {"zh": "[*] 修复完成，重试反编译", "en": "[*] Repair applied, retrying decompilation"},
    "[-] apktool output: {}": {"zh": "[-] apktool 输出: {}", "en": "[-] apktool output: {}"},
    "[-] Decompilation failed, please submit error information at https://github.com/kelvinBen/AppInfoScanner/issues": {"zh": "[-] 反编译失败，请到 https://github.com/kelvinBen/AppInfoScanner/issues 提交错误信息", "en": "[-] Decompilation failed, please submit error information at https://github.com/kelvinBen/AppInfoScanner/issues"},
    "[*] Detect shell by manifest: {} (加固厂商: {})": {"zh": "[*] 壳检测(manifest): {} (加固厂商: {})", "en": "[*] Detect shell by manifest: {} (packer vendor: {})"},
    "[*] Suspected shell: package {} not found in any dex (业务dex被壳加密的典型特征)": {"zh": "[*] 疑似加固: 包名 {} 未出现在任何 dex 中(业务dex被壳加密的典型特征)", "en": "[*] Suspected packer: package {} not found in any dex (business dex encrypted by shell)"},
    "[*] Shell file signatures confirmed ({}): {}": {"zh": "[*] 壳文件特征已确认 ({}): {}", "en": "[*] Shell file signatures confirmed ({}): {}"},
    "[*] Shell suspected but no vendor signature found in decoded output": {"zh": "[*] 疑似加固，但反编译产物中未找到厂商文件特征", "en": "[*] Shell suspected but no vendor signature found in decoded output"},
    "[*] Shell confirmed by manifest only ({} 无文件特征记录)": {"zh": "[*] 仅凭 manifest 确认壳({} 无文件特征记录)", "en": "[*] Shell confirmed by manifest only (no file signatures recorded for {})"},
    "Frida server failed to start, check the terminal output above.": {"zh": "Frida server 启动失败，请检查上方终端输出。", "en": "Frida server failed to start, check the terminal output above."},
    "Failed to install the APK on the device.": {"zh": "APK 安装到设备失败。", "en": "Failed to install the APK on the device."},
    "frida-dexdump unpack failed.": {"zh": "frida-dexdump 脱壳失败。", "en": "frida-dexdump unpack failed."},
    "can't get the app info": {"zh": "无法获取应用信息(aapt)", "en": "can't get the app info (aapt)"},
    "{}: it's not a valid APK(zip) file. Please check the file integrity.": {"zh": "{}: 不是有效的 APK(zip) 文件，请检查文件完整性。", "en": "{}: it's not a valid APK(zip) file. Please check the file integrity."},
    "{}: it's not a valid IPA(zip) file. Please check the file integrity.": {"zh": "{}: 不是有效的 IPA(zip) 文件，请检查文件完整性。", "en": "{}: it's not a valid IPA(zip) file. Please check the file integrity."},
    "Decompilation failed": {"zh": "反编译失败", "en": "Decompilation failed"},
    # ---- 任务流程/输出 ----
    "[*] AI is analyzing filtering rules......": {"zh": "[*] AI 正在分析过滤规则......", "en": "[*] AI is analyzing filtering rules......"},
    "[*] The filtering rules obtained by AI are as follows: {}": {"zh": "[*] AI 得到的过滤规则如下: {}", "en": "[*] The filtering rules obtained by AI are as follows: {}"},
    "[*] =========  Searching for strings that match the rules ===============": {"zh": "[*] =========  正在搜索匹配规则的内容  ===============", "en": "[*] =========  Searching for strings that match the rules  ==============="},
    "[*] ========= The package name of this APP is: ===============": {"zh": "[*] =========  应用包名:  ===============", "en": "[*] =========  Package name:  ==============="},
    "[*] ========= Shell detection: ===============": {"zh": "[*] =========  壳检测:  ===============", "en": "[*] =========  Shell detection:  ==============="},
    "[*] ========= Component information is as follows: ===============": {"zh": "[*] =========  组件信息:  ===============", "en": "[*] =========  Components:  ==============="},
    "[*] ========= Sensitive permission information is as follows: ===============": {"zh": "[*] =========  敏感权限:  ===============", "en": "[*] =========  Sensitive permissions:  ==============="},
    "[*] ========= Sniffing the URL address of the search ===============": {"zh": "[*] =========  正在嗅探搜索到的 URL  ===============", "en": "[*] =========  Sniffing discovered URLs  ==============="},
    "[*] ========= Summary: ===============": {"zh": "[*] =========  摘要:  ===============", "en": "[*] =========  Summary:  ==============="},
    "[*] Progress: {} files scanned, {} hits": {"zh": "[*] 进度: 已扫描 {} 个文件, 命中 {} 条", "en": "[*] Progress: {} files scanned, {} hits"},
    "[*] Skipped sniffing {} internal addresses (kept in reports)": {"zh": "[*] 已跳过 {} 个内网地址的嗅探(仍保留在报告中)", "en": "[*] Skipped sniffing {} internal addresses (kept in reports)"},
    "[*] unpacking": {"zh": "[*] 正在脱壳", "en": "[*] unpacking"},
    "[-] Unpack stage timed out after {}s (suspected anti-debug or device issue)": {"zh": "[-] 脱壳阶段超时({}秒)，疑似反调试或设备异常", "en": "[-] Unpack stage timed out after {}s (suspected anti-debug or device issue)"},
    "[*] Falling back to static scan of shell payload": {"zh": "[*] 降级到壳 payload 静态扫描", "en": "[*] Falling back to static scan of shell payload"},
    "[-] Frida server {} failed (possible anti-debug kill)": {"zh": "[-] Frida server {} 失败(可能被反调试杀掉)", "en": "[-] Frida server {} failed (possible anti-debug kill)"},
    "[-] frida-dexdump failed (target process may be killed by anti-debug)": {"zh": "[-] frida-dexdump 失败(目标进程可能被反调试杀掉)", "en": "[-] frida-dexdump failed (target process may be killed by anti-debug)"},
    "[*] Unpack failed, continuing with static scan of decoded artifacts": {"zh": "[*] 脱壳失败，继续扫描已解出的静态产物", "en": "[*] Unpack failed, continuing with static scan of decoded artifacts"},
    "[*] Scanning pre-dumped DEX from: {}": {"zh": "[*] 扫描已有 dump 目录: {}", "en": "[*] Scanning pre-dumped DEX from: {}"},
    "[*] Scope file loaded: {} domains": {"zh": "[*] 已加载授权域名清单: {} 条", "en": "[*] Scope file loaded: {} domains"},
    "[*] Sniffing restricted to {} scope domains": {"zh": "[*] 嗅探限定在 {} 个授权域名内", "en": "[*] Sniffing restricted to {} scope domains"},
    "[*] Intermediate artifacts in out/: {:.1f} MB, clean with: rm -rf {}": {"zh": "[*] 中间产物 out/ 占用 {:.1f} MB, 清理: rm -rf {}", "en": "[*] Intermediate artifacts in out/: {:.1f} MB, clean with: rm -rf {}"},
    "[*] Log file: {}": {"zh": "[*] 日志文件: {}", "en": "[*] Log file: {}"},
    "[*] Config v{} -> v{} migrating...": {"zh": "[*] 配置格式 v{} -> v{} 迁移中...", "en": "[*] Config v{} -> v{} migrating..."},
    "[-] Cannot reach GitHub for update check. Download manually: {}": {"zh": "[-] 无法连接 GitHub 检测更新，请手动下载: {}", "en": "[-] Cannot reach GitHub for update check. Download manually: {}"},
    "[!] New version available: v{} (current v{}). Run 'python app.py update' or download: {}": {"zh": "[!] 新版本可用: v{}(当前 v{})。执行 python app.py update 或手动下载: {}", "en": "[!] New version available: v{} (current v{}). Run 'python app.py update' or download: {}"},
    "[-] Cannot reach GitHub. Download manually: {} (Gitee: {})": {"zh": "[-] 无法连接 GitHub。请手动下载: {}(Gitee: {})", "en": "[-] Cannot reach GitHub. Download manually: {} (Gitee: {})"},
    "[*] Already up to date (v{})": {"zh": "[*] 已是最新版本(v{})", "en": "[*] Already up to date (v{})"},
    "[*] Updating to v{}...": {"zh": "[*] 正在更新到 v{}...", "en": "[*] Updating to v{}..."},
    "[-] No release package found. Download manually: {}": {"zh": "[-] 未找到发布包。请手动下载: {}", "en": "[-] No release package found. Download manually: {}"},
    "[-] Download failed. Download manually: {} (Gitee: {})": {"zh": "[-] 下载失败。请手动下载: {}(Gitee: {})", "en": "[-] Download failed. Download manually: {} (Gitee: {})"},
    "[+] MD5 verified": {"zh": "[+] MD5 校验通过", "en": "[+] MD5 verified"},
    "[-] MD5 verification failed. File may be corrupted. Please retry.": {"zh": "[-] MD5 校验失败，文件可能损坏，请重试", "en": "[-] MD5 verification failed. File may be corrupted. Please retry."},
    "[+] Updated to v{} successfully": {"zh": "[+] 已成功更新到 v{}", "en": "[+] Updated to v{} successfully"},
    "[*] Please restart the tool to apply changes": {"zh": "[*] 请重启工具以应用更新", "en": "[*] Please restart the tool to apply changes"},
    "[*] Tool updates available: {}": {"zh": "[*] 工具更新可用: {} 个", "en": "[*] Tool updates available: {}"},
    "[*] Sniffing: {} done, current {}": {"zh": "[*] 嗅探: 已完成 {}, 当前 {}", "en": "[*] Sniffing: {} done, current {}"},
    "[+] The string searched for matching rule is: {}": {"zh": "[+] 命中规则的内容: {}", "en": "[+] Hit: {}"},
    "[*] Log file: {}": {"zh": "[*] 日志文件: {}", "en": "[*] Log file: {}"},
    "[*] Pruned {} old log files, kept {}": {"zh": "[*] 已清理 {} 个过期日志，保留最新 {}", "en": "[*] Pruned {} old log files, kept {}"},
    "[*] Loopback capture hint: run a proxy on host, then 'adb reverse tcp:P tcp:P' for ports: {}": {"zh": "[*] 回环抓包提示: 宿主机起代理后执行 adb reverse tcp:P tcp:P, 涉及端口: {}", "en": "[*] Loopback capture hint: run a proxy on host, then 'adb reverse tcp:P tcp:P' for ports: {}"},
    "[*] Reports saved to: {}": {"zh": "[*] 报告已保存至: {}", "en": "[*] Reports saved to: {}"},
    "[-] Write {} report failed: {}": {"zh": "[-] 写入 {} 报告失败: {}", "en": "[-] Write {} report failed: {}"},
    "[-] Some worker threads aborted, results may be incomplete (see log file)": {"zh": "[-] 部分工作线程异常退出，结果可能不完整(详见 run.log)", "en": "[-] Some worker threads aborted, results may be incomplete (see run.log)"},
    "[-] Task failed: {}": {"zh": "[-] 任务失败: {}", "en": "[-] Task failed: {}"},
    "[-] We can't detect protect": {"zh": "[-] 未识别到已知加固", "en": "[-] No known packer detected"},
    "[*] unpacking": {"zh": "[*] 正在脱壳", "en": "[*] unpacking"},
    "[*] Install the APK": {"zh": "[*] 安装 APK", "en": "[*] Install the APK"},
    "Push Frida Server": {"zh": "推送 Frida Server", "en": "Push Frida Server"},
    "[*] Running Frida Server": {"zh": "[*] 启动 Frida Server", "en": "[*] Running Frida Server"},
    "[*] Frida Server started": {"zh": "[*] Frida Server 已启动", "en": "[*] Frida Server started"},
    "[-] Running failed, please check the error in terminal": {"zh": "[-] 运行失败，请检查终端错误输出", "en": "[-] Running failed, please check the error in terminal"},
    "[-] We can't install the APP": {"zh": "[-] 无法安装应用", "en": "[-] We can't install the APP"},
    "[-] An error occurred in the unpack": {"zh": "[-] 脱壳过程出错", "en": "[-] An error occurred in the unpack"},
    "[*] Detected that the task is not local, preparing to download file......": {"zh": "[*] 检测到输入非本地路径，准备下载文件......", "en": "[*] Input is not local, preparing to download......"},
    "[*] The filtering rules obtained by AI are as follows: %s": {"zh": "[*] AI 得到的过滤规则如下: %s", "en": "[*] The filtering rules obtained by AI are as follows: %s"},
}


def detect_lang():
    override = os.environ.get("APPINFO_LANG")
    if override:
        return override.strip().lower()[:2]
    for env in ("LC_ALL", "LC_MESSAGES", "LANG"):
        value = os.environ.get(env)
        if value and value not in ("C", "POSIX"):
            return value.split(".")[0].split("_")[0].lower()[:2]
    try:
        current = locale.getlocale()[0] or locale.getdefaultlocale()[0]
        if current:
            return current.split("_")[0].lower()[:2]
    except Exception:
        pass
    return "zh"


def get_lang():
    global _LANG
    if _LANG is None:
        _LANG = detect_lang()
    return _LANG


def set_lang(lang):
    global _LANG
    _LANG = lang.strip().lower()[:2]


def t(template, *args):
    """动态模板翻译：按目录取译文后 format。无目录条目时原样返回。"""
    entry = _CATALOG.get(template)
    text = entry.get(get_lang(), template) if entry else template
    return text.format(*args) if args else text


def ts(message):
    """静态消息翻译：logp/progress 等出口处对完整消息做精确匹配。"""
    entry = _CATALOG.get(message)
    if entry:
        return entry.get(get_lang(), message)
    return message
