#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen (微信/WeChat: bromomo )
# Github: https://github.com/kelvinBen/AppInfoScanner
# Gitee: https://gitee.com/kelvin_ben/AppInfoScanner
# AppInfoScanner 工具链自动供给(macOS/Linux)：
#   - Java(apktool/baksmali 的运行时) : brew/apt/dnf/yum/pacman/zypper
#   - adb(脱壳/端口转发)             : 同上；Windows 走仓库自带 unpacker/adb.exe
#   - frida CLI                       : 当前解释器 pip 安装(含 PEP668 回退)
# apktool.jar/baksmali.jar 随工作区部署，无需安装；strings 为系统自带。
# 所有安装命令以参数列表执行并写入 run.log；Linux 下 sudo 需要终端交互输密。
import os
import sys
import shutil
import subprocess

# 各包管理器对应的安装命令(参数列表，不经 shell)
_JAVA_INSTALL = {
    "brew": [("brew", "install", "--cask", "temurin")],
    "apt": [("sudo", "apt-get", "update"), ("sudo", "apt-get", "install", "-y", "default-jre-headless")],
    "dnf": [("sudo", "dnf", "install", "-y", "java-11-openjdk-headless")],
    "yum": [("sudo", "yum", "install", "-y", "java-11-openjdk-headless")],
    "pacman": [("sudo", "pacman", "-S", "--noconfirm", "jre-openjdk-headless")],
    "zypper": [("sudo", "zypper", "--non-interactive", "install", "java-11-openjdk-headless")],
}
_ADB_INSTALL = {
    "brew": ("brew", "install", "android-platform-tools"),
    "apt": ("sudo", "apt-get", "install", "-y", "adb"),
    "dnf": ("sudo", "dnf", "install", "-y", "android-tools"),
    "yum": ("sudo", "yum", "install", "-y", "android-tools"),
    "pacman": ("sudo", "pacman", "-S", "--noconfirm", "android-tools"),
    "zypper": ("sudo", "zypper", "--non-interactive", "install", "android-tools"),
}


def detect_pkg_manager():
    """探测可用的系统包管理器，无则返回 None(无法自动安装)。"""
    for manager in ("brew", "apt-get", "dnf", "yum", "pacman", "zypper"):
        if shutil.which(manager):
            return "apt" if manager == "apt-get" else manager
    return None


def _run_install(cmds):
    """执行安装命令(继承终端以便 sudo 交互)，全部记入日志。"""
    import libs.core as cores
    for cmd in cmds:
        cores.logf("[CMD] " + " ".join(cmd))
        # 不捕获输出: sudo 密码提示与安装进度需要到达用户终端
        if subprocess.call(cmd) != 0:
            return False
    return True


def ensure_java():
    """Java 运行时存在返回 True；缺失则按包管理器自动安装。"""
    import libs.core as cores
    if shutil.which("java"):
        return True
    if os.name == "nt":
        cores.logp("[-] Java not found. Install JDK 11+ manually (e.g. https://adoptium.net).")
        return False
    manager = detect_pkg_manager()
    if manager is None:
        cores.logp("[-] Java missing and no supported package manager (brew/apt/dnf/yum/pacman/zypper). "
                   "Install JDK 11+ manually, e.g. https://adoptium.net")
        return False
    cores.logp(cores.i18n.t("[*] Java not found, auto-installing via {}...", manager))
    if _run_install(_JAVA_INSTALL[manager]) and shutil.which("java"):
        cores.logp(cores.i18n.t("[+] Java installed successfully"))
        return True
    cores.logp(cores.i18n.t("[-] Java auto-install failed, please install JDK 11+ manually"))
    return False


def ensure_adb():
    """返回可用的 adb 可执行文件路径；缺失则自动安装，失败返回 None。"""
    import libs.core as cores
    existing = shutil.which("adb")
    if existing:
        return existing
    if os.name == "nt":
        # Windows 走仓库自带 unpacker/adb.exe
        bundled = getattr(cores, "adb_path", "") or ""
        return bundled if bundled and os.path.exists(bundled) else None
    manager = detect_pkg_manager()
    if manager is None:
        cores.logp("[-] adb not found and no supported package manager. "
                   "Install android-platform-tools/adb manually.")
        return None
    cores.logp(cores.i18n.t("[*] adb not found, auto-installing via {}...", manager))
    if _run_install([_ADB_INSTALL[manager]]) and shutil.which("adb"):
        cores.logp(cores.i18n.t("[+] adb installed successfully"))
        return shutil.which("adb")
    cores.logp(cores.i18n.t("[-] adb auto-install failed, please install android platform-tools manually"))
    return None


_FRIDA_PKGS = ("frida", "frida-tools", "frida-dexdump")


def pinned_frida_requirements():
    """从 requirements.txt 解析 frida 三件套的锁定版本(单一版本源)。

    解析失败(文件缺失/未锁定)时回退为不带版本号的包名。
    """
    import libs.core as cores
    import re as _re2
    try:
        # Bootstrapper 正常会设置 script_root_dir；单测等场景回退 cwd
        script_dir = getattr(cores, "script_root_dir", "") or os.getcwd()
        with open(os.path.join(script_dir, "requirements.txt"), "r", encoding="utf-8") as f:
            content = f.read()
    except OSError:
        return list(_FRIDA_PKGS)
    pinned = []
    for name in _FRIDA_PKGS:
        match = _re2.search(r"^{}==([\d.]+)\s*$".format(_re2.escape(name)),
                            content, _re2.M)
        pinned.append("{}=={}".format(name, match.group(1)) if match else name)
    return pinned


def ensure_frida():
    """frida CLI 与 frida-dexdump 均存在返回 True；缺失则按 requirements 锁定版本 pip 安装。

    frida-dexdump 是独立包(脱壳流程实际调用的可执行文件)，只装 frida-tools 不够。
    """
    import libs.core as cores
    if shutil.which("frida") and shutil.which("frida-dexdump"):
        return True
    targets = pinned_frida_requirements()
    bases = [
        [sys.executable, "-m", "pip", "install", "--user"] + targets,
        [sys.executable, "-m", "pip", "install", "--break-system-packages"] + targets,
    ]
    cores.logp(cores.i18n.t("[*] frida not found, auto-installing via pip..."))
    for cmd in bases:
        cores.logf("[CMD] " + " ".join(cmd))
        if subprocess.call(cmd) == 0:
            # pip 的用户级脚本目录可能不在 PATH 中，补充后重查(追加而非前置，系统路径优先)
            if os.name == "nt":
                user_bin = os.path.join(os.environ.get("APPDATA", ""), "Python", "Scripts")
            else:
                user_bin = os.path.expanduser("~/.local/bin")
            if os.path.isdir(user_bin) and user_bin not in os.environ.get("PATH", ""):
                os.environ["PATH"] += os.pathsep + user_bin
            if shutil.which("frida") and shutil.which("frida-dexdump"):
                cores.logp(cores.i18n.t("[+] frida installed successfully"))
                return True
    cores.logp(cores.i18n.t("[-] frida auto-install failed, run: python3 -m pip install frida-tools"))
    return False


# ---------------------------------------------------------------------------
# frida 版本一致性: Python 侧 frida core 与设备端 frida-server 必须同版本，
# 否则出现 "unable to connect / Failed to enumerate processes" 类故障。
# 以 frida core 版本为基准: 自带 hexl-server 匹配则用之，否则按设备 ABI
# 从 frida 官方 release 下载对应版本 server 到工作区 tools/frida/。
import lzma
import re as _re
import urllib.request

_FRIDA_RELEASE_URL = ("https://github.com/frida/frida/releases/download/"
                      "{version}/frida-server-{version}-android-{arch}.xz")
_ABI_TO_ARCH = {"arm64-v8a": "arm64", "armeabi-v7a": "arm", "armeabi": "arm",
                "x86": "x86", "x86_64": "x86_64"}


def frida_core_version():
    """返回当前解释器安装的 frida core 版本，取不到返回 None。"""
    try:
        output = subprocess.run(
            [sys.executable, "-c", "import frida; print(frida.__version__)"],
            capture_output=True, text=True, timeout=30)
        version = (output.stdout or "").strip()
        return version if _re.match(r"^\d+\.\d+\.\d+$", version) else None
    except Exception:
        return None


def server_matches(server_path, core_version):
    """二进制内嵌版本串包含 core 版本即视为匹配(frida-server 内嵌自身完整版本号)。"""
    try:
        with open(server_path, "rb") as f:
            return core_version.encode() in f.read()
    except OSError:
        return False


def server_version_guess(server_path):
    """诊断用: 从二进制猜测 frida-server 版本(过滤明显非版本的数字串)。"""
    try:
        with open(server_path, "rb") as f:
            data = f.read()
    except OSError:
        return None
    counts = {}
    for match in _re.finditer(rb"(1[0-9]\.(\d{1,2})\.(\d{1,2}))(?![0-9.])", data):
        version = match.group(1).decode()
        counts[version] = counts.get(version, 0) + 1
    if not counts:
        return None
    # 与 core 同版的最优先，其余按出现频次
    core = frida_core_version()
    if core in counts:
        return core
    return max(counts, key=counts.get)


def ensure_frida_server(device_abi, adb_path="adb"):
    """返回与本地 frida core 版本一致的 frida-server 路径。

    顺序: 工作区已下载的同版 server -> 自带 hexl-server(版本匹配时) ->
    从 frida 官方 release 下载对应版本(按设备 ABI) -> 均失败返回 None。
    """
    import libs.core as cores
    core = frida_core_version()
    if not core:
        cores.logp("[-] frida core not importable; run provision.ensure_frida() first")
        return None
    arch = _ABI_TO_ARCH.get((device_abi or "").strip())
    if not arch:
        cores.logp("[-] Unsupported device ABI for frida-server: {}".format(device_abi))
        return None

    hexl_name = "hexl-server-arm64" if arch == "arm64" else "hexl-server-arm32"
    candidates = [
        os.path.join(cores.default_out_root, "tools", "frida",
                     "frida-server-{}-android-{}".format(core, arch)),
        os.path.join(cores.default_out_root, "tools", "unpacker", hexl_name),
    ]
    for path in candidates:
        if os.path.isfile(path):
            if server_matches(path, core):
                cores.logp(cores.i18n.t(
                    "[*] frida core {} <-> frida-server {} aligned ({})", core, core, path))
                return path
            cores.logp(cores.i18n.t(
                "[-] frida-server version mismatch: bundled {} vs core {}, downloading matching release...",
                server_version_guess(path) or "?", core))

    # 从官方 release 下载匹配版本
    url = _FRIDA_RELEASE_URL.format(version=core, arch=arch)
    target_dir = os.path.join(cores.default_out_root, "tools", "frida")
    target = os.path.join(target_dir, "frida-server-{}-android-{}".format(core, arch))
    try:
        os.makedirs(target_dir, exist_ok=True)
        cores.logf("[CMD] download " + url)
        with urllib.request.urlopen(url, timeout=120) as resp:
            compressed = resp.read()
        with open(target, "wb") as f:
            f.write(lzma.decompress(compressed))
        os.chmod(target, 0o755)
        cores.logp(cores.i18n.t("[+] frida-server {} downloaded for {}", core, arch))
        return target
    except Exception as e:
        cores.logp(cores.i18n.t(
            "[-] frida-server download failed ({}); ensure a matching frida-server {} manually",
            e, core))
        return None
