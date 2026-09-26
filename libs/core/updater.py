#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen (微信/WeChat: bromomo )
# Github: https://github.com/kelvinBen/AppInfoScanner
# Gitee: https://gitee.com/kelvin_ben/AppInfoScanner
# 自动更新: 从 GitHub Release 检测/下载/MD5验证, 工具链版本管理
import os
import sys
import json
import time
import hashlib
import zipfile
import shutil
import tempfile
import urllib.request
import urllib.error

# 当前程序版本(与 update.md / README 徽章保持同步)
APP_VERSION = "1.0.11"

# Release 信息源
GITHUB_API = "https://api.github.com/repos/kelvinBen/AppInfoScanner/releases/latest"
GITHUB_RELEASE_PAGE = "https://github.com/kelvinBen/AppInfoScanner/releases/latest"
GITEE_PAGE = "https://gitee.com/kelvin_ben/AppInfoScanner/releases"

# 工具链版本清单(与 tools/ 目录对应)
TOOL_MANIFEST = {
    "apktool.jar": {"version": "3.0.3", "type": "jar"},
    "baksmali.jar": {"version": "2.5.2-dev", "type": "jar"},
}

# 检测缓存(避免每次启动都请求 API)
_CHECK_INTERVAL = 3600  # 秒
_CACHE_FILE = ".update_check"


# 从 GitHub API 获取最新 Release 信息
def fetch_latest_release():
    try:
        req = urllib.request.Request(GITHUB_API, headers={"User-Agent": "AppInfoScanner"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return {
            "tag": data.get("tag_name", ""),
            "url": data.get("html_url", GITHUB_RELEASE_PAGE),
            "body": data.get("body", ""),
            "assets": [
                {"name": a["name"], "url": a["browser_download_url"],
                 "size": a["size"], "md5": _extract_md5(a.get("body", ""))}
                for a in data.get("assets", [])
            ],
        }
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, OSError):
        return None


# 从 Release body 中提取 MD5(格式: "MD5: xxx" 或 asset 描述)
def _extract_md5(text):
    import re
    m = re.search(r'[Mm][Dd]5[:\s]+([a-f0-9]{32})', text or "")
    return m.group(1) if m else None


# 版本比较: a < b 返回 True
def version_lt(a, b):
    pa = [int(x) for x in a.lstrip("Vv").split("_")[0].split(".") if x.isdigit()]
    pb = [int(x) for x in b.lstrip("Vv").split("_")[0].split(".") if x.isdigit()]
    for i in range(max(len(pa), len(pb))):
        va = pa[i] if i < len(pa) else 0
        vb = pb[i] if i < len(pb) else 0
        if va < vb:
            return True
        if va > vb:
            return False
    return False


# 是否需要检测更新(冷却时间)
def _should_check(workspace_root):
    cache = os.path.join(workspace_root, _CACHE_FILE)
    if not os.path.exists(cache):
        return True
    try:
        return time.time() - os.path.getmtime(cache) > _CHECK_INTERVAL
    except OSError:
        return True


# 写入检测缓存
def _touch_cache(workspace_root):
    cache = os.path.join(workspace_root, _CACHE_FILE)
    try:
        with open(cache, "w") as f:
            f.write(str(time.time()))
    except OSError:
        pass


# 启动时非阻塞检测: 有新版本时输出提示
def check_for_update(workspace_root, silent=True):
    import libs.core as cores
    if not _should_check(workspace_root):
        return None
    _touch_cache(workspace_root)
    release = fetch_latest_release()
    if not release:
        if not silent:
            cores.logp(cores.i18n.t(
                "[-] Cannot reach GitHub for update check. Download manually: {}", GITHUB_RELEASE_PAGE))
        return None
    latest_ver = release["tag"].lstrip("Vv").split("_")[0]
    if version_lt(APP_VERSION, latest_ver):
        cores.logp(cores.i18n.t(
            "[!] New version available: v{} (current v{}). Run 'python app.py update' or download: {}",
            latest_ver, APP_VERSION, release["url"]))
        return release
    return None


# MD5 校验
def verify_md5(file_path, expected_md5):
    if not expected_md5:
        return True  # 无期望值时跳过校验
    md5 = hashlib.md5(open(file_path, "rb").read()).hexdigest()
    return md5 == expected_md5


# 下载文件(带进度提示)
def download_file(url, dest_path, timeout=300):
    import libs.core as cores
    try:
        cores.logf("[CMD] download " + url)
        req = urllib.request.Request(url, headers={"User-Agent": "AppInfoScanner"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            total = int(resp.headers.get("Content-Length", 0))
            with open(dest_path, "wb") as f:
                downloaded = 0
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total > 0:
                        cores.progress("[*] Download: {:.0f}%".format(downloaded / total * 100))
        cores.progress_end()
        return True
    except (urllib.error.URLError, OSError) as e:
        cores.progress_end()
        cores.logp("[-] Download failed: {}".format(e))
        return False


# 执行更新: 下载 zip -> MD5 校验 -> 解压替换
def perform_update(workspace_root):
    import libs.core as cores
    release = fetch_latest_release()
    if not release:
        cores.logp(cores.i18n.t(
            "[-] Cannot reach GitHub. Download manually: {} (Gitee: {})", GITHUB_RELEASE_PAGE, GITEE_PAGE))
        return False

    latest_ver = release["tag"].lstrip("Vv").split("_")[0]
    if not version_lt(APP_VERSION, latest_ver):
        cores.logp(cores.i18n.t("[*] Already up to date (v{})", APP_VERSION))
        return True

    cores.logp(cores.i18n.t("[*] Updating to v{}...", latest_ver))

    # 找到 zip 附件
    asset = next((a for a in release["assets"] if a["name"].endswith(".zip")), None)
    if not asset:
        cores.logp(cores.i18n.t(
            "[-] No release package found. Download manually: {}", release["url"]))
        return False

    # 下载到临时目录
    tmp_dir = tempfile.mkdtemp(prefix="ais_update_")
    zip_path = os.path.join(tmp_dir, asset["name"])
    if not download_file(asset["url"], zip_path):
        shutil.rmtree(tmp_dir, ignore_errors=True)
        cores.logp(cores.i18n.t(
            "[-] Download failed. Download manually: {} (Gitee: {})", GITHUB_RELEASE_PAGE, GITEE_PAGE))
        return False

    # MD5 校验
    if not verify_md5(zip_path, asset.get("md5")):
        shutil.rmtree(tmp_dir, ignore_errors=True)
        cores.logp("[-] MD5 verification failed. File may be corrupted. Please retry.")
        return False
    cores.logp(cores.i18n.t("[+] MD5 verified"))

    # 解压到脚本目录(替换当前安装)
    script_dir = os.path.dirname(os.path.abspath(sys.argv[0])) or os.getcwd()
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            # 检查 zip 根目录结构(可能带一级目录)
            names = zf.namelist()
            root_prefix = ""
            first_parts = set(n.split("/")[0] for n in names if n and not n.endswith("/"))
            if len(first_parts) == 1:
                root_prefix = list(first_parts)[0] + "/"

            for name in names:
                if name.endswith("/"):
                    continue
                rel = name[len(root_prefix):] if root_prefix and name.startswith(root_prefix) else name
                if not rel:
                    continue
                target = os.path.join(script_dir, rel)
                os.makedirs(os.path.dirname(target), exist_ok=True)
                zf.extract(name, tmp_dir)
                shutil.copy2(os.path.join(tmp_dir, name), target)
        cores.logp(cores.i18n.t("[+] Updated to v{} successfully", latest_ver))
        cores.logp(cores.i18n.t("[*] Please restart the tool to apply changes"))
        return True
    except (zipfile.BadZipFile, OSError) as e:
        cores.logp("[-] Extract failed: {}".format(e))
        return False
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# 工具链版本检测与更新(tools/ 目录下的 jar 文件)
def check_tools(script_dir):
    import libs.core as cores
    updates = []
    for name, info in TOOL_MANIFEST.items():
        path = os.path.join(script_dir, "tools", name)
        if not os.path.exists(path):
            updates.append((name, "missing", info["version"]))
            continue
        # jar 文件从内部 manifest 读版本
        actual = _jar_version(path)
        if actual and actual != info["version"]:
            updates.append((name, actual, info["version"]))
    if updates:
        cores.logp(cores.i18n.t("[*] Tool updates available: {}", len(updates)))
        for name, current, expected in updates:
            cores.logp("  {} : {} -> {}".format(name, current, expected))
    return updates


# 从 jar 文件的 META-INF/MANIFEST.MF 读版本
def _jar_version(jar_path):
    try:
        with zipfile.ZipFile(jar_path, "r") as zf:
            manifest = zf.read("META-INF/MANIFEST.MF").decode("utf-8", "ignore")
            import re
            m = re.search(r'Implementation-Version:\s*(.+)', manifest)
            if m:
                return m.group(1).strip()
            m = re.search(r'Bundle-Version:\s*(.+)', manifest)
            if m:
                return m.group(1).strip()
    except (zipfile.BadZipFile, KeyError, OSError):
        pass
    return None
