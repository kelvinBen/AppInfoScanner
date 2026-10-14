#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen (微信/WeChat: bromomo )
# Github: https://github.com/kelvinBen/AppInfoScanner
# Gitee: https://gitee.com/kelvin_ben/AppInfoScanner

import os
import sys

import click

import libs.core as cores
from libs.core import Bootstrapper
from libs.task.base_task import BaseTask
from libs.core import updater


@click.group(help="Python script for automatically retrieving key information in app.")
def cli():
    pass


# 创建Android任务


@cli.command(help="Get the key information of Android system.")
@click.option("-i", "--inputs", required=True, type=str,
              help="Please enter the APK file or DEX file to be scanned or the corresponding APK download address.")
@click.option("-r", "--rules", required=False, type=str, default="",
              help="Please enter a rule for temporary scanning of file contents.")
@click.option("-n", '--no-resource', is_flag=True, default=False,
              help="Ignore all resource files, including network sniffing. It is not enabled by default.")
@click.option("-a", '--all', is_flag=True, default=False,
              help="Output the string content that conforms to the scan rules.It is on by default.")
@click.option("-t", '--threads', required=False, type=int, default=10,
              help="Set the number of concurrency. The larger the concurrency, the faster the speed. The default value is 10.")
@click.option("-o", '--output', required=False, type=str, default=None, help="Specify the result set output directory.")
@click.option("-p", '--package', required=False, type=str, default="",
              help="Specifies the package name information that needs to be scanned.")
# ---- V1.0.11 行为安全: 脱壳必须显式开启, 嗅探默认关闭 ----
@click.option("--unpack", is_flag=True, default=False,
              help="Explicitly unpack a hardened APK (pushes frida-server to the device). Default: report only.")
@click.option("--prefer-dump", required=False, type=str, default=None,
              help="Scan a directory of already-dumped DEX files instead of unpacking.")
@click.option("--sniffer/--no-sniffer", default=False,
              help="Enable network sniffing (default: disabled for safety).")
@click.option("--scope", required=False, type=str, default=None,
              help="Path to an authorized-domain list file; only listed domains are sniffed.")
@click.option("--agent", is_flag=True, default=False,
              help="AI Agent mode: sniffing forced off, --unpack banned, English output, isolated results.")
@click.option("--redact", required=False,
              type=click.Choice(["none", "hash", "full"]), default=None,
              help="Output redaction level (default: hash in agent mode, none otherwise).")
@click.option("--format", "output_format", required=False,
              type=click.Choice(["all", "json-only"]), default="all",
              help="Output format: json-only prints the report JSON to stdout (for Agent piping).")
@click.option("--timeout", required=False, type=int, default=None,
              help="Total task timeout in seconds (agent mode defaults to 300).")
def android(inputs: str, rules: str, sniffer: bool, no_resource: bool, all: bool, threads: int, output,
            package: str, unpack: bool, prefer_dump: str, scope: str, agent: bool, redact: str = None, output_format: str = "all", timeout: int = None) -> None:
    if agent:
        os.environ["APPINFO_LANG"] = "en"
        output = output or "agent-out"
    cores.redact_mode = redact or ("hash" if agent else "none")
    deadline = timeout if timeout else (300 if agent else None)

    def _run():
        BaseTask("Android", inputs, rules, sniffer, threads, package,
                 unpack=unpack, prefer_dump=prefer_dump, scope=scope, agent=agent,
                 output_format=output_format).start()

    try:
        bootstrapper = Bootstrapper(__file__, output, all, no_resource, inputs)
        bootstrapper.init()
        _run_with_timeout(_run, deadline)
    except TimeoutError as e:
        cores.logexc("[!] Task aborted")
        cores.logp(cores.i18n.t("[-] Task failed: {}", e))
        sys.exit(cores.TaskTimeout.exit_code)
    except cores.TaskError as e:
        cores.logexc("[!] Task aborted")
        cores.logp(cores.i18n.t("[-] Task failed: {}", e))
        sys.exit(getattr(e, "exit_code", 1))
    except Exception as e:
        cores.logexc("[!] Task aborted")
        cores.logp(cores.i18n.t("[-] Task failed: {}", e))
        raise e


@cli.command(help="Get the key information of iOS system.")
@click.option("-i", "--inputs", required=True, type=str,
              help="Please enter IPA file or ELF file to scan or corresponding IPA download address. App store is not supported at present.")
@click.option("-r", "--rules", required=False, type=str, default="",
              help="Please enter a rule for temporary scanning of file contents.")
@click.option("--sniffer/--no-sniffer", default=False,
              help="Enable network sniffing (default: disabled for safety).")
@click.option("--scope", required=False, type=str, default=None,
              help="Path to an authorized-domain list file; only listed domains are sniffed.")
@click.option("-n", '--no-resource', is_flag=True, default=False,
              help="Ignore all resource files, including network sniffing. It is not enabled by default.")
@click.option("-a", '--all', is_flag=True, default=False,
              help="Output the string content that conforms to the scan rules.It is on by default.")
@click.option("-t", '--threads', required=False, type=int, default=10,
              help="Set the number of concurrency. The larger the concurrency, the faster the speed. The default value is 10.")
@click.option("-o", '--output', required=False, type=str, default=None, help="Specify the result set output directory.")
@click.option("--agent", is_flag=True, default=False,
              help="AI Agent mode: sniffing forced off, --unpack banned, English output, isolated results.")
@click.option("--redact", required=False,
              type=click.Choice(["none", "hash", "full"]), default=None,
              help="Output redaction level (default: hash in agent mode, none otherwise).")
@click.option("--format", "output_format", required=False,
              type=click.Choice(["all", "json-only"]), default="all",
              help="Output format: json-only prints the report JSON to stdout (for Agent piping).")
@click.option("--timeout", required=False, type=int, default=None,
              help="Total task timeout in seconds (agent mode defaults to 300).")
def ios(inputs: str, rules: str, sniffer: bool, no_resource: bool, all: bool, threads: int, output: str, scope: str = None, agent: bool = False, redact: str = None, output_format: str = "all", timeout: int = None) -> None:
    if agent:
        os.environ["APPINFO_LANG"] = "en"
        output = output or "agent-out"
    cores.redact_mode = redact or ("hash" if agent else "none")
    deadline = timeout if timeout else (300 if agent else None)

    def _run():
        BaseTask("iOS", inputs, rules, sniffer, threads, scope=scope,
                 agent=agent, output_format=output_format).start()

    try:
        bootstrapper = Bootstrapper(__file__, output, all, no_resource, inputs)
        bootstrapper.init()
        _run_with_timeout(_run, deadline)
    except TimeoutError as e:
        cores.logexc("[!] Task aborted")
        cores.logp(cores.i18n.t("[-] Task failed: {}", e))
        sys.exit(cores.TaskTimeout.exit_code)
    except cores.TaskError as e:
        cores.logexc("[!] Task aborted")
        cores.logp(cores.i18n.t("[-] Task failed: {}", e))
        sys.exit(getattr(e, "exit_code", 1))
    except Exception as e:
        cores.logexc("[!] Task aborted")
        cores.logp(cores.i18n.t("[-] Task failed: {}", e))
        raise e


@cli.command(help="Get the key information of Web system.")
@click.option("-i", "--inputs", required=True, type=str,
              help="Please enter the site directory or site file to scan or the corresponding site download address.")
@click.option("-r", "--rules", required=False, type=str, default="",
              help="Please enter a rule for temporary scanning of file contents.")
@click.option("--sniffer/--no-sniffer", default=False,
              help="Enable network sniffing (default: disabled for safety).")
@click.option("--scope", required=False, type=str, default=None,
              help="Path to an authorized-domain list file; only listed domains are sniffed.")
@click.option("-n", '--no-resource', is_flag=True, default=False,
              help="Ignore all resource files, including network sniffing. It is not enabled by default.")
@click.option("-a", '--all', is_flag=True, default=False,
              help="Output the string content that conforms to the scan rules.It is on by default.")
@click.option("-t", '--threads', required=False, type=int, default=10,
              help="Set the number of concurrency. The larger the concurrency, the faster the speed. The default value is 10.")
@click.option("-o", '--output', required=False, type=str, default=None, help="Specify the result set output directory.")
@click.option("--agent", is_flag=True, default=False,
              help="AI Agent mode: sniffing forced off, --unpack banned, English output, isolated results.")
@click.option("--redact", required=False,
              type=click.Choice(["none", "hash", "full"]), default=None,
              help="Output redaction level (default: hash in agent mode, none otherwise).")
@click.option("--format", "output_format", required=False,
              type=click.Choice(["all", "json-only"]), default="all",
              help="Output format: json-only prints the report JSON to stdout (for Agent piping).")
@click.option("--timeout", required=False, type=int, default=None,
              help="Total task timeout in seconds (agent mode defaults to 300).")
def web(inputs: str, rules: str, sniffer: bool, no_resource: bool, all: bool, threads: int, output: str, scope: str = None, agent: bool = False, redact: str = None, output_format: str = "all", timeout: int = None) -> None:
    if agent:
        os.environ["APPINFO_LANG"] = "en"
        output = output or "agent-out"
    cores.redact_mode = redact or ("hash" if agent else "none")
    deadline = timeout if timeout else (300 if agent else None)

    def _run():
        BaseTask("Web", inputs, rules, sniffer, threads, scope=scope,
                 agent=agent, output_format=output_format).start()

    try:
        bootstrapper = Bootstrapper(__file__, output, all, no_resource, inputs)
        bootstrapper.init()
        _run_with_timeout(_run, deadline)
    except TimeoutError as e:
        cores.logexc("[!] Task aborted")
        cores.logp(cores.i18n.t("[-] Task failed: {}", e))
        sys.exit(cores.TaskTimeout.exit_code)
    except cores.TaskError as e:
        cores.logexc("[!] Task aborted")
        cores.logp(cores.i18n.t("[-] Task failed: {}", e))
        sys.exit(getattr(e, "exit_code", 1))
    except Exception as e:
        cores.logexc("[!] Task aborted")
        cores.logp(cores.i18n.t("[-] Task failed: {}", e))
        raise e


# 检查更新/执行更新/工具版本
@cli.command(help="Check and install updates.")
@click.option("--check", is_flag=True, default=False, help="Only check for updates, do not install.")
@click.option("--tools", is_flag=True, default=False, help="Check tool versions (apktool/baksmali).")
def update(check, tools):
    if tools:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        updates = updater.check_tools(script_dir)
        if not updates:
            print("All tools are up to date.")
        return
    if check:
        release = updater.fetch_latest_release()
        if not release:
            print("Cannot reach GitHub. Download manually:")
            print("  https://github.com/kelvinBen/AppInfoScanner/releases/latest")
            print("  https://gitee.com/kelvin_ben/AppInfoScanner/releases")
            return
        latest = release["tag"].lstrip("Vv").split("_")[0]
        print("Current: v{}  Latest: v{}".format(updater.APP_VERSION, latest))
        if updater.version_lt(updater.APP_VERSION, latest):
            print("Update available. Run 'python app.py update' to install.")
        else:
            print("Already up to date.")
        return
    # 执行更新
    updater.perform_update(os.path.expanduser("~"))


# 总超时执行: daemon 线程 + join(seconds); 超时抛 TimeoutError(退出码 3)
def _run_with_timeout(fn, seconds):
    import threading
    if not seconds:
        fn()
        return
    worker = threading.Thread(target=fn, daemon=True)
    worker.start()
    worker.join(seconds)
    if worker.is_alive():
        raise TimeoutError("task exceeded {}s total timeout".format(seconds))


# 引导式配置(非规则层): 分步向导, 每步可 q 取消, 写回前备份
@cli.command(help="Guided configuration for non-rule settings (interactive wizard).")
@click.option("--section", required=False,
              type=click.Choice(["all", "ai", "download", "space"]),
              default="all", help="Section to configure (default: all).")
def init(section):
    from libs.core import wizard
    try:
        wizard.run(section)
    except wizard.Cancel:
        print("[*] 已取消, 未做任何修改")
    except OSError as e:
        print("[-] {}".format(e))


def main():
    cli()


if __name__ == "__main__":
    main()
