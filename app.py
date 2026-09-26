#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen (微信/WeChat: bromomo )
# Github: https://github.com/kelvinBen/AppInfoScanner
# Gitee: https://gitee.com/kelvin_ben/AppInfoScanner

import os
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
def android(inputs: str, rules: str, sniffer: bool, no_resource: bool, all: bool, threads: int, output,
            package: str, unpack: bool, prefer_dump: str, scope: str) -> None:
    try:
        bootstrapper = Bootstrapper(__file__, output, all, no_resource, inputs)
        bootstrapper.init()

        BaseTask("Android", inputs, rules, sniffer, threads, package,
                 unpack=unpack, prefer_dump=prefer_dump, scope=scope).start()
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
def ios(inputs: str, rules: str, sniffer: bool, no_resource: bool, all: bool, threads: int, output: str, scope: str = None) -> None:
    try:
        bootstrapper = Bootstrapper(__file__, output, all, no_resource, inputs)
        bootstrapper.init()

        BaseTask("iOS", inputs, rules, sniffer, threads, scope=scope).start()
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
def web(inputs: str, rules: str, sniffer: bool, no_resource: bool, all: bool, threads: int, output: str, scope: str = None) -> None:
    try:
        bootstrapper = Bootstrapper(__file__, output, all, no_resource, inputs)
        bootstrapper.init()

        BaseTask("Web", inputs, rules, sniffer, threads, scope=scope).start()
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


def main():
    cli()


if __name__ == "__main__":
    main()
