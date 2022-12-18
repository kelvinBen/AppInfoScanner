#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen
# Github: https://github.com/kelvinBen/AppInfoScanner

import click

from libs.core import Bootstrapper
from libs.task.base_task import BaseTask


@click.group(help="Python script for automatically retrieving key information in app.")
def cli():
    pass


# 创建Android任务


@cli.command(help="Get the key information of Android system.")
@click.option("-i", "--inputs", required=True, type=str,
              help="Please enter the APK file or DEX file to be scanned or the corresponding APK download address.")
@click.option("-r", "--rules", required=False, type=str, default="",
              help="Please enter a rule for temporary scanning of file contents.")
@click.option("-s", "--sniffer", is_flag=True, default=False,
              help="Enable the network sniffer function. It is on by default.")
@click.option("-n", '--no-resource', is_flag=True, default=False,
              help="Ignore all resource files, including network sniffing. It is not enabled by default.")
@click.option("-a", '--all', is_flag=True, default=False,
              help="Output the string content that conforms to the scan rules.It is on by default.")
@click.option("-t", '--threads', required=False, type=int, default=10,
              help="Set the number of concurrency. The larger the concurrency, the faster the speed. The default value is 10.")
@click.option("-o", '--output', required=False, type=str, default=None, help="Specify the result set output directory.")
@click.option("-p", '--package', required=False, type=str, default="",
              help="Specifies the package name information that needs to be scanned.")
def android(inputs: str, rules: str, sniffer: bool, no_resource: bool, all: bool, threads: int, output,
            package: str) -> None:
    try:
        bootstrapper = Bootstrapper(__file__, output, all, no_resource)
        bootstrapper.init()

        BaseTask("Android", inputs, rules, sniffer, threads, package).start()
    except Exception as e:
        raise e


@cli.command(help="Get the key information of iOS system.")
@click.option("-i", "--inputs", required=True, type=str,
              help="Please enter IPA file or ELF file to scan or corresponding IPA download address. App store is not supported at present.")
@click.option("-r", "--rules", required=False, type=str, default="",
              help="Please enter a rule for temporary scanning of file contents.")
@click.option("-s", "--sniffer", is_flag=True, default=False,
              help="Enable the network sniffer function. It is on by default.")
@click.option("-n", '--no-resource', is_flag=True, default=False,
              help="Ignore all resource files, including network sniffing. It is not enabled by default.")
@click.option("-a", '--all', is_flag=True, default=False,
              help="Output the string content that conforms to the scan rules.It is on by default.")
@click.option("-t", '--threads', required=False, type=int, default=10,
              help="Set the number of concurrency. The larger the concurrency, the faster the speed. The default value is 10.")
@click.option("-o", '--output', required=False, type=str, default=None, help="Specify the result set output directory.")
def ios(inputs: str, rules: str, sniffer: bool, no_resource: bool, all: bool, threads: int, output: str) -> None:
    try:
        bootstrapper = Bootstrapper(__file__, output, all, no_resource)
        bootstrapper.init()

        BaseTask("iOS", inputs, rules, sniffer, threads).start()
    except Exception as e:
        raise e


@cli.command(help="Get the key information of Web system.")
@click.option("-i", "--inputs", required=True, type=str,
              help="Please enter the site directory or site file to scan or the corresponding site download address.")
@click.option("-r", "--rules", required=False, type=str, default="",
              help="Please enter a rule for temporary scanning of file contents.")
@click.option("-s", "--sniffer", is_flag=True, default=False,
              help="Enable the network sniffer function. It is on by default.")
@click.option("-n", '--no-resource', is_flag=True, default=False,
              help="Ignore all resource files, including network sniffing. It is not enabled by default.")
@click.option("-a", '--all', is_flag=True, default=False,
              help="Output the string content that conforms to the scan rules.It is on by default.")
@click.option("-t", '--threads', required=False, type=int, default=10,
              help="Set the number of concurrency. The larger the concurrency, the faster the speed. The default value is 10.")
@click.option("-o", '--output', required=False, type=str, default=None, help="Specify the result set output directory.")
def web(inputs: str, rules: str, sniffer: bool, no_resource: bool, all: bool, threads: int, output: str) -> None:
    try:
        bootstrapper = Bootstrapper(__file__, output, all, no_resource)
        bootstrapper.init()

        BaseTask("Web", inputs, rules, sniffer, threads).start()
    except Exception as e:
        raise e


def main():
    cli()


if __name__ == "__main__":
    main()
