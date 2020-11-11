#!/usr/bin/env python
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
@click.option("-i", "--inputs", required=True, type=str, help="Input APK file or DEX directory.")
@click.option("-r", "--rules", required=False, type=str, default="", help="Add regular search rule.")
@click.option("-s", "--net-sniffer", is_flag=True, default=False, help="Whether to enable network sniffing.")
@click.option("-n", '--no-resource', is_flag=True, default=False,help="Ignore resource files.")
@click.option("-p", '--package',required=False,type=str,default="",help="Specifies the retrieval package name.")
@click.option("-a", '--all-str',is_flag=True, default=False,help="Output all strings.")
@click.option("-t", '--threads',required=False, type=int,default=10,help="Set the number of threads to 10 by default")
def android(inputs: str, rules: str, net_sniffer: bool,no_resource:bool,package:str,all_str:bool,threads:int) -> None:
    try:
        # 初始化全局对象
        bootstrapper = Bootstrapper(__file__)
        bootstrapper.init()

        BaseTask("Android", inputs, rules, net_sniffer, no_resource, package, all_str, threads).start()
    except Exception as e:
        raise e


@cli.command(help="Get the key information of iOS system.")
@click.option("-i", "--inputs", required=True, type=str, help="Input IPA file or ELF file.")
@click.option("-r", "--rules", required=False, type=str, default="", help="Add regular search rule.")
@click.option("-s", "--net-sniffer", is_flag=True, default=False, help="Whether to enable network sniffing.")
@click.option("-n", '--no-resource', is_flag=True, default=False,help="Ignore resource files.")
@click.option("-a", '--all-str',is_flag=True, default=False,help="Output all strings.")
@click.option("-t", '--threads',required=False, type=int,default=10,help="Set the number of threads to 10 by default")
def ios(inputs: str, rules: str, net_sniffer: bool,no_resource:bool,all_str:bool,threads:int) -> None:
    try:
        # 初始化全局对象
        bootstrapper = Bootstrapper(__file__)
        bootstrapper.init()

        BaseTask("iOS", inputs, rules, net_sniffer, no_resource, all_str, threads).start()
        
    except Exception as e:
        raise e


@cli.command(help="Get the key information of Web system.")
@click.option("-i", "--inputs", required=True, type=str, help="Input WebSite dir.")
@click.option("-r", "--rules", required=False, type=str, default="", help="Add regular search rule.")
@click.option("-a", '--all-str',is_flag=True, default=False,help="Output all strings.")
@click.option("-t", '--threads',required=False, type=int,default=10,help="Set the number of threads to 10 by default")
def web(inputs: str, rules: str, all_str:bool,threads:int) -> None:
    try:
        # 初始化全局对象
        bootstrapper = Bootstrapper(__file__)
        bootstrapper.init()

        BaseTask("Web", inputs, rules,all_str, threads).start()

        # task = WebTask(input, rules,all,threads)
        # task.start()

    except Exception as e:
        raise e


def main():
    cli()

if __name__ == "__main__":
    main()

