#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: kelvinBen
# Github: https://github.com/kelvinBen/AppInfoScanner


import click

from libs.core import Bootstrapper
from libs.task.android_task import AndroidTask
from libs.task.ios_task import iOSTask
from libs.task.web_task import WebTask

@click.group(help="Python script for automatically retrieving key information in app.")
def cli():
    pass

# 创建Android任务
@cli.command(help="Get the key information of Android system.")
@click.option("-i", "--input", required=True, type=str, help="Input APK file or DEX directory.")
@click.option("-r", "--rules", required=False, type=str, default="", help="Add regular search rule.")
@click.option("-s", "--net-sniffer", is_flag=True, default=False, help="Whether to enable network sniffing.")
@click.option("-n", '--no-resource', is_flag=True, default=False,help="Ignore resource files.")
@click.option("-p", '--package',required=False,type=str,default="",help="Specifies the retrieval package name.")
@click.option("-a", '--all',is_flag=True, default=False,help="Output all strings.")
@click.option("-t", '--threads',required=False, type=int,default=10,help="Set the number of threads to 10 by default")
def android(input: str, rules: str, net_sniffer: bool,no_resource:bool,package:str,all:bool,threads:int) -> None:
    try:
        # 初始化全局对象
        bootstrapper = Bootstrapper(__file__)
        bootstrapper.init()

        task = AndroidTask(input, rules, net_sniffer,no_resource,package,all,threads)
        # 让内层代码直接抛出异常，不做rollback。
        task.start()
    except Exception as e:
        raise e


@cli.command(help="Get the key information of iOS system.")
@click.option("-i", "--input", required=True, type=str, help="Input IPA file or ELF file.")
@click.option("-r", "--rules", required=False, type=str, default="", help="Add regular search rule.")
@click.option("-s", "--net-sniffer", is_flag=True, default=False, help="Whether to enable network sniffing.")
@click.option("-n", '--no-resource', is_flag=True, default=False,help="Ignore resource files.")
@click.option("-a", '--all',is_flag=True, default=False,help="Output all strings.")
@click.option("-t", '--threads',required=False, type=int,default=10,help="Set the number of threads to 10 by default")
def ios(input: str, rules: str, net_sniffer: bool,no_resource:bool,all:bool,threads:int) -> None:
    try:
        # 初始化全局对象
        bootstrapper = Bootstrapper(__file__)
        bootstrapper.init()

        task = iOSTask(input, rules, net_sniffer,no_resource,all,threads)
        # 让内层代码直接抛出异常，不做rollback。
        task.start()
    except Exception as e:
        raise e


@cli.command(help="Get the key information of Web system.")
@click.option("-i", "--input", required=True, type=str, help="Input WebSite dir.")
@click.option("-r", "--rules", required=False, type=str, default="", help="Add regular search rule.")
@click.option("-a", '--all',is_flag=True, default=False,help="Output all strings.")
@click.option("-t", '--threads',required=False, type=int,default=10,help="Set the number of threads to 10 by default")
def web(input: str, rules: str, all:bool,threads:int) -> None:
    try:
        # 初始化全局对象
        bootstrapper = Bootstrapper(__file__)
        bootstrapper.init()

        task = WebTask(input, rules,all,threads)
        # 让内层代码直接抛出异常，不做rollback。
        task.start()
    except Exception as e:
        raise e


def main():
    cli()

if __name__ == "__main__":
    main()

