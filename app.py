#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen
# Github: https://github.com/kelvinBen/AppInfoScanner

import click
import logging

from libs.core import Bootstrapper
from libs.task.base_task import BaseTask

@click.group(help="Python script for automatically retrieving key information in app.")
def cli():
    try:
        LOG_FORMAT = "%(message)s"    # 日志格式化输出
        fp = logging.FileHandler('info.log', mode='w',encoding='utf-8')
        fs = logging.StreamHandler()
        logging.basicConfig(level=logging.INFO, format=LOG_FORMAT, handlers=[fp, fs])    # 调用
    except Exception as e:
        logging.error("{}".format(e))

# 创建Android任务
@cli.command(help="Get the key information of Android system.")
@click.option("-i", "--inputs", required=True, type=str, help="Please enter the APK file or DEX file to be scanned or the corresponding APK download address.")
@click.option("-r", "--rules", required=False, type=str, default="", help="Please enter a rule for temporary scanning of file contents.")
@click.option("-s", "--sniffer", is_flag=True, default=False, help="Enable the network sniffer function. It is on by default.")
@click.option("-n", '--no-resource', is_flag=True, default=False,help="Ignore all resource files, including network sniffing. It is not enabled by default.")
@click.option("-a", '--all',is_flag=True, default=False,help="Output the string content that conforms to the scan rules.It is on by default.")
@click.option("-t", '--threads',required=False, type=int,default=10,help="Set the number of concurrency. The larger the concurrency, the faster the speed. The default value is 10.")
@click.option("-o", '--output',required=False, type=str,default=None,help="Specify the result set output directory.")
@click.option("-p", '--package',required=False,type=str,default="",help="Specifies the package name information that needs to be scanned.")
def android(inputs: str, rules: str, sniffer: bool, no_resource:bool, all:bool, threads:int, output, package:str) -> None:
    
    
    bootstrapper = Bootstrapper(rules, sniffer, threads, all ,no_resource)
    bootstrapper.init_dir(__file__, output)

    BaseTask().start("Android", inputs, package)


@cli.command(help="Get the key information of iOS system.")
@click.option("-i", "--inputs", required=True, type=str, help="Please enter IPA file or ELF file to scan or corresponding IPA download address. App store is not supported at present.")
@click.option("-r", "--rules", required=False, type=str, default="", help="Please enter a rule for temporary scanning of file contents.")
@click.option("-s", "--sniffer", is_flag=True, default=False, help="Enable the network sniffer function. It is on by default.")
@click.option("-n", '--no-resource', is_flag=True, default=False,help="Ignore all resource files, including network sniffing. It is not enabled by default.")
@click.option("-a", '--all',is_flag=True, default=False,help="Output the string content that conforms to the scan rules.It is on by default.")
@click.option("-t", '--threads',required=False, type=int,default=10,help="Set the number of concurrency. The larger the concurrency, the faster the speed. The default value is 10.")
@click.option("-o", '--output',required=False, type=str,default=None,help="Specify the result set output directory.")
def ios(inputs: str, rules: str, sniffer: bool, no_resource:bool, all:bool, threads:int, output:str) -> None:
    

    
    bootstrapper = Bootstrapper(rules, sniffer, threads, all ,no_resource)
    bootstrapper.init_dir(__file__, output)
    BaseTask().start("iOS", inputs)

@cli.command(help="Get the key information of Web system.")
@click.option("-i", "--inputs", required=True, type=str, help="Please enter the site directory or site file to scan or the corresponding site download address.")
@click.option("-r", "--rules", required=False, type=str, default="", help="Please enter a rule for temporary scanning of file contents.")
@click.option("-s", "--sniffer", is_flag=True, default=False, help="Enable the network sniffer function. It is on by default.")
@click.option("-n", '--no-resource', is_flag=True, default=False,help="Ignore all resource files, including network sniffing. It is not enabled by default.")
@click.option("-a", '--all',is_flag=True, default=False,help="Output the string content that conforms to the scan rules.It is on by default.")
@click.option("-t", '--threads',required=False, type=int,default=10,help="Set the number of concurrency. The larger the concurrency, the faster the speed. The default value is 10.")
@click.option("-o", '--output',required=False, type=str,default=None,help="Specify the result set output directory.")
def web(inputs: str, rules: str, sniffer: bool, no_resource:bool, all:bool, threads:int, output:str) -> None:
    

    bootstrapper = Bootstrapper(rules, sniffer, threads, all ,no_resource)
    bootstrapper.init_dir(__file__, output)
    BaseTask().start("Web", inputs)

def main():

    cli()

if __name__ == "__main__":
    main()

