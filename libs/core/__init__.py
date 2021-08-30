#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen
# Github: https://github.com/kelvinBen/AppInfoScanner

import os
import shutil
import platform
import logging

backsmali_file = None
apktool_file = None
strings_file = None
app_history_file= None
domain_history_file = None
result_dir = None
download_dir = None
decode_dir = None
user_add_rules = None

download_flag = False
net_sniffer_flag = False
all_string_out = False
no_resource_flag = False

excel_row = 1
threads_num = 10


class Bootstrapper(object):

    def __init__(self, rules, threads, sniffer, all, no_resource):
        # backsmali 加载路径
        global backsmali_file
        # apktool 加载路径
        global apktool_file
        # string 加载路径
        global strings_file
        # App 扫描历史文件
        global app_history_file
        # 域名 扫描历史文件
        global domain_history_file
        # 结果输出目录
        global result_dir
        # 临时文件下载目录
        global download_dir
        # 临时反编译目录
        global decode_dir
        # 下载完成标记
        global download_flag
        # excel 行号
        global excel_row 
        # 用户自定义规则
        global user_add_rules 
        # 用户指定线程数
        global threads_num
        # 网络嗅探标记
        global net_sniffer_flag
        # 输出所有字符传
        global all_string_out
        # 忽略资源标记
        global no_resource_flag

        user_add_rules = rules
        threads_num = threads
        net_sniffer_flag = not sniffer
        all_string_out = all 
        no_resource_flag = no_resource

        # 需要创建的目录列表
        self.__create_dir_list__= []
        # 需要删除目录的列表
        self.__remove_dir_list__= []

        logging.info("[*] System env: {}".format(platform.system()))

    def init_dir(self, app_input_path, user_out_path):
        logging.info("[*] init dir...")
        
        # 脚本执行目录
        script_root_dir =  os.path.dirname(os.path.abspath(app_input_path))

        # 加载集成的工具
        self.__tools_loading__(script_root_dir)
        
        # 构建持久化目录
        self.__build_persistent_path__(script_root_dir)
       
        # 构建结果输出目录
        self.__build_result_out__path__(script_root_dir,user_out_path)
        
        # 统一目录构建中心
        self.__build_dir__()
    
    # 加载集成的工具
    def __tools_loading__(self,script_root_dir):
        tools_dir = os.path.join(script_root_dir,"tools")
        
        backsmali_file = os.path.join(tools_dir,"baksmali.jar")
        logging.info("[*] Backsmali Path: {}".format(backsmali_file))
        
        apktool_file = os.path.join(tools_dir, "apktool.jar")
        logging.info("[*] Apktool Path: {}".format(apktool_file))
        
        if platform.system() == "Windows":
            machine2bits = {'AMD64':64, 'x86_64': 64, 'i386': 32, 'x86': 32}
            machine2bits.get(platform.machine())

            if platform.machine() == 'i386' or platform.machine() == 'x86':
                strings_file = os.path.join(tools_dir,"strings.exe")
            else:
                strings_file = os.path.join(tools_dir,"strings64.exe")
        else:
            strings_file ="strings"

        logging.info("[*] Strings Path: {}".format(strings_file))

    # 构建持久化目录
    def __build_persistent_path__(self,script_root_dir):
        # 当前用户文档目录
        doc_path = os.path.join(os.path.expanduser("~"), 'Documents')
        if os.path.exists(doc_path):
            app_dir = os.path.join(doc_path,"AppInfoScanner")
        else:
            app_dir = os.path.join(script_root_dir,"AppInfoScanner")

        # 历史任务加载目录
        history_path = os.path.join(app_dir,"history")

        app_history_file = os.path.join(history_path,"app_history.txt")
        domain_history_file = os.path.join(history_path,"domain_history.txt")
        
        self.__create_dir_list__.append(app_dir)
        self.__create_dir_list__.append(history_path)

    # 构建结果输出目录
    def __build_result_out__path__(self,script_root_dir,user_out_path):
        result_out_dir = script_root_dir
        
        # 用户指定输出目录结果则为输出到指定目录
        if user_out_path:
            result_out_dir = user_out_path        
        
        # 统一输出目录
        out_dir = os.path.join(result_out_dir,"out")
        # 临时结果输出目录
        decode_dir = os.path.join(out_dir,"decode")
        # 临时文件下载目录
        download_dir = os.path.join(out_dir,"download")
        # 最终结果输出目录
        result_dir = os.path.join(out_dir,"result")

        self.__create_dir_list__.append(out_dir)
        self.__create_dir_list__.append(decode_dir)
        self.__create_dir_list__.append(download_dir)
        self.__create_dir_list__.append(result_dir)
        self.__remove_dir_list__.append(decode_dir)

    # 统一目录构建中心
    def __build_dir__(self):
        for dir_path in self.__create_dir_list__:
            if (os.path.exists(dir_path)) and (dir_path in self.__remove_dir_list__):
                # 删除目录
                try:
                    shutil.rmtree(dir_path)
                    logging.info("[-] Remove Dir: {}".format(dir_path))
                except Exception as e:
                    # 解决windows超长文件名删除问题
                    if not (platform.system() == "Windows"):
                        raise e
                    self.__removed_dirs_cmd__(dir_path)
            
            # 创建目录
            if not os.path.exists(dir_path):
                os.makedirs(dir_path)
                logging.info("[+] Create Dir: {}".format(dir_path))

    def __removed_dirs_cmd__(self,output_path):
        files = os.listdir(output_path)
        for file in files:
            new_dir = os.path.join(output_path,"newdir")
            old_dir = os.path.join(output_path,file)
            if not os.path.exists(new_dir):
                os.makedirs(new_dir)
                logging.info("[+] Create Dir: {}".format(new_dir))
            os.chdir(output_path)
            cmd = ("robocopy %s %s /purge") % (new_dir, old_dir)
            logging.debug("[*] cmd : {}".format(cmd))
            os.system(cmd)
            os.removedirs(new_dir)
            os.removedirs(old_dir)
            logging.info("[-] Remove Dir: {}".format(new_dir))
            logging.info("[-] Remove Dir: {}".format(old_dir))