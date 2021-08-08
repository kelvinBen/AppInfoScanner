#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen
# Github: https://github.com/kelvinBen/AppInfoScanner
import os
import time
import shutil
import platform

# smali 所在路径
smali_path = ""

# backsmli 所在路径
backsmali_path = ""

# apktool 所在路径
apktool_path = ""

# 系统类型
os_type = ""

# 输出路径
output_path = ""

# 下载完成标记
download_flag = False

# excel 起始行号
excel_row = 0

class Bootstrapper(object):

    def __init__(self, path, out_path, all=False, no_resource= False):
        global smali_path
        global backsmali_path
        global apktool_path
        global os_type
        global output_path
        global script_root_dir
        global txt_result_path
        global xls_result_path
        global strings_path
        global history_path
        global app_history_path
        global domain_history_path
        global excel_row 
        global download_path
        global download_flag
        global out_dir
        global all_flag
        global resource_flag 

        all_flag = not all
        resource_flag = no_resource

        create_time = time.strftime("%Y%m%d%H%M%S", time.localtime())
        script_root_dir =  os.path.dirname(os.path.abspath(path))
        if out_path:
            out_dir = out_path
        else:
            out_dir = script_root_dir
        tools_dir = os.path.join(script_root_dir,"tools")
        output_path = os.path.join(out_dir,"out")
        history_path = os.path.join(script_root_dir,"history")
        
        if platform.system() == "Windows":
            machine2bits = {'AMD64':64, 'x86_64': 64, 'i386': 32, 'x86': 32}
            machine2bits.get(platform.machine())

            if platform.machine() == 'i386' or platform.machine() == 'x86':
                strings_path = os.path.join(tools_dir,"strings.exe")
            else:
                strings_path = os.path.join(tools_dir,"strings64.exe")
        else:
            strings_path ="strings"
        
        backsmali_path = os.path.join(tools_dir,"baksmali.jar")
        apktool_path = os.path.join(tools_dir, "apktool.jar")
        download_path = os.path.join(out_dir,"download")
        txt_result_path = os.path.join(out_dir,"result_"+str(create_time)+".txt")
        xls_result_path = os.path.join(out_dir,"result_"+str(create_time)+".xls")
        app_history_path = os.path.join(history_path,"app_history.txt")
        domain_history_path = os.path.join(history_path,"domain_history.txt")

    def init(self):
        if not os.path.exists(out_dir):
            os.makedirs(out_dir)
            print("[*] Create directory {}".format(out_dir))

        if os.path.exists(output_path):
            try:
                shutil.rmtree(output_path)
            except Exception as e:
                # 解决windows超长文件名删除问题
                if not (platform.system() == "Windows"):
                    raise e
                self.__removed_dirs_cmd__(output_path)
                
        os.makedirs(output_path)
        print("[*] Create directory {}".format(output_path))

        if not os.path.exists(download_path):
            # shutil.rmtree(download_path)
            os.makedirs(download_path)
            print("[*] Create directory {}".format(download_path))

        if not os.path.exists(history_path):
            os.makedirs(history_path)
            print("[*] Create directory {}".format(history_path))
        
        if os.path.exists(txt_result_path):
            os.remove(txt_result_path)

        if os.path.exists(xls_result_path):
            os.remove(xls_result_path)
    
    def __removed_dirs_cmd__(self,output_path):
        files = os.listdir(output_path)
        for file in files:
            new_dir = os.path.join(output_path,"newdir")
            old_dir = os.path.join(output_path,file)
            if not os.path.exists(new_dir):
                os.makedirs(new_dir)
            os.chdir(output_path)
            cmd = ("robocopy %s %s /purge") % (new_dir, old_dir)
            os.system(cmd)
            os.removedirs(new_dir)
            os.removedirs(old_dir)