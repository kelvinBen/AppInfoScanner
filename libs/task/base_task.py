#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen
# Github: https://github.com/kelvinBen/AppInfoScanner
import os
import re
import config
import threading
from queue import Queue
import libs.core as cores
from libs.task.ios_task import iOSTask
from libs.task.web_task import WebTask
from libs.task.net_task import NetTask
from libs.core.parses import ParsesThreads
from libs.task.android_task import AndroidTask
from libs.task.download_task import DownloadTask

class BaseTask(object):
    thread_list =[]
    result_dict = {}
    app_history_list=[]
    domain_history_list=[]
    # 统一初始化入口
    def __init__(self, types="Android", inputs="", rules="", sniffer=True, threads=10, package=""):
        self.types = types
        self.path = inputs
        if rules:
            config.filter_strs.append(r'.*'+str(rules)+'.*')
        self.sniffer = not sniffer
        self.threads = threads
        self.package = package
        self.file_queue = Queue()
        
    
    # 统一调度平台
    def start(self):
    
        print("[*] AI is analyzing filtering rules......")

        # 获取历史记录
        self.__history_handle__()

        print("[*] The filtering rules obtained by AI are as follows: %s" % (set(config.filter_no)) )

        # 任务控制中心
        task_info = self.__tast_control__()
        if len(task_info) < 1:
            return

        file_queue = task_info["file_queue"]
        shell_flag = task_info["shell_flag"]
        comp_list = task_info["comp_list"]
        packagename = task_info["packagename"]
        file_identifier = task_info["file_identifier"]
        
        if shell_flag:
            print('[-] \033[3;31m Error: This application has shell, the retrieval results may not be accurate, Please remove the shell and try again!')
            return

        # 线程控制中心
        print("[*] =========  Searching for strings that match the rules ===============")
        self.__threads_control__(file_queue)

        # 等待线程结束
        for thread in self.thread_list:
            thread.join()
    
        # 结果输出中心
        self.__print_control__(packagename,comp_list,file_identifier)


    def __tast_control__(self):
        task_info = {}
        # 自动根据文件后缀名称进行修正
        cache_info = DownloadTask().start(self.path,self.types)
        cacar_path = cache_info["path"]
        types = cache_info["type"]
        
        if (not os.path.exists(cacar_path) and cores.download_flag):
            print("[-] File download failed! Please download the file manually and try again.")
            return task_info

        # 调用Android 相关处理逻辑
        if types == "Android":
            task_info = AndroidTask(cacar_path,self.package).start()
        # 调用iOS 相关处理逻辑
        elif types == "iOS":
            task_info = iOSTask(cacar_path).start()
        # 调用Web 相关处理逻辑
        else:
            task_info = WebTask(cacar_path).start()
        return task_info

    def __threads_control__(self,file_queue):
        for threadID in range(1,self.threads): 
            name = "Thread - " + str(int(threadID))
            thread =  ParsesThreads(threadID,name,file_queue,self.result_dict,self.types)
            thread.start()
            self.thread_list.append(thread)

    def __print_control__(self,packagename,comp_list,file_identifier):
        txt_result_path = cores.txt_result_path
        xls_result_path = cores.xls_result_path
        all_flag = cores.all_flag
                
        if self.sniffer:
            print("[*] ========= Sniffing the URL address of the search ===============")
            NetTask(self.result_dict,self.app_history_list,self.domain_history_list,file_identifier,self.threads).start()
            
        if packagename: 
            print("[*] =========  The package name of this APP is: ===============")
            print(packagename)

        if len(comp_list) != 0:
            print("[*] ========= Component information is as follows :===============")
            for json in comp_list:
                print(json)
        
        if all_flag:
            value_list = []
            with open(txt_result_path,"a+",encoding='utf-8',errors='ignore') as f:
                for key,value in self.result_dict.items():
                    f.write(key+"\r")
                    for result in value:
                        if result in value_list:
                            continue
                        value_list.append(result)
                        f.write("\t"+result+"\r")
                f.close()
            print("[*] For more information about the search, see TXT file result: %s" %(txt_result_path))

        if self.sniffer:
            print("[*] For more information about the search, see XLS file result: %s" %(xls_result_path))

    def __history_handle__(self):
        domain_history_path =  cores.domain_history_path
        app_history_path = cores.app_history_path
        if os.path.exists(domain_history_path):
            domain_counts = {}
            app_size = 0 
            with open(app_history_path,"r",encoding='utf-8',errors='ignore') as f:
                lines = f.readlines()
                app_size = len(lines)
                for line in  lines:
                   self.app_history_list.append(line.replace("\r","").replace("\n",""))

                f.close()

            with open(domain_history_path,"r",encoding='utf-8',errors='ignore') as f:
                lines = f.readlines()
                cout = 3
                if (app_size>3) and (app_size%3==0):
                    cout = cout + 1
                for line in lines:
                    domain = line.replace("\r","").replace("\n","")
                    self.domain_history_list.append(domain)
                    domain_count = lines.count(line)
                    if domain_count >= cout:
                        config.filter_no.append(".*" + domain)
                f.close()

    
