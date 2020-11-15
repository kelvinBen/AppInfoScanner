# -*- coding: utf-8 -*-
# Author: kelvinBen
# Github: https://github.com/kelvinBen/AppInfoScanner
import os
import re
import config
import threading
from queue import Queue
import libs.core as cores
from libs.core.parses import ParsesThreads
from libs.task.android_task import AndroidTask
from libs.task.ios_task import iOSTask
from libs.task.web_task import WebTask
from libs.task.net_task import NetTask

class BaseTask(object):
    thread_list =[]
    result_dict = {}
    app_history_list=[]
    
    # 统一初始化入口
    def __init__(self, types="Android", inputs="", rules="", net_sniffer=False, no_resource=False, package="", all_str=False, threads=10):
        self.types = types
        self.net_sniffer = net_sniffer
        self.path = inputs
        if rules:
            config.filter_strs.append(r'.*'+str(rules)+'.*')
        self.no_resource = no_resource
        self.package = package
        self.all = all_str
        self.threads = threads
        self.file_queue = Queue()
        
    
    # 统一调度平台
    def start(self):
    
        print("[*] AI决策系统正在分析规则中...")

        # 获取历史记录
        self.__history_handle__()

        print("[*] 本次的过滤规则为：" , config.filter_no)

        # 任务控制中心
        task_info = self.__tast_control__()
        file_queue = task_info["file_queue"]
        shell_flag = task_info["shell_flag"]
        comp_list = task_info["comp_list"]
        packagename = task_info["packagename"]
        file_identifier = task_info["file_identifier"]
        
        if shell_flag:
            print('\033[3;31m Error: This application has shell, the retrieval results may not be accurate, Please remove the shell and try again!')
            return

        # 线程控制中心
        self.__threads_control__(file_queue)

        # 等待线程结束
        for thread in self.thread_list:
            thread.join()
    
        # 结果输出中心
        self.__print_control__(packagename,comp_list,file_identifier)


    def __tast_control__(self):
        task_info = {}
        # 调用Android 相关处理逻辑
        if self.types == "Android":
            task_info = AndroidTask(self.path,self.no_resource,self.package).start()
        # 调用iOS 相关处理逻辑
        elif self.types == "iOS":
            task_info = iOSTask(self.path,self.no_resource).start()
        # 调用Web 相关处理逻辑
        else:
            task_info = WebTask(self.path).start()
        return task_info

    def __threads_control__(self,file_queue):
        for threadID in range(1,self.threads): 
            name = "Thread - " + str(threadID)
            thread =  ParsesThreads(threadID,name,file_queue,self.all,self.result_dict,self.types)
            thread.start()
            self.thread_list.append(thread)

    def __print_control__(self,packagename,comp_list,file_identifier):
        txt_result_path = cores.txt_result_path
        xls_result_path = cores.xls_result_path
        
        # 此处需要hash值或者应用名称, apk文件获取pachage, dex文件获取hash, macho-o获取文件名

        if packagename: 
            print("=========  The package name of this APP is: ===============")
            print(packagename)

        if len(comp_list) != 0:
            print("========= Component information is as follows :===============")
            for json in comp_list:
                print(json)
        print("=========The result set for the static scan is shown below:===============")

        NetTask(self.result_dict,self.app_history_list,file_identifier,self.threads).start()
        
        # with open(txt_result_path,"a+",encoding='utf-8',errors='ignore') as f:
        #     row = 1
        #     for key,value in self.result_dict.items():
        #         f.write(key+"\r")

        #         for result in value:
        #             if result in self.value_list:
        #                 continue
        #             if not(file_identifier in self.app_history_list) and ("http://" in result or "https://" in result):
        #                 domain = result.replace("https://","").replace("http://","")
        #                 if "/" in domain:
        #                     domain = domain[:domain.index("/")]
                        
        #                 if not(domain in self.domain_list):
        #                     self.domain_list.append(domain)
        #                     self.__write_content_in_file__(cores.domain_history_path,domain)
        #                 if append_file_flag:
        #                     for identifier in  file_identifier:
        #                         self.__write_content_in_file__(cores.app_history_path,identifier)
        #                         append_file_flag = False
                            
        #             self.value_list.append(result)
        #             worksheet.write(row,0, label = result)
        #             row = row + 1
        #             f.write("\t"+result+"\r")
        print("For more information about the search, see TXT file result: %s" %(cores.txt_result_path))
        print("For more information about the search, see XLS file result: %s" %(cores.xls_result_path))
    
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
                    domain_count = lines.count(line)
                    
                    if domain_count >= cout:
                        config.filter_no.append(domain)
                f.close()

    
