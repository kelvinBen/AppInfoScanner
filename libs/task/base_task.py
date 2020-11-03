# -*- coding: utf-8 -*-
# Author: kelvinBen
# Github: https://github.com/kelvinBen/AppInfoScanner

# 接收传入的参数信息，根据参数进行平台分发
import os
import re
import xlwt
import config
import threading
from queue import Queue
import libs.core as cores
from libs.core.parses import ParsesThreads
from libs.task.android_task import AndroidTask
from libs.task.ios_task import iOSTask
from libs.task.web_task import WebTask

class BaseTask(object):
    thread_list =[]
    result_dict = {}
    value_list = []

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
        workbook = xlwt.Workbook(encoding = 'utf-8')

        # 创建excel头
        worksheet = self.__creating_excel_header__(workbook)
        
        # 任务控制中心
        task_info = self.__tast_control__()
        file_queue = task_info["file_queue"]
        shell_flag = task_info["shell_flag"]
        comp_list = task_info["comp_list"]
        packagename = task_info["packagename"]
        
        if shell_flag:
            print('\033[3;31m Error: This application has shell, the retrieval results may not be accurate, Please remove the shell and try again!')
            return

        # 线程控制中心
        self.__threads_control__(file_queue)

        # 等待线程结束
        for thread in self.thread_list:
            thread.join()

        # 结果输出中心
        self.__print_control__(packagename,comp_list,workbook,worksheet)

    def __creating_excel_header__(self,workbook):
        worksheet = workbook.add_sheet("扫描信息",cell_overwrite_ok=True)
        worksheet.write(0,0, label = "扫描结果")
        return worksheet

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
            task_info = WebTask.start()
        return task_info

    def __threads_control__(self,file_queue):
        for threadID in range(1,self.threads): 
            name = "Thread - " + str(threadID)
            thread =  ParsesThreads(threadID,name,file_queue,self.all,self.result_dict,self.types)
            thread.start()
            self.thread_list.append(thread)

    def __print_control__(self,packagename,comp_list,workbook,worksheet):
        txt_result_path = cores.txt_result_path
        xls_result_path = cores.xls_result_path
        
        if packagename: 
            print("=========  The package name of this APP is: ===============")
            print(packagename)

        if len(comp_list) != 0:
            print("========= Component information is as follows :===============")
            for json in comp_list:
                print(json)

        print("=========The result set for the static scan is shown below:===============")
        with open(txt_result_path,"a+",encoding='utf-8',errors='ignore') as f:
            row = 1
            for key,value in self.result_dict.items():
                f.write(key+"\r")
                for result in value:
                    if result in self.value_list:
                        continue
                    self.value_list.append(result)
                    print(result)
                    worksheet.write(row,0, label = result)
                    row = row + 1
                    f.write("\t"+result+"\r")
        print("For more information about the search, see TXT file result: %s" %(txt_result_path))
        print("For more information about the search, see XLS file result: %s" %(xls_result_path))
        workbook.save(xls_result_path)
        

