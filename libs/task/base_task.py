#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen
# Github: https://github.com/kelvinBen/AppInfoScanner
import os
import re
import config
import logging
import threading
from queue import Queue
import libs.core as cores
from libs.task.ios_task import iOSTask
from libs.task.web_task import WebTask
from libs.task.net_task import NetTask
from libs.core.parses import ParsesThreads
from libs.task.android_task import AndroidTask
from libs.core.download import DownloadThreads

class BaseTask(object):

    def __init__(self):
        if cores.user_add_rules:
            config.filter_strs.append(r'.*'+str(cores.user_add_rules)+'.*')
        self.file_queue = Queue()
        # 文件下载队列
        self.download_file_queue = Queue()
        # 文件下载列表
        self.download_file_list = []
        self.thread_list = []
        self.app_history_list= []
        self.domain_history_list = []
        self.result_dict = {}
        
    # 统一启动
    def start(self, types="Android", user_input_path="", package=""):
        # 如果输入路径为目录,且类型非web,则自动检索DEX、IPA、APK等文件
        if not(types == "Web") and os.path.isdir(user_input_path):
            self.__scanner_specified_file__(user_input_path)
        
        # 如果输入的路径为txt, 则加载txt中的内容实现批量操作
        elif user_input_path.endswith("txt"):
            with open(user_input_path) as f:
                lines = f.readlines()
                for line in lines:
                    # http:// 或者 https:// 开头 或者 apk/dex/ipa结尾的文件且文件存在
                    if (line.startswith("http://") or line.startswith("https://")) or ((line.endswith("apk") or line.endswith(".dex") or line.endswith("ipa")) and os.path.exists(line)):
                        self.download_file_queue.put(line)
                f.close()
        else:
            # 如果是文件或者类型为web的目录
            self.download_file_queue.put(user_input_path)

        # 长度小于1需重新选择目录
        if self.download_file_queue.qsize() < 1:
            raise Exception('[x] The specified DEX, IPA and APK files are not found. Please re-enter the directory to be scanned!') 

        # 统一文件下载中心
        self.__download_file_center__(types)
        
        for download_file in self.download_file_list:
            file_path = download_file["path"]
            types = download_file["type"]
            # 控制中心
            self.__control_center__(file_path, types)

    # 统一文件下载中心
    def __download_file_center__(self,types):
        # 杜绝资源浪费
        if self.download_file_queue.qsize() < cores.threads_num:
            threads_num = self.download_file_queue.qsize()
        else:
            threads_num = cores.threads_num

        for threadID in range(1, threads_num): 
            threadName = "Thread - " + str(int(threadID))
            thread = DownloadThreads(threadID, threadName, self.download_file_queue, self.download_file_list, types)
            thread.start()
            thread.join()

    # 控制中心
    def __control_center__(self, file_path, types):
        logging.info("[*] Processing {}".format(file_path))
        logging.info("[*] AI is analyzing filtering rules......")
        
        # 处理历史记录
        self.__history_handle__()
        logging.info("[*] The filtering rules obtained by AI are as follows: {}".format(set(config.filter_no)))

        # 任务控制中心
        task_info = self.__tast_control__(file_path, types)
        if len(task_info) < 1:
            return 

        # 文件队列    
        file_queue = task_info["file_queue"]
        # 是否存在壳
        shell_flag = task_info["shell_flag"]
        # 组件列表(仅适用于Android)
        comp_list = task_info["comp_list"]
        # 报名信息(仅适用于Android)
        packagename = task_info["packagename"]
        # 文件标识符
        file_identifier = task_info["file_identifier"]
            
        if shell_flag:
            logging.error('[x] This application has shell, the retrieval results may not be accurate, Please remove the shell and try again!')
            return

        # 线程控制中心
        logging.info("[*] =========  Searching for strings that match the rules ===============")
        self.__threads_control__(file_queue)

        # 等待线程结束
        for thread in self.thread_list:
            thread.join()
        
        # 结果输出中心
        self.__print_control__(packagename,comp_list,file_identifier)


    # 任务控制中心
    def __tast_control__(self, file_path, types):
        task_info = {}
        
        # 通过网络下载的文件如果不存在就直接返回任务控制中心
        if (not os.path.exists(file_path) and cores.download_flag):
            logging.error("[x] {} download failed! Please download the file manually and try again.".format(file_path))
            return task_info

        # 调用Android 相关处理逻辑
        if types == "Android":
            task_info = AndroidTask(file_path, self.package).start()
        # 调用iOS 相关处理逻辑
        elif types == "iOS":
            task_info = iOSTask(file_path).start()
        # 调用Web 相关处理逻辑
        else:
            task_info = WebTask(file_path).start()
        return task_info

    # 线程控制中心
    def __threads_control__(self,file_queue):
        for threadID in range(1, cores.threads_num): 
            name = "Thread - " + str(int(threadID))
            thread =  ParsesThreads(threadID,name,file_queue,self.result_dict,self.types)
            thread.start()
            self.thread_list.append(thread)
    
    # 信息输出中心
    def __print_control__(self,packagename,comp_list,file_identifier):                
        if cores.net_sniffer_flag:
            logging.info("[*] ========= Sniffing the URL address of the search ===============")
            NetTask(self.result_dict,self.app_history_list,self.domain_history_list,file_identifier).start()
            
        if packagename: 
            logging.info("[*] =========  The package name of this APP is: ===============")
            logging.info(packagename)

        if len(comp_list) != 0:
            logging.info("[*] ========= Component information is as follows :===============")
            for json in comp_list:
                logging.info(json)
        
        if cores.all_flag:
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
            logging.info("[>] For more information about the search, see TXT file result: {}".format(cores.txt_result_path))

        if cores.net_sniffer_flag:
            logging.info("[>] For more information about the search, see XLS file result: {}".format(cores.xls_result_path))

    # 获取历史记录
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
    
    # 扫描指定后缀文件
    def __scanner_specified_file__(self, base_dir, file_suffix=['dex','ipa','apk']):
        files = os.listdir(base_dir)
        for file in files:
            dir_or_file_path = os.path.join(base_dir,file) 
            if os.path.isdir(dir_or_file_path):
                self.__scanner_specified_file__(dir_or_file_path,file_suffix)
            else: 
                if dir_or_file_path.split(".")[-1] in file_suffix:
                    self.download_file_queue.put(dir_or_file_path)