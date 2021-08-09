#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen
# Github: https://github.com/kelvinBen/AppInfoScanner
import os
import re
import time
import config
import hashlib
import logging
from queue import Queue
import libs.core as cores
from libs.core.download import DownloadThreads

class DownloadTask(object):
    def __init__(self):
        self.download_file_queue = Queue()
        self.thread_list = []

    def start(self, path, types):
        self.__local_or_remote__(path, types)

        for threadID in range(1, cores.threads_num): 
            name = "Thread - " + str(int(threadID))
            thread = DownloadThreads(threadID,name,self.download_file_queue)
            thread.start()
            thread.join()     

    # 判断文件是本地加载还是远程加载
    def __local_or_remote__(self,path,types):
        # 处理本地文件
        if not(path.startswith("http://") or path.startswith("https://")):
            if not os.path.isdir(path): # 不是目录
                return {"path":path,"type":types}
            else: # 目录处理
                return {"path":path,"type":types}
        else:
           self.__net_header__(path,types)
            # self.download_file_queue.put(path)

    # 处理网络请求
    def __net_header__(self, path, types):
        create_time = time.strftime("%Y%m%d%H%M%S", time.localtime())
        if path.endswith("apk") or types == "Android":
            types = "Android"
            file_name = create_time+ ".apk"
        elif path.endswith("ipa") or types == "iOS":
            types = "iOS"
            file_name = create_time + ".ipa"
        else:
            types = "WEB"
            file_name = create_time + ".html"

        logging.info("[*] Detected that the task is not local, preparing to download file......")
        cache_path = os.path.join(cores.download_dir, file_name)
        self.download_file_queue.put({"path":path, "cache_path":cache_path, "types":types})        
        # thread = DownloadThreads(path,file_name,cache_path,types)
        # thread.start()
        # thread.join()
        return {"path":cache_path,"type":types}
    
    def __update_type__(self, path, types, file_name=None):
        create_time = time.strftime("%Y%m%d%H%M%S", time.localtime())
        if path.endswith("apk") or types == "Android":
            types = "Android"
            if not file_name:
                file_name = create_time+ ".apk"
        elif path.endswith("ipa") or types == "iOS":
            types = "iOS"
            if not file_name:
                file_name = create_time + ".ipa"
        else:
            types = "WEB"
            if not file_name:
                file_name = create_time + ".html"
        return types,file_name