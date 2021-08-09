#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen
# Github: https://github.com/kelvinBen/AppInfoScanner
from genericpath import exists
import re
import os
import sys
import time
import uuid
import config
import logging
import requests
import threading
import libs.core as cores
from requests.packages import urllib3
from requests.adapters import HTTPAdapter    

class DownloadThreads(threading.Thread):   

    def __init__(self,threadID, threadName, download_file_queue, download_file_list, types):
        threading.Thread.__init__(self) 
        self.threadID = threadID
        self.threadName = threadName
        self.download_file_queue = download_file_queue
        self.download_file_list = download_file_list
        self.types = types
        self.cache_path = None
    
    def __start__(self):
        # 从队列中取数据，直到队列数据不为空为止
        while not self.download_file_queue.empty():
            file_or_url = self.download_file_queue.get()
            if not file_or_url:
                logging.error("[x] Failed to get file!")
                continue
            self.__auto_update_type__(file_or_url)

    # 自动更新文件类型
    def __auto_update_type__(self,file_or_url):
        uuid_name =  str(uuid.uuid1()).replace("-","")
        # 文件后缀为apk 或者 类型为 Android 则自动修正为Android类型
        if file_or_url.endswith("apk") or self.types == "Android":
            types = "Android"
            file_name = uuid_name + ".apk"
        # 文件后缀为dex 或者 类型为 Android 则自动修正为Android类型
        elif file_or_url.endswith("dex") or self.types == "Android":
            types = "Android"
            file_name = uuid_name + ".dex"
        # 文件后缀为ipa 或者 类型为 iOS 则自动修正为iOS类型
        elif file_or_url.endswith("ipa") or self.types == "iOS":
            types = "iOS"
            file_name = uuid_name + ".ipa"
        else:
            # 路径以http://开头或者以https://开头 且 文件是不存在的自动修正为web类型
            if (file_or_url.startswith("http://") or file_or_url.startswith("https://")) and (not os.path.exists(file_or_url)):
                types = "WEB"
                file_name = uuid_name + ".html"
            # 其他情况如：types为WEB 或者目录 或者 单独的二进制文件 等交给后面逻辑处理
        
        if file_or_url.startswith("http://") or file_or_url.startswith("https://"):
            # 进行文件下载
            self.__file_deduplication__(file_name, uuid_name)
            if self.cache_path:
                file_path = self.cache_path
                self.__download_file__(file_or_url,file_path)
            #TODO 标记下载过的文件，避免重复下载
        else:
            types = self.types
            file_path = file_or_url

        self.download_file_list.append({"path": file_path, "type": types})
         
    # 防止文件名重复导致文件被复写
    def __file_deduplication__(self,file_name, uuid_name):
        cache_path = os.path.join(cores.download_dir, file_name)
        if not os.path.exists(cache_path):
            self.cache_path = cache_path
            return
        new_uuid_name = str(uuid.uuid1()).replace("-","")
        new_file_name = file_name.replace(uuid_name,new_uuid_name) 
        self.__file_deduplication__(new_file_name,new_uuid_name)

    # 文件下载    
    def __download_file__(self, url, file_path):
        try:
            session = requests.Session()
            session.mount('http://', HTTPAdapter(max_retries=3))
            session.mount('https://', HTTPAdapter(max_retries=3))
            session.keep_alive =False
            session.adapters.DEFAULT_RETRIES = 5
            urllib3.disable_warnings()

            if config.method.upper() == "POST":
                resp = session.post(url=url, params=config.data, headers=config.headers, timeout=30)
            else:
                resp = session.get(url=url, data=config.data, headers=config.headers, timeout=30)
            
            if resp.status_code == requests.codes.ok:
                # 下载二进制文件
                if self.types == "Android" or self.types == "iOS":
                    count = 0
                    progress_tmp = 0
                    length = float(resp.headers['content-length'])
                    with open(file_path, "wb") as f:
                        for chunk in resp.iter_content(chunk_size = 512):
                            if chunk:
                                f.write(chunk)
                                count += len(chunk)
                                progress = int(count / length * 100)
                                if progress != progress_tmp:
                                    progress_tmp = progress
                                    logging.info("\r", end="")
                                    logging.info("[*] Download progress: {}%: ".format(progress), "▋" * (progress // 2), end="")
                                    sys.stdout.flush()
                        f.close()
                else:
                    html = resp.text
                    with open(file_path,"w",encoding='utf-8',errors='ignore') as f:
                        f.write(html)
                        f.close()
                cores.download_flag = True
            else:
               logging.error("[x] {} download fails, status code is {} !!!".format(url, str(resp.status_code)))

        except Exception as e:
            logging.error("[x] {} download fails, the following exception information:".format(url))
            logging.exception(e)

    def run(self):
        threadLock = threading.Lock()
        self.__start__()