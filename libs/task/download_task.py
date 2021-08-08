#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen
# Github: https://github.com/kelvinBen/AppInfoScanner
import os
import re
import time
import config
import hashlib
from queue import Queue
import libs.core as cores
from libs.core.download import DownloadThreads

class DownloadTask(object):

    def start(self,path,types):
        create_time = time.strftime("%Y%m%d%H%M%S", time.localtime())
        if path.endswith("apk"):
            types = "Android"
            file_name = create_time+ ".apk"
        elif path.endswith("ipa"):
            types = "iOS"
            file_name = create_time + ".ipa"
        else:
            if types == "Android":
                types = "Android"
                file_name = create_time+ ".apk"
            elif types == "iOS":
                types = "iOS"
                file_name = create_time + ".ipa"
            else:
                types = "WEB"
                file_name = create_time + ".html"
        if not(path.startswith("http://") or path.startswith("https://")):
            if not os.path.isdir(path): # 不是目录
                return {"path":path,"type":types}
            else: # 目录处理
                return {"path":path,"type":types}
        else:
            print("[*] Detected that the task is not local, preparing to download file......")
            cache_path = os.path.join(cores.download_path, file_name)            
            thread = DownloadThreads(path,file_name,cache_path,types)
            thread.start()
            thread.join()
            print()
            return {"path":cache_path,"type":types}