#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen
# Github: https://github.com/kelvinBen/AppInfoScanner
import re
import os
import sys
import time
import config
import requests
import threading
import libs.core as cores
from requests.packages import urllib3
from requests.adapters import HTTPAdapter    

class DownloadThreads(threading.Thread):    

    def __init__(self,input_path,file_name,cache_path,types):
        threading.Thread.__init__(self) 
        self.url = input_path 
        self.types = types
        self.cache_path = cache_path
        self.file_name = file_name

    def __requset__(self):
        try:
            session = requests.Session()
            session.mount('http://', HTTPAdapter(max_retries=3))
            session.mount('https://', HTTPAdapter(max_retries=3))
            session.keep_alive =False
            session.adapters.DEFAULT_RETRIES = 5
            urllib3.disable_warnings()

            if config.method.upper() == "POST":
                resp = session.post(url=self.url,params=config.data ,headers=config.headers,timeout=30)
            else:
                resp = session.get(url=self.url,data=config.data ,headers=config.headers,timeout=30)
            
            if resp.status_code == requests.codes.ok:
                if self.types == "Android" or self.types == "iOS":
                    count = 0
                    progress_tmp = 0
                    time1 = time.time()
                    length = float(resp.headers['content-length'])
                    with open(self.cache_path, "wb") as f:
                        for chunk in resp.iter_content(chunk_size = 512):
                            if chunk:
                                f.write(chunk)
                                count += len(chunk)
                                progress = int(count / length * 100)
                                if progress != progress_tmp:
                                    progress_tmp = progress
                                    print("\r", end="")
                                    print("[*] Download progress: {}%: ".format(progress), "▋" * (progress // 2), end="")
                                    sys.stdout.flush()
                        f.close()
                else:
                    html = resp.text
                    with open(self.cache_path,"w",encoding='utf-8',errors='ignore') as f:
                        f.write(html)
                        f.close()
                cores.download_flag = True
        except Exception as e:
            raise Exception(e)
            return

    def run(self):
        threadLock = threading.Lock()
        self.__requset__()