# -*- coding: utf-8 -*-
# Author: kelvinBen
# Github: https://github.com/kelvinBen/AppInfoScanner
import re
import os
import time
import config
import threading
import requests
import libs.core as cores

class DownloadThreads(threading.Thread):    

    def __init__(self, path, type):
        self.url = path 
        self.type = type

    def __requset__(self):
        try:
            create_time = time.strftime("%Y%m%d%H%M%S", time.localtime())
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
                if self.type == "apk":
                    count = 0
                    count_tmp = 0
                    time1 = time.time()
                    length = float(resp.headers['content-length'])
                    apk_path = os.path.join(cores.download_path, create_time+".apk")
                    with open(apk_path, "wb") as f:
                        for chunk in resp.iter_content(chunk_size = 512):
                            if chunk:
                                f.write(chunk)
                                count += len(chunk)
                                if time.time() - time1 > 2:
                                    p = count / length * 100
                                    speed = (count - count_tmp) / 1024 / 1024 / 2
                                    count_tmp = count
                                    print(name + ': ' + formatFloat(p) + '%' + ' Speed: ' + formatFloat(speed) + 'M/S')
                                    time1 = time.time()
                        f.close()
                else:
                    html_path = os.path.join(cores.download_path, create_time+".html")
                    html = resp.html()
                    with open(html_path,"w",encoding='utf-8',errors='ignore') as f:
                        f.write(html)
                        f.close()
        except Exception:
            break
        

    def run(self):
        threadLock = threading.Lock()
        self.__get_Http_info__(threadLock)