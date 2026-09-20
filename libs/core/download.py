#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen (微信/WeChat: bromomo )
# Github: https://github.com/kelvinBen/AppInfoScanner
# Gitee: https://gitee.com/kelvin_ben/AppInfoScanner
import os
import requests
import threading
import libs.core as cores
from requests.packages import urllib3
from requests.adapters import HTTPAdapter


class DownloadThreads(threading.Thread):

    def __init__(self, input_path, file_name, cache_path, types):
        threading.Thread.__init__(self)
        self.url = input_path
        self.types = types
        # 防御路径穿越：文件名只保留路径末段并过滤 ..，固定写入下载目录
        safe_name = os.path.basename(str(cache_path or file_name))
        safe_name = safe_name.replace("..", "_")
        download_dir = str(cores.download_path)
        self.cache_path = os.path.join(download_dir, safe_name)
        self.file_name = file_name

    def __requset__(self):
        try:
            session = requests.Session()
            session.mount('http://', HTTPAdapter(max_retries=3))
            session.mount('https://', HTTPAdapter(max_retries=3))
            session.keep_alive = False
            urllib3.disable_warnings()

            if cores.config.method.upper() == "POST":
                resp = session.post(
                    url=self.url, params=cores.config.data, headers=cores.config.headers, timeout=30)
            else:
                resp = session.get(url=self.url, data=cores.config.data,
                                   headers=cores.config.headers, timeout=30)

            if resp.status_code == requests.codes.ok:
                if self.types == "Android" or self.types == "iOS":
                    count = 0
                    progress_tmp = 0
                    length = float(resp.headers['content-length'])
                    with open(self.cache_path, "wb") as f:
                        for chunk in resp.iter_content(chunk_size=512):
                            if chunk:
                                f.write(chunk)
                                count += len(chunk)
                                progress = int(count / length * 100)
                                if progress != progress_tmp:
                                    progress_tmp = progress
                                    cores.progress("[*] Download progress: {}% {}".format(
                                        progress, "▋" * (progress // 2)))
                        f.close()
                else:
                    html = resp.text
                    with open(self.cache_path, "w", encoding='utf-8', errors='ignore') as f:
                        f.write(html)
                        f.close()
                cores.download_flag = True
        except Exception as e:
            cores.logp("[-] Download failed ({}): {}".format(self.url, e))
            raise

    def run(self):
        try:
            self.__requset__()
        except Exception:
            cores.thread_failed = True
            cores.logexc("[!] DownloadThread aborted: {}".format(self.url))
