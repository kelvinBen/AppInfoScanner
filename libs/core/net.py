#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen (微信/WeChat: bromomo )
# Github: https://github.com/kelvinBen/AppInfoScanner
# Gitee: https://gitee.com/kelvin_ben/AppInfoScanner
import re
import time
import threading
import requests
import libs.core as cores

class NetThreads(threading.Thread):

    def __init__(self, threadID, name, domain_queue, rows):
        threading.Thread.__init__(self)
        self.name = name
        self.threadID = threadID
        self.lock = threading.Lock()
        self.domain_queue = domain_queue
        # xlsx 的生成收敛到 report 模块，这里只收集行数据
        self.rows = rows

    def __get_Http_info__(self, threadLock):
        while True:
            if self.domain_queue.empty():
                break
            domains = self.domain_queue.get(timeout=5)
            domain = domains["domain"]
            url_ip = domains["url_ip"]
            time.sleep(2)
            result = self.__get_request_result__(url_ip)
            with cores._progress_lock:
                cores.sniff_done += 1
            cores.progress("[*] Sniffing: %d done, current %s" % (cores.sniff_done, url_ip))
            if result != "error":
                row = [cores.sniff_done, url_ip, domain, "", "", "", "", "", ""]
                if result != "timeout":
                    row[3] = result["status"]
                    row[4] = result["des_ip"]
                    row[5] = result["server"]
                    row[6] = result["title"]
                    row[7] = result["cdn"]
                if self.lock.acquire(True):
                    self.rows.append(row)
                    self.lock.release()

    def __get_request_result__(self, url):
        result = {"status": "", "server": "", "cookie": "",
                  "cdn": "", "des_ip": "", "sou_ip": "", "title": ""}
        cdn = ""
        try:
            with requests.get(url, timeout=5, stream=True) as rsp:
                status_code = rsp.status_code
                result["status"] = status_code
                headers = rsp.headers
                if "Server" in headers:
                    result["server"] = headers['Server']
                if "Cookie" in headers:
                    result["cookie"] = headers['Cookie']
                if "X-Via" in headers:
                    cdn = cdn + headers['X-Via']
                if "Via" in headers:
                    cdn = cdn + headers['Via']
                result["cdn"] = cdn
                sock = rsp.raw._connection.sock

                if sock:
                    des_ip = sock.getpeername()[0]
                    sou_ip = sock.getsockname()[0]
                    if des_ip:
                        result["des_ip"] = des_ip
                    if sou_ip:
                        result["sou_ip"] = sou_ip
                    sock.close()
                html = rsp.text
                title = re.findall('<title>(.+)</title>', html)
                if title:
                    result["title"] = title[0]
                rsp.close()
                return result
        except requests.exceptions.InvalidURL:
            return "error"
        except requests.exceptions.ConnectionError:
            return "timeout"
        except requests.exceptions.ReadTimeout:
            return "timeout"

    def run(self):
        threadLock = threading.Lock()
        try:
            self.__get_Http_info__(threadLock)
        except Exception:
            cores.thread_failed = True
            cores.logexc("[!] NetThread %s aborted" % self.name)
