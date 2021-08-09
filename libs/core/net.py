#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen
# Github: https://github.com/kelvinBen/AppInfoScanner
import re
import time
import logging
import threading
import requests
import libs.core as cores

class NetThreads(threading.Thread):
    
    def __init__(self,threadID,name,domain_queue,worksheet):
        threading.Thread.__init__(self) 
        self.name = name
        self.threadID = threadID
        self.lock =  threading.Lock()
        self.domain_queue = domain_queue 
        self.worksheet = worksheet

    def __get_Http_info__(self,threadLock):
        while True:
            if self.domain_queue.empty():
                break
            domains = self.domain_queue.get(timeout=5)
            domain = domains["domain"] 
            url_ip = domains["url_ip"]
            time.sleep(2)
            result = self.__get_request_result__(url_ip)
            logging.info("[+] " + url_ip)
            if result != "error":
                if self.lock.acquire(True):
                    cores.excel_row = cores.excel_row + 1
                    self.worksheet.cell(row=cores.excel_row, column=1).value = cores.excel_row
                    self.worksheet.cell(row=cores.excel_row, column=2).value = url_ip
                    self.worksheet.cell(row=cores.excel_row, column=3).value = domain

                    if result != "timeout":
                        self.worksheet.cell(row=cores.excel_row, column=4).value = result["status"]
                        self.worksheet.cell(row=cores.excel_row, column=5).value = result["des_ip"]
                        self.worksheet.cell(row=cores.excel_row, column=6).value = result["server"]
                        self.worksheet.cell(row=cores.excel_row, column=7).value = result["title"]
                        self.worksheet.cell(row=cores.excel_row, column=8).value = result["cdn"]
                        self.worksheet.cell(row=cores.excel_row, column=9).value = ""
                        
                    self.lock.release()
            
    def __get_request_result__(self,url):
        result={"status":"","server":"","cookie":"","cdn":"","des_ip":"","sou_ip":"","title":""}
        cdn = ""
        try:
            with requests.get(url, timeout=5,stream=True) as rsp:
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
                result["cdn"]  = cdn
                sock = rsp.raw._connection.sock
                
                if sock:
                    des_ip = sock.getpeername()[0]
                    sou_ip = sock.getsockname()[0]
                    if des_ip:
                        result["des_ip"]  = des_ip
                    if sou_ip:
                        result["sou_ip"]  = sou_ip
                    sock.close()
                html = rsp.text
                title = re.findall('<title>(.+)</title>',html)
                if title:
                    result["title"]  = title[0]
                rsp.close()
                return result
        except requests.exceptions.InvalidURL as e:
            return "error"
        except requests.exceptions.ConnectionError as e1:
            return "timeout"
        except requests.exceptions.ReadTimeout as e2:
            return "timeout"

    def run(self):
        threadLock = threading.Lock()
        self.__get_Http_info__(threadLock)
