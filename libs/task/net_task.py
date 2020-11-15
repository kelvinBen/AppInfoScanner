# -*- coding: utf-8 -*-
# Author: kelvinBen
# Github: https://github.com/kelvinBen/AppInfoScanner

import re
import xlwt
import socket
from queue import Queue
import libs.core as cores
from libs.core.net import NetThreads

import requests
class NetTask(object):
    value_list = []
    domain_list=[]
    
    def __init__(self,result_dict,app_history_list,file_identifier,threads):
        self.result_dict = result_dict
        self.app_history_list = app_history_list
        self.file_identifier = file_identifier
        self.domain_queue = Queue()
        self.threads = threads 
        self.thread_list = []

    def start(self):
        xls_result_path = cores.xls_result_path
        workbook = xlwt.Workbook(encoding = 'utf-8')
        worksheet = self.__creating_excel_header__(workbook)
        self.__start_threads__(worksheet)
        self.__write_result_to_txt__()

        for thread in self.thread_list:
            thread.join()


        workbook.save(xls_result_path)

    def __creating_excel_header__(self,workbook):
        worksheet = workbook.add_sheet("Result",cell_overwrite_ok=True)
        worksheet.write(0,0, label = "Number")
        worksheet.write(0,1, label = "IP/URL")
        worksheet.write(0,2, label = "Domain")
        worksheet.write(0,3, label = "Status")
        worksheet.write(0,4, label = "IP")
        worksheet.write(0,5, label = "Server")
        worksheet.write(0,6, label = "Title")
        worksheet.write(0,7, label = "CDN")
        worksheet.write(0,8, label = "Finger")
        return worksheet 
        
    def __write_result_to_txt__(self):
        txt_result_path = cores.txt_result_path
        append_file_flag = True
        
        with open(txt_result_path,"a+",encoding='utf-8',errors='ignore') as f:
            for key,value in self.result_dict.items():
                f.write(key+"\r")
                for result in value:
                    if result in self.value_list:
                        continue
                    
                    # 100个文件标识
                    for file in self.file_identifier:
                        if not(file in self.app_history_list) and ("http://" in result or "https://" in result):

                    # print(self.file_identifier,self.app_history_list,not(self.file_identifier[0] in self.app_history_list))
                    # if not(self.file_identifier in self.app_history_list) and ("http://" in result or "https://" in result):
                            domain = result.replace("https://","").replace("http://","")
                            if "/" in domain:
                                domain = domain[:domain.index("/")]
                            
                            self.domain_queue.put({"domain":domain,"url_ip":result})

                            print(domain,self.domain_list,not(domain in self.domain_list))
                            if not(domain in self.domain_list):
                                self.domain_list.append(domain)
                                self.__write_content_in_file__(cores.domain_history_path,domain)
                            if append_file_flag:
                                for identifier in self.file_identifier:
                                    if self.file_identifier in self.app_history_list:
                                        continue
                                    self.__write_content_in_file__(cores.app_history_path,identifier)
                                    append_file_flag = False
                    self.value_list.append(result)
                    f.write("\t"+result+"\r")
            f.close()

    def __start_threads__(self,worksheet):
        for threadID in range(0,self.threads) : 
            name = "Thread - " + str(threadID)
            thread =  NetThreads(threadID,name,self.domain_queue,worksheet)
            thread.start()
            self.thread_list.append(thread)

    def __write_content_in_file__(self,file_path,content):
        with open(file_path,"a+",encoding='utf-8',errors='ignore') as f:
            f.write(content+"\r")
            f.close()


def __get_request_result__(url):
        result={"status":"","server":"","cookie":"","cdn":"","des_ip":"","sou_ip":"","title":""}
        cdn = ""
        try:
            rsp = requests.get(url, timeout=5,stream=True)
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
            html = rsp.text
            title = re.findall('<title>(.+)</title>',html)
            result["title"]  = title
            return result
        except requests.exceptions.InvalidURL as e:
            return "error"
        except requests.exceptions.ConnectionError as e1:
           return "timeout"

# print(__get_request_result__("http://download.sxzwfw.gov.cn/getMerchantSign"))