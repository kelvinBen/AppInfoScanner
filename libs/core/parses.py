#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen
# Github: https://github.com/kelvinBen/AppInfoScanner

import re
import os
import config
import threading
import libs.core as cores

class ParsesThreads(threading.Thread):

    def __init__(self,threadID,name,file_queue,result_dict,types):
        threading.Thread.__init__(self) 
        self.file_queue = file_queue
        self.name = name
        self.threadID = threadID
        self.result_list = []
        self.result_dict=result_dict
        self.types = types
            
    def __regular_parse__(self):
        while True:
            if self.file_queue.empty():
                break
            
            file_path = self.file_queue.get(timeout = 5)
            scan_str = ("[+] Scan file : %s" % file_path)
            if self.types == "iOS":
                self.__get_string_by_iOS__(file_path)
            else:
                self.__get_string_by_file__(file_path)
            
            result_set = set(self.result_list)
            if len(result_set) != 0:
                self.result_dict[file_path] = result_set

    def __get_string_by_iOS__(self,file_path):
        output_path = cores.output_path
        strings_path = cores.strings_path
        temp =  os.path.join(output_path,"temp.txt")
        cmd_str = ('"%s" "%s" > "%s"') % (str(strings_path),str(file_path),str(temp))
        if os.system(cmd_str) == 0:
            with open(temp,"r",encoding='utf-8',errors='ignore') as f:
                lines = f.readlines()
                for line in lines:
                    self.__parse_string__(line)

    def __get_string_by_file__(self,file_path):
        with open(file_path,"r",encoding="utf8",errors='ignore') as f :
            file_content =  f.read()
            # 获取到所有的字符串
            pattern = re.compile(r'\"(.*?)\"') 
            results = pattern.findall(file_content)

            # 搜素AK和SK信息
            if not ".js" == file_path[-3:]:
                akAndSkList = re.compile(r'.*accessKeyId.*".*"|.*accessKeySecret.*".*"|.*secret.*".*"').findall(file_content)
                for akAndSk in akAndSkList:
                    self.result_list.append(akAndSk.strip())
                    print("[+] AK or SK in:",akAndSk.strip())

            # 遍历所有的字符串
            for result in set(results): 
                self.__parse_string__(result)    
        
    def __parse_string__(self,result):
        # 通过正则筛选需要过滤的字符串
        for filter_str in config.filter_strs:
            filter_str_pat = re.compile(filter_str) 
            filter_resl = filter_str_pat.findall(result)
            # 过滤掉未搜索到的内容
            if len(filter_resl)!=0:
                # 提取第一个结果
                resl_str = filter_resl[0]
                # 过滤
                if self.__filter__(resl_str) == 0:
                    continue

                self.threadLock.acquire()
                if cores.all_flag:
                    print("[+] The string searched for matching rule is: %s" % (resl_str))
                self.result_list.append(resl_str)
                self.threadLock.release()
            continue

    def __filter__(self,resl_str):
        return_flag = 1 
        resl_str = resl_str.replace("\r","").replace("\n","").replace(" ","")
        
        if len(resl_str) == 0:
            return 0
            
        for filte in set(config.filter_no):
            resl_str = resl_str.replace(filte,"")
            if len(resl_str) == 0:
                return_flag = 0 
                continue
            
            if re.match(filte,resl_str):
                return_flag = 0 
                continue
        return return_flag  

    def run(self):
        self.threadLock = threading.Lock()
        self.__regular_parse__()