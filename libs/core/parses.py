# -*- coding: utf-8 -*-
# Author: kelvinBen
# Github: https://github.com/kelvinBen/AppInfoScanner


import threading
import config
import re
import os
import libs.core as cores

class ParsesThreads(threading.Thread):

    def __init__(self,threadID,name,file_queue,all,result_dict):
        threading.Thread.__init__(self) 
        self.file_queue = file_queue
        self.name = name
        self.threadID = threadID
        self.result_list = []
        self.all = all
        self.result_dict=result_dict
            
    def __regular_parse__(self,threadLock):
        while True:
            try:
                file_path = self.file_queue.get(timeout = 5)
                scan_str = ("Scan file : %s" % file_path)
                print(scan_str)

                try:
                    os.path.basename(file_path).split(".")[1]
                except Exception as e:
                    self.__get_string__(file_path,threadLock)
                    continue
                self.__file_parse__(file_path,threadLock)

                result_set =  set(self.result_list)
                if len(result_set) !=0:
                    self.result_dict[file_path] = result_set

                if self.file_queue.empty():
                    break
            except Exception as e:
                break

    def __file_parse__(self,file_path,threadLock):
        with open(file_path,"r",encoding="utf8") as file :
            file_content =  file.read()
            # 获取到所有的字符串
            pattern = re.compile(r'\"(.*?)\"') 
            results = pattern.findall(file_content)

            # 遍历所有的字符串
            for result in set(results): 
                self.__parse_string__(result,threadLock)

    def __get_string__(self,dir_file_path,threadLock):
        temp =  os.path.join(cores.output_path,"temp.txt")
        cmd_str = ("%s %s > %s") % (cores.strings_path,dir_file_path,temp)
        if os.system(cmd_str) == 0:
            with open(temp,"r") as f:
                lines = f.readlines()
                for line in lines:
                    self.__parse_string__(line,threadLock)

    def __parse_string__(self,result,threadLock):
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

                threadLock.acquire()
                self.result_list.append(filter_resl[0])
                threadLock.release()
            continue

    def __filter__(self,resl_str):
        return_flag = 1 
        resl_str = resl_str.replace("\r","").replace("\n","").replace(" ","")
        if len(resl_str) == 0:
            return 0

        # 单独处理https或者http开头的字符串
        http_list =["https","https://","https:","http","http://","https:",]
        for filte in http_list:
            if filte == resl_str:
                return 0

        for filte in config.filter_no:
            resl_str = resl_str.replace(filte,"")
            if len(resl_str) == 0:
                return_flag = 0 
                continue
            
            if re.match(filte,resl_str):
                return_flag = 0 
                continue
        return return_flag  

    def run(self):
        threadLock = threading.Lock()
        self.__regular_parse__(threadLock)
