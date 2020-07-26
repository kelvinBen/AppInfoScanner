# -*- coding: utf-8 -*-
# Author: kelvinBen
# Github: https://github.com/kelvinBen/AppInfoScanner


import os
import re
import zipfile
import libs.core as cores
from queue import Queue
from libs.core.parses import ParsesThreads


class iOSTask(object):
    thread_list =[]
    value_list = []
    result_dict = {}

    def __init__(self,input, rules, net_sniffer,no_resource,all,threads):
        self.path = input
        self.rules = rules
        self.net_sniffer = net_sniffer
        self.no_resource = no_resource
        self.all = all
        self.threads = threads
        if rules:
            config.filter_strs.append(r'.*'+str(rules)+'.*')
        self.file_queue = Queue()
        self.shell_falg=False

    def start(self):
        # ipa 文件
        if self.path.split(".")[1] == 'ipa':
            # 对ipa进行解包
            self.__decode_ipa__(cores.output_path)

            #文件提取
            self.__scanner_file_by_ipa__(cores.output_path)
        
        self.__start_threads()
        
        for thread in self.thread_list:
            thread.join()

        self.__print__()
        

    def __scanner_file_by_ipa__(self,output):   
        scanner_file_suffix = ["plist","js","xml","html"]
        scanner_dir =  os.path.join(output,"Payload")
        self.__get_scanner_file__(scanner_dir,scanner_file_suffix)

    def __get_scanner_file__(self,scanner_dir,file_suffix):
        dir_or_files = os.listdir(scanner_dir)
        for dir_file in dir_or_files:
            dir_file_path = os.path.join(scanner_dir,dir_file)
            if os.path.isdir(dir_file_path):
                if dir_file.endswith(".app"):
                    self.elf_file_name = dir_file.split(".")[0]
                self.__get_scanner_file__(dir_file_path,file_suffix)
            else:
                if self.elf_file_name == dir_file:
                    self.file_queue.put(dir_file_path)
                    continue
                if self.no_resource:    
                    dir_file_suffix =  dir_file.split(".")
                    if len(dir_file_suffix) > 1:
                        if dir_file_suffix[1] in file_suffix:
                            self.file_queue.put(dir_file_path)

    def __decode_ipa__(self,output_path):
        zip_files = zipfile.ZipFile(self.path)
        for zip_file in zip_files.filelist:
            zip_files.extract(zip_file.filename,output_path)

    def __start_threads(self):
        for threadID in range(1,self.threads) : 
            name = "Thread - " + str(threadID)
            thread =  ParsesThreads(threadID,name,self.file_queue,self.all,self.result_dict)
            thread.start()
            self.thread_list.append(thread)
    

    def __print__(self):
        print("=========The result set for the static scan is shown below:===============")
        with open(cores.result_path,"a+") as f:
            for key,value in self.result_dict.items():
                f.write(key+"\r")
                for result in value:
                    if result in self.value_list:
                        continue
                    self.value_list.append(result)
                    print(result)
                    f.write("\t"+result+"\r")
        print("For more information about the search, see: %s" %(cores.result_path))

        if self.shell_falg:
            print('\033[1;33mWarning: This application has shell, the retrieval results may not be accurate, Please remove the shell and try again!')