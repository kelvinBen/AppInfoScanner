# -*- coding: utf-8 -*-
# Author: kelvinBen
# Github: https://github.com/kelvinBen/AppInfoScanner


import os
import re
import config
import threading
from queue import Queue
import libs.core as cores
from libs.core.parses import ParsesThreads

class AndroidTask(object):
    comp_list =[]
    thread_list =[]
    result_dict = {}
    value_list = []

    def __init__(self, input, rules, net_sniffer,no_resource,package,all,threads):
        self.net_sniffer = net_sniffer
        self.path = input
        if rules:
            config.filter_strs.append(r'.*'+str(rules)+'.*')
        self.no_resource = no_resource
        self.package = package
        self.all = all
        self.threads = threads
        self.file_queue = Queue()
        self.shell_falg=False
        self.packagename=""
        

    def start(self):
        # 检查java环境是否存在
        if os.system("java -version") !=0 :
            raise Exception("Please install the Java environment!")
        
        # 根据不同的文件后缀进行文件解析
        if os.path.isfile(self.path):
            if self.path.split(".")[1] == "apk":
                self.__decode_apk__(self.path)
            elif self.path.split(".")[1] == "dex":
                self.__decode_dex__(self.path)
            else:
                # 抛出异常
                raise Exception("Retrieval of this file type is not supported. Select APK file or DEX file.")
        else:
            self.__get_file_type__(self.path)
        self.__start_threads()
        
        for thread in self.thread_list:
            thread.join()

        self.__print__()
        
        # if self.net_sniffer:
        #     self.__start_net__()

    # 分解apk
    def __decode_apk__(self,path):
        if self.no_resource:
            self.__decode_dex__(path)
        else:
            cmd_str = ("java -jar %s d -f %s -o %s") % (cores.apktool_path,path,cores.output_path)
            if os.system(cmd_str) == 0:
                self.__scanner_file_by_apktool__(cores.output_path)
            else:
                raise Exception("The Apktool tool was not found.")

    # 分解dex
    def __decode_dex__(self,path):
        cmd_str = ("java -jar %s d %s") % (cores.backsmali_path,path)
        if os.system(cmd_str) == 0:
            self.__get_scanner_file__(cores.output_path,"smali")
        else:
            raise Exception("The baksmali tool was not found.")
    

    # 初始化检测文件信息
    def __scanner_file_by_apktool__(self,output):

        # shell检测
        self.__shell_test__(output)

        scanner_dir_list =  ["smali","assets"]    
        scanner_file_suffix = ["smali","js","xml"]

        for dir in scanner_dir_list:
            scanner_dir =  os.path.join(output,dir)
            if os.path.exists(scanner_dir):
                self.__get_scanner_file__(scanner_dir,scanner_file_suffix)

    def __get_scanner_file__(self,scanner_dir,file_suffix):
        dir_or_files = os.listdir(scanner_dir)
        for dir_file in dir_or_files:
            dir_file_path = os.path.join(scanner_dir,dir_file)
            if os.path.isdir(dir_file_path):
                self.__get_scanner_file__(dir_file_path,file_suffix)
            else:
                if "." not in dir_file:
                    continue
                if len(dir_file.split("."))>1:
                    if dir_file.split(".")[1] in file_suffix:
                        self.file_queue.put(dir_file_path)
                        for component in config.filter_components:
                            comp = component.replace(".","/")
                            if( comp in dir_file_path):
                                if(component not in self.comp_list):
                                    self.comp_list.append(component)


    def __get_file_type__(self,root_path):
        dir_or_files = os.listdir(root_path)
        for dir_file in dir_or_files:
            dir_file_path = os.path.join(root_path,dir_file)
            if os.path.isdir(dir_file_path):
                self.__get_file_type__(dir_file_path)
            else:
                if dir_file.split(".")[1] == "apk":
                    self.__decode_apk__(dir_file)
                elif dir_file.split(".")[1] == "dex":
                    self.__decode_dex__(dir_file)
                else:
                    continue

    def __print__(self):
        if self.packagename: 
            print("=========  The package name of this APP is: ===============")
            print(self.packagename)

        if len(self.comp_list) != 0:
            print("========= Component information is as follows :===============")
            for json in self.comp_list:
                print(json)

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

    def __start_threads(self):
        for threadID in range(1,self.threads) : 
            name = "Thread - " + str(threadID)
            thread =  ParsesThreads(threadID,name,self.file_queue,self.all,self.result_dict)
            thread.start()
            self.thread_list.append(thread)

    def __shell_test__(self,output):
        am_path = os.path.join(output,"AndroidManifest.xml")
        
        with open(am_path,"r") as f:
            am_str = f.read()

            am_package=  re.compile(r'<manifest.*package=\"(.*?)\".*')
            apackage = am_package.findall(am_str)
            if len(apackage) >=1:
                self.packagename = apackage

            am_name = re.compile(r'<application.*android:name=\"(.*?)\".*>') 
            aname = am_name.findall(am_str)
            if aname and len(aname)>=1:
                if aname[0] in config.shell_list:
                    self.shell_falg = True