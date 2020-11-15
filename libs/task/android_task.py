# -*- coding: utf-8 -*-
# Author: kelvinBen
# Github: https://github.com/kelvinBen/AppInfoScanner
import os
import re
import config
import hashlib
from queue import Queue
import libs.core as cores


class AndroidTask(object):

    def __init__(self,path,no_resource,package):
        self.path = path
        self.no_resource = no_resource
        self.package = package

        self.file_queue = Queue()
        self.shell_flag=False
        self.packagename=""
        self.comp_list=[]
        self.file_identifier=[]
        
    def start(self):
        # 检查java环境是否存在
        if os.system("java -version") !=0 :
            raise Exception("Please install the Java environment!")
        
        input_file_path = self.path
        
        if os.path.isdir(input_file_path):
            self.__decode_dir__(input_file_path)
        else:
           if self.__decode_file__(input_file_path) == "error":
               raise Exception("Retrieval of this file type is not supported. Select APK file or DEX file.")
        
        return {"comp_list":self.comp_list,"shell_flag":self.shell_flag,"file_queue":self.file_queue,"packagename":self.packagename,"file_identifier":self.file_identifier}

    def __decode_file__(self,file_path):
        apktool_path = str(cores.apktool_path)
        output_path = str(cores.output_path)
        backsmali_path = str(cores.backsmali_path)
        suffix_name = file_path.split(".")[-1]
        if suffix_name == "apk":
            self.__decode_apk__(file_path,apktool_path,output_path)
        elif suffix_name == "dex":
            with open(file_path,'rb') as f:
                dex_md5 = str(hashlib.md5().update(f.read()).hexdigest()).upper()
                self.file_identifier.append(dex_md5)
            self.__decode_dex__(file_path,backsmali_path,output_path)
        else:
            return "error"
    
    def __decode_dir__(self,root_dir):
        dir_or_files = os.listdir(root_dir)
        for dir_or_file in dir_or_files:
            dir_or_file_path = os.path.join(root_dir,dir_or_file) 
            if os.path.isdir(dir_or_file_path):
                self.__decode_dir__(dir_or_file_path)
            else: 
                if self.__decode_file__(dir_or_file_path) == "error":
                    continue

    # 分解apk
    def __decode_apk__(self,file_path,apktool_path,output_path):
        cmd_str = ("java -jar %s d -f %s -o %s --only-main-classe") % (apktool_path,str(file_path),output_path)
        if os.system(cmd_str) == 0:
            self.__shell_test__(output_path)
            self.__scanner_file_by_apktool__(output_path)
        else:
            print("Decompilation failed, please submit error information at https://github.com/kelvinBen/AppInfoScanner/issues")
            raise Exception(file_path + ", Decompilation failed.")
                

    # 分解dex
    def __decode_dex__(self,file_path,backsmali_path,output_path):
        cmd_str = ("java -jar %s d %s") % (backsmali_path,str(file_path))
        if os.system(cmd_str) == 0:
            self.__get_scanner_file__(output_path)
        else:
            print("Decompilation failed, please submit error information at https://github.com/kelvinBen/AppInfoScanner/issues")
            raise Exception(file_path + ", Decompilation failed.")
    

    # 初始化检测文件信息
    def __scanner_file_by_apktool__(self,output_path):
        file_names = os.listdir(output_path)
        for file_name in file_names:
            file_path =  os.path.join(output_path,file_name)
            if not os.path.isdir(file_path):
                continue

            if "smali" in file_name or "assets" in file_name:
                scanner_file_suffixs = ["smali","js","xml"]
                if self.no_resource:
                    scanner_file_suffixs =["smali"]
                self.__get_scanner_file__(file_path,scanner_file_suffixs)

    def __get_scanner_file__(self,scanner_dir,scanner_file_suffixs=["smali"]):
        dir_or_files = os.listdir(scanner_dir)
        for dir_or_file in dir_or_files:
            dir_file_path = os.path.join(scanner_dir,dir_or_file)
            
            if os.path.isdir(dir_file_path):
                self.__get_scanner_file__(dir_file_path,scanner_file_suffixs)
            else:
                if ("." not in dir_or_file) or (len(dir_or_file.split(".")) < 1) or (dir_or_file.split(".")[-1] not in scanner_file_suffixs):
                    continue
                self.file_queue.put(dir_file_path)
                for component in config.filter_components:
                    comp = component.replace(".","/")
                    if(comp in dir_file_path):
                        if(component not in self.comp_list):
                            self.comp_list.append(component)

    def __shell_test__(self,output):
        am_path = os.path.join(output,"AndroidManifest.xml")
        
        with open(am_path,"r",encoding='utf-8',errors='ignore') as f:
            am_str = f.read()

            am_package=  re.compile(r'<manifest.*package=\"(.*?)\".*')
            apackage = am_package.findall(am_str)
            if len(apackage) >=1:
                self.packagename = apackage[0]
                self.file_identifier.append(apackage[0])

            am_name = re.compile(r'<application.*android:name=\"(.*?)\".*>') 
            aname = am_name.findall(am_str)
            if aname and len(aname)>=1:
                if aname[0] in config.shell_list:
                    self.shell_flag = True