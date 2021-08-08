#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen
# Github: https://github.com/kelvinBen/AppInfoScanner
import os
import config
from queue import Queue

class WebTask(object):
    thread_list =[]
    value_list = []
    result_dict = {}

    def __init__(self, path):
        self.path = path
        self.file_queue = Queue()
        self.file_identifier = []

    def start(self):
        if len(config.web_file_suffix) <=0:
            scanner_file_suffix = ["html","js","html","xml"]
            
        scanner_file_suffix = config.web_file_suffix
        if os.path.isdir(self.path):
            self.__get_scanner_file__(self.path,scanner_file_suffix)
        else:
            if not (self.path.split(".")[-1] in scanner_file_suffix):
                err_info = ("Retrieval of this file type is not supported. Select a file or directory with a suffix of %s" % ",".join(scanner_file_suffix))
                raise Exception(err_info)
            self.file_queue.put(self.path)
        return {"comp_list":[],"shell_flag":False,"file_queue":self.file_queue,"packagename":None,"file_identifier":self.file_identifier}

    def __get_scanner_file__(self,scanner_dir,file_suffix):
        dir_or_files = os.listdir(scanner_dir)
        for dir_file in dir_or_files:
            dir_file_path = os.path.join(scanner_dir,dir_file)
            if os.path.isdir(dir_file_path):
                self.__get_scanner_file__(dir_file_path,file_suffix)
            else:
                if len(dir_file.split("."))>1:
                    if dir_file.split(".")[-1] in file_suffix:
                        with open(file_path,'rb') as f:
                            dex_md5 = str(hashlib.md5().update(f.read()).hexdigest()).upper()
                            self.file_identifier.append(dex_md5)
                        self.file_queue.put(dir_file_path)