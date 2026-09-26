#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen (微信/WeChat: bromomo )
# Github: https://github.com/kelvinBen/AppInfoScanner
# Gitee: https://gitee.com/kelvin_ben/AppInfoScanner
import os
import hashlib
from queue import Queue
import libs.core as cores


class WebTask(object):
    thread_list = []
    value_list = []
    result_dict = {}

    def __init__(self, path):
        self.path = path
        self.file_queue = Queue()
        self.file_identifier = []
        self.permissions = []

    def start(self):
        # 后缀表转set, 空配置回退基础后缀
        suffixes = [str(suffix).lower() for suffix in cores.config.web_file_suffix]
        if not suffixes:
            suffixes = ["html", "js", "xml"]
        scanner_file_suffix = set(suffixes)
        if os.path.isdir(self.path):
            self.__get_scanner_file__(self.path, scanner_file_suffix)
        else:
            if not (self.path.rsplit(".", 1)[-1].lower() in scanner_file_suffix):
                err_info = ("Retrieval of this file type is not supported. Select a file or directory with a suffix of %s" % ",".join(sorted(scanner_file_suffix)))
                raise Exception(err_info)
            self.file_queue.put(self.path)
        return {"comp_list": [], "shell_flag": False, "file_queue": self.file_queue, "packagename": None, "file_identifier": self.file_identifier, "permissions": self.permissions}

    def __get_scanner_file__(self, scanner_dir, file_suffix):
        dir_or_files = os.listdir(scanner_dir)
        for dir_file in dir_or_files:
            dir_file_path = os.path.join(scanner_dir, dir_file)
            if os.path.isdir(dir_file_path):
                self.__get_scanner_file__(dir_file_path, file_suffix)
            else:
                if "." in dir_file and dir_file.rsplit(".", 1)[-1].lower() in file_suffix:
                    with open(dir_file_path, "rb") as f:
                        dex_md5 = hashlib.md5(f.read()).hexdigest().upper()
                        self.file_identifier.append(dex_md5)
                    self.file_queue.put(dir_file_path)
