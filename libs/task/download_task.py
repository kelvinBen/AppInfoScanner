# -*- coding: utf-8 -*-
# Author: kelvinBen
# Github: https://github.com/kelvinBen/AppInfoScanner
import os
import re
import config
import hashlib
from queue import Queue
import libs.core as cores


class DownloadTask(object):

    def __init__(self):
        self.path = path

    def start(self):
        input_path = self.path
        if input_path.startswith("http://") or input_path.startswith("https://"):
            if input_path.endswith("apk"):
                # 用来下载APK或者缓存H5或者页面内容
                pass
            
        return input_path
        
