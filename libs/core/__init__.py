# -*- coding: utf-8 -*-
# Author: kelvinBen
# Github: https://github.com/kelvinBen/AppInfoScanner

import platform
import os
import shutil

# smali 所在路径
smali_path = ""

# backsmli 所在路径
backsmali_path = ""

# apktool 所在路径
apktool_path = ""

# 系统类型
os_type = ""

# 输出路径
output_path = ""

class Bootstrapper(object):

    def __init__(self, path):
        global smali_path
        global backsmali_path
        global apktool_path
        global os_type
        global output_path
        global script_root_dir
        global result_path
        global strings_path

        script_root_dir =  os.path.dirname(os.path.abspath(path))
        tools_dir = os.path.join(script_root_dir,"tools")

        if platform.system() == "Windows":
            machine2bits = {'AMD64':64, 'x86_64': 64, 'i386': 32, 'x86': 32}
            machine2bits.get(platform.machine())

            if platform.machine() == 'i386' or platform.machine() == 'x86':
                strings_path = os.path.join(script_root_dir,"strings.exe")
            else:
                strings_path = os.path.join(script_root_dir,"strings64.exe")
        else:
            strings_path ="strings"
        #     os_type = "win"
        #     smali_str = "smali.bat"
        #     back_smali_str = "backsmali.bat"
        #     apktool_path_str = "apktool.bat"
        # elif platform.system() == "Linux":
        #     os_type = "lin"
        #     smali_str = "smali"
        #     back_smali_str = "backsmali"
        #     apktool_path_str = "apktool"
        # else:
        #     os_type = "mac"
        #     smali_str = "smali"
        

        # smali_path = os.path.join(tools_dir,str(os_type) + os.sep + smali_str)
        backsmali_path = os.path.join(tools_dir,"baksmali.jar")
        apktool_path = os.path.join(tools_dir, "apktool.jar")
        output_path = os.path.join(script_root_dir,"out")
        result_path = os.path.join(script_root_dir,"result.txt")

    def init(self):
        if os.path.exists(output_path):
            shutil.rmtree(output_path)
        os.makedirs(output_path)

        if os.path.exists(result_path):
            os.remove(result_path)

        
            


        