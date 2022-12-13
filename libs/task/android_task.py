#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen
# Github: https://github.com/kelvinBen/AppInfoScanner
import json
import os
import re
import shutil
import subprocess

import config
import hashlib
import zipfile
import platform
from queue import Queue
import libs.core as cores


class AndroidTask(object):

    def __init__(self, path, package):
        self.path = path
        self.package = package
        self.file_queue = Queue()
        self.shell_flag = False
        self.packagename = ""
        self.comp_list = []
        self.file_identifier = []
        self.permissions = []
        self.files = []
        self.protect_flag = """{
          "360加固": [
            "assets/.appkey",
            "assets/libjiagu.so",
            "libjiagu.so",
            "libjiagu_art.so",
            "libjiagu_x86.so",
            "libprotectClass.so",
            ".appkey",
            "1ibjgdtc.so",
            "libjgdtc.so",
            "libjgdtc_a64.so",
            "libjgdtc_art.so",
            "libjgdtc_x64.so",
            "libjgdtc_x86.so",
            "libjiagu_a64.so",
            "libjiagu_ls.so",
            "libjiagu_x64.so"
          ],
          "APKProtect": [
            "libAPKProtect.so"
          ],
          "UU安全": [
            "libuusafe.jar.so",
            "libuusafe.so",
            "libuusafeempty.so",
            "assets/libuusafe.jar.so",
            "assets/libuusafe.so",
            "lib/armeabi/libuusafeempty.so"
          ],
          "apktoolplus": [
            "assets/jiagu_data.bin",
            "assets/sign.bin",
            "jiagu_data.bin",
            "lib/armeabi/libapktoolplus_jiagu.so",
            "libapktoolplus_jiagu.so",
            "sign.bin"
          ],
          "中国移动加固": [
            "assets/mogosec_classes",
            "assets/mogosec_data",
            "assets/mogosec_dexinfo",
            "assets/mogosec_march",
            "ibmogosecurity.so",
            "lib/armeabi/libcmvmp.so",
            "lib/armeabi/libmogosec_dex.so",
            "lib/armeabi/libmogosec_sodecrypt.so",
            "lib/armeabi/libmogosecurity.so",
            "libcmvmp.so",
            "libmogosec_dex.so",
            "libmogosec_sodecrypt.so",
            "mogosec_classes",
            "mogosec_data",
            "mogosec_dexinfo",
            "mogosec_march"
          ],
          "几维安全": [
            "assets/dex.dat",
            "lib/armeabi/kdpdata.so",
            "lib/armeabi/libkdp.so",
            "lib/armeabi/libkwscmm.so",
            "libkwscmm.so",
            "libkwscr.so",
            "libkwslinker.so"
          ],
          "启明星辰": [
            "libvenSec.so",
            "libvenustech.so"
          ],
          "网秦加固": [
            "libnqshield.so"
          ],
          "娜迦加固": [
            "libchaosvmp.so",
            "libddog.so",
            "libfdog.so"
          ],
          "娜迦加固（新版2022）": [
            "assets/maindata/fake_classes.dex",
            "lib/armeabi/libxloader.so",
            "lib/armeabi-v7a/libxloader.so",
            "lib/arm64-v8a/libxloader.so",
            "libxloader.so"
          ],
          "娜迦加固（企业版）": [
            "libedog.so"
          ],
          "梆梆安全（企业版）": [
            "libDexHelper-x86.so",
            "libDexHelper.so",
            "1ibDexHelper.so"
          ],
          "梆梆安全": [
            "libSecShell.so",
            "libsecexe.so",
            "libsecmain.so",
            "libSecShel1.so"
          ],
          "梆梆安全（定制版）": [
            "assets/classes.jar",
            "lib/armeabi/DexHelper.so"
          ],
          "梆梆安全（免费版）": [
            "assets/secData0.jar",
            "lib/armeabi/libSecShell-x86.so",
            "lib/armeabi/libSecShell.so"
          ],
          "海云安加固": [
            "assets/itse",
            "lib/armeabi/libitsec.so",
            "libitsec.so"
          ],
          "爱加密": [
            "assets/af.bin",
            "assets/ijiami.ajm",
            "assets/ijm_lib/X86/libexec.so",
            "assets/ijm_lib/armeabi/libexec.so",
            "assets/signed.bin",
            "ijiami.dat",
            "lib/armeabi/libexecmain.so",
            "libexecmain.so"
          ],
          "爱加密企业版": [
            "ijiami.ajm"
          ],
          "珊瑚灵御": [
            "assets/libreincp.so",
            "assets/libreincp_x86.so",
            "libreincp.so",
            "libreincp_x86.so"
          ],
          "瑞星加固": [
            "librsprotect.so"
          ],
          "百度加固": [
            "libbaiduprotect.so",
            "assets/baiduprotect.jar",
            "assets/baiduprotect1.jar",
            "baiduprotect1.jar",
            "lib/armeabi/libbaiduprotect.so",
            "libbaiduprotect_art.so",
            "libbaiduprotect_x86.so"
          ],
          "盛大加固": [
            "libapssec.so"
          ],
          "网易易盾": [
            "libnesec.so"
          ],
          "腾讯": [
            "libexec.so",
            "libshell.so"
          ],
          "腾讯加固": [
            "lib/armeabi/mix.dex",
            "lib/armeabi/mixz.dex",
            "lib/armeabi/libshella-xxxx.so",
            "lib/armeabi/libshellx-xxxx.so",
            "tencent_stub"
          ],
          "腾讯乐固（旧版）": [
            "libtup.so",
            "mix.dex",
            "liblegudb.so",
            "libshella",
            "mixz.dex",
            "libshel1x"
          ],
          "腾讯乐固": [
            "libshellx"
          ],
          "腾讯乐固（VMP）": [
            "lib/arm64-v8a/libxgVipSecurity.so",
            "lib/armeabi-v7a/libxgVipSecurity.so",
            "libxgVipSecurity.so"
          ],
          "腾讯云": [
            "assets/libshellx-super.2021.so",
            "lib/armeabi/libshell-super.2019.so",
            "lib/armeabi/libshell-super.2020.so",
            "lib/armeabi/libshell-super.2021.so",
            "lib/armeabi/libshell-super.2022.so",
            "lib/armeabi/libshell-super.2023.so",
            "tencent_sub"
          ],
          "腾讯云移动应用安全": [
            "0000000lllll.dex",
            "00000olllll.dex",
            "000O00ll111l.dex",
            "00O000ll111l.dex",
            "0OO00l111l1l",
            "o0oooOO0ooOo.dat"
          ],
          "腾讯云移动应用安全（腾讯御安全）": [
            "libBugly-yaq.so",
            "libshell-super.2019.so",
            "libshellx-super.2019.so",
            "libzBugly-yaq.so",
            "t86",
            "tosprotection",
            "tosversion",
            "000000011111.dex",
            "000000111111.dex",
            "000001111111",
            "00000o11111.dex",
            "o0ooo000oo0o.dat"
          ],
          "腾讯御安全": [
            "libtosprotection.armeabi-v7a.so",
            "libtosprotection.armeabi.so",
            "libtosprotection.x86.so",
            "assets/libtosprotection.armeabi-v7a.so",
            "assets/libtosprotection.armeabi.so",
            "assets/libtosprotection.x86.so",
            "assets/tosversion",
            "lib/armeabi/libTmsdk-xxx-mfr.so",
            "lib/armeabi/libtest.so"
          ],
          "腾讯Bugly": [
            "lib/arm64-v8a/libBugly.so",
            "libBugly.so"
          ],
          "蛮犀": [
            "assets/mxsafe.config",
            "assets/mxsafe.data",
            "assets/mxsafe.jar",
            "assets/mxsafe/arm64-v8a/libdSafeShell.so",
            "assets/mxsafe/x86_64/libdSafeShell.so",
            "libdSafeShell.so"
          ],
          "通付盾": [
            "libNSaferOnly.so",
            "libegis.so"
          ],
          "阿里加固": [
            "assets/armeabi/libfakejni.so",
            "assets/armeabi/libzuma.so",
            "assets/classes.dex.dat",
            "assets/dp.arm-v7.so.dat",
            "assets/dp.arm.so.dat",
            "assets/libpreverify1.so",
            "assets/libzuma.so",
            "assets/libzumadata.so",
            "dexprotect"
          ],
          "阿里聚安全": [
            "aliprotect.dat",
            "libdemolish.so",
            "libfakejni.so",
            "libmobisec.so",
            "libsgmain.so",
            "libzuma.so",
            "libzumadata.so",
            "libdemolishdata.so",
            "libpreverify1.so",
            "libsgsecuritybody.so"
          ],
          "顶像科技": [
            "libx3g.so",
            "lib/armeabi/libx3g.so"
          ]
        }"""

    def start(self):
        # 检查java环境是否存在
        if os.system("java -version") != 0:
            raise Exception("Please install the Java environment!")
        # 检查Frida环境是否存在
        if os.system("frida --version") != 0:
            raise Exception("Please install the Frida environment!")

        input_file_path = self.path
        if os.path.isdir(input_file_path):
            self.__decode_dir__(input_file_path)
        else:
            if self.__decode_file__(input_file_path) == "error":
                raise Exception(
                    "Retrieval of this file type is not supported. Select APK file or DEX file.")

        return {"comp_list": self.comp_list, "shell_flag": self.shell_flag, "file_queue": self.file_queue,
                "packagename": self.packagename, "file_identifier": self.file_identifier,
                "permissions": self.permissions}

    def __detect_protect__(self, file_path):
        markNameMap = json.loads(self.protect_flag)
        markNameMap = dict(markNameMap)
        zip_stream = zipfile.ZipFile(file_path)  # 默认模式r,读
        flag = ''
        for zippath in zip_stream.namelist():
            if 'lib' in zippath:
                for key, value in markNameMap.items():
                    for mark in value:
                        if mark in zippath:
                            print("detect 【{}】 protector\nspecific code:{}->{}\n".format(key, zippath, mark))
                            flag += ("detect 【{}】 protector\nspecific code:{}->{}\n".format(key, zippath, mark))
        if len(flag) > 0:
            self.__android_unpack__()
        # so库文件模式找不到就全量匹配
        for zippath in zip_stream.namelist():
            for key, value in markNameMap.items():
                for mark in value:
                    if mark in zippath:
                        print("detect 【{}】 protector\nspecific code:{}->{}\n".format(key, zippath, mark))
                        flag += ("detect 【{}】 protector\nspecific code:{}->{}\n".format(key, zippath, mark))
        if len(flag) > 0:
            self.__android_unpack__()
        print("We can't detect protect")

    def __android_unpack__(self):
        print('[*] unpacking')
        cmd_str = ('%s install %s') % (str(cores.adb_path), str(self.path))
        print('[*] Install the APK')
        if os.system(cmd_str) == 0:
            print("Push Frida Server")
            cmd_str = ('%s push %s /data/local/tmp') % (str(cores.adb_path), str(cores.frida32_path))
            cmd_str1 = ('%s push %s /data/local/tmp') % (str(cores.adb_path), str(cores.frida64_path))
            cmd_str2 = ('%s shell su -c "chmod 777 /data/local/tmp/hexl-server-arm64"') % (str(cores.adb_path))
            cmd_str3 = ('%s shell su -c "setenforce 0"') % (str(cores.adb_path))
            cmd_str4 = ('%s shell su -c "./data/local/tmp/hexl-server-arm64 &"') % (str(cores.adb_path))
            print("[*] Running Frida Server")
            if os.system(cmd_str) == 0 and os.system(cmd_str1) == 0 and os.system(cmd_str2) == 0 \
                    and os.system(cmd_str3) == 0 and os.system(cmd_str4) == 0:
                print("[*] Frida Server started")
            else:
                print("[-] Running failed, please check the error in terminal")
                exit()
        else:
            print("[-] We can't install the APP")
            exit()
        get_info_command = "%s dump badging %s" % (cores.aapt_apth, self.path)
        pip = os.popen(get_info_command)
        output = pip.buffer.read().decode('utf-8', 'ignore')
        if output == "":
            raise Exception("can't get the app info")
        match = re.compile("package: name='(\S+)'").match(
            output)  # 通过正则匹配，获取包名
        print(match.group(1))
        cmd_str = ('frida-dexdump -U -f %s') % (str(match.group(1)))
        if os.system(cmd_str) != 0:
            print("An error occurred in the unpack")
            exit()

    def __decode_file__(self, file_path):
        apktool_path = str(cores.apktool_path)
        backsmali_path = str(cores.backsmali_path)
        base_out_path = str(cores.output_path)
        filename = os.path.basename(file_path)
        suffix_name = filename.split(".")[-1]

        if suffix_name == "apk":
            self.__detect_protect__(file_path)

        if suffix_name == "apk" or suffix_name == "hpk":
            name = filename.split(".")[0]
            output_path = os.path.join(base_out_path, name)
            self.__decode_apk__(file_path, apktool_path, output_path)
        elif suffix_name == "dex":
            f = open(file_path, 'rb')
            md5_obj = hashlib.md5()
            while True:
                r = f.read(1024)
                if not r:
                    break
                md5_obj.update(r)
            dex_md5 = md5_obj.hexdigest().lower()
            self.file_identifier.append(dex_md5)
            output_path = os.path.join(base_out_path, dex_md5)
            if not os.path.exists(output_path):
                os.makedirs(output_path)
            self.__decode_dex__(file_path, backsmali_path, output_path)
        else:
            return "error"

    def __decode_dir__(self, root_dir):
        dir_or_files = os.listdir(root_dir)
        for dir_or_file in dir_or_files:
            dir_or_file_path = os.path.join(root_dir, dir_or_file)
            if os.path.isdir(dir_or_file_path):
                self.__decode_dir__(dir_or_file_path)
            else:
                if self.__decode_file__(dir_or_file_path) == "error":
                    continue

    # 分解apk
    def __decode_apk__(self, file_path, apktool_path, output_path):
        cmd_str = ('java -jar "%s" d -f "%s" -o "%s" --only-main-classe') % (
            str(apktool_path), str(file_path), str(output_path))
        if os.system(cmd_str) == 0:
            self.__shell_test__(output_path)
            self.__scanner_file_by_apktool__(output_path)
        else:
            print(
                "[-] Decompilation failed, please submit error information at https://github.com/kelvinBen/AppInfoScanner/issues")
            raise Exception(file_path + ", Decompilation failed.")

    # 分解dex
    def __decode_dex__(self, file_path, backsmali_path, output_path):
        cmd_str = ('java -jar "%s" d "%s"') % (str(backsmali_path),
                                               str(file_path))
        if os.system(cmd_str) == 0:
            self.__get_scanner_file__(output_path)
        else:
            print(
                "[-] Decompilation failed, please submit error information at https://github.com/kelvinBen/AppInfoScanner/issues")
            raise Exception(file_path + ", Decompilation failed.")

    # 初始化检测文件信息
    def __scanner_file_by_apktool__(self, output_path):
        file_names = os.listdir(output_path)
        for file_name in file_names:
            file_path = os.path.join(output_path, file_name)
            if not os.path.isdir(file_path):
                continue

            if "smali" in file_name or "assets" in file_name:
                scanner_file_suffixs = ["smali", "js", "xml"]
                if cores.resource_flag:
                    scanner_file_suffixs = ["smali"]
                self.__get_scanner_file__(file_path, scanner_file_suffixs)

    def __get_scanner_file__(self, scanner_dir, scanner_file_suffixs=["smali"]):
        dir_or_files = os.listdir(scanner_dir)
        for dir_or_file in dir_or_files:
            dir_file_path = os.path.join(scanner_dir, dir_or_file)

            if os.path.isdir(dir_file_path):
                self.__get_scanner_file__(dir_file_path, scanner_file_suffixs)
            else:
                if ("." not in dir_or_file) or (len(dir_or_file.split(".")) < 1) or (
                        dir_or_file.split(".")[-1] not in scanner_file_suffixs):
                    continue
                self.file_queue.put(dir_file_path)
                for component in config.filter_components:
                    comp = component.replace(".", "/")
                    if (comp in dir_file_path):
                        if (component not in self.comp_list):
                            self.comp_list.append(component)

    def __shell_test__(self, output):
        am_path = os.path.join(output, "AndroidManifest.xml")

        with open(am_path, "r", encoding='utf-8', errors='ignore') as f:
            am_str = f.read()

            am_package = re.compile(r'<manifest.*package=\"(.*?)\".*')
            apackage = am_package.findall(am_str)
            if len(apackage) >= 1:
                self.packagename = apackage[0]
                self.file_identifier.append(apackage[0])

            am_name = re.compile(r'<application.*android:name=\"(.*?)\".*>')
            aname = am_name.findall(am_str)
            if aname and len(aname) >= 1:
                if aname[0] in config.shell_list:
                    self.shell_flag = True

            am_permission = re.compile(r'<uses-permission android:name="(.*)"/>')
            ampermissions = am_permission.findall(am_str)
            for ampermission in ampermissions:
                if ampermission in config.apk_permissions:
                    self.permissions.append(ampermission)
