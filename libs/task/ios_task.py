#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen (微信/WeChat: bromomo )
# Github: https://github.com/kelvinBen/AppInfoScanner
# Gitee: https://gitee.com/kelvin_ben/AppInfoScanner
import os
import shutil
import zipfile
import binascii
import plistlib
import libs.core as cores
from queue import Queue


class iOSTask(object):
    elf_file_name = ""

    def __init__(self, path):
        self.path = path
        self.file_queue = Queue()
        self.shell_flag = False
        self.file_identifier = []
        self.permissions = []

    def start(self):
        file_path = self.path
        if file_path.split(".")[-1] == 'ipa':
            self.__decode_ipa__(cores.output_path)
            self.__parse_plist_permissions__(cores.output_path)
            self.__scanner_file_by_ipa__(cores.output_path)
        elif self.__get_file_header__(file_path):
            self.file_queue.put(file_path)
        else:
            raise Exception(cores.i18n.t(
                "Retrieval of this file type is not supported. Select IPA file or Mach-o file."))
        return {"shell_flag": self.shell_flag, "file_queue": self.file_queue, "comp_list": [], "packagename": None, "file_identifier": self.file_identifier, "permissions": self.permissions}

    def __parse_plist_permissions__(self, output_path):
        """从解包后的 .app/Info.plist（含内嵌 framework 的）检测隐私权限声明，附带中文说明。"""
        for root, _, files in os.walk(output_path):
            for file_name in files:
                if file_name != "Info.plist":
                    continue
                plist_path = os.path.join(root, file_name)
                try:
                    with open(plist_path, "rb") as f:
                        plist = plistlib.load(f)
                except Exception:
                    # 损坏/非 plist 文件跳过，不中断扫描
                    continue
                if not isinstance(plist, dict):
                    continue
                for key, desc in cores.config.ios_permissions.items():
                    entry = "{} ({})".format(key, desc)
                    if key in plist and entry not in self.permissions:
                        self.permissions.append(entry)

    def __get_file_header__(self, file_path):
        hex_hand = 0x0
        macho_name = os.path.split(file_path)[-1]
        self.file_identifier.append(macho_name)
        with open(file_path, "rb") as macho_file:
            macho_file.seek(hex_hand, 0)
            magic = binascii.hexlify(macho_file.read(4)).decode().upper()
            macho_magics = ["CFFAEDFE", "CEFAEDFE", "BEBAFECA", "CAFEBABE"]
            if magic in macho_magics:
                self.__shell_test__(macho_file, hex_hand)
                macho_file.close()
                return True
            macho_file.close()
            return False

    def __shell_test__(self, macho_file, hex_hand):
        while True:
            magic = binascii.hexlify(macho_file.read(4)).decode().upper()
            if magic == "2C000000":
                macho_file.seek(hex_hand, 0)
                encryption_info_command = binascii.hexlify(
                    macho_file.read(24)).decode()
                cryptid = encryption_info_command[-8:len(
                    encryption_info_command)]
                if cryptid == "01000000":
                    self.shell_flag = True
                break
            hex_hand = hex_hand + 4

    def __scanner_file_by_ipa__(self, output):
        scanner_file_suffix = ["plist", "js", "xml", "html"]
        scanner_dir = os.path.join(output, "Payload")
        self.__get_scanner_file__(scanner_dir, scanner_file_suffix)

    def __get_scanner_file__(self, scanner_dir, file_suffix):
        dir_or_files = os.listdir(scanner_dir)
        for dir_file in dir_or_files:
            dir_file_path = os.path.join(scanner_dir, dir_file)
            if os.path.isdir(dir_file_path):
                if str(dir_file).endswith(".app"):
                    self.elf_file_name = str(dir_file).replace(".app", "")
                self.__get_scanner_file__(dir_file_path, file_suffix)
            else:
                if self.elf_file_name == dir_file:
                    self.__get_file_header__(dir_file_path)
                    self.file_queue.put(dir_file_path)
                    continue
                if cores.resource_flag:
                    dir_file_suffix = str(dir_file).split(".")
                    if len(dir_file_suffix) > 1:
                        if dir_file_suffix[-1] in file_suffix:
                            self.__get_file_header__(dir_file_path)
                            self.file_queue.put(dir_file_path)

    def __decode_ipa__(self, output_path):
        # 空文件/损坏的 IPA 打不开 zip 流，给出明确报错而不是裸 BadZipFile traceback
        try:
            zip_files = zipfile.ZipFile(self.path, "r")
        except zipfile.BadZipFile:
            cores.logp("[-] Invalid IPA file: {}".format(self.path))
            raise Exception(cores.i18n.t(
                "{}: it's not a valid IPA(zip) file. Please check the file integrity.",
                self.path)) from None
        with zip_files:
            zip_file_names = zip_files.namelist()
            zip_files.extract(zip_file_names[0], output_path)
            try:
                new_zip_file = zip_file_names[0].encode('cp437').decode('utf-8')
            except UnicodeEncodeError:
                new_zip_file = zip_file_names[0].encode('utf-8').decode('utf-8')

                old_zip_dir = self.__get_parse_dir__(output_path, zip_file_names[0])
                new_zip_dir = self.__get_parse_dir__(output_path, new_zip_file)
                os.rename(old_zip_dir, new_zip_dir)

            for zip_file in zip_file_names:
                old_ext_path = zip_files.extract(zip_file, output_path)
                if not "Payload" in old_ext_path:
                    continue
                start = str(old_ext_path).index("Payload")
                dir_path = old_ext_path[start:len(old_ext_path)]
                old_ext_path = os.path.join(output_path, dir_path)
                try:
                    new_zip_file = zip_file.encode('cp437').decode('utf-8')
                except UnicodeEncodeError:
                    new_zip_file = zip_file.encode('utf-8').decode('utf-8')

                # zip 成员名按 zip 规范固定用 "/" 分隔，normpath 负责转换为当前系统的标准分隔符
                new_ext_path = os.path.normpath(os.path.join(output_path, new_zip_file))

                if not os.path.exists(new_ext_path):
                    dir_path = os.path.dirname(new_ext_path)
                    if not os.path.exists(dir_path):
                        os.makedirs(dir_path)
                shutil.move(old_ext_path, new_ext_path)
                # 当旧目录与新目录不一致时，删除旧的目录
                if not (old_ext_path == new_ext_path) and os.path.exists(old_ext_path) and (".app" in old_ext_path):
                    try:
                        # mac发生权限问题的时候做处理
                        os.remove(old_ext_path)
                    except Exception:
                        shutil.rmtree(old_ext_path)

    def __get_parse_dir__(self, output_path, file_path):
        start = file_path.index("Payload/")
        end = file_path.index(".app")
        root_dir = file_path[start:end]
        old_root_dir = os.path.normpath(os.path.join(output_path, root_dir + ".app"))
        return old_root_dir
