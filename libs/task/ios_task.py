#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen
# Github: https://github.com/kelvinBen/AppInfoScanner
import os
import zipfile
import binascii
import platform
import libs.core as cores
from queue import Queue

class iOSTask(object):
    elf_file_name = ""
    def __init__(self,path):
        self.path = path
        self.file_queue = Queue()
        self.shell_flag = False
        self.file_identifier= []

    def start(self):
        file_path = self.path
        if file_path.split(".")[-1] == 'ipa':
            self.__decode_ipa__(cores.output_path)
        elif self.__get_file_header__(file_path): 
            self.file_queue.put(file_path)
        else:
            raise Exception("Retrieval of this file type is not supported. Select IPA file or Mach-o file.")
        return {"shell_flag":self.shell_flag,"file_queue":self.file_queue,"comp_list":[],"packagename":None,"file_identifier":self.file_identifier}
                    
    def __get_file_header__(self,file_path):
        crypt_load_command_hex = "2C000000"
        macho_name =  os.path.split(file_path)[-1]
        self.file_identifier.append(macho_name)
        with open(file_path,"rb") as macho_file:
            macho_file.seek(0x0,0)
            magic = binascii.hexlify(macho_file.read(4)).decode().upper()
            macho_magics =  ["CFFAEDFE","CEFAEDFE","BEBAFECA","CAFEBABE"]
            if magic in macho_magics:
                hex_str = binascii.hexlify(macho_file.read()).decode().upper()
                if crypt_load_command_hex in hex_str:
                    macho_file.seek(int(hex_str.index("2C000000")/2)+20,0)
                    cryptid = binascii.hexlify(macho_file.read(4)).decode()
                    if cryptid == "01000000":
                        self.shell_flag = True
                macho_file.close()
                return True
            macho_file.close()
            return False

    def __get_scanner_file__(self,scanner_dir,file_suffix):
        dir_or_files = os.listdir(scanner_dir)
        for dir_file in dir_or_files:
            dir_file_path = os.path.join(scanner_dir,dir_file)
            if os.path.isdir(dir_file_path):
                if dir_file.endswith(".app"):
                    self.elf_file_name = dir_file.replace(".app","")
                self.__get_scanner_file__(dir_file_path,file_suffix)
            else:
                if self.elf_file_name == dir_file:
                    self.__get_file_header__(dir_file_path)
                    self.file_queue.put(dir_file_path)
                    continue
                if cores.resource_flag:    
                    dir_file_suffix =  dir_file.split(".")
                    if len(dir_file_suffix) > 1:
                        if dir_file_suffix[-1] in file_suffix:
                            self.__get_file_header__(dir_file_path)
                            self.file_queue.put(dir_file_path)

    def __decode_ipa__(self,output_path):
        scanner_file_suffix = ["plist","js","xml","html"]
        scanner_dir =  os.path.join(output_path,"Payload")

        with zipfile.ZipFile(self.path,"r") as zip_files:
            zip_file_names = zip_files.namelist()
            for zip_file_name in zip_file_names:
                try:
                    if platform.system() == "Windows":
                        new_file_name = zip_file_name.encode('cp437').decode('GBK')
                    else:
                        new_file_name = zip_file_name.encode('cp437').decode('utf-8')
                except UnicodeEncodeError:
                    new_file_name = zip_file_name.encode('utf-8').decode('utf-8')

                new_ext_file_path = os.path.join(output_path,new_file_name)
                ext_file_path  = zip_files.extract(zip_file_name,output_path)
                os.rename(ext_file_path,new_ext_file_path)
        self.__get_scanner_file__(scanner_dir,scanner_file_suffix)

    def __get_parse_dir__(self,output_path,file_path):
        start = file_path.index("Payload/")
        end = file_path.index(".app")
        root_dir = file_path[start:end]
        if platform.system() == "Windows":
            root_dir = root_dir.replace("/","\\")
        old_root_dir = os.path.join(output_path,root_dir+".app")
        return old_root_dir