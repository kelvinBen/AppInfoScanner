#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen (微信/WeChat: bromomo )
# Github: https://github.com/kelvinBen/AppInfoScanner
# Gitee: https://gitee.com/kelvin_ben/AppInfoScanner
# AppInfoScanner v1.0.10 增强模块：dex/zip/axml 魔数检测与修复
#
# 位置说明：本模块为自研代码，置于 libs/core/ 与 download/net/parses 平级；
#   tools/ 仅存放第三方二进制（apktool.jar/baksmali.jar/unpacker 等）。
#
# 背景 (issue #52 / #44 / #42)：
#   脱壳 (frida-dexdump 等) 得到的 dex 文件常见三类损坏，导致 baksmali/apktool
#   反编译失败或输出为空：
#     1. 头部 8 字节魔数被反调试逻辑抹除（不再以 "dex\n035\0" 开头）
#     2. file_size 字段 (offset 32) 与实际文件大小不一致（多 dump / 少 dump）
#     3. checksum (offset 8, adler32) 与 signature (offset 12, sha1) 校验失败
#   apktool 侧对 APK(zip) 的解析则要求文件以 "PK\x03\x04" 开头。
#   APK 内的 AndroidManifest.xml 为 Android 二进制 XML (AXML)，脱壳/dump 产物
#   同样常见两类损坏，导致 apktool 报 manifest 解析失败：
#     1. 文件头 4 字节魔数被抹（应固定为 03 00 08 00，即 ResChunk_header 的
#        type=RES_XML_TYPE(0x0003) + headerSize=0x0008，对照 AOSP ResourceTypes.h）
#     2. 文件总大小字段 (offset 4, uint32 小端) 与实际文件大小不一致
#   AXML 无 checksum/signature 字段；文件头之后紧跟的第一个内部块必为字符串池
#   (type=0x0001 + headerSize=0x001C)，据此做内容佐证，避免把任意文件误判为 AXML。
#
# dexlib2 (baksmali) 校验行为（对照 JesusFreke/smali 源码）：
#   - DexBackedDexReader 读取时先校验 magic 前 4 字节必须为 "dex\n"，
#     否则抛 NotADexFile / DexException，直接拒绝解析；
#   - 默认加载路径还会调用 verifyChecksumAndSignature：
#     checksum 为 offset 8 起 4 字节小端 adler32（对 offset 12 至文件尾计算），
#     signature 为 offset 12 起 20 字节 sha1（对 offset 32 至文件尾计算），
#     不匹配时抛 ChecksumFailedException；脱壳 dex 几乎必然命中。
#     注意：signature 用 SHA-1 是 DEX 文件格式规范（Android 官方文档
#     https://source.android.com/docs/core/runtime/dex-format) 的强制要求，
#     不是安全用途，无法换成其他算法。
#
# 用法（独立命令行）：
#   python3 libs/core/fix_magic.py detect <file>    检测魔数/大小/校验和状态
#   python3 libs/core/fix_magic.py fix dex <file>   修复 dex 六个头字段
#   python3 libs/core/fix_magic.py fix zip <file>   修复 zip/apk 魔数前 4 字节
#   python3 libs/core/fix_magic.py fix axml <file>  修复 AndroidManifest.xml 等 AXML 头
#                                                  (xml 为 axml 的别名)
# 或作为模块调用：
#   from libs.core.fix_magic import detect, fix_dex, fix_axml
#
# 修复前自动备份原文件为 <file>.bak。
import os
import sys
import zlib
import shutil
import hashlib

DEX_MAGIC = b"dex\n035\x00"
ZIP_MAGIC = b"PK\x03\x04"
# ResChunk_header: type=RES_XML_TYPE(0x0003) + headerSize(0x0008)，均为 uint16 小端
AXML_MAGIC = b"\x03\x00\x08\x00"
# 文件头后紧跟的字符串池块头前 4 字节: type=RES_STRING_POOL_TYPE(0x0001) + headerSize(0x001C)
AXML_STRING_POOL_HEAD = b"\x01\x00\x1c\x00"
DEX_HEADER_SIZE = 112
AXML_HEADER_SIZE = 8


def detect_dex(path):
    """返回 dex 文件各字段的状态字典；非 dex 结构返回 None。"""
    size = os.path.getsize(path)
    if size < DEX_HEADER_SIZE:
        return None
    with open(path, "rb") as f:
        content = f.read()
    header = content[:DEX_HEADER_SIZE]
    status = {
        "type": "dex",
        "magic_ok": header[:8] == DEX_MAGIC,
        "magic_now": header[:8],
        "file_size_field": int.from_bytes(header[32:36], "little"),
        "file_size_real": size,
        "size_ok": int.from_bytes(header[32:36], "little") == size,
        "checksum": int.from_bytes(header[8:12], "little"),
        "signature": header[12:32].hex(),
        "checksum_ok": int.from_bytes(header[8:12], "little") == zlib.adler32(content[12:]),
        "signature_ok": header[12:32] == hashlib.sha1(content[32:]).digest(),
    }
    return status


# 检测AXML文件头状态; 需魔数完好或字符串池佐证, 否则返回None
def detect_axml(path):
    size = os.path.getsize(path)
    if size < AXML_HEADER_SIZE:
        return None
    with open(path, "rb") as f:
        content = f.read()
    magic_ok = content[:4] == AXML_MAGIC
    string_pool_follows = len(content) >= 12 and content[8:12] == AXML_STRING_POOL_HEAD
    if not magic_ok and not string_pool_follows:
        return None
    size_field = int.from_bytes(content[4:8], "little")
    return {
        "type": "axml",
        "magic_ok": magic_ok,
        "magic_now": content[:4],
        "file_size_field": size_field,
        "file_size_real": size,
        "size_ok": size_field == size,
    }


def detect_zip(path):
    with open(path, "rb") as f:
        magic = f.read(4)
    return {"type": "zip/apk", "magic_ok": magic == ZIP_MAGIC, "magic_now": magic}


def detect(path):
    # 识别顺序: axml(需内容佐证，最严格) -> dex(宽松) -> zip(兜底)。
    # axml 必须放在 dex 之前：完好的 AndroidManifest.xml 通常超过 112 字节，
    # 若先走 detect_dex 会被误报为魔数损坏的 dex。
    status = detect_axml(path)
    if status is None:
        status = detect_dex(path)
    if status is None:
        status = detect_zip(path)
    print("[*] File: {}".format(path))
    for key, value in status.items():
        print("    {:<16} {}".format(key, value))
    if status.get("type") in ("dex", "axml"):
        problems = [k for k in ("magic_ok", "size_ok", "checksum_ok", "signature_ok")
                    if k in status and not status[k]]
        if problems:
            print("[-] Broken fields: {}".format(", ".join(problems)))
            print("    run: python3 libs/core/fix_magic.py fix {} {}".format(
                status["type"], path))
        else:
            print("[+] {} header is healthy".format(status["type"]))
    elif not status["magic_ok"]:
        print("[-] Broken magic, run: python3 libs/core/fix_magic.py fix zip {}".format(path))
    return status


def backup(path):
    bak = path + ".bak"
    if not os.path.exists(bak):
        shutil.copy2(path, bak)
        print("[*] Backup saved: {}".format(bak))


def fix_dex(path):
    """按实际文件内容重写 dex 头的魔数、file_size、header_size、endian_tag、checksum、signature 六个字段。"""
    with open(path, "rb") as f:
        content = bytearray(f.read())
    if len(content) < DEX_HEADER_SIZE:
        print("[-] File too small to be a dex")
        return False
    backup(path)
    content[0:8] = DEX_MAGIC                                          # 魔数
    content[32:36] = len(content).to_bytes(4, "little")               # file_size
    content[36:40] = (0x70).to_bytes(4, "little")                     # header_size
    content[40:44] = (0x12345678).to_bytes(4, "little")               # endian_tag (小端固定值)
    content[12:32] = hashlib.sha1(content[32:]).digest()              # signature
    content[8:12] = zlib.adler32(content[12:]).to_bytes(4, "little")  # checksum
    with open(path, "wb") as f:
        f.write(content)
    print("[+] dex header rewritten: magic/file_size/header_size/endian_tag/signature/checksum")
    detect(path)
    return True


def fix_zip(path):
    with open(path, "rb") as f:
        head = f.read(4)
    backup(path)
    with open(path, "r+b") as f:
        f.seek(0)
        f.write(ZIP_MAGIC)
    print("[+] zip magic rewritten: {} -> {}".format(head, ZIP_MAGIC))
    detect(path)
    return True


def fix_axml(path):
    """按实际文件内容重写 AXML 文件头的魔数与文件总大小两个字段。

    AXML 无 checksum/signature 字段；其余内部块 (字符串池/命名空间/元素) 不在
    修复范围内 —— 若这些块本身损坏，重写文件头也无法恢复。
    """
    with open(path, "rb") as f:
        content = bytearray(f.read())
    if len(content) < AXML_HEADER_SIZE:
        print("[-] File too small to be an Android binary XML")
        return False
    backup(path)
    content[0:4] = AXML_MAGIC                                   # type=0x0003 + headerSize=0x0008
    content[4:8] = len(content).to_bytes(4, "little")           # 文件总大小
    with open(path, "wb") as f:
        f.write(content)
    print("[+] axml header rewritten: magic/file_size")
    detect(path)
    return True


def resolve_path(path):
    """规范化入参路径：转绝对路径并拒绝路径穿越片段。"""
    if ".." in path.replace("\\", "/").split("/"):
        print("[-] Path traversal segments are not allowed: {}".format(path))
        return None
    return os.path.abspath(path)


def main(argv):
    if len(argv) < 3 or argv[1] not in ("detect", "fix"):
        print(__doc__)
        return 1
    if argv[1] == "detect":
        path = resolve_path(argv[2])
        if path is None or not os.path.isfile(path):
            print("[-] No such file: {}".format(argv[2]))
            return 1
        detect(path)
        return 0
    # fix 子命令：fix dex <file> / fix zip <file> / fix axml <file> (xml 为别名)
    if len(argv) < 4 or argv[2] not in ("dex", "zip", "axml", "xml"):
        print(__doc__)
        return 1
    ftype, path = argv[2], resolve_path(argv[3])
    if path is None or not os.path.isfile(path):
        print("[-] No such file: {}".format(argv[3]))
        return 1
    if ftype == "dex":
        if detect_dex(path) is None:
            print("[-] Not a dex file: {}".format(path))
            return 1
        fix_dex(path)
    elif ftype in ("axml", "xml"):
        if detect_axml(path) is None:
            print("[-] Not an Android binary XML (AXML) file: {}".format(path))
            return 1
        fix_axml(path)
    else:
        fix_zip(path)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
