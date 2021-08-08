#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen
# Github: https://github.com/kelvinBen/AppInfoScanner


# 此处用于搜索组件信息
# com.alibaba.fastjson -> fastjson
# com.google.gson -> gson
# com.fasterxml.jackson -> jackson
# net.sf.json -> 
# javax.xml.parsers.DocumentBuilder -> dom方式
# javax.xml.parsers.SAXParser -> sax方式
# org.jdom.input.SAXBuilder -> jdom
# org.dom4j.io.SAXReader -> dom4j
filter_components = [
    'com.alibaba.fastjson',
    'com.google.gson',
    'com.fasterxml.jackson',
    'net.sf.json',
    'javax.xml.parsers.DocumentBuilder',
    'javax.xml.parsers.SAXParser',
    'org.jdom.input.SAXBuilder',
    'org.dom4j.io.SAXReader'
]

# 此处目前支持过滤
# 1. https://以及http://开头的
# 2. IPv4的ip地址
# 3. URI地址,URI不能很好的拼接所以此处忽略
filter_strs =[
    r'https://.*|http://.*',
    # r'.*://([[0-9]{1,3}\.]{3}[0-9]{1,3}).*',
    r'.*://([\d{1,3}\.]{3}\d{1,3}).*',
    # r'/[a-z0-9A-Z]+/.*'
]

# 此处忽略常见的域名等信息
filter_no = [
    r'.*127.0.0.1',
    r'.*0.0.0.0',
    r'.*localhost',
    r'.*w3.org',
    r'.*apache.org',
    r'.*android.com',
    r'.*jpush.cn',
    r'.*umengcloud.com',
    r'.*umeng.com',
    r'.*github.com',
    r'.*w3school.com.cn',
    r'.*apple.com',
    r'.*.amap.com',
]

# 此处配置壳信息
shell_list =[
    'com.stub.StubApp',
    's.h.e.l.l.S',
    'com.Kiwisec.KiwiSecApplication',
    'com.Kiwisec.ProxyApplication',
    'com.secshell.secData.ApplicationWrapper',
    'com.secneo.apkwrapper.ApplicationWrapper',
    'com.tencent.StubShell.TxAppEntry',
    'c.b.c.b',
    'MyWrapperProxyApplication',
    'cn.securitystack.stee.AppStub',
    'com.linchaolong.apktoolplus.jiagu.ProxyApplication',
    'com.coral.util.StubApplication',
    'com.mogosec.AppMgr',
    'io.flutter.app.FlutterApplication'
]

# 此处配置需要扫描的web文件后缀
web_file_suffix =[
    "html",
    "js",
    "xml",
    "php",
    "jsp",
    "class",
    "asp",
    "aspx",
    "py"
]

# 配置需要忽略网络嗅探的文件后缀名,此处根据具体需求进行配置，默认为不过滤
sniffer_filter=[
    "jpg",
    "png",
    "jpeg",
    "gif",
]

# 配置自动下载Apk文件或者缓存HTML的请求头信息
headers = {
    "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:81.0) Gecko/20100101 Firefox/81.0",
    "Connection":"close"
}

# 配置自动下载Apk文件或者缓存HTML的请求体信息
data = {

}

# 配置自动下载Apk文件或者缓存HTML的请求方法信息，目前仅支持GET和POST
method = "GET"

