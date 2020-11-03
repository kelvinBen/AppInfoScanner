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
# 3. URI地址
filter_strs =[
    r'^http://.*',
    r'^https://.*',
    r'.*(http://.*)',
    r'.*(https://.*)', 
    r'.*((?:[0-9]{1,3}\.){3}[0-9]{1,3}).*',
    # r'/[a-z0-9A-Z]+/.*'
]

# 过滤无用的内容,
filter_no = [
    u'127.0.0.1',
    u'0.0.0.0',
    u'localhost',
    r"^http://www.w3.org"
    r"L.*/",
    r"/.*;",
    r"/.*<",
    r'^http://schemas.android.com',
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
    "html",
    "xml",
    "php",
    "jsp",
    "class",
    "asp",
    "aspx",
    "py"
]
