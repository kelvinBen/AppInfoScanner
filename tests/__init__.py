#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen (微信/WeChat: bromomo )
# Github: https://github.com/kelvinBen/AppInfoScanner
# Gitee: https://gitee.com/kelvin_ben/AppInfoScanner
# AppInfoScanner 单元测试套件（零第三方依赖）：
#   python3 -m unittest discover -s tests -v
# 覆盖本版本沉淀的关键回归点：报告分类/默认配置序列化/提取与过滤规则/
# 壳检测门控/fix_magic 修复/i18n/嗅探内网拦截。
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from libs.core import default_config as dc


def load_runtime_config():
    """测试用运行时配置：不走 Bootstrapper(不触碰用户工作区)。"""
    import libs.core as cores
    import copy
    cores.config = types.SimpleNamespace(**copy.deepcopy(dc.DEFAULTS))
    # Bootstrapper 正常会设置的运行时开关
    cores.all_flag = True       # 默认安静模式(逐条打印走 -a)
    cores.resource_flag = False
    return cores
