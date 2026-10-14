#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen (微信/WeChat: bromomo )
# Github: https://github.com/kelvinBen/AppInfoScanner
# Gitee: https://gitee.com/kelvin_ben/AppInfoScanner
# init 引导式配置(非规则层): 分步向导, 每步可 q 取消, 写回前备份
import os
import shutil
import time

import requests

import libs.core as cores
from libs.core import default_config as dc
from libs.core import ai_verify

# 云厂商模板(预填 base_url/kind/常用模型), 本地 Ollama 由探测自动发现
CLOUD_TEMPLATES = {
    "deepseek": {"kind": "openai_compatible", "base_url": "https://api.deepseek.com/v1",
                 "model_text": "deepseek-chat"},
    "glm": {"kind": "openai_compatible", "base_url": "https://open.bigmodel.cn/api/paas/v4",
            "model_text": "glm-4-flash"},
    "kimi": {"kind": "openai_compatible", "base_url": "https://api.moonshot.cn/v1",
             "model_text": "moonshot-v1-8k"},
    "openai": {"kind": "openai_compatible", "base_url": "https://api.openai.com/v1",
               "model_text": "gpt-4o-mini"},
    "anthropic": {"kind": "anthropic", "base_url": "https://api.anthropic.com",
                  "model_text": "claude-sonnet-4"},
}
LOCAL_OLLAMA = {"kind": "openai_compatible", "base_url": "http://127.0.0.1:11434/v1"}

# 非规则层配置项注册表: (键路径, 中文说明, 输入类型 text|bool|int|choice)
REGISTRY = [
    ("download", "下载任务个人配置", [
        ("method", "HTTP 方法(get/post)", "choice:get,post"),
        ("headers", "自定义请求头(TOML 字符串, 留空跳过)", "text"),
        ("data", "POST 数据(TOML 字符串, 留空跳过)", "text"),
    ]),
    ("ai", "AI 语义复核([ai_verify])", [
        ("ai_verify.enabled", "启用 AI 复核(true/false)", "bool"),
        ("ai_verify.timeout", "请求超时秒数", "int"),
        ("ai_verify.batch_size", "每批送检文件数", "int"),
        ("ai_verify.granularity", "送检粒度 method(仅命中方法体)/file(全文件)", "choice:method,file"),
        ("ai_verify.max_file_tokens", "单文件 token 上限", "int"),
    ]),
    ("space", "空间测绘(引擎配置将在 V1.0.15 提供)", None),
]


class Cancel(Exception):
    # 用户按 q/Ctrl-C 取消, 不落盘
    pass


# 提问器: 生产用 input, 测试注入应答序列
def _stdin_ask(prompt, default=None):
    try:
        tip = "[{}] ".format(default) if default is not None else "[] "
        raw = input("{}{}".format(prompt, tip)).strip()
    except (EOFError, KeyboardInterrupt):
        raise Cancel()
    if raw.lower() == "q":
        raise Cancel()
    return raw


def run(section="all", config_path=None, ask=None):
    # 入口: 读工作区配置->分节引导->确认->备份->写回; 返回变更摘要
    ask = ask or _stdin_ask
    path = config_path or getattr(cores, "config_path", "") or os.path.join(
        str(getattr(cores, "default_out_root", os.path.expanduser("~/Documents/AppInfoScanner"))),
        "config.toml")
    if not os.path.exists(path):
        raise OSError("workspace config not found: {} (先运行一次扫描任务以部署工作区)".format(path))
    import tomllib
    with open(path, "rb") as f:
        parsed = tomllib.load(f)
    cfg = dc.merge_over_defaults(parsed)
    changed = []
    for sec_name, sec_desc, items in REGISTRY:
        if section not in ("all", sec_name):
            continue
        if items is None:
            print("[*] {} : 本版本暂无可配置项, 跳过".format(sec_desc))
            continue
        print("\n===== {} ({}) =====".format(sec_desc, sec_name))
        for key_path, desc, kind in items:
            new_value = _ask_value(cfg, key_path, desc, kind, ask)
            if new_value is not None:
                _set_path(cfg, key_path, new_value)
                changed.append("{} = {!r}".format(key_path, new_value))
        if sec_name == "ai":
            provider = _wizard_provider(ask)
            if provider:
                name, fields = provider
                cfg.setdefault("ai_verify", {}).setdefault("provider", {})[name] = fields
                changed.append("ai_verify.provider.{} = {{...}}".format(name))
    if not changed:
        print("[*] 无变更")
        return changed
    print("\n===== 变更摘要 =====")
    for c in changed:
        print("  " + c)
    if ask("确认写入 {} ? (y/n) ".format(path), "y").lower() not in ("y", "yes"):
        raise Cancel()
    backup = "{}.bak.{}".format(path, time.strftime("%Y%m%d%H%M%S"))
    shutil.copy2(path, backup)
    with open(path, "w", encoding="utf-8") as f:
        f.write(dc.dump_config(cfg))
    print("[+] 已写入, 备份: {}".format(backup))
    return changed


# 单键提问: 回车保留现值; 返回 None 表示未改
def _ask_value(cfg, key_path, desc, kind, ask):
    current = _get_path(cfg, key_path)
    raw = ask("{} (现值 {!r}, 回车保留, q 取消): ".format(desc, current))
    if raw.lower() == "q":
        raise Cancel()
    if raw == "":
        return None
    if kind == "bool":
        return raw.lower() in ("true", "1", "yes", "y")
    if kind == "int":
        return int(raw)
    if kind.startswith("choice:"):
        options = kind.split(":", 1)[1].split(",")
        if raw not in options:
            print("[-] 无效选项, 保留现值")
            return None
        return raw
    return raw


# AI provider 向导: 探测本地 Ollama -> 云模板 -> key(${ENV} 支持) -> 拉模型 -> 连通测试
def _wizard_provider(ask):
    print("\n----- AI provider 向导 -----")
    local_up = _probe_local_ollama()
    options = []
    if local_up:
        options.append("local-ollama(已探测到本地服务)")
    options.extend("{}({})".format(k, v["base_url"]) for k, v in CLOUD_TEMPLATES.items())
    options.append("skip(跳过)")
    print("可选 provider:")
    for i, opt in enumerate(options, 1):
        print("  {}. {}".format(i, opt))
    pick = ask("选择序号: ")
    if pick.lower() == "q":
        raise Cancel()
    try:
        chosen = options[int(pick) - 1]
    except (ValueError, IndexError):
        print("[-] 无效序号, 跳过 provider 配置")
        return None
    if chosen.startswith("skip"):
        return None
    if chosen.startswith("local-ollama"):
        name, fields = "local-ollama", dict(LOCAL_OLLAMA)
    else:
        vendor = chosen.split("(")[0]
        name, fields = vendor, dict(CLOUD_TEMPLATES[vendor])
    raw_key = ask("api_key(支持 ${ENV_VAR} 写法, 本地可回车留空): ")
    if raw_key.lower() == "q":
        raise Cancel()
    fields["api_key"] = raw_key
    models = _fetch_models(fields)
    if models:
        print("可用模型(前 10):")
        for i, m in enumerate(models[:10], 1):
            print("  {}. {}".format(i, m))
        pick_m = ask("选择 model_text 序号(回车用默认 {}): ".format(fields.get("model_text", "")))
        if pick_m.isdigit() and 1 <= int(pick_m) <= min(10, len(models)):
            fields["model_text"] = models[int(pick_m) - 1]
    else:
        manual = ask("模型列表拉取失败, 手动输入 model_text(回车用默认): ")
        if manual:
            fields["model_text"] = manual
    fields.setdefault("model_text", "")
    print("[*] 连通性测试中...")
    if ai_verify.healthy(fields):
        print("[+] 连通正常")
        return name, fields
    print("[-] 连通失败, 仍写入配置(可稍后修改 api_key/model)")
    return name, fields


# 探测本地 Ollama(短超时, 失败即视为无)
def _probe_local_ollama():
    try:
        resp = requests.get(LOCAL_OLLAMA["base_url"] + "/models", timeout=2)
        return resp.status_code == 200
    except Exception:
        return False


# 拉取 /models 模型列表(失败返回 [])
def _fetch_models(fields):
    try:
        headers = {}
        key = ai_verify.expand_env(fields.get("api_key", "")).strip()
        if key:
            headers["Authorization"] = "Bearer " + key
        resp = requests.get(fields["base_url"].rstrip("/") + "/models",
                            headers=headers, timeout=8)
        if resp.status_code != 200:
            return []
        return [m.get("id", "") for m in resp.json().get("data", []) if m.get("id")]
    except Exception:
        return []


# 按点路径取值(支持 ai_verify.enabled 两级)
def _get_path(cfg, key_path):
    node = cfg
    for part in key_path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


# 按点路径写值(中间层缺失自动建 dict)
def _set_path(cfg, key_path, value):
    parts = key_path.split(".")
    node = cfg
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = value
