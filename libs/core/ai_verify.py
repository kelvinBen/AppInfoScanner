#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen (微信/WeChat: bromomo )
# Github: https://github.com/kelvinBen/AppInfoScanner
# Gitee: https://gitee.com/kelvin_ben/AppInfoScanner
# AI 语义复核: 多 provider(本地优先)双协议适配(openai_compatible/anthropic)
import os
import re

import requests

import libs.core as cores

# ${ENV_VAR} 引用展开(避免明文密钥落 config)
_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
# 本地部署特征: base_url 指向本机时默认最高优先(数据不出内网)
_LOCAL_HOSTS = ("127.0.0.1", "localhost", "[::1]", "0.0.0.0")


# 展开 ${ENV_VAR}; 未定义的环境变量原样保留
def expand_env(value):
    return _ENV_RE.sub(lambda m: os.environ.get(m.group(1), m.group(0)), value or "")


# 读取 [ai_verify.provider.*], 按 priority 升序; 本地 base_url 未显式指定时默认 0(最高)
def providers():
    cfg = getattr(cores.config, "ai_verify", {}) or {}
    items = []
    for name, p in (cfg.get("provider") or {}).items():
        if not isinstance(p, dict) or not p.get("base_url"):
            continue
        base = p.get("base_url", "")
        default_prio = 0 if any(h in base for h in _LOCAL_HOSTS) else 100
        items.append((int(p.get("priority", default_prio)), name, p))
    return [(name, p) for _, name, p in sorted(items, key=lambda t: (t[0], t[1]))]


# 按能力挑 provider(能力=模型槽 text/vision/audio; text 槽缺省回退 provider 本身)
def select(capability="text"):
    for name, p in providers():
        if capability != "text" and not p.get("model_" + capability):
            continue
        return name, p
    return None, None


# 单轮对话: 按 kind 走 openai_compatible 或 anthropic 协议, 返回纯文本
def chat(provider_cfg, prompt, capability="text", max_tokens=1024):
    kind = provider_cfg.get("kind", "openai_compatible")
    base = provider_cfg["base_url"].rstrip("/")
    key = expand_env(provider_cfg.get("api_key", "")).strip()
    model = provider_cfg.get("model_" + capability) or provider_cfg.get("model_text", "")
    timeout = int((getattr(cores.config, "ai_verify", {}) or {}).get("timeout", 60))
    if kind == "anthropic":
        resp = requests.post(
            base + "/v1/messages",
            headers={"x-api-key": key, "anthropic-version": "2023-06-01",
                     "content-type": "application/json"},
            json={"model": model, "max_tokens": max_tokens,
                  "messages": [{"role": "user", "content": prompt}]},
            timeout=timeout)
        resp.raise_for_status()
        return "".join(block.get("text", "") for block in resp.json().get("content", []))
    headers = {"content-type": "application/json"}
    if key:
        headers["Authorization"] = "Bearer " + key
    resp = requests.post(
        base + "/chat/completions",
        headers=headers,
        json={"model": model, "max_tokens": max_tokens,
              "messages": [{"role": "user", "content": prompt}]},
        timeout=timeout)
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"]


# 带故障降级的调用: 按 providers 顺序逐个尝试, 全部失败返回 (None, None)
def call_with_fallback(prompt, capability="text", max_tokens=1024):
    for name, p in providers():
        if capability != "text" and not p.get("model_" + capability):
            continue
        try:
            return name, chat(p, prompt, capability, max_tokens)
        except Exception as e:
            cores.logf("[AI] provider {} failed: {}".format(name, e))
    return None, None


# 连通性探测(引导向导用): 最小请求, 通了返回 True
def healthy(provider_cfg):
    try:
        chat(provider_cfg, "ping", max_tokens=8)
        return True
    except Exception as e:
        cores.logf("[AI] health check failed: {}".format(e))
        return False
