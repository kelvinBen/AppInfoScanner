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


# ---- 多模态资产理解: 图片/视频帧直送 vision, 音频走转写 ----

_MEDIA_TYPES = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
                ".webp": "image/webp", ".gif": "image/gif"}
_ASSET_EXTS = set(_MEDIA_TYPES) | {".mp4", ".mov", ".mp3", ".aac", ".wav", ".m4a"}
_DEFAULT_KEYWORDS = ("screenshot", "qr", "code", "login", "cert", "key",
                     "pay", "account", "idcard", "passport", "账号", "二维码")


# 采集多模态资产: 解码产物(assets/res/壳payload)下的图片/视频/音频,
# 命名关键词优先 + 单文件大小/总数量双预算, 防素材目录打爆配额
def collect_assets(root_dir):
    cfg = getattr(cores.config, "ai_verify", {}) or {}
    max_count = int(cfg.get("asset_max_count", 20))
    max_mb = int(cfg.get("asset_max_mb", 4))
    keywords = tuple(cfg.get("asset_keywords", list(_DEFAULT_KEYWORDS)))
    picked, candidates = [], []
    try:
        for dirpath, _, files in os.walk(root_dir):
            for name in files:
                ext = os.path.splitext(name)[1].lower()
                if ext not in _ASSET_EXTS:
                    continue
                fp = os.path.join(dirpath, name)
                try:
                    size = os.path.getsize(fp)
                except OSError:
                    continue
                if size > max_mb * 1024 * 1024 or size <= 0:
                    continue
                lowered = name.lower()
                pri = 0 if any(k in lowered for k in keywords) else 1
                candidates.append((pri, size, fp, ext))
    except OSError:
        return []
    candidates.sort(key=lambda t: (t[0], t[1]))
    for _, _, fp, ext in candidates:
        if len(picked) >= max_count:
            break
        picked.append((fp, ext))
    return picked


# 图片文件转 base64 data(超限返回 None)
def _image_b64(path, max_mb):
    import base64
    try:
        if os.path.getsize(path) > max_mb * 1024 * 1024:
            return None
        with open(path, "rb") as f:
            return base64.b64encode(f.read()).decode("ascii")
    except OSError:
        return None


# 图文请求: openai_compatible(content 数组 image_url) / anthropic(image 块)
def chat_image(provider_cfg, prompt, image_path):
    import base64
    kind = provider_cfg.get("kind", "openai_compatible")
    base = provider_cfg["base_url"].rstrip("/")
    key = expand_env(provider_cfg.get("api_key", "")).strip()
    model = provider_cfg.get("model_vision") or provider_cfg.get("model_text", "")
    media = _MEDIA_TYPES.get(os.path.splitext(image_path)[1].lower(), "image/png")
    cfg = getattr(cores.config, "ai_verify", {}) or {}
    max_mb = int(cfg.get("asset_max_mb", 4))
    timeout = int(cfg.get("timeout", 60))
    data = _image_b64(image_path, max_mb)
    if data is None:
        raise ValueError("image too large: " + image_path)
    if kind == "anthropic":
        resp = requests.post(
            base + "/v1/messages",
            headers={"x-api-key": key, "anthropic-version": "2023-06-01",
                     "content-type": "application/json"},
            json={"model": model, "max_tokens": 1024, "messages": [{"role": "user", "content": [
                {"type": "text", "text": prompt},
                {"type": "image", "source": {"type": "base64", "media_type": media, "data": data}}]}]},
            timeout=timeout)
        resp.raise_for_status()
        return "".join(b.get("text", "") for b in resp.json().get("content", []))
    headers = {"content-type": "application/json"}
    if key:
        headers["Authorization"] = "Bearer " + key
    resp = requests.post(
        base + "/chat/completions", headers=headers,
        json={"model": model, "max_tokens": 1024, "messages": [{"role": "user", "content": [
            {"type": "text", "text": prompt},
            {"type": "image_url", "image_url": {"url": "data:%s;base64,%s" % (media, data)}}]}]},
        timeout=timeout)
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"]


# 音频转写(openai_compatible /audio/transcriptions; anthropic 无音频协议跳过)
def transcribe(provider_cfg, audio_path):
    if provider_cfg.get("kind", "openai_compatible") == "anthropic":
        return None
    model = provider_cfg.get("model_audio")
    if not model:
        return None
    base = provider_cfg["base_url"].rstrip("/")
    key = expand_env(provider_cfg.get("api_key", "")).strip()
    timeout = int((getattr(cores.config, "ai_verify", {}) or {}).get("timeout", 60))
    with open(audio_path, "rb") as f:
        resp = requests.post(
            base + "/audio/transcriptions",
            headers={"Authorization": "Bearer " + key} if key else {},
            files={"file": (os.path.basename(audio_path), f)},
            data={"model": model}, timeout=timeout)
    resp.raise_for_status()
    return resp.json().get("text", "")


# 资产理解入口: 图片直送 vision, 音频转写后归入摘要; 逐 provider 懒降级
ASSET_PROMPT = ("识别图中与安全相关的敏感要素(账号/密钥/token/内部URL/二维码内容/"
                "证件信息), 逐条列出; 无则回答: 无敏感要素")


def run_asset_review(root_dir):
    cfg = getattr(cores.config, "ai_verify", {}) or {}
    if not cfg.get("enabled") or not (cfg.get("provider") or {}):
        return []
    assets = collect_assets(root_dir)
    if not assets:
        return []
    results = []
    for fp, ext in assets:
        name, p = select("vision")
        if name and ext in _MEDIA_TYPES:
            try:
                text = chat_image(p, ASSET_PROMPT, fp)
                results.append({"file": fp, "kind": "image", "summary": (text or "").strip()[:500]})
                continue
            except Exception as e:
                cores.logf("[AI] vision failed ({}): {}".format(fp, e))
        name_a, p_a = select("audio")
        if name_a and ext in (".mp3", ".aac", ".wav", ".m4a"):
            try:
                text = transcribe(p_a, fp)
                if text:
                    results.append({"file": fp, "kind": "audio", "summary": text.strip()[:500]})
                continue
            except Exception as e:
                cores.logf("[AI] transcribe failed ({}): {}".format(fp, e))
        # 视频需 ffmpeg 抽帧, 环境缺失时跳过并提示
        if ext in (".mp4", ".mov"):
            cores.logf("[AI] video frame extraction not bundled yet, skip: " + fp)
    if results:
        cores.logp(cores.i18n.t(
            "[*] AI asset review: {} media reviewed", len(results)))
    return results


# ---- 复核流程: 收集 -> 粒度提取 -> 分批调用 -> 解析回写 ----

_HIT_RE = re.compile(r"^\[([A-Za-z0-9_]+)\]-->:?\s*(.+)$", re.S)


# 收集送检单元: {文件: [(规则名, 值), ...]}, 只取 verify_buckets 两桶
def collect_targets(result_dict):
    cfg = getattr(cores.config, "ai_verify", {}) or {}
    buckets = set(cfg.get("verify_buckets", ["pii", "credentials"]))
    ak_names = set(getattr(cores.config, "filter_ak_map", {}) or {})
    pii_names = set(getattr(cores.config, "filter_pii_map", {}) or {})
    files = {}
    for fp, results in result_dict.items():
        for r in results:
            m = _HIT_RE.match(r.strip())
            if not m:
                continue
            name, value = m.group(1), m.group(2).strip()
            bucket = "credentials" if name in ak_names else ("pii" if name in pii_names else None)
            if bucket in buckets:
                files.setdefault(fp, [])
                if (name, value) not in files[fp]:
                    files[fp].append((name, value))
    return files


# 送检粒度提取: method=命中值邻近方法体(smali 感知 .method 边界, 其余回退窗口);
# file=全文件按 max_file_tokens 上限截断(约 3 字符/token 估算)
def extract_regions(file_path, values, granularity, max_chars):
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read(max_chars * 3)
    except OSError:
        return ""
    if granularity == "file":
        return content
    regions = []
    for value in values:
        pos = content.find(value)
        if pos < 0:
            pos = 0
        start = content.rfind(".method", max(0, pos - 4000), pos)
        start = start if start >= 0 else max(0, pos - 800)
        end = content.find(".end method", pos, pos + 4000)
        end = end if end >= 0 else min(len(content), pos + 800)
        regions.append((start, end))
    if not regions:
        return content[:max_chars * 3]
    regions.sort()
    merged = [list(regions[0])]
    for s, e in regions[1:]:
        if s <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e])
    return "\n...\n".join(content[s:e] for s, e in merged)


# 构造复核 prompt: 命中清单 + 来源代码, 要求只输出 JSON 数组判定
def build_prompt(batch_items, granularity, max_chars):
    cfg = getattr(cores.config, "ai_verify", {}) or {}
    max_chars = max_chars or int(cfg.get("max_file_tokens", 6000)) * 3
    lines = ["你是安全扫描结果复核助手。以下为移动应用扫描命中的敏感信息及来源代码。",
             "对每条命中输出判定, 只输出 JSON 数组(无其他文字), 每元素:",
             '{"value":"原值前16字符","verdict":"confirm|reject|unknown",',
             '"type":"修正类型(如 手机号/身份证/密钥/测试数据/格式巧合)",',
             '"basis":"一句话依据(引用方法名/上下文)",',
             '"call_chain":"值的来源与消费方法简述, 无则空串",',
             '"flows":["network|storage|log|sdk|test", ...]}',
             "命中清单:"]
    for fp, hits in batch_items:
        for name, value in hits:
            lines.append("- [{}] {}: {} (文件 {})".format(name, value[:16], name, fp))
    lines.append("来源代码:")
    for fp, hits in batch_items:
        code = extract_regions(fp, [v for _, v in hits], granularity, max_chars)
        lines.append("=== {} ===".format(fp))
        lines.append(code)
    return "\n".join(lines)


# 解析模型响应: 容忍 markdown 代码栅栏与前后杂文, 取第一个 JSON 数组
def parse_verdicts(text):
    text = text or ""
    fence = re.search(r"```(?:json)?\s*(\[.*?\])\s*```", text, re.S)
    if fence:
        text = fence.group(1)
    start, end = text.find("["), text.rfind("]")
    if start < 0 or end <= start:
        return []
    import json
    try:
        data = json.loads(text[start:end + 1])
    except ValueError:
        return []
    out = []
    for item in data:
        if isinstance(item, dict) and "verdict" in item:
            out.append({"value": str(item.get("value", "")),
                        "verdict": str(item.get("verdict", "unknown")),
                        "type": str(item.get("type", "")),
                        "basis": str(item.get("basis", "")),
                        "call_chain": str(item.get("call_chain", "")),
                        "flows": [str(x) for x in item.get("flows", []) if x]})
    return out


# 复核入口: 未启用或无 provider 静默返回空; 分批调用带懒降级; 送检内容不写日志
def run_verify(result_dict):
    cfg = getattr(cores.config, "ai_verify", {}) or {}
    if not cfg.get("enabled") or not (cfg.get("provider") or {}):
        return []
    files = collect_targets(result_dict)
    if not files:
        return []
    granularity = cfg.get("granularity", "method")
    max_chars = int(cfg.get("max_file_tokens", 6000)) * 3
    batch = max(1, int(cfg.get("batch_size", 5)))
    items = list(files.items())
    total_hits = sum(len(v) for v in files.values())
    cores.logp(cores.i18n.t(
        "[*] AI verify: {} files / {} hits, granularity={}", len(items), total_hits, granularity))
    verdicts = []
    for i in range(0, len(items), batch):
        name, text = call_with_fallback(build_prompt(items[i:i + batch], granularity, max_chars))
        if not name:
            cores.logp(cores.i18n.t("[-] AI verify: all providers failed, skip remaining"))
            break
        verdicts.extend(parse_verdicts(text))
    confirm = sum(1 for v in verdicts if v["verdict"] == "confirm")
    cores.logp(cores.i18n.t(
        "[*] AI verify done: {} verdicts ({} confirm)", len(verdicts), confirm))
    return verdicts


# 连通性探测(引导向导用): 最小请求, 通了返回 True
def healthy(provider_cfg):
    try:
        chat(provider_cfg, "ping", max_tokens=8)
        return True
    except Exception as e:
        cores.logf("[AI] health check failed: {}".format(e))
        return False
