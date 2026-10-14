#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen (微信/WeChat: bromomo )
# Github: https://github.com/kelvinBen/AppInfoScanner
# Gitee: https://gitee.com/kelvin_ben/AppInfoScanner
# MCP Server(stdio): 将扫描能力暴露为 Agent 工具, 兼容 Claude Desktop/Cursor 等
import json
import os
import subprocess
import sys

# 工具定义(scan_app/scan_web): 内部经子进程走 --agent --format json-only,
# 安全默认(关嗅探/禁脱壳/脱敏)与退出码语义全部复用 CLI
TOOLS = [
    {
        "name": "scan_app",
        "description": "Scan a mobile app package (APK/DEX file or directory) and return "
                       "the structured report JSON (URLs/IPs/credentials/PII/components).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "APK/DEX path or directory"},
                "task_type": {"type": "string", "enum": ["android", "ios"],
                              "description": "Platform (default: android)"},
                "rules": {"type": "string", "description": "Optional temporary regex rule"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "scan_web",
        "description": "Scan a web/H5 site directory or file and return the structured report JSON.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Site directory/file path or URL"},
                "rules": {"type": "string", "description": "Optional temporary regex rule"},
            },
            "required": ["target"],
        },
    },
]

# agent 子进程超时(MCP 侧兜底, 与 CLI --timeout 默认一致)
SCAN_TIMEOUT = 600


# app.py 入口路径(仓库根)
def _app_entry():
    return os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "app.py")


# 执行扫描工具: 子进程 --agent --format json-only, 解析 stdout JSON
def call_tool(name, arguments):
    target = str(arguments.get("target", "")).strip()
    if not target:
        return {"isError": True, "content": [{"type": "text", "text": "missing target"}]}
    rules = str(arguments.get("rules", "") or "")
    cmd = [sys.executable, _app_entry()]
    if name == "scan_web":
        cmd.append("web")
    else:
        cmd.append(arguments.get("task_type", "android") or "android")
    cmd += ["-i", target, "--agent", "--format", "json-only", "--timeout", "540"]
    if rules:
        cmd += ["-r", rules]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT)
    except subprocess.TimeoutExpired:
        return {"isError": True, "content": [{"type": "text", "text": "scan timeout"}]}
    payload = None
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                payload = json.loads(line)
            except ValueError:
                payload = None
    if payload is None:
        tail = "\n".join((proc.stderr or "").splitlines()[-5:])
        return {"isError": True,
                "content": [{"type": "text", "text": "exit {}: {}".format(proc.returncode, tail)}]}
    return {"content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False)}]}


# JSON-RPC 分发
def handle(request):
    method = request.get("method", "")
    req_id = request.get("id")
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": req_id, "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "appinfoscanner", "version": "1.0.13"}}}
    if method == "notifications/initialized":
        return None   # 通知无响应
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}}
    if method == "tools/call":
        params = request.get("params", {})
        return {"jsonrpc": "2.0", "id": req_id, "result": call_tool(
            params.get("name", ""), params.get("arguments", {}))}
    if req_id is not None:
        return {"jsonrpc": "2.0", "id": req_id,
                "error": {"code": -32601, "message": "method not found: " + method}}
    return None


# stdio 主循环: 按行读 JSON-RPC
def serve(stdin=None, stdout=None):
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except ValueError:
            continue
        response = handle(request)
        if response is not None:
            stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
            stdout.flush()


if __name__ == "__main__":
    serve()
