#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen (微信/WeChat: bromomo )
# Github: https://github.com/kelvinBen/AppInfoScanner
# Gitee: https://gitee.com/kelvin_ben/AppInfoScanner
# AppInfoScanner v1.0.10 输出体系：结果分类聚合与 txt/json/xlsx 三格式报告。
#
# 输入是 ParsesThreads 产出的 result_dict {文件路径: set(结果字符串)}，
# 分类规则：
#   - "[规则集]-->: 值" 形态 -> 凭据(AK/SK)或个人/企业敏感信息(PII)，按
#     filter_ak_map / filter_pii_map 的规则集名归属
#   - 带 scheme 的地址(http(s)/jdbc/redis/... 同 filter_strs 规则口径) -> URL，
#     从中提取 host 聚合为域名清单
#   - 纯 IPv4/IPv6 -> IP 清单，IPv4 再分内网(10./172.16-31./192.168.与169.254链路本地)
#     与公网；私网与链路本地在渗透场景是高价值资产
#   - 其余(格式串/裸 token 等) -> other，只进明细区
import re
import json
import datetime

SNIFFER_HEADER = ("Number", "IP/URL", "Domain", "Status", "IP",
                  "Server", "Title", "CDN", "Finger")

# 与 default_config.filter_strs 的协议规则同口径：带 scheme 的视为 URL
_URL_PATTERN = re.compile(
    r'(?i)^(?:jdbc(?::[a-z0-9]+)*:(?:@)?//|(?:https?|ftps?|sftp|wss?|ssl|tcp|udp|ssh|telnet|smtp|imap|pop3?|ldaps?|rtmps?|rtsps?|mysql|mariadb|mssql|mongodb|redis|memcached|amqp|mqtt|file|gopher)://)')
_IP4_PATTERN = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?$')
# 每值文件清单封顶: json 的 files 数组与内部路径列表上限, 真实计数在 _totals
MAX_FILES_PER_VALUE = 20

# 域名形态校验: 点分标签(字母数字连字符, 首尾非连字符) + 纯字母 TLD;
# 拦截模板碎片("or wss"/"%1$s"/自然语句)混入域名清单, IP 字面量另行放行
_HOST_VALID_RE = re.compile(
    r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"          # 单标签(内网主机名)
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")  # 或点分标签


def host_valid(host):
    # 字符集合法的单标签/点分域名或 IPv4 字面量才入清单;
    # 模板碎片(or wss/%1$s/自然语句)含空格与特殊字符, 全部拦截
    if not _HOST_VALID_RE.match(host):
        return bool(_IP4_PATTERN.match(host))
    # 点分形态要求末标签为纯字母 TLD(拦 a.b.c123 类数字尾缀), 单标签直接放行
    if "." in host:
        tld = host.rsplit(".", 1)[-1]
        return tld.isalpha() and len(tld) >= 2
    return True


# PII 命中值的降权标注后缀(入桶前剥除, 同值带标注/不带标注归并)
_ANNOTATION_RE = re.compile(r"\s*\(疑似测试向量[^)]*\)\s*$")
_SENSITIVE_PATTERN = re.compile(r'^\[([A-Za-z0-9_]+)\]-->:?\s*(.+)$', re.S)
_IPV6_HINT = re.compile(r'^[0-9a-fA-F:]+$')


# 从URL/地址串取host
def extract_host(value):
    rest = value
    if "://" in rest:
        rest = rest.split("://", 1)[1]
    elif "@//" in rest:  # jdbc:oracle:thin:@//host:port 形态
        rest = rest.rsplit("@//", 1)[1]
    rest = rest.split("/", 1)[0]
    if "@" in rest:
        rest = rest.rsplit("@", 1)[1]
    if rest.startswith("["):
        return rest[1:rest.index("]")] if "]" in rest else rest
    return rest.rsplit(":", 1)[0]


# 判定是否私网/链路本地IPv4
def is_private_ip4(ip):
    try:
        parts = [int(x) for x in ip.split(".")]
    except ValueError:
        return False
    if parts[0] == 10 or parts[0] == 192 and parts[1] == 168:
        return True
    if parts[0] == 172 and 16 <= parts[1] <= 31:
        return True
    if parts[0] == 169 and parts[1] == 254:  # 链路本地(含云元数据端点)
        return True
    return False


# 从地址串提取端口(URL/ip:port形态; 无端口或IPv6返回None)
def extract_port(value):
    rest = value
    if "://" in rest:
        rest = rest.split("://", 1)[1]
    elif "@//" in rest:
        rest = rest.rsplit("@//", 1)[1]
    rest = rest.split("/", 1)[0]
    if "@" in rest:
        rest = rest.rsplit("@", 1)[1]
    if rest.startswith("["):
        return None
    if ":" in rest:
        port = rest.rsplit(":", 1)[-1]
        if port.isdigit() and 1 <= int(port) <= 65535:
            return port
    return None


# 内网/回环/链路本地IPv4与IPv6字面量不嗅探(仅对IP字面量生效,域名照常)
def sniff_allowed(host):
    host = (host or "").strip().strip("[]").lower()
    if not host:
        return False
    if host == "localhost":  # 回环域名，不打到分析机本机
        return False
    if ":" in host:  # IPv6 字面量(含 ::1/fe80/fc00 ULA)，一律不嗅探
        return False
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        first, second = int(parts[0]), int(parts[1])
        if first in (10, 127, 0) or (first == 192 and second == 168):
            return False
        if first == 172 and 16 <= second <= 31:
            return False
        if first == 169 and second == 254:  # 链路本地(含云元数据端点)
            return False
    return True


# 把result_dict分类聚合为报告数据结构
def classify_results(result_dict, ak_names, pii_names):
    data = {
        "urls": {},
        "hosts": {},
        "ip_private": {},
        "ip_public": {},
        "ip_v6": {},
        "loopback": {},
        "credentials": {},
        "pii": {},
        "other": {},
    }

    # 文件清单去重走 set 索引: 高频值(如 file:///)可命中近全量 smali 文件,
    # list 成员判断在 baksmali 规模下是 O(N²) 字符串比较, 报告阶段直接卡死
    _file_sets = {}
    # 每值文件清单封顶(路径全量落盘曾把 report.json 撑到 4.1GB);
    # 真实计数存 data["_totals"], 三格式计数口径不变
    _file_totals = {}
    totals = data.setdefault("_totals", {})

    def put(bucket, bucket_name, key, file_path):
        seen = _file_sets.setdefault((id(bucket), key), set())
        if file_path in seen:
            return
        seen.add(file_path)
        _file_totals[(id(bucket), key)] = _file_totals.get((id(bucket), key), 0) + 1
        totals.setdefault(bucket_name, {})[key] = _file_totals[(id(bucket), key)]
        lst = bucket.setdefault(key, [])
        if len(lst) < MAX_FILES_PER_VALUE:
            lst.append(file_path)

    for file_path, results in result_dict.items():
        for value in results:
            value = value.strip()
            if not value:
                continue
            sensitive = _SENSITIVE_PATTERN.match(value)
            if sensitive:
                name, raw = sensitive.group(1), sensitive.group(2).strip()
                # 剥掉降权标注后再入桶: 同值"带标注/不带标注"两条目归并为一个键
                raw = _ANNOTATION_RE.sub("", raw).strip()
                if name in ak_names:
                    put(data["credentials"], "credentials", "%s|%s" % (name, raw), file_path)
                elif name in pii_names:
                    put(data["pii"], "pii", "%s|%s" % (name, raw), file_path)
                else:
                    put(data["other"], "other", value, file_path)
                continue
            host = extract_host(value) if _URL_PATTERN.match(value) or _IP4_PATTERN.match(value) else ""
            # 回环(127.x / localhost)是本地服务通讯情报: 独立归类保留端口，不进常规资产桶
            if host and (host == "localhost" or host.startswith("127.")):
                put(data["loopback"], "loopback", value, file_path)
                continue
            if _URL_PATTERN.match(value):
                put(data["urls"], "urls", value, file_path)
                if host and host_valid(host):
                    put(data["hosts"], "hosts", host, file_path)
                continue
            if _IP4_PATTERN.match(value):
                # 值可能带端口(独立IP规则捕获 ip:port)，按 host 部分判定内外网
                bucket = "ip_private" if is_private_ip4(host) else "ip_public"
                put(data[bucket], bucket, value, file_path)
                continue
            if ":" in value and _IPV6_HINT.match(value):
                put(data["ip_v6"], "ip_v6", value, file_path)
                continue
            put(data["other"], "other", value, file_path)
    for bucket in ("urls", "hosts", "ip_private", "ip_public", "ip_v6", "loopback", "other"):
        data[bucket] = dict(sorted(data[bucket].items()))
    return data


def cores_mod():
    import libs.core as _cores
    return _cores


# full 模式: 报告 JSON 全量脱敏(值段落与命中行)
def _deep_redact(node):
    cores = cores_mod()
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            if isinstance(v, str):
                if "]-->:" in v:
                    head, _, val = v.partition("]-->:")
                    v = head + "]-->: " + cores.redact(val.strip())
                if "|" in k:
                    k = _redact_key(k, "full")
                out[k] = v
            else:
                out[k] = _deep_redact(v)
        return out
    if isinstance(node, list):
        return [_deep_redact(x) for x in node]
    if isinstance(node, str) and "]-->:" in node:
        head, _, val = node.partition("]-->:")
        return head + "]-->: " + cores.redact(val.strip())
    return node


# 键 "Name|value" 的值段脱敏(redact 模式来自 extra)
def _redact_key(key, mode):
    if mode == "none":
        return key
    name, sep, value = key.partition("|")
    if not sep:
        import libs.core as cores
        return cores.redact(key) if mode else key
    import libs.core as cores
    return name + sep + cores.redact(value)


def build_report_meta(sample, task_type, tool_version=None, agent=False):
    if tool_version is None:
        from libs.core import updater
        tool_version = "v" + updater.APP_VERSION
    return {
        "sample": sample,
        "task_type": task_type,
        "tool_version": tool_version,
        "create_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "agent_mode": bool(agent),
    }


def _split_sensitive(key):
    name, _, value = key.partition("|")
    return name, value


# 结构化 payload 组装(json-only 模式复用于 stdout 输出)
def build_report_payload(meta, data, extra):
    payload = {"meta": meta}
    totals = data.get("_totals", {})
    for section in ("urls", "hosts", "ip_private", "ip_public", "ip_v6"):
        st = totals.get(section, {})
        payload[section] = [
            {"value": key, "files": files,
             "files_total": st.get(key, len(files))}
            for key, files in data[section].items()]
    slt = totals.get("loopback", {})
    payload["loopback"] = [
        {"value": key, "port": extract_port(key), "files": files,
         "files_total": slt.get(key, len(files))}
        for key, files in data["loopback"].items()]
    payload["credentials"] = _group_by_rule(data["credentials"])
    payload["pii"] = _group_by_rule(data["pii"])
    payload["other"] = [
        {"value": key, "files": files} for key, files in data["other"].items()]
    payload.update(extra)  # components/permissions/shell/sniffer 等
    if getattr(cores_mod(), "redact_mode", "none") == "full":
        payload = _deep_redact(payload)
    return payload


# 结构化JSON报告
def write_json_report(path, meta, data, extra):
    payload = build_report_payload(meta, data, extra)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def _group_by_rule(flat):
    grouped = {}
    for key, files in flat.items():
        name, value = _split_sensitive(key)
        grouped.setdefault(name, []).append({"value": value, "files": files})
    return grouped


# TXT分区汇总报告
def write_txt_report(path, meta, data, extra):
    lines = []
    lines.append("=" * 64)
    lines.append("AppInfoScanner 扫描报告")
    lines.append("=" * 64)
    lines.append("样本: %s    类型: %s    时间: %s" % (
        meta["sample"], meta["task_type"], meta["create_time"]))
    lines.append("")

    lines.append("[概要]")
    lines.append("  URL: %d    域名: %d    内网IP: %d    公网IP: %d    IPv6: %d" % (
        len(data["urls"]), len(data["hosts"]), len(data["ip_private"]),
        len(data["ip_public"]), len(data["ip_v6"])))
    lines.append("  敏感凭据(AK/SK): %d    个人/企业敏感信息(PII): %d    其他命中: %d" % (
        len(data["credentials"]), len(data["pii"]), len(data["other"])))
    lines.append("")

    shell = extra.get("shell") or []
    lines.append("[壳检测]")
    lines.extend("  " + s for s in shell) if shell else lines.append("  未检出加固壳")
    lines.append("")

    comps = extra.get("components") or []
    lines.append("[组件]")
    lines.extend("  " + c for c in comps) if comps else lines.append("  无")
    lines.append("")

    perms = extra.get("permissions") or []
    lines.append("[敏感权限]")
    lines.extend("  " + p for p in perms) if perms else lines.append("  无")
    lines.append("")

    assets = extra.get("ai_assets") or []
    if assets:
        lines.append("[AI 资产理解] (%d)" % len(assets))
        for a in assets:
            lines.append("  %s [%s]: %s" % (a.get("file", ""), a.get("kind", ""), a.get("summary", "")))
        lines.append("")

    verdicts = extra.get("ai_verdict") or []
    if verdicts:
        lines.append("[AI 复核与调用链] (%d)" % len(verdicts))
        for v in verdicts:
            lines.append("  %s -> %s [%s] %s" % (
                v.get("value", ""), v.get("verdict", ""), v.get("type", ""), v.get("basis", "")))
            if v.get("call_chain"):
                lines.append("    链: %s" % v["call_chain"])
            if v.get("flows"):
                lines.append("    流向: %s" % ", ".join(v["flows"]))
        lines.append("")

    def dump_list(title, bucket, bucket_name):
        lines.append("[%s] (%d)" % (title, len(bucket)))
        _t = data.get("_totals", {}).get(bucket_name, {})
        for key in bucket:
            lines.append("  %s    <- %d 个文件" % (key, _t.get(key, len(bucket[key]))))
        lines.append("")

    dump_list("域名清单", data["hosts"], "hosts")
    dump_list("内网IP", data["ip_private"], "ip_private")
    dump_list("公网IP", data["ip_public"], "ip_public")
    dump_list("IPv6", data["ip_v6"], "ip_v6")
    dump_list("本地回环服务(loopback)", data["loopback"], "loopback")
    loop_ports = sorted({p for p in (extract_port(k) for k in data["loopback"]) if p})
    if loop_ports:
        lines.append("  # 抓包建议(金融/股票类APP常用本地回环通讯): 宿主机起代理监听对应端口后执行:")
        for port in loop_ports:
            lines.append("  #   adb reverse tcp:{0} tcp:{0}   (设备 127.0.0.1:{0} -> 宿主机代理)".format(port))
        lines.append("")

    import libs.core as _cores
    _rm = getattr(_cores, "redact_mode", "none")
    lines.append("[敏感凭据 AK/SK] (%d)" % len(data["credentials"]))
    for key, files in data["credentials"].items():
        name, value = _split_sensitive(key)
        lines.append("  [%s] %s" % (name, _cores.redact(value) if _rm != "none" else value))
    lines.append("")
    lines.append("[个人/企业敏感信息 PII] (%d)" % len(data["pii"]))
    for key, files in data["pii"].items():
        name, value = _split_sensitive(key)
        lines.append("  [%s] %s" % (name, _cores.redact(value) if _rm != "none" else value))
    lines.append("")

    if extra.get("sniffer"):
        lines.append("[网络嗅探] (%d)" % len(extra["sniffer"]))
        for row in extra["sniffer"][:50]:
            lines.append("  " + " | ".join(str(x) for x in row))
        lines.append("")

    def _redact_line(line):
        if _rm == "none" or "]-->:" not in line:
            return line
        head, _, value = line.partition("]-->:")
        return head + "]-->: " + _cores.redact(value.strip())

    lines.append("[明细] (按文件)")
    for file_path, results in sorted(extra.get("details", {}).items()):
        lines.append("  %s:" % file_path)
        for value in sorted(results):
            lines.append("      %s" % _redact_line(value))
    lines.append("")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


# XLSX多sheet报告
def write_xlsx_report(path, meta, data, extra):
    import openpyxl
    workbook = openpyxl.Workbook()
    summary = workbook.active
    summary.title = "Summary"
    summary_rows = [
        ("样本", meta["sample"]), ("类型", meta["task_type"]),
        ("时间", meta["create_time"]), ("工具版本", meta["tool_version"]),
        ("URL", len(data["urls"])), ("域名", len(data["hosts"])),
        ("内网IP", len(data["ip_private"])), ("公网IP", len(data["ip_public"])),
        ("IPv6", len(data["ip_v6"])), ("敏感凭据", len(data["credentials"])),
        ("个人/企业敏感信息", len(data["pii"])),
    ]
    for row in summary_rows:
        summary.append(row)

    def sheet(name, header, rows):
        ws = workbook.create_sheet(name)
        ws.append(header)
        for row in rows:
            ws.append(row)

    _tx = data.get("_totals", {})
    _th, _tp, _tu, _tv = (_tx.get("hosts", {}), _tx.get("ip_private", {}),
                          _tx.get("ip_public", {}), _tx.get("ip_v6", {}))
    sheet("Hosts", ("Host", "Files"),
          [(k, _th.get(k, len(v))) for k, v in data["hosts"].items()])
    sheet("IPs", ("IP", "Category", "Files"),
          [(k, "private", _tp.get(k, len(v))) for k, v in data["ip_private"].items()] +
          [(k, "public", _tu.get(k, len(v))) for k, v in data["ip_public"].items()] +
          [(k, "ipv6", _tv.get(k, len(v))) for k, v in data["ip_v6"].items()])
    sheet("Loopback", ("Loopback Service", "Port", "adb reverse", "Files"),
          [(k, extract_port(k) or "-",
            "adb reverse tcp:{0} tcp:{0}".format(extract_port(k)) if extract_port(k) else "-",
            len(v)) for k, v in data["loopback"].items()])
    sheet("URLs", ("URL", "Files"),
          [(k, _tx.get("urls", {}).get(k, len(v))) for k, v in data["urls"].items()])
    _sensitive_sheet(workbook, "Credentials", data["credentials"], data.get("_totals", {}).get("credentials"))
    _sensitive_sheet(workbook, "PII", data["pii"], data.get("_totals", {}).get("pii"))
    # 组件明细: 宿主归属+版本+结论 三列结构(无明细时回退行式条目)
    comp_detail = extra.get("components_detail") or []
    if comp_detail:
        sheet("Components", ("Component", "Host SDK", "Version", "Verdict"),
              [(d.get("component", ""), d.get("host", ""), d.get("version", ""), d.get("verdict", ""))
               for d in comp_detail])
    else:
        sheet("Components", ("Component",), [(c,) for c in extra.get("components") or []])
    sheet("Permissions", ("Permission",), [(p,) for p in extra.get("permissions") or []])
    sheet("Shell", ("Conclusion",), [(s,) for s in extra.get("shell") or []])
    if extra.get("sniffer"):
        sheet("Sniffer", SNIFFER_HEADER, [tuple(r) for r in extra["sniffer"]])
    assets = extra.get("ai_assets") or []
    if assets:
        sheet("AI_Assets", ("File", "Kind", "Summary"),
              [(a.get("file", ""), a.get("kind", ""), a.get("summary", "")) for a in assets])
    verdicts = extra.get("ai_verdict") or []
    if verdicts:
        sheet("AI_Verdict", ("Value", "Verdict", "Type", "Basis", "Call chain", "Flows"),
              [(v.get("value", ""), v.get("verdict", ""), v.get("type", ""),
                v.get("basis", ""), v.get("call_chain", ""), ", ".join(v.get("flows", [])))
               for v in verdicts])
    details = extra.get("details") or {}
    import libs.core as _cores
    _rm2 = getattr(_cores, "redact_mode", "none")

    def _xl_line(v):
        if _rm2 == "none" or "]-->:" not in str(v):
            return v
        head, _, value = str(v).partition("]-->:")
        return head + "]-->: " + _cores.redact(value.strip())

    sheet("Details", ("File", "Result"),
          [(fp, _xl_line(v)) for fp, values in sorted(details.items()) for v in sorted(values)])
    workbook.save(path)


def _sensitive_sheet(workbook, name, flat, totals=None):
    import libs.core as _cores
    _rm = getattr(_cores, "redact_mode", "none")
    ws = workbook.create_sheet(name)
    ws.append(("Rule", "Value", "Files"))
    for key, files in flat.items():
        rule, value = _split_sensitive(key)
        if _rm != "none":
            value = _cores.redact(value)
        ws.append((rule, value, (totals or {}).get(key, len(files))))
