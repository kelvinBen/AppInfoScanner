#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Author: kelvinBen (微信/WeChat: bromomo )
# Github: https://github.com/kelvinBen/AppInfoScanner
# Gitee: https://gitee.com/kelvin_ben/AppInfoScanner
# AppInfoScanner 内置默认配置与 config.toml 的生成/序列化/迁移。
#
# 本模块是代码层的默认值，不是用户接口 —— 用户配置位于用户工作区
# (~/Documents/AppInfoScanner/config.toml)，由 Bootstrapper 首次运行时
# 从这里的默认值生成，或从旧版工作区 config.py 一次性迁移；
# 加载时工作区 config.toml 以同名键覆盖默认值，缺失键沿用默认。
#
# 形状约定：filter_ak_map 在 Python 侧为 {规则集名: [正则, ...]}，
# 在 TOML 中落为 [filter_ak_map.<规则集名>] 下的 rules 数组，加载时还原。
import copy

# 配置格式版本: 跨版本升级时自动迁移用户 config.toml
CONFIG_VERSION = "1.0.11"

DEFAULTS = {
    # 配置格式版本(工具自动管理)
    "config_version": CONFIG_VERSION,
    # 组件识别规则：包名片段 -> 组件与风险说明（按 smali 路径匹配）
    "filter_components": {
        # JSON 反序列化 RCE 家族
        "com.alibaba.fastjson": "fastjson, autoType反序列化RCE(CVE-2022-25845等)",
        "com.fasterxml.jackson": "jackson, 多态反序列化(CVE-2017-7525等)",
        "com.google.gson": "gson JSON解析",
        "net.sf.json": "json-lib(老旧JSON库)",
        "com.thoughtworks.xstream": "XStream, 反序列化RCE(CVE-2021-21344等)",
        # Java 反序列化 gadget 链
        "org.apache.commons.collections": "Commons Collections, 反序列化RCE gadget链",
        "org.apache.commons.beanutils": "Commons BeanUtils, 反序列化gadget",
        "org.apache.commons.fileupload": "Commons FileUpload(CVE-2016-1000031)",
        # 框架级 RCE
        "org.apache.logging.log4j": "Log4j, JNDI注入RCE(Log4Shell, CVE-2021-44228)",
        "org.apache.shiro": "Shiro, rememberMe反序列化(CVE-2016-4437/CVE-2019-12422)",
        "org.apache.struts2": "Struts2, OGNL注入RCE(S2-045/S2-057等)",
        "org.springframework": "Spring框架(Spring4Shell CVE-2022-22965等)",
        "org.yaml.snakeyaml": "SnakeYAML, 反序列化RCE(CVE-2022-1471)",
        # XML 解析 XXE
        "javax.xml.parsers.DocumentBuilder": "DOM解析, XXE风险",
        "javax.xml.parsers.SAXParser": "SAX解析, XXE风险",
        "org.jdom.input.SAXBuilder": "jdom, XXE风险",
        "org.dom4j.io.SAXReader": "dom4j, XXE(CVE-2020-10642)",
        "org.apache.xerces": "Xerces, XXE风险(关注版本)",
        # 加密/网络库(版本相关CVE)
        "org.bouncycastle": "BouncyCastle加密库(CVE-2023-33201等,关注版本)",
        "io.netty": "Netty网络库(CVE-2021-21290等,关注版本)",
    },
    # iOS 组件识别：标记串 -> 组件与风险说明（按二进制 strings 内容匹配）
    "ios_components": {
        # 高危/版本相关组件
        "SSZipArchive": "解压库, Zip-Slip目录穿越(CVE-2018-1002200)",
        "OpenSSL": "OpenSSL(关注版本对应CVE)",
        "libxml": "libxml2, XXE(CVE系列)",
        "curl/": "libcurl(版本相关CVE)",
        # 网络库
        "AFNetworking": "HTTP库(老版本证书校验问题)",
        "Alamofire": "Swift HTTP库",
        "SocketRocket": "WebSocket库",
        "Starscream": "Swift WebSocket库",
        # 常见第三方SDK(攻击面/信息收集)
        "Firebase": "Firebase SDK",
        "FIRMessaging": "Firebase推送",
        "WXApi": "微信SDK",
        "AlipaySDK": "支付宝SDK",
        "JPUSHService": "极光推送",
        "UMCommon": "友盟统计",
        "Bugly": "腾讯Bugly",
        "ShareSDK": "ShareSDK分享",
        "NIMSDK": "网易云信IM",
        "RongCloudIM": "融云IM",
        "HyphenateChat": "环信IM",
        "GrowingIO": "GrowingIO统计",
        # 调试/攻击面
        "FLEX": "FLEX运行时调试工具, 泄漏大量应用内部信息",
        "WebViewJavascriptBridge": "JS-Native桥, 评估桥接口攻击面",
    },
    # 需要提取的内容规则（正则，每条最多一个捕获组：管线对 findall 结果按单值处理）：
    # 1. 常见协议地址(http(s)/ftp/ws(s)/tcp/udp/ssh/jdbc/redis/mysql 等，不区分大小写)
    # 2. 任意 scheme 的 URI 中内嵌的 IPv4
    # 3. 独立 IPv4（字符串本身为 IP，可带端口/路径；八位组严格 0-255 且拒绝前导零，
    #    用于排除 300+ 段与零填充的版本号/日期，如 1.02.3.4、2023.09.20.1）
    # 4. IPv6（完整形式或含 :: 的压缩形式；分组数约束可避免误报 MAC 地址）
    # 残余噪声：全段合法的版本号(如 1.2.3.4)与 IPv4 语法同形，仅凭字符串无法区分，
    # 交由人工甄别；漏报代价高于误报，不再追加启发式
    "filter_strs": [
        r'(?i)(?:jdbc(?::[a-z0-9]+)*:(?:@)?//.*|(?:https?|ftps?|sftp|wss?|ssl|tcp|udp|ssh|telnet|smtp|imap|pop3?|ldaps?|rtmps?|rtsps?|mysql|mariadb|mssql|mongodb|redis|memcached|amqp|mqtt|file|gopher)://.*)',
        r'.*://((?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)).*',
        r'^((?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?::\d{1,5})?)(?:/.*)?$',
        # 分支顺序: 完整形式 -> "::压缩+尾部值" -> "头部::压缩" -> "::结尾"，
        # 顺序错误会使贪婪的 :: 结尾分支截断掉尾部值(2001:db8::1 只捕到 2001:db8::)
        r'((?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|:(?::[0-9a-fA-F]{1,4}){1,7}|(?:[0-9a-fA-F]{1,4}:){1,7}:)',
    ],
    # 忽略的常见内容（正则，仅放真正的正则需求；公共域名走 filter_no_domains）。
    # 刻意保留不过滤：私网(10./172.16-31./192.168.)与 169.254 链路本地地址
    # (169.254.169.254 云元数据端点是高价值发现) —— 它们是渗透目标资产
    "filter_no": [
        # 回环 127.0.0.0/8 不过滤: 127.0.0.1+端口 是本地服务通讯的重要情报,
        # 由报告层归入 loopback 类别(仍不嗅探)
        r'^0\.',                                # 本网络 0.0.0.0/8(含 0.0.0.0)
        r'^255\.255\.255\.255$',                # 广播地址
        r'^(?:192\.0\.2|198\.51\.100|203\.0\.113)\.',  # RFC5737 文档示例网段
        r'::1',
        r'::$',
    ],
    # 公共域名后缀表（命中 host 或其任意父域后缀即丢弃）：
    # 按后缀匹配，"w3.org" 覆盖 www.w3.org，"bugly.qq.com" 只覆盖自身及子域、
    # 不会误杀 qq.com —— 比旧的 ".*域名" 子串匹配更精确（ notw3.organization.cn 不再误杀）。
    # 刻意不收：qq.com/facebook.com/aliyuncs.com/myqcloud.com/sentry.io 等
    # 可能是真实资产的域名。
    "filter_no_domains": [
        # 标准组织/规范
        "w3.org", "whatwg.org", "ietf.org", "unicode.org", "json.org", "xml.org",
        "oasis-open.org", "xmlsoap.org", "openxmlformats.org", "schema.org",
        "openssl.org", "sqlite.org", "zlib.net", "in-addr.arpa", "ip6.arpa",
        # 开源构建/包仓库/文档
        "apache.org", "github.com", "github.io", "githubusercontent.com",
        "npmjs.com", "npmjs.org", "pypi.org", "rubygems.org", "maven.org",
        "sonatype.org", "jitpack.io", "gradle.org", "spring.io", "hibernate.org",
        "jetbrains.com", "mozilla.org", "gnu.org", "debian.org", "sourceforge.net",
        "kernel.org", "python.org", "golang.org", "rust-lang.org", "nodejs.org",
        "jquery.com", "getbootstrap.com", "jsdelivr.net", "unpkg.com",
        "cdnjs.cloudflare.com", "cdn.bootcss.com", "staticfile.org",
        # Google/Android 生态
        "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
        "googlesource.com", "googlecode.com", "google-analytics.com",
        "googletagmanager.com", "googlesyndication.com", "googleadservices.com",
        "doubleclick.net", "app-measurement.com", "android.com", "firebaseio.com",
        "crashlytics.com", "fabric.io", "flutter.dev", "pub.dev", "dart.dev",
        # Apple/iOS 生态
        "apple.com", "icloud.com", "mzstatic.com", "cdn-apple.com", "apple-cloudkit.com",
        # 证书 CA/OCSP（iOS 二进制里的高频噪声）
        "digicert.com", "verisign.com", "symantec.com", "symcb.com", "symcd.com",
        "geotrust.com", "thawte.com", "entrust.net", "globalsign.com",
        "letsencrypt.org", "sectigo.com", "comodoca.com", "starfieldtech.com",
        "addtrust.com", "secomtrust.net",
        # Microsoft/.NET
        "microsoft.com", "nuget.org", "xamarin.com", "live.com", "windows.com",
        "msftconnecttest.com", "msftncsi.com",
        # 国内推送/统计/SDK（APK 高频噪声）
        "umeng.com", "umengcloud.com", "jpush.cn", "jiguang.cn", "getui.com",
        "igexin.com", "bugly.qq.com", "talkingdata.com", "sensorsdata.cn",
        "sensorsdata.com", "growingio.com", "appsflyer.com", "appsee.com",
        "bdstatic.com", "bdimg.com", "hm.baidu.com", "mmstat.com", "alicdn.com",
        "aliapp.org", "amap.com", "gtimg.com", "qpic.cn", "hicloud.com",
        "netease.im", "yunpian.com", "rongcloud.cn", "easemob.com", "uc.cn",
        # 示例/保留地址与连通性检测
        "example.com", "example.org", "example.net", "example.edu",
        "pool.ntp.org",
    ],
    # AK/SK 检测规则集：{规则集名: [正则, ...]}
    # AK/SK 检测规则集：{规则集名: [正则, ...]}（匹配结果多条捕获组时取第一个非空组）
    "filter_ak_map": {
        # 国内云
        "Aliyun_OSS": [
            r'(?i)(?:aliyun|ali|oss)[_-]?(?:access[_-]?key[_-]?id|access[_-]?key[_-]?secret)[\'"]?\s*[:=]\s*[\'"][0-9a-zA-Z]{10,}[\'"]',
            r'(?i)(?:aliyun|ali|oss)[_-]?secret[\'"]?\s*[:=]\s*[\'"][0-9a-zA-Z]{20,}[\'"]',
            r'LTAI[A-Za-z0-9]{12,20}',
        ],
        "Tencent_Cloud": [
            r'AKID[A-Za-z0-9]{32}',
        ],
        # 海外云
        "Amazon_AWS_AccessKeyID": [
            r'(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|A3T)[A-Z0-9]{16}',
        ],
        "Google_APIKey": [
            r'AIza[0-9A-Za-z\-_]{35}',
        ],
        "Google_OAuth_ClientID": [
            r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
        ],
        "Cloudinary": [
            r'cloudinary://[0-9]{15}:[0-9A-Za-z]+@[a-z]+',
        ],
        # 代码/协作平台
        "GitHub_Token": [
            r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}',
            r'github_pat_[A-Za-z0-9_]{20,}',
        ],
        "GitLab_PAT": [
            r'glpat-[A-Za-z0-9\-_]{20}',
        ],
        "Slack_Token": [
            r'xox[bapoir]-[A-Za-z0-9\-]{10,}',
        ],
        "Slack_Webhook": [
            r'https://hooks\.slack\.com/services/T[A-Za-z0-9_]{8,}/B[A-Za-z0-9_]{8,}/[A-Za-z0-9_]{24}',
        ],
        # 支付
        "Stripe_Key": [
            r'[sr]k_live_[0-9a-zA-Z]{24}',
        ],
        "Square_Token": [
            r'sq0atp-[0-9A-Za-z\-_]{22}',
            r'sq0csp-[0-9A-Za-z\-_]{43}',
        ],
        "PayPal_Braintree": [
            r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
        ],
        # 通讯/邮件
        "Twilio_APIKey": [
            r'SK[0-9a-fA-F]{32}',
        ],
        "SendGrid_Key": [
            r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}',
        ],
        "Mailgun_Key": [
            r'key-[0-9a-zA-Z]{32}',
        ],
        # 社交平台
        "Facebook_AccessToken": [
            r'EAACEdEose0c[A-Za-z0-9]+',
        ],
        "Discord_Bot_Token": [
            r'[NMz][A-Za-z0-9]{23}\.[A-Za-z0-9]{6}\.[A-Za-z0-9]{27}',
        ],
        # 通用凭据形态
        "JWT": [
            r'eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*',
        ],
        "Private_Key_Block": [
            r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----',
        ],
        "Authorization_Header": [
            r'(?i)basic\s+[A-Za-z0-9_\-:\.=]{16,}',
            r'(?i)bearer\s+[A-Za-z0-9_\-:\.=]{16,}',
        ],
        "Password_In_URL": [
            r'://[A-Za-z0-9_\-]+:[A-Za-z0-9_@!#$%^&*\-]{3,}@',
        ],
        "Generic_API_Key": [
            r'(?i)(?:api[_-]?key|apikey|app[_-]?key|access[_-]?key)[\'"]?\s*[:=]\s*[\'"][0-9a-zA-Z\-_]{8,}[\'"]',
        ],
        "Generic_Secret": [
            r'(?i)(?:secret|password|passwd|pwd|pass)[a-z_-]*[\'"]?\s*[:=]\s*[\'"][0-9a-zA-Z\-_!@#$%^&*]{8,}[\'"]',
        ],
        "Generic_Token": [
            r'(?i)token[\'"]?\s*[:=]\s*[\'"][0-9a-zA-Z\-_.=+]{8,}[\'"]',
        ],
        "Cloud_OSS_Key": [
            r'(?i)(?:oss|cos|s3|storage)[_-]?(?:access[_-]?(?:key|id)|secret|key)[a-z]*[\'"]?\s*[:=]\s*[\'"][0-9a-zA-Z\-_]{8,}[\'"]',
        ],
        # 国内 SDK 密钥(移动端渗透高频目标)
        "WeChat_SDK": [
            r'(?i)(?:wx|wechat|weixin)[_-]?(?:app[_-]?secret|secret)[\'"]?\s*[:=]\s*[\'"][0-9a-f]{32}[\'"]',
            r'(?i)(?:app[_-]?id)[\'"]?\s*[:=]\s*[\'"]wx[0-9a-f]{16}[\'"]',
        ],
        "Alipay_SDK": [
            r'(?i)(?:alipay|ali)[_-]?(?:app[_-]?id|pid|merchant[_-]?id)[\'"]?\s*[:=]\s*[\'"]\d{16}[\'"]',
            r'(?i)(?:alipay|ali)[_-]?(?:private[_-]?key|secret)[\'"]?\s*[:=]\s*[\'"]MIIC[a-zA-Z0-9+/=]{50,}[\'"]',
        ],
        "Weibo_SDK": [
            r'(?i)(?:weibo|sina)[_-]?(?:app[_-]?key|secret)[\'"]?\s*[:=]\s*[\'"][0-9a-f]{10,32}[\'"]',
        ],
        # 数据库连接串(带认证信息)
        "Database_Auth": [
            r'(?i)(?:mongo(?:db)?|postgres(?:ql)?|mysql|mariadb|amqp|rabbitmq)://[^\s"\':]+:[^\s"\']+@[^\s"\']+',
            r'(?i)redis://:[^\s"\']+@',  # redis 无用户名仅密码
        ],
        # 云厂商补充
        "Huawei_Cloud": [
            r'(?i)(?:huawei|hw)[_-]?(?:ak|access[_-]?key)[\'"]?\s*[:=]\s*[\'"][A-Z0-9]{10,}[\'"]',
        ],
        "Azure_Storage": [
            r'AccountKey=[A-Za-z0-9+/=]{50,}',
        ],
        "AWS_SecretKey": [
            r'(?i)aws[_-]?secret[_-]?access[_-]?key[\'"]?\s*[:=]\s*[\'"][A-Za-z0-9/+=]{40}[\'"]',
        ],
        "Sentry_DSN": [
            r'https://[0-9a-f]{32}@[0-9a-f]{16}\.ingest\.sentry\.io',
        ],
        # AI 服务密钥(大模型 API Key, 高价值目标)
        "AI_OpenAI": [
            r'sk-(?!ant-)(?:proj-)?[a-zA-Z0-9_-]{20,}',
        ],
        "AI_Anthropic": [
            r'sk-ant-(?:api03-)?[a-zA-Z0-9_-]{20,}',
        ],
        "AI_HuggingFace": [
            r'hf_[a-zA-Z0-9]{20,}',
        ],
        "AI_DashScope": [
            r'(?i)(?:dashscope|qwen|tongyi)[_-]?(?:key|secret)[\'"]?\s*[:=]\s*[\'"]sk-[a-zA-Z0-9]{10,}[\'"]',
        ],
        "AI_GLM": [
            r'(?i)(?:zhipu|glm|chatglm)[_-]?(?:key|api[_-]?key)[\'"]?\s*[:=]\s*[\'"]\w{6,12}\.[a-zA-Z0-9]{8,}[\'"]',
        ],
        "AI_Baidu_ERNIE": [
            r'(?i)(?:ernie|wenxin|baidu[_-]?ai|千帆)[_-]?(?:secret[_-]?key)[\'"]?\s*[:=]\s*[\'"][0-9a-zA-Z]{20,}[\'"]',
        ],
        # 地图服务密钥(国内移动端高频)
        "Map_AMap": [
            r'(?i)(?:amap|gaode|高德)[_-]?(?:key|api[_-]?key|secret)[\'"]?\s*[:=]\s*[\'"][0-9a-f]{32}[\'"]',
        ],
        "Map_Baidu": [
            r'(?i)(?:bmap|baidu[_-]?map|百度地图)[_-]?(?:ak|api[_-]?key|sn)[\'"]?\s*[:=]\s*[\'"][0-9a-zA-Z]{24}[\'"]',
        ],
        "Map_Tencent": [
            r'(?i)(?:qq[_-]?map|tencent[_-]?map|腾讯地图)[_-]?(?:key|sk)[\'"]?\s*[:=]\s*[\'"][0-9A-Z]{26,32}[\'"]',
        ],
        "Map_Box": [
            r'(?:pk|sk)\.eyJ[a-zA-Z0-9._-]{40,}',
        ],
        # 国内大模型补充(与 OpenAI 同构 sk- 前缀, 按服务名上下文区分)
        "AI_DeepSeek": [
            r'(?i)deepseek[_-]?(?:key|api[_-]?key|token)[\'"]?\s*[:=]\s*[\'"]sk-[a-zA-Z0-9]{20,}[\'"]',
            r'api\.deepseek\.com',
        ],
        "AI_Moonshot": [
            r'(?i)(?:moonshot|kimi)[_-]?(?:key|api[_-]?key|token)[\'"]?\s*[:=]\s*[\'"]sk-[a-zA-Z0-9]{20,}[\'"]',
            r'api\.moonshot\.cn',
        ],
        "AI_MiniMax": [
            r'(?i)minimax[_-]?(?:key|api[_-]?key|token)[\'"]?\s*[:=]\s*[\'"]eyJ[a-zA-Z0-9._-]{20,}[\'"]',
            r'api\.minimaxi?\.chat',
        ],
        "AI_Volcengine": [
            r'(?i)(?:volcengine|doubao|huoshan|ark)[_-]?(?:key|api[_-]?key|token|secret)[\'"]?\s*[:=]\s*[\'"][a-zA-Z0-9\-_.]{16,}[\'"]',
            r'ark\.cn-[a-z]+\.volces\.com',
        ],
        "AI_SiliconCloud": [
            r'(?i)silicon(?:cloud|flow)[_-]?(?:key|api[_-]?key)[\'"]?\s*[:=]\s*[\'"]sk-[a-zA-Z0-9]{20,}[\'"]',
            r'api\.siliconflow\.cn',
        ],
        "AI_Iflytek_Spark": [
            r'(?i)(?:spark|xunfei|iflytek)[_-]?(?:api[_-]?key|api[_-]?secret)[\'"]?\s*[:=]\s*[\'"][0-9a-f]{16,}[\'"]',
        ],
        # 海外推理平台(独特前缀)
        "AI_Groq": [
            r'gsk_[a-zA-Z0-9]{20,}',
        ],
        "AI_OpenRouter": [
            r'sk-or-(?:v1-)?[a-zA-Z0-9-]{20,}',
        ],
        "AI_Together": [
            r'tgp_[a-zA-Z0-9_]{20,}',
        ],
        # AI 服务端点(识别应用连接了哪些 AI 后端)
        "AI_Endpoints": [
            r'https?://api\.(?:openai|deepseek|anthropic|groq|together)\.com[/\w.-]*',
            r'https?://api\.(?:moonshot\.cn|minimaxi?\.chat|siliconflow\.cn)[/\w.-]*',
            r'https?://dashscope\.aliyuncs\.com[/\w.-]*',
            r'https?://ark\.cn-[a-z]+\.volces\.com[/\w.-]*',
            r'https?://open\.bigmodel\.cn[/\w.-]*',
            r'https?://aip\.baidubce\.com[/\w.-]*',
            r'https?://api\.minimax\.chat[/\w.-]*',
        ],
        # AI 编程工具密钥(Cursor/Windsurf/Copilot 等)
        "Coding_AI": [
            r'(?i)(?:cursor|windsurf|codeium|tabnine|copilot|jetbrains[_-]?ai|cody|sourcegraph|augment)[_-]?(?:key|token|api[_-]?key)[\'"]?\s*[:=]\s*[\'"][a-zA-Z0-9\-_.=+]{16,}[\'"]',
        ],
        "Firebase_Config": [
            r'(?i)firebase[_-]?(?:api[_-]?key|config)[\'"]?\s*[:=]\s*[\'"][A-Za-z0-9\-_]{30,}[\'"]',
        ],
    },
    # 个人/企业敏感信息规则集：{规则集名: [正则, ...]}（参考 HaE 规则分类）
    # IDCard_CN_18 与 USCC_CN 命中后在 parses.py 中做校验位验证(GB 11643 / GB 32100)
    # 以压低误报；Email 命中后按 filter_no_domains 过滤公共域名来信
    "filter_pii_map": {
        "Phone_CN": [
            r'(?<!\d)1[3-9]\d{9}(?!\d)',
        ],
        "IDCard_CN_18": [
            r'(?<![0-9Xx])[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[0-9Xx](?![0-9Xx])',
        ],
        "Email": [
            r'[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}',
        ],
        "BankCard_CN": [
            r'(?<!\d)62\d{14,17}(?!\d)',
        ],
        "Plate_CN": [
            r'[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼使领][A-HJ-NP-Z](?:[A-HJ-NP-Z0-9]{4}[挂学警港澳]|[A-HJ-NP-Z0-9]{5,6})',
        ],
        "Person_Name_CN": [
            r'(?:姓名|联系人|真实姓名|收货人|经办人)[：:\s]{0,4}([\u4e00-\u9fa5·]{2,4})',
        ],
        "QQ_Number": [
            r'(?i)(?:qq|扣扣|企鹅号)[^\d]{0,6}([1-9]\d{5,10})(?!\d)',
        ],
        "USCC_CN": [
            r'(?<![0-9A-Z])[1-9A-HJ-NPQRTUWXY][0-9A-HJ-NPQRTUWXY]\d{6}[0-9A-HJ-NPQRTUWXY]{10}(?![0-9A-Z])',
        ],
        "MAC_Address": [
            r'(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f])',
        ],
        "Passport_CN": [
            r'(?:护照|passport|护照号)[：:\s]{0,4}([EeGg]\d{8})(?!\d)',
        ],
        "VIN": [
            r'(?:vin|车架号|车架)[：:\s]{0,4}([A-HJ-NPR-Z0-9]{17})(?![A-Z0-9])',
        ],
        "IMEI": [
            r'(?:imei|device[_-]?id|设备号)[：:\s]{0,4}(\d{15})(?!\d)',
        ],
        "Phone_Intl": [
            r'(?:tel|phone|mobile|电话|手机)[：:\s]{0,4}(\+\d{1,3}[\s\d\-]{8,16})(?![\d])',
        ],
        "Address_CN": [
            r'(?:地址|住址|收货地址|address)[：:\s]{0,4}([\u4e00-\u9fa5]{2,6}(?:省|市|区|县|镇|乡|村|路|街|道|号|楼|室)[\u4e00-\u9fa50-9A-Za-z\-]{4,40})',
        ],
    },
    # 组件版本影响范围表: 从 smali 提取版本号后对照此表判断是否受已知 CVE 影响
    # version_field: smali 中的版本常量字段名(如 fastjson 的 VERSION)
    # version_pattern: 备用版本提取正则(如 bcprov 的 "bouncycastle 1.68" 模式)
    # safe_above: 该 CVE 的修复版本, 低于此版本判定为受影响
    # 从 smali 提取版本号后对照此表给出"受影响/不受影响"结论
    "component_versions": {
        "com.alibaba.fastjson": {
            "version_field": "VERSION",  # smali 中 Version.VERSION 字段
            "safe_above": "1.2.83",
            "cve": "CVE-2022-25845 (autoType RCE)",
            "safe_note": ">=1.2.83 已修复 autoType 绕过",
        },
        "org.bouncycastle": {
            "version_pattern": r'bouncycastle[^0-9]*(\d+\.\d+[\.\d]*)',
            "safe_above": "1.74",
            "cve": "CVE-2023-33201 (LDAP injection)",
            "safe_note": ">=1.74 已修复",
        },
        "org.apache.logging.log4j": {
            "version_field": "VERSION",
            "safe_above": "2.17.0",
            "cve": "CVE-2021-44228 (Log4Shell)",
            "safe_note": ">=2.17.0 已修复 JNDI 注入",
        },
    },
    # USCC(统一社会信用代码)格式校验数据:
    # 首位必须是合法的登记管理部门码, 次位必须是合法的机构类别码
    # 用于拒绝恰好通过校验位计算但实际不是信用代码的 hex 串
    "uscc_valid_codes": {
        "dept": "123456789Y",  # 1机构编制 2外交 3教育 4公安 5民政 6司法 7交通 8文化 9工商 Y其他
        "type": "123193",       # 1企业 2个体 3农民专业合作 9其他 1(企业子) 3(事业子) 9(其他子)
    },
    # PII 测试向量黑名单: 密码学库(BC/听云/JDK/RFC)的官方测试数据。
    # 这些数字串恰好通过银行卡 Luhn 校验或手机号段校验, 但不是真实凭据。
    # 命中黑名单的 PII 直接丢弃不进报告; 不在名单但来源可疑的降权标注。
    "pii_test_vectors": [
        # BouncyCastle GOST3411 / LongDigest 测试向量
        "6272217099150286", "15258229321",
        # JDK MessageDigest 测试向量(常见)
        "6162636465666768696a6b6c6d6e6f70",
        # 常见 digest 测试向量前缀(匹配到的标记为疑似)
        "000102030405060708090a0b0c0d0e0f",
        "d41d8cd98f00b204e9800998ecf8427e",
        "0cc175b9c0f1b6a831c399e269772661",
        # RFC 2202 HMAC 测试向量
        "b617318655057264e28bc0b6fb378c8e",
        "effcdf6ae5eb2fa2d27416d5f184df9c",
        # RFC 4231 HMAC-SHA 测试向量
        "b0344c61d8db38535ca8afceaf0bf12b",
        "5bdcc146bf60754e6a042426089575c7",
    ],
    # Android 加固特征库：厂商 -> {classes: 替换后的application类名,
    # so: lib下的so文件特征, assets: assets/文件特征}。检测流程: manifest 中
    # application 类名先行匹配(门控)，命中厂商后才用该厂商的文件特征确认。
    "shell_vendors": {
        "360加固": {
            "classes": [
                "com.stub.StubApp",
                "com.qihoo.util.StubApp",
            ],
            "so": [
                "libjiagu.so",
                "libjiagu_art.so",
                "libjiagu_x86.so",
                "libprotectClass.so",
                "1ibjgdtc.so",
                "libjgdtc.so",
                "libjgdtc_a64.so",
                "libjgdtc_art.so",
                "libjgdtc_x64.so",
                "libjgdtc_x86.so",
                "libjiagu_a64.so",
                "libjiagu_ls.so",
                "libjiagu_x64.so",
            ],
            "assets": [
                "assets/.appkey",
                "assets/libjiagu.so",
                ".appkey",
            ],
        },
        "APKProtect": {
            "classes": [],
            "so": [
                "libAPKProtect.so",
            ],
            "assets": [],
        },
        "UU安全": {
            "classes": [],
            "so": [
                "libuusafe.jar.so",
                "libuusafe.so",
                "libuusafeempty.so",
                "lib/armeabi/libuusafeempty.so",
            ],
            "assets": [
                "assets/libuusafe.jar.so",
                "assets/libuusafe.so",
            ],
        },
        "apktoolplus": {
            "classes": [
                "com.linchaolong.apktoolplus.jiagu.ProxyApplication",
            ],
            "so": [
                "lib/armeabi/libapktoolplus_jiagu.so",
                "libapktoolplus_jiagu.so",
            ],
            "assets": [
                "assets/jiagu_data.bin",
                "assets/sign.bin",
                "jiagu_data.bin",
                "sign.bin",
            ],
        },
        "中国移动加固": {
            "classes": [
                "com.mogosec.AppMgr",
            ],
            "so": [
                "ibmogosecurity.so",
                "lib/armeabi/libcmvmp.so",
                "lib/armeabi/libmogosec_dex.so",
                "lib/armeabi/libmogosec_sodecrypt.so",
                "lib/armeabi/libmogosecurity.so",
                "libcmvmp.so",
                "libmogosec_dex.so",
                "libmogosec_sodecrypt.so",
            ],
            "assets": [
                "assets/mogosec_classes",
                "assets/mogosec_data",
                "assets/mogosec_dexinfo",
                "assets/mogosec_march",
                "mogosec_classes",
                "mogosec_data",
                "mogosec_dexinfo",
                "mogosec_march",
            ],
        },
        "几维安全": {
            "classes": [
                "com.Kiwisec.KiwiSecApplication",
                "com.Kiwisec.ProxyApplication",
            ],
            "so": [
                "lib/armeabi/kdpdata.so",
                "lib/armeabi/libkdp.so",
                "lib/armeabi/libkwscmm.so",
                "libkwscmm.so",
                "libkwscr.so",
                "libkwslinker.so",
            ],
            "assets": [
                "assets/dex.dat",
            ],
        },
        "厂商未知": {
            "classes": [
                "com.coral.util.StubApplication",
            ],
            "so": [],
            "assets": [],
        },
        "启明星辰": {
            "classes": [],
            "so": [
                "libvenSec.so",
                "libvenustech.so",
            ],
            "assets": [],
        },
        "娜迦加固": {
            "classes": [
                "com.nagain.NagainApplication",
            ],
            "so": [
                "libchaosvmp.so",
                "libddog.so",
                "libfdog.so",
            ],
            "assets": [],
        },
        "娜迦加固（企业版）": {
            "classes": [],
            "so": [
                "libedog.so",
            ],
            "assets": [],
        },
        "娜迦加固（新版2022）": {
            "classes": [],
            "so": [
                "lib/armeabi/libxloader.so",
                "lib/armeabi-v7a/libxloader.so",
                "lib/arm64-v8a/libxloader.so",
                "libxloader.so",
            ],
            "assets": [
                "assets/maindata/fake_classes.dex",
            ],
        },
        "梆梆安全": {
            "classes": [
                "com.secneo.apkwrapper.ApplicationWrapper",
                "com.secshell.secData.ApplicationWrapper",
            ],
            "so": [
                "libSecShell.so",
                "libsecexe.so",
                "libsecmain.so",
                "libSecShel1.so",
            ],
            "assets": [],
        },
        "梆梆安全（企业版）": {
            "classes": [],
            "so": [
                "libDexHelper-x86.so",
                "libDexHelper.so",
                "1ibDexHelper.so",
            ],
            "assets": [],
        },
        "梆梆安全（免费版）": {
            "classes": [],
            "so": [
                "lib/armeabi/libSecShell-x86.so",
                "lib/armeabi/libSecShell.so",
            ],
            "assets": [
                "assets/secData0.jar",
            ],
        },
        "梆梆安全（定制版）": {
            "classes": [],
            "so": [
                "lib/armeabi/DexHelper.so",
            ],
            "assets": [
                "assets/classes.jar",
            ],
        },
        "海云安加固": {
            "classes": [],
            "so": [
                "lib/armeabi/libitsec.so",
                "libitsec.so",
            ],
            "assets": [
                "assets/itse",
            ],
        },
        "爱加密": {
            "classes": [
                "s.h.e.l.l.S",
            ],
            "so": [
                "lib/armeabi/libexecmain.so",
                "libexecmain.so",
            ],
            "assets": [
                "assets/af.bin",
                "assets/ijiami.ajm",
                "assets/ijm_lib/X86/libexec.so",
                "assets/ijm_lib/armeabi/libexec.so",
                "assets/signed.bin",
                "ijiami.dat",
            ],
        },
        "爱加密企业版": {
            "classes": [
                "c.b.c.b",
            ],
            "so": [],
            "assets": [
                "ijiami.ajm",
            ],
        },
        "珊瑚灵御": {
            "classes": [],
            "so": [
                "libreincp.so",
                "libreincp_x86.so",
            ],
            "assets": [
                "assets/libreincp.so",
                "assets/libreincp_x86.so",
            ],
        },
        "瑞星加固": {
            "classes": [],
            "so": [
                "librsprotect.so",
            ],
            "assets": [],
        },
        "百度加固": {
            "classes": [
                "com.baidu.px.PaxApp",
            ],
            "so": [
                "libbaiduprotect.so",
                "lib/armeabi/libbaiduprotect.so",
                "libbaiduprotect_art.so",
                "libbaiduprotect_x86.so",
            ],
            "assets": [
                "assets/baiduprotect.jar",
                "assets/baiduprotect1.jar",
                "baiduprotect1.jar",
            ],
        },
        "盛大加固": {
            "classes": [],
            "so": [
                "libapssec.so",
            ],
            "assets": [],
        },
        "网易易盾": {
            "classes": [
                "com.netease.nis.wrapper.MyApplication",
            ],
            "so": [
                "libnesec.so",
            ],
            "assets": [],
        },
        "网秦加固": {
            "classes": [],
            "so": [
                "libnqshield.so",
            ],
            "assets": [],
        },
        "腾讯": {
            "classes": [],
            "so": [
                "libexec.so",
                "libshell.so",
            ],
            "assets": [],
        },
        "腾讯Bugly": {
            "classes": [],
            "so": [
                "lib/arm64-v8a/libBugly.so",
                "libBugly.so",
            ],
            "assets": [],
        },
        "腾讯乐固": {
            "classes": [
                "com.tencent.StubShell.TxAppEntry",
                "MyWrapperProxyApplication",
                "com.wrapper.proxyapplication.WrapperProxyApplication",
            ],
            "so": [],
            "assets": [
                "libshellx",
            ],
        },
        "腾讯乐固（VMP）": {
            "classes": [],
            "so": [
                "lib/arm64-v8a/libxgVipSecurity.so",
                "lib/armeabi-v7a/libxgVipSecurity.so",
                "libxgVipSecurity.so",
            ],
            "assets": [],
        },
        "腾讯乐固（旧版）": {
            "classes": [],
            "so": [
                "libtup.so",
                "liblegudb.so",
            ],
            "assets": [
                "mix.dex",
                "libshella",
                "mixz.dex",
                "libshel1x",
            ],
        },
        "腾讯云": {
            "classes": [],
            "so": [
                "lib/armeabi/libshell-super.2019.so",
                "lib/armeabi/libshell-super.2020.so",
                "lib/armeabi/libshell-super.2021.so",
                "lib/armeabi/libshell-super.2022.so",
                "lib/armeabi/libshell-super.2023.so",
            ],
            "assets": [
                "assets/libshellx-super.2021.so",
                "tencent_sub",
            ],
        },
        "腾讯云移动应用安全": {
            "classes": [],
            "so": [],
            "assets": [
                "0000000lllll.dex",
                "00000olllll.dex",
                "000O00ll111l.dex",
                "00O000ll111l.dex",
                "0OO00l111l1l",
                "o0oooOO0ooOo.dat",
            ],
        },
        "腾讯云移动应用安全（腾讯御安全）": {
            "classes": [],
            "so": [
                "libBugly-yaq.so",
                "libshell-super.2019.so",
                "libshellx-super.2019.so",
                "libzBugly-yaq.so",
            ],
            "assets": [
                "t86",
                "tosprotection",
                "tosversion",
                "000000011111.dex",
                "000000111111.dex",
                "000001111111",
                "00000o11111.dex",
                "o0ooo000oo0o.dat",
            ],
        },
        "腾讯加固": {
            "classes": [],
            "so": [
                "lib/armeabi/libshella-xxxx.so",
                "lib/armeabi/libshellx-xxxx.so",
            ],
            "assets": [
                "lib/armeabi/mix.dex",
                "lib/armeabi/mixz.dex",
                "tencent_stub",
            ],
        },
        "腾讯御安全": {
            "classes": [],
            "so": [
                "libtosprotection.armeabi-v7a.so",
                "libtosprotection.armeabi.so",
                "libtosprotection.x86.so",
                "lib/armeabi/libTmsdk-xxx-mfr.so",
                "lib/armeabi/libtest.so",
            ],
            "assets": [
                "assets/libtosprotection.armeabi-v7a.so",
                "assets/libtosprotection.armeabi.so",
                "assets/libtosprotection.x86.so",
                "assets/tosversion",
            ],
        },
        "蛮犀": {
            "classes": [],
            "so": [
                "libdSafeShell.so",
            ],
            "assets": [
                "assets/mxsafe.config",
                "assets/mxsafe.data",
                "assets/mxsafe.jar",
                "assets/mxsafe/arm64-v8a/libdSafeShell.so",
                "assets/mxsafe/x86_64/libdSafeShell.so",
            ],
        },
        "通付盾": {
            "classes": [
                "com.tongfudun.android.shell.SuperApplication",
            ],
            "so": [
                "libegis.so",
                "lib/armeabi/libegis.so",
            ],
            "assets": [],
        },
        "阿里加固": {
            "classes": [],
            "so": [],
            "assets": [
                "assets/armeabi/libfakejni.so",
                "assets/armeabi/libzuma.so",
                "assets/classes.dex.dat",
                "assets/dp.arm-v7.so.dat",
                "assets/dp.arm.so.dat",
                "assets/libpreverify1.so",
                "assets/libzuma.so",
                "assets/libzumadata.so",
                "dexprotect",
            ],
        },
        "阿里聚安全": {
            "classes": [],
            "so": [
                "libdemolish.so",
                "libfakejni.so",
                "libmobisec.so",
                "libsgmain.so",
                "libzuma.so",
                "libzumadata.so",
                "libdemolishdata.so",
                "libpreverify1.so",
                "libsgsecuritybody.so",
            ],
            "assets": [
                "aliprotect.dat",
            ],
        },
        "顶像科技": {
            "classes": [
                "cn.securitystack.stee.AppStub",
            ],
            "so": [
                "libx3g.so",
                "lib/armeabi/libx3g.so",
            ],
            "assets": [],
        },
    },
    # 需要关注的 Android 敏感权限（manifest 声明 -> 中文风险说明）
    "apk_permissions": {
        # 位置
        "android.permission.ACCESS_FINE_LOCATION": "精确定位(GPS)",
        "android.permission.ACCESS_COARSE_LOCATION": "粗略定位(基站/WiFi)",
        "android.permission.ACCESS_BACKGROUND_LOCATION": "后台持续定位",
        "android.permission.CONTROL_LOCATION_UPDATES": "控制定位更新开关",
        # 通讯录/通话/短信
        "android.permission.READ_CONTACTS": "读取联系人",
        "android.permission.WRITE_CONTACTS": "写入联系人",
        "android.permission.READ_CALL_LOG": "读取通话记录",
        "android.permission.WRITE_CALL_LOG": "写入通话记录",
        "android.permission.CALL_PHONE": "直接拨打电话",
        "android.permission.ANSWER_PHONE_CALLS": "接听来电",
        "android.permission.PROCESS_OUTGOING_CALLS": "监听外呼电话",
        "android.permission.READ_PHONE_STATE": "读取设备/通话状态与IMEI",
        "android.permission.READ_PHONE_NUMBERS": "读取本机手机号码",
        "android.permission.ADD_VOICEMAIL": "添加语音信箱",
        "android.permission.SEND_SMS": "发送短信(可能产生资费)",
        "android.permission.READ_SMS": "读取短信",
        "android.permission.RECEIVE_SMS": "接收/拦截短信",
        "android.permission.RECEIVE_MMS": "接收彩信",
        # 相机/麦克风/传感器
        "android.permission.CAMERA": "使用相机",
        "android.permission.RECORD_AUDIO": "录音/麦克风",
        "android.permission.BODY_SENSORS": "读取身体传感器(心率等)",
        "android.permission.BODY_SENSORS_BACKGROUND": "后台读取身体传感器",
        "android.permission.ACTIVITY_RECOGNITION": "识别身体活动(计步)",
        # 存储/媒体
        "android.permission.READ_EXTERNAL_STORAGE": "读取外部存储",
        "android.permission.WRITE_EXTERNAL_STORAGE": "写入外部存储",
        "android.permission.MANAGE_EXTERNAL_STORAGE": "所有文件访问权限",
        "android.permission.READ_MEDIA_IMAGES": "读取图片(API33+)",
        "android.permission.READ_MEDIA_VIDEO": "读取视频(API33+)",
        "android.permission.READ_MEDIA_AUDIO": "读取音频(API33+)",
        "android.permission.ACCESS_MEDIA_LOCATION": "读取媒体文件中的位置信息",
        # 日历/账户
        "android.permission.READ_CALENDAR": "读取日历",
        "android.permission.WRITE_CALENDAR": "写入日历",
        "android.permission.GET_ACCOUNTS": "读取设备账户列表",
        # 设备控制/高危能力
        "android.permission.USE_BIOMETRIC": "生物识别",
        "android.permission.USE_FINGERPRINT": "指纹识别(旧)",
        "android.permission.BIND_DEVICE_ADMIN": "设备管理器(可锁屏/擦除数据)",
        "android.permission.BIND_ACCESSIBILITY_SERVICE": "无障碍服务(可读屏与操控)",
        "android.permission.SYSTEM_ALERT_WINDOW": "悬浮窗(界面劫持风险)",
        "android.permission.QUERY_ALL_PACKAGES": "枚举所有已安装应用",
        "android.permission.PACKAGE_USAGE_STATS": "读取应用使用统计",
        "android.permission.REQUEST_INSTALL_PACKAGES": "安装其他应用",
        "android.permission.REQUEST_DELETE_PACKAGES": "卸载应用",
        "android.permission.RECEIVE_BOOT_COMPLETED": "开机自启动",
        "android.permission.POST_NOTIFICATIONS": "发送通知",
        "android.permission.NFC": "NFC",
        "android.permission.BLUETOOTH_SCAN": "蓝牙扫描(发现周边设备)",
        "android.permission.BLUETOOTH_CONNECT": "蓝牙连接",
        "android.permission.BLUETOOTH_ADMIN": "蓝牙管理(旧)",
        "android.permission.READ_PROFILE": "读取用户资料(旧)",
    },
    # 需要关注的 iOS 隐私权限（Info.plist 声明键 -> 中文风险说明）
    "ios_permissions": {
        "NSCameraUsageDescription": "相机",
        "NSMicrophoneUsageDescription": "麦克风/录音",
        "NSPhotoLibraryUsageDescription": "读取相册",
        "NSPhotoLibraryAddUsageDescription": "写入相册",
        "NSLocationWhenInUseUsageDescription": "使用期间定位",
        "NSLocationAlwaysAndWhenInUseUsageDescription": "始终允许定位",
        "NSLocationAlwaysUsageDescription": "始终定位(旧键)",
        "NSContactsUsageDescription": "通讯录",
        "NSCalendarsUsageDescription": "日历",
        "NSRemindersUsageDescription": "提醒事项",
        "NSMotionUsageDescription": "运动与健身数据",
        "NSHealthShareUsageDescription": "读取健康数据",
        "NSHealthUpdateUsageDescription": "写入健康数据",
        "NSFaceIDUsageDescription": "Face ID",
        "NSAppleMusicUsageDescription": "媒体资料库(音乐)",
        "NSBluetoothAlwaysUsageDescription": "蓝牙",
        "NSBluetoothPeripheralUsageDescription": "蓝牙外设(旧键)",
        "NSSpeechRecognitionUsageDescription": "语音识别",
        "NSLocalNetworkUsageDescription": "本地网络访问",
        "NSUserTrackingUsageDescription": "跨应用追踪(IDFA)",
        "NSHomeKitUsageDescription": "HomeKit智能家居",
        "NSSiriUsageDescription": "Siri",
    },
    # web 扫描的文件后缀（大小写不敏感；含模板/配置/source map 等含资产线索的类型）
    "web_file_suffix": [
        # html 家族
        "html", "htm", "xhtml", "shtml",
        # 前端脚本与样式
        "js", "mjs", "cjs", "jsx", "ts", "tsx", "vue", "map",
        "css", "scss", "less", "sass",
        # 数据/配置（常含 API 端点）
        "json", "har", "xml", "svg", "plist", "properties",
        "yml", "yaml", "ini", "conf", "env",
        # 服务端模板
        "php", "phtml", "jsp", "jspx", "asp", "aspx", "ashx", "ascx", "cshtml",
        # 其他可含端点的代码
        "class", "py", "rb", "pl", "cgi",
        # 小程序
        "wxml", "wxss",
    ],
    # 网络嗅探需要忽略的文件后缀（静态资源/二进制，探测无信息量；仅 -n 时生效）
    "sniffer_filter": [
        # 图片
        "jpg", "jpeg", "png", "gif", "webp", "bmp", "ico", "svg", "tiff", "heic",
        # 字体
        "woff", "woff2", "ttf", "otf", "eot",
        # 音视频
        "mp3", "mp4", "avi", "mov", "wmv", "flv", "mkv", "webm",
        "wav", "aac", "flac", "m4a", "ogg", "m3u8",
        # 文档与压缩包
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
        "zip", "rar", "7z", "tar", "gz", "bz2",
        # 安装包/二进制
        "apk", "ipa", "jar", "war", "dmg", "exe", "msi", "iso", "so", "dll", "bin",
    ],
    # 自动下载/缓存站点的请求头
    "headers": {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:81.0) Gecko/20100101 Firefox/81.0",
        "Connection": "close"
    },
    # 自动下载的 POST 报文体（默认为空）
    "data": {},
    # 自动下载的请求方法，仅支持 GET / POST
    "method": "GET",
}

# 生成默认 config.toml 时每个配置段的前置说明
_DOC = {
    "filter_components": ["组件识别规则: 包名片段 -> 组件与风险说明(按smali路径匹配);",
                          "聚焦存在RCE/CVE的组件(fastjson/Log4j/Shiro/XStream/CC链/XXE等)"],
    "ios_components": ["iOS组件识别: 标记串 -> 组件与风险说明(按二进制strings内容匹配);",
                       "含高危组件(SSZipArchive/OpenSSL/libxml)与常见SDK、调试工具(FLEX)"],
    "filter_strs": ["需要提取的内容规则(正则): 常见协议地址(http(s)/ftp/ws/tcp/udp/ssh/jdbc/redis/mysql等)、",
                    "URI内嵌IPv4、独立IPv4(可带端口/路径)、IPv6(完整或::压缩形式)"],
    "filter_no": ["忽略的内容规则(正则,仅真正的正则需求如回环/未指定地址);",
                  "公共域名忽略走 filter_no_domains 的后缀表,按 host 逐级父域匹配"],
    "filter_no_domains": ["公共域名后缀表: 命中 host 或其任意父域后缀即丢弃;",
                          "新增条目写裸域名即可(不带 .* 和正则),如 'sentry.io'"],
    "filter_pii_map": ["个人/企业敏感信息规则集(规则集名 -> 正则数组, 参考 HaE 分类):",
                       "手机号/身份证(校验位验证)/邮箱/银行卡/车牌/姓名/QQ/统一社会信用代码(校验位验证)/MAC"],
    "filter_ak_map": ["AK/SK等敏感凭据检测规则集；覆盖云厂商与平台的密钥/令牌、JWT/私钥/通用凭据形态",
                      "更多规则示例见文件末尾注释，按需复制到上方并解除注释"],
    "shell_vendors": ["Android加固特征库: 厂商 -> {classes: application类名, so/assets: 文件特征};",
                      "检测流程: manifest类名先行匹配, 命中厂商后才用该厂商文件特征确认"],
    "apk_permissions": ["需要关注的Android敏感权限: manifest声明 -> 中文风险说明;",
                        "命中后以 '权限 (说明)' 形式输出"],
    "ios_permissions": ["需要关注的iOS隐私权限: Info.plist声明键 -> 中文风险说明;",
                        "从解包后的 .app/Info.plist 中检测"],
    "web_file_suffix": ["web扫描的文件后缀(大小写不敏感);含html/js/ts/vue/source map/",
                        "css/模板/配置json-yaml-env等含资产线索的类型"],
    "sniffer_filter": ["网络嗅探需要忽略的文件后缀(静态资源/二进制,探测无信息量);仅 -n 时生效"],
    "headers": ["配置自动下载Apk文件或者缓存HTML的请求头信息"],
    "data": ["配置自动下载Apk文件或者缓存HTML的请求体信息(POST时使用,默认为空)"],
    "method": ["配置自动下载的请求方法，目前仅支持GET和POST"],
}

# 旧版 config.py 中被注释的 AK/SK 规则库，迁移为 TOML 注释保留；
# 语法已按 TOML 字面量串(单引号,反斜杠原样)修正
_AK_EXAMPLES = """#
# ---- 更多 AK/SK 规则示例(从旧版注释迁移,按需解除注释) ----
# 注意: TOML 单引号字面量串中反斜杠原样生效,无需双写
#[filter_ak_map."Amazon_AWS_Access_Key_ID"]
#rules = ['([^A-Z0-9]|^)(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,}']
#[filter_ak_map."Amazon_AWS_S3_Bucket"]
#rules = ['//s3-[a-z0-9-]+\\.amazonaws\\.com/[a-z0-9._-]+',
#         '//s3\\.amazonaws\\.com/[a-z0-9._-]+',
#         '[a-z0-9.-]+\\.s3\\.amazonaws\\.com']
#[filter_ak_map."Authorization_Basic"]
#rules = ['basic\\s[a-zA-Z0-9_\\-:\\.=]+']
#[filter_ak_map."Authorization_Bearer"]
#rules = ['bearer\\s[a-zA-Z0-9_\\-:\\.=]+']
#[filter_ak_map."AWS_API_Key"]
#rules = ['AKIA[0-9A-Z]{16}']
#[filter_ak_map."Generic_API_Key"]
#rules = ['[a|A][p|P][i|I][_]?[k|K][e|E][y|Y].*[\'|\\"][0-9a-zA-Z]{32,45}[\'|\\"]']
#[filter_ak_map."Generic_Secret"]
#rules = ['[s|S][e|E][c|C][r|R][e|E][t|T].*[\'|\\"][0-9a-zA-Z]{32,45}[\'|\\"]']
#[filter_ak_map."GitHub"]
#rules = ['[g|G][i|I][t|T][h|H][u|U][b|B].*[\'|\\"][0-9a-zA-Z]{35,40}[\'|\\"]']
#[filter_ak_map."Google_API_Key"]
#rules = ['AIza[0-9A-Za-z\\-_]{35}']
#[filter_ak_map."JSON_Web_Token"]
#rules = ['(?i)^((?=.*[a-z])(?=.*[0-9])(?:[a-z0-9_=]+\\.){2}(?:[a-z0-9_\\-\\+\\/=]*))$']
#[filter_ak_map."MailChimp_API_Key"]
#rules = ['[0-9a-f]{32}-us[0-9]{1,2}']
#[filter_ak_map."Mailgun_API_Key"]
#rules = ['key-[0-9a-zA-Z]{32}']
#[filter_ak_map."PGP_private_key_block"]
#rules = ['-----BEGIN PGP PRIVATE KEY BLOCK-----']
#[filter_ak_map."RSA_Private_Key"]
#rules = ['-----BEGIN RSA PRIVATE KEY-----']
#[filter_ak_map."Slack_Token"]
#rules = ['(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})']
#[filter_ak_map."Slack_Webhook"]
#rules = ['https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}']
#[filter_ak_map."Square_Access_Token"]
#rules = ['sq0atp-[0-9A-Za-z\\-_]{22}']
#[filter_ak_map."Square_OAuth_Secret"]
#rules = ['sq0csp-[0-9A-Za-z\\-_]{43}']
#[filter_ak_map."Stripe_API_Key"]
#rules = ['sk_live_[0-9a-zA-Z]{24}']
#[filter_ak_map."Stripe_Restricted_API_Key"]
#rules = ['rk_live_[0-9a-zA-Z]{24}']
#[filter_ak_map."Twilio_API_Key"]
#rules = ['SK[0-9a-fA-F]{32}']
#[filter_ak_map."Twitter_Access_Token"]
#rules = ['[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[1-9][0-9]+-[0-9a-zA-Z]{40}']
#[filter_ak_map."Twitter_OAuth"]
#rules = ['[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[\'|\\"][0-9a-zA-Z]{35,44}[\'|\\"]']
"""


def _toml_key(key):
    """裸键仅允许 ASCII 字母/数字/-/_（TOML 规范），中文等其余键名按字符串规则加引号。"""
    if key and all(c.isascii() and (c.isalnum() or c in "-_") for c in key):
        return key
    return _toml_str(key)


def _toml_str(value):
    """优先单引号字面量串(反斜杠原样,适合正则)；含单引号/换行时退回基本串并转义。"""
    if "'" not in value and "\n" not in value:
        return "'" + value + "'"
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return '"' + escaped + '"'


def _toml_array(values):
    if not values:
        return "[]"
    items = ",\n    ".join(_toml_str(v) for v in values)
    return "[\n    " + items + ",\n]"


def dump_config(config_map):
    """把 {键: 标量/列表/字典} 序列化为 TOML 文本。

    TOML 要求表小节([section])之后不能再出现顶层键，因此标量/数组键先输出、
    dict 值(落为独立小节)最后输出。dict-of-list(filter_ak_map) 的每个子键
    落为 [节.名] 下的 rules 数组，其余 dict(headers/data) 直接平铺为 [节]。
    """
    lines = []
    scalar_keys = [key for key, value in config_map.items() if not isinstance(value, dict)]
    table_keys = [key for key, value in config_map.items() if isinstance(value, dict)]
    for key in scalar_keys + table_keys:
        value = config_map[key]
        if isinstance(value, dict):
            if value and all(isinstance(v, dict) for v in value.values()):
                # dict-of-dicts(shell_vendors/component_versions) 子键:
                # list 值 -> TOML 数组; str/数值 -> TOML 标量
                for name, subs in value.items():
                    lines.append("[" + _toml_key(key) + "." + _toml_key(name) + "]")
                    for kind, val in subs.items():
                        if isinstance(val, list):
                            lines.append(_toml_key(kind) + " = " + _toml_array(val))
                        else:
                            lines.append(_toml_key(kind) + " = " + _toml_str(str(val)))
                    lines.append("")
            elif value and all(isinstance(v, list) for v in value.values()):
                for name, rules in value.items():
                    lines.append("[" + _toml_key(key) + "." + _toml_key(name) + "]")
                    lines.append("rules = " + _toml_array(rules))
                    lines.append("")
            else:
                lines.append("[" + _toml_key(key) + "]")
                for sub_key, sub_value in value.items():
                    if isinstance(sub_value, str):
                        lines.append(_toml_key(sub_key) + " = " + _toml_str(sub_value))
                lines.append("")
        elif isinstance(value, list):
            lines.append(_toml_key(key) + " = " + _toml_array(value))
            lines.append("")
        else:
            lines.append(_toml_key(key) + " = " + _toml_str(value))
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


# 版本迁移注册表
MIGRATIONS = {
    # 示例: "1.0.12": [_remove_filter_no_prefix("^127\\.")],
}


# 语义化版本比较: a < b 返回 True
def version_lt(a, b):
    pa = [int(x) for x in a.split(".") if x.isdigit()]
    pb = [int(x) for x in b.split(".") if x.isdigit()]
    for i in range(max(len(pa), len(pb))):
        va = pa[i] if i < len(pa) else 0
        vb = pb[i] if i < len(pb) else 0
        if va < vb:
            return True
        if va > vb:
            return False
    return False


# 按版本顺序执行迁移; 返回(迁移后config, 是否有变更)
def migrate_config(config, from_version):
    changed = False
    for target_ver in sorted(MIGRATIONS.keys()):
        if version_lt(from_version, target_ver):
            for fn in MIGRATIONS[target_ver]:
                config = fn(config)
            changed = True
    config["config_version"] = CONFIG_VERSION
    return config, changed


def generate_default_toml():
    """生成带说明注释的默认 config.toml 文本。

    TOML 表小节([section])之后不能再出现顶层键，因此按值类型自动排序：
    标量/数组键在前、dict 值(表小节)殿后 —— 新增 dict 型配置键无须手工维护顺序。
    """
    parts = [
        "# AppInfoScanner 工作区配置",
        "# 修改后无需重启以外的操作，下次运行即生效；删除本文件并重新运行可恢复默认。",
    ]
    _DOC["config_version"] = ["配置格式版本(工具自动管理, 勿手动修改)"]
    ordered = ["config_version", "filter_components", "ios_components", "filter_strs", "filter_no", "filter_no_domains",
               "shell_vendors", "apk_permissions", "ios_permissions",
               "web_file_suffix", "sniffer_filter", "method",
               "filter_ak_map", "filter_pii_map", "headers", "data"]
    table_keys = [key for key in ordered if isinstance(DEFAULTS[key], dict)]
    scalar_keys = [key for key in ordered if key not in table_keys]
    for key in scalar_keys + table_keys:
        if key in _DOC:
            parts.extend("# " + line for line in _DOC[key])
        parts.append(dump_config({key: DEFAULTS[key]}).rstrip())
        parts.append("")
        if key == "filter_ak_map":
            parts.append(_AK_EXAMPLES.rstrip())
            parts.append("")
    return "\n".join(parts).rstrip() + "\n"


# 需要子键级合并的规则库键(用户子键优先, 代码新增子键自动保留)
DEEP_MERGE_DICT_KEYS = (
    "filter_ak_map", "filter_pii_map",      # 凭据/PII 规则集
    "shell_vendors",                         # 加固特征库
    "filter_components", "ios_components",   # 组件
    "apk_permissions", "ios_permissions",    # 权限
    "uscc_valid_codes",                      # 格式校验
    "component_versions",                    # 版本影响
)
# 需要并集合并的列表键(用户列表 + 代码新增项)
UNION_MERGE_LIST_KEYS = (
    "filter_strs", "filter_no", "filter_no_domains",
    "web_file_suffix", "sniffer_filter", "pii_test_vectors",
)
# TOML 中 {规则集: [正则...]} 落为 [表.规则集名] 下的 rules 数组
RULE_SET_KEYS = ("filter_ak_map", "filter_pii_map")


# 把 tomllib 解析出的 dict 合并到默认值上(深合并, 不丢新增规则)
def merge_over_defaults(parsed):
    merged = copy.deepcopy(DEFAULTS)
    for key, value in parsed.items():
        if key in DEEP_MERGE_DICT_KEYS and isinstance(value, dict) and isinstance(merged.get(key), dict):
            for name, sub in value.items():
                if key in RULE_SET_KEYS:
                    rules = sub.get("rules", []) if isinstance(sub, dict) else sub
                    merged[key][name] = rules
                elif isinstance(sub, dict) and isinstance(merged[key].get(name), dict):
                    merged[key][name].update(sub)
                else:
                    merged[key][name] = sub
        elif key in UNION_MERGE_LIST_KEYS and isinstance(value, list) and isinstance(merged.get(key), list):
            merged[key] = value + [item for item in DEFAULTS[key] if item not in value]
        else:
            merged[key] = value
    merged["config_version"] = CONFIG_VERSION
    return merged


def load_legacy_config(path):
    """读取旧版 config.py(工作区内本地可信文件)的公开常量，用于一次性迁移到 TOML。"""
    namespace = {}
    with open(path, "r", encoding="utf-8") as f:
        exec(compile(f.read(), path, "exec"), namespace)
    return {key: value for key, value in namespace.items() if not key.startswith("_")}
