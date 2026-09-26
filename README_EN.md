# AppInfoScanner (English)

![License](https://img.shields.io/badge/Version-V1.0.11-red) ![Language](https://img.shields.io/badge/Language-Python3-blue) ![License](https://img.shields.io/badge/License-GPL3.0-orange) [![HitCount](https://hits.dwyl.com/kelvinBen/kelvinBen/AppInfoScanner.svg?style=flat&show=unique)](http://hits.dwyl.com/kelvinBen/kelvinBen/AppInfoScanner)

**Language**: [简体中文](README.md) | [English](README_EN.md)

This project is just the tip of the iceberg of a larger plan. If you are interested in contributing to development or translation, please email [blsm@vip.qq.com](mailto:blsm@vip.qq.com) with your skills and intent.

## AppInfoScanner

A mobile (Android, iOS, WEB, H5, static sites) information-gathering scanner for HW operations / red team / penetration testing teams. It helps pentesters, attack team members, and red teamers quickly collect key asset information from mobile apps or static web bundles, providing basic information output such as: Title, Domain, CDN, status info, etc.

## Preface

- The developer is an individual developer with a full-time job; new features are developed in spare time, bugs are prioritized.
- If you encounter problems or have feature requests, please submit a bug report at [issues](https://github.com/kelvinBen/AppInfoScanner/issues). Read the FAQ at the end before submitting.
- If you find this project useful, please click the "star" button at the top right.
- If you want to follow new versions, please click the "Watch" button at the top right.
- If you want to contribute to this project, please click the "Fork" button. Otherwise, please do NOT click "Fork".

## Disclaimer

Do NOT use this project's techniques or code for malicious software creation, software copyright/IP theft, or improper profit. Violations may constitute violations of the Criminal Law of the People's Republic of China (Articles 217, 286), the Cybersecurity Law, the Computer Software Protection Regulations, and other laws. The techniques mentioned in this project may only be used for private learning and testing in lawful scenarios. The project author is not responsible for any criminal or civil liability arising from improper use of these techniques.

## Use Cases

- Daily pentest: key asset information collection from APPs (URLs, IPs, keywords, etc.)
- Large-scale attack-defense exercises: key asset information collection from APPs
- WEB source code information collection (open-source code or saved page source)
- H5 page URL, IP, keyword collection
- Targeted information gathering on a specific APP

## Features

- [x] Directory-level batch scanning
- [x] DEX, APK, IPA, Mach-O, HTML, JS, Smali file information collection
- [x] Auto-download and one-shot scanning of APK, IPA, H5 files
- [x] Custom request headers, body, method
- [x] Custom rules: workspace config.toml
- [x] Custom resource file filtering
- [x] Android packer detection: unified vendor signature library detection
- [x] CVE/RCE component detection: 20 Android and 22 iOS CVE/RCE components
- [x] Sensitive permission detection: 49 Android and 22 iOS high-risk permissions
- [x] Credential (AK/SK) detection: Aliyun/Tencent/AWS/Google/GitHub/GitLab/Slack/Stripe/JWT/private keys/URL-embedded passwords and more
- [x] Personal/corporate sensitive information detection: phone/ID card/email/bank card/license plate/name/passport/VIN/IMEI/USCC and more
- [x] Common protocol collection: http(s)/ws/jdbc/redis/mysql and more
- [x] Basic network sniffing: status code/title/Server/CDN/resolved IP (--sniffer explicit, --scope authorized)
- [x] Multiple output formats: json, txt, xlsx result files
- [x] i18n: auto-output Chinese/English based on system language
- [x] Windows/macOS/Linux and other mainstream OS support
- [x] APK file magic number auto-repair
- [x] Component version detection: extract version, assess CVE impact (affected/safe)
- [x] Authorized sniffing: domain list file to limit sniffing scope (--scope)
- [x] Auto-update: GitHub Release check/download/MD5 verify (update subcommand)
- [x] Config version management: config.toml versioned with cross-version auto-migration preserving user rules
- [ ] Fingerprint module (Web framework/CDN/WAF/CMS)
- [ ] ELF/.so and Flutter (libapp.so) parsing, HarmonyOS/HyperOS package support
- [ ] AI Agent integration (MCP Server/--agent mode/structured output contract)

## Screenshots

![](result.png)

## Environment

- Python 3.11+ runtime (3.14 verified)
- Toolchain and versions (auto-install on macOS/Linux, bundled or manual on Windows):

| Tool | Version | How to get |
| --- | --- | --- |
| Java | 11+ (Zulu 11 verified) | Manual on Windows; auto via brew/apt on macOS/Linux |
| adb | platform-tools current | Bundled in tools/unpacker on Windows; auto-install on macOS/Linux when unpacking |
| frida | 17.18.0 | pip install, must match device frida-server version |
| frida-tools | 14.10.4 | pip install |
| frida-dexdump | 2.0.1 | pip install |
| apktool | 3.0.3 | Bundled tools/apktool.jar, auto-deployed to workspace |
| baksmali | 2.5.2-dev | Bundled tools/baksmali.jar |
| smali | 3.0.9-dev | Built into apktool (for dex rebuilding) |

## Directory Structure
```
AppInfoScanner
    |-- libs  Core code
        |-- core
            |-- __init__.py Global config, workspace/log init (Bootstrapper)
            |-- default_config.py Built-in defaults, config.toml generation/migration
            |-- parses.py Static info parsing and extraction (filters/AK/PII)
            |-- report.py Result classification and json/txt/xlsx report output
            |-- download.py File auto-download
            |-- net.py Network sniffing
            |-- i18n.py Multi-language messages
            |-- provision.py Toolchain auto-install and frida version consistency
            |-- fix_magic.py dex/zip/AndroidManifest magic detection and repair
        |-- task
            |-- base_task.py Unified task dispatch center
            |-- android_task.py Android tasks
            |-- ios_task.py iOS tasks
            |-- web_task.py Web/H5 tasks
            |-- net_task.py Network sniffing tasks
            |-- download_task.py Auto-download tasks
    |-- tools Third-party tools
        |-- apktool.jar / baksmali.jar Decompilation tools
        |-- strings.exe / strings64.exe String extraction on Windows
        |-- unpacker Windows unpacking tools (adb/aapt/frida-server)
    |-- tests Unit tests (python3 -m unittest discover -s tests)
    |-- app.py Main program
    |-- requirements.txt Dependencies (explicit versions)
    |-- README.md / README_EN.md Documentation (CN/EN)
    |-- update.md / update_EN.md Changelog (CN/EN)
```

## Usage

1. Download
```
    git clone https://github.com/kelvinBen/AppInfoScanner.git

    Or copy this link to your browser to download the latest release:

    https://github.com/kelvinBen/AppInfoScanner/releases/latest

    Fast download in China:

    git clone https://gitee.com/kelvin_ben/AppInfoScanner.git
```

2. Install dependencies
```
    cd AppInfoScanner
    python -m pip install -r requirements.txt
```

3. Run (basic)

- Scan Android APK files, DEX files, APK download URLs, or directories

```
    python app.py android -i <APK/DEX file or download URL or directory>
```

- Scan iOS IPA files, Mach-O files, IPA download URLs, or directories

```
    python app.py ios -i <IPA/Mach-O file or download URL or directory>
```

- Scan Web site files, directories, or URLs to cache

```
    python app.py web -i <site file or directory or URL>
```

## Advanced Guide

### Basic Command Format
```
python app.py [TYPE] [OPTIONS] <the file or directory or URL to scan>
```

### Symbol Description

```
<> The file or directory or URL to scan
| OR relationship, choose only one
[] Parameter to input
```

### TYPE Parameter
Corresponds to [TYPE] in the basic command format. Currently supports android/ios/web, must specify one.

```
android: For scanning Android app related file contents
ios: For scanning iOS app related file contents
web: For scanning WEB site or H5 related file contents
```

Auto-correction by file suffix: even if you input ios, if the -i parameter's file is XXX.apk, android scanning will be executed.

### OPTIONS Parameter
Corresponds to [OPTIONS] in the basic command format. Multiple parameters can be combined.

```
-i or --inputs: File, directory, or URL to scan (or auto-download). Wrap long paths in double quotes("). Required.
-r or --rules: Temporary scan rules for file content.
--sniffer / --no-sniffer: Enable network sniffing. Default: disabled. Use with --scope in red team scenarios.
--scope: Authorized domain list file path (one domain or suffix per line). Only listed domains are sniffed.
--unpack: Explicitly unpack a hardened APK (pushes frida-server to device). Default: report only, no device interaction. Android only.
--prefer-dump: Directory of already-dumped DEX files to scan directly, no device interaction. Android only.
-n or --no-resource: Ignore all resource files including network sniffing resources (configure sniffer_filter in workspace config.toml first). Default: do not ignore.
-a or --all: Output each matching string (verbose mode). Default: summary only.
-t or --threads: Set concurrent thread count. Default: 10.
-o or --output: Output directory for results and temporary files. Default: AppInfoScanner under user documents. Log files follow this directory.
-p or --package: Java package name to scan within APK/DEX. Android only.
```

### update Subcommand

```
python app.py update --check    Check for updates only, show current/latest version
python app.py update            Perform update (GitHub Release download/MD5 verify/auto-replace)
python app.py update --tools    Check tool versions (apktool/baksmali)
```

### Specific Usage Examples

#### Android Basic Operations
- Scan a local APK file
```
python app.py android -i <Your apk file>

Example:

python app.py android -i C:\Users\Administrator\Desktop\Demo.apk
```

- Scan a local DEX file
```
python app.py android -i <Your DEX file>

Example:

python app.py android -i C:\Users\Administrator\Desktop\Demo.dex
```

- Scan an APK from a URL
```
python app.py android -i <APK Download Url>

Example:

python app.py android -i "https://127.0.0.1/Demo.apk"
```
Note: wrap long URLs in double quotes(")

#### iOS Basic Operations
- Scan a local IPA file
```
python app.py ios -i <Your ipa file>

Example:

python app.py ios -i "C:\Users\Administrator\Desktop\Demo.ipa"
```

- Scan a local Mach-O file
```
python app.py ios -i <Your Mach-o file>

Example:

python app.py ios -i "C:\Users\Administrator\Desktop\Demo\Payload\Demo.app\Demo"
```

- Scan an IPA from a URL
```
python app.py ios -i <IPA Download Url>

Example:

python app.py ios -i "https://127.0.0.1/Demo.ipa"
```
Note: wrap long URLs in double quotes("). App Store IPAs are not supported.

#### Web Basic Operations

- Scan a local WEB site
```
python app.py web -i <Your web file>

Example:

python app.py web -i "C:\Users\Administrator\Desktop\Demo.html"
```
- Scan a WEB file from a URL
```
python app.py web -i <Web Download Url>

Example:

python app.py web -i "https://127.0.0.1/Demo.html"
```

#### Common Operations

The following examples use android type:

- Scan a local directory
```
python app.py android -i <Your Dir>

Example:

python app.py android -i C:\Users\Administrator\Desktop\Demo
```

- Add temporary rules or keywords

```
python app.py android -i <Your apk> -r <the keyword | the rules>

Example:
Add scanning for Baidu domains

python app.py android -i C:\Users\Administrator\Desktop\Demo.apk -r ".*baidu.com.*"
```

- Disable network sniffing
```
python app.py android -i <Your apk> --no-sniffer

Example:
python app.py android -i C:\Users\Administrator\Desktop\Demo.apk --no-sniffer
```

- Ignore all resource files
```
python app.py android -i <Your apk> -n

Example:
python app.py android -i C:\Users\Administrator\Desktop\Demo.apk -n
```

- Enable verbose output (show each match)
```
python app.py android -i <Your apk> -a

Example:

python app.py android -i C:\Users\Administrator\Desktop\Demo.apk -a
```

- Set concurrency
```
python app.py android -i <Your apk> -t 20

Example:
Set 20 concurrent threads
python app.py android -i C:\Users\Administrator\Desktop\Demo.apk -t 20
```

- Specify output directory
```
python app.py android -i <Your apk> -o <output path>

Example:
Output to Desktop Temp directory
python app.py android -i C:\Users\Administrator\Desktop\Demo.apk -o C:\Users\Administrator\Desktop\Temp
```

- Scan specific Java package (Android only)

```
python app.py android -i <Your apk> -p <Java package name>

Example:
Filter content under com.baidu package

python app.py android -i C:\Users\Administrator\Desktop\Demo.apk -p "com.baidu"
```

## Advanced Usage

Built-in rules are limited; not all inputs yield ideal results. Adjust rules in config.toml as needed — proper rule configuration significantly improves retrieval quality.

- Config is in TOML format, auto-deployed to ~/Documents/AppInfoScanner/config.toml on first run, with Chinese comments. Edit directly; takes effect on next run. Delete the file and re-run to restore defaults.
- Legacy config.py is automatically migrated to config.toml on first run after upgrade; original preserved as config.py.bak.
- TOML regex syntax: single-quoted literal strings preserve backslashes verbatim, ideal for regex rules like '.*accessKeyId.*".*?"'. Use double-quoted strings with doubled backslashes only when the rule contains single quotes.

### Configuration Items
```
apk_permissions: Android sensitive permission map (manifest declaration -> Chinese risk note)
ios_permissions: iOS privacy permission map (Info.plist key -> Chinese risk note), auto-parsed from .app/Info.plist
filter_components: Android component map (package prefix -> component and risk note), focused on RCE/CVE components
ios_components: iOS component map (marker string -> component and risk note), matched via binary strings
filter_strs: Extraction rules (regex), covering common protocols, IPv4/IPv6, loopback services
filter_no: Ignore rules (regex), defaults include reserved address blocks only
filter_no_domains: Public domain suffix table; bare domains, no .* prefix needed
shell_vendors: Android packer unified signature library (vendor -> {classes, so, assets})
web_file_suffix: Web scan file suffixes (case-insensitive)
sniffer_filter: Network sniffing ignored suffixes (static/binary resources)
headers: Request headers for auto-download
data: Request body for auto-download
method: Request method for auto-download
```

## FAQ

### 1. Too much garbage data?

```
Method 1: Adjust rules in workspace config.toml
Method 2: Ignore resource files
```

### 2. Error: This application has shell, the retrieval results may not be accurate, Please remove the shell and try again!

The app has a shell/packer. You need to unpack it first:
```
    Android:
        xposed module: dexdump
        frida module: FRIDA-DEXDump
        No-root unpacking: blackdex
    iOS:
        frida module:
            Windows: frida-ipa-dump
            macOS: frida-ios-dump
```

### 3. Error: File download failed! Please download the file manually and try again.

File download failed.
```
1) Check if the URL is correct
2) Check network issues or configure headers, data, method in workspace config.toml
```

### 4. Error: Decompilation failed, please submit error information at https://github.com/kelvinBen/AppInfoScanner/issues

File decompilation failed.
```
Please submit the error screenshot and corresponding APK file at https://github.com/kelvinBen/AppInfoScanner/issues
```

## Custom Rule Submission

Submit path: [Add custom rules](https://github.com/kelvinBen/AppInfoScanner/issues/7)

Format:
```
1. APP component addition

Example: fastjson rule
APP component: fastjson com.alibaba.fastjson

2. String to search

Example: Aliyun AK rule
String:
Aliyun AK .*accessKeyId.*".*"

3. Web file suffix to search

Example: jsp rule
Site: java jsp

4. Android shell rule
Example: a certain digital company's shell rule
Shell: DigitalCompany com.stub.StubApp
```

## Contact Author

**WeChat**: bromomo (note: GitHub)

**WeChat Group**:

![image](https://user-images.githubusercontent.com/19259171/177041407-66b627d7-39b5-40e7-9858-85dca5b4f958.png)

If you can't join, add the author as a friend first.

**Email**: [blsm@vip.qq.com](mailto:blsm@vip.qq.com)

For feature requests, bug fixes, technical discussion, or business cooperation.

## Stargazers over time
[![Stargazers over time](https://api.star-history.com/svg?repos=kelvinBen/AppInfoScanner&type=Date)](https://star-history.com/#kelvinBen/AppInfoScanner&Date)

## 404StarLink 2.0 - Galaxy
![](https://github.com/knownsec/404StarLink-Project/raw/master/logo.png)

AppInfoScanner is part of 404Team [StarLink 2.0](https://github.com/knownsec/404StarLink2.0-Galaxy). For questions or discussion, refer to the StarLink community.

[https://github.com/knownsec/404StarLink2.0-Galaxy#community](https://github.com/knownsec/404StarLink2.0-Galaxy#community)
