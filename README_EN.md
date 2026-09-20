# AppInfoScanner (English)

**Language**: [简体中文](README.md) | [English](README_EN.md)

Console messages switch automatically with your system language (Chinese/English). You can force one with the `APPINFO_LANG=zh|en` environment variable.

This project is only the tip of the iceberg of a larger plan. If you are interested in contributing to development or translation, email blsm@vip.qq.com with your skills and intent.

## AppInfoScanner

A mobile-side (Android, iOS, WEB, H5, static sites) information-gathering scanner for authorized penetration-testing / red-team workflows. It helps pentesters and red-teamers quickly extract key assets from mobile apps or static web bundles — URLs, IPs, domains, third-party components (with CVE notes), sensitive permissions, credentials (AK/SK) and personal/corporate PII — with consolidated console, JSON/TXT/XLSX reports and a full run log.

## Highlights of V1.0.10

- **Workspace model**: config and third-party tools are deployed once to `~/Documents/AppInfoScanner/` (fallback `~/AppInfoScanner`); the workspace `config.toml` overrides built-in defaults and is edited directly by the user.
- **TOML config**: the repo no longer ships `config.py`; defaults live in `libs/core/default_config.py` and the workspace file is loaded with the stdlib `tomllib`. Legacy workspace `config.py` is migrated automatically on first run.
- **Detection packs**: 20 Android + 22 iOS component signatures (RCE/CVE-annotated), 49 Android + 22 iOS sensitive permissions (Chinese descriptions), 39-vendor unified packer library with three-signal shell detection, 24 credential rule sets (cloud tokens, JWT, private keys...), 9 PII rule sets (phone/ID-card with checksum/USCC/email/bank card/plate/name/QQ/MAC), protocol + strict IPv4 + IPv6 extraction, 126-entry public-domain suffix table.
- **Output system**: `result/<sample>_<timestamp>/` holds `report.json` / `report.txt` / `report.xlsx`; per-task run logs go to the workspace `logs/` directory (newest 20 retained).
- **Console UX**: noise-reduced — progress renders on a single line, findings are highlighted with `[!]`, per-hit URL lines only with `-a`.
- **i18n**: messages follow the system language (`APPINFO_LANG` overrides).

## Disclaimer

Do NOT use this project's techniques or code for malicious software, IP theft or illegal profit. Violations may fall under PRC criminal law (Art. 217/286), the Cybersecurity Law and related regulations. Only use it for lawful, authorized testing; the author takes no responsibility for misuse.

## Use cases

- Asset discovery (URLs/IPs/keywords) from APK/DEX/IPA/Mach-O during pentests and drills.
- Extracting URLs/IPs/keywords from web source code, H5 pages or saved page bundles.
- Targeted recon on a specific app.

## Features

- [x] Directory-level batch scanning
- [x] DEX, APK, IPA, Mach-O, HTML, JS, Smali support (ELF/.so not yet — see roadmap)
- [x] Auto-download of APK/IPA/H5 targets and one-shot scanning
- [x] Custom request headers/body/method
- [x] Custom rules via workspace `config.toml` (auto-deployed; legacy `config.py` migrated)
- [x] Custom resource filtering
- [x] Android packer detection: 39-vendor library, three signals (manifest class gate / so+assets signature confirmation / package-missing heuristic) with vendor & evidence output
- [x] Component detection: 20 Android + 22 iOS signatures with CVE/risk notes
- [x] Sensitive permissions: 49 Android + 22 iOS, with Chinese risk notes
- [x] Credentials (AK/SK): 24 rule sets — Aliyun/Tencent/AWS/Google/GitHub/GitLab/Slack/Stripe/JWT/private keys/URL-embedded/credential-shaped
- [x] PII: 9 rule sets — phone/ID-card/email/bank card/plate/name/USCC etc., ID-card & USCC checksum-validated
- [x] IP/URL collection: multi-scheme URLs, strict IPv4 with ports (private/public classified), IPv6, and dedicated loopback-service classification with adb-reverse capture hints; 126-entry public-domain suffix table
- [x] Per-package scanning on Android
- [x] Network sniffing: status/title/Server/CDN/resolved IP (private/loopback/link-local and IPv6 literals are never probed)
- [x] Output system: `report.json` / `report.txt` / `report.xlsx` under `result/<sample>_<ts>/`; per-task logs centralized in `logs/`, newest 20 kept
- [x] i18n: Chinese/English messages following system language (`APPINFO_LANG` override)
- [x] Windows / macOS / Linux
- [x] History-based noise reduction: repeatedly seen domains auto-added to the ignore table (statistics, not AI)
- [ ] Fingerprint module (web framework / CDN / WAF / CMS)
- [x] Integrated APK auto-repair: on apktool failure, fix_magic detects and repairs (zip magic / inner dex headers / AndroidManifest AXML, EOCD-validated, `.bak` backup) then retries decompilation once
- [ ] Unpack automation (currently Windows + rooted device via frida-dexdump; dumped dex is not auto-rescanned)
- [ ] ELF/.so & Flutter (libapp.so) parsing, HarmonyOS/HyperOS tasks (see roadmap)

## Environment

- Python 3.10+ (3.14 verified; `tomllib` requires 3.11+)
- Missing toolchains are **auto-installed** on macOS/Linux: Java via Homebrew/apt/dnf/yum/pacman/zypper (sudo prompts in terminal on Linux); adb installed on demand when unpacking is triggered; the frida CLI via the current interpreter's pip (with PEP-668 fallback). apktool.jar / baksmali.jar ship with the workspace — no install needed. Manual guidance is printed when no package manager is available; Windows keeps using the bundled `tools/unpacker` binaries

## Usage

```
python3 -m pip install -r requirements.txt

python app.py android -i <apk|dex|dir|url> [options]
python app.py ios     -i <ipa|macho|dir|url> [options]
python app.py web     -i <html|js|dir|url>  [options]
```

The task type auto-corrects by file suffix (e.g. passing an `.apk` to `ios` still runs the Android path).

### Options

```
-i/--inputs   file / directory / URL to scan (required)
-r/--rules    temporary extra scan rule (regex)
-s/--sniffer  disable network sniffing (enabled by default)
-n/--no-resource  ignore resource files (suffixes from sniffer_filter in config.toml)
-a/--all      verbose: print every matching string (default: quiet console)
-t/--threads  worker threads (default 10)
-o/--output   output directory (default: ~/Documents/AppInfoScanner)
-p/--package  Android only: limit scan to a Java package
```

### Reports

All artifacts land in `result/<sample>_<timestamp>/`:

- `report.json` — structured results (hosts, public/private IPs, credentials, PII, components, permissions, shell verdicts, per-file details)
- `report.txt` — human-readable sectioned summary
- `report.xlsx` — multi-sheet workbook

Per-task run logs are kept in the workspace `logs/` directory (`<sample>_<timestamp>.log`, full process log with config events, tool commands, warnings and tracebacks); only the newest 20 log files are retained.

## Configuration

Edit the workspace config at `~/Documents/AppInfoScanner/config.toml` (deployed on first run; delete it to reset). Legacy workspace `config.py` is migrated automatically. Highlights:

```
filter_components   Android component map: package prefix -> risk note
ios_components      iOS component map: marker string -> risk note
filter_strs         extraction rules (protocol URLs, strict IPv4, IPv6)
filter_no           ignore rules (true regex needs only: loopback/unspecified)
filter_no_domains   public-domain suffix table (126 entries; add bare domains)
shell_list -> shell_vendors  packer library: vendor -> {classes, so, assets}
apk_permissions / ios_permissions  sensitive permissions with Chinese notes
web_file_suffix / sniffer_filter  scan & sniff suffix tables
filter_ak_map       credential rules (24 sets: cloud tokens, JWT, keys...)
filter_pii_map      PII rules (9 sets; ID card & USCC checksum-validated)
headers/data/method download request options
```

TOML notes: single-quoted literal strings keep backslashes verbatim — ideal for regex; use double quotes only when the rule itself contains a single quote.

## FAQ

**Too much noise?** Tune rules in the workspace `config.toml`, or run with `-n`.

**"This application has shell"** — unpack/dump the shell first (Android: FRIDA-DEXDump, BlackDex; iOS: frida-ios-dump), then rescan. The scanner prints the detected packer vendor and file-signature evidence.

**Download failed** — check the URL/network, or configure `headers`/`data`/`method` in `config.toml`.

**Finance/stock apps detected with 127.0.0.1 loopback traffic — how to capture?** Such apps often route market/trading channels through localhost to evade sniffing. Run a proxy on your host (Burp/mihomo) listening on the port, then run the command printed in the report's loopback section:

```
adb reverse tcp:8080 tcp:8080   # device 127.0.0.1:8080 now tunnels to your host proxy
```

Use `adb forward tcp:P tcp:P` to reach a device-local service from the host instead.

**Decompilation failed** — report at the GitHub issues page with the APK.

## Links

- Rules contribution: GitHub issue #7 of the upstream project
- 404StarLink 2.0 member

## Contact

WeChat: bromomo (note: GitHub) · Email: blsm@vip.qq.com
