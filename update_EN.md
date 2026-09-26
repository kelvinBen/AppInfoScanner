# Changelog (English)

**Language**: [简体中文](update.md) | [English](update_EN.md)

### V1.0.11
Added:
- Added --unpack flag for explicit APK unpacking (default: report only, no device interaction)
- Added --prefer-dump option to scan pre-dumped DEX directories directly
- Added --sniffer/--no-sniffer flag (default: sniffing disabled for safety)
- Added --scope authorized-domain list file (only listed domains are sniffed)
- Added component version extraction (fastjson/bcprov/log4j) with CVE impact assessment
- Added intermediate artifact size report (out/ usage with cleanup hint)
- Added credential detection expanded to 56 rule sets (AI service keys/Chinese SDK/database connections/map keys)
- Added PII detection expanded to 14 rule sets (passport/VIN/IMEI/intl phone/Chinese address)
- Added dex partial decompilation fallback (scan smali output even when baksmali returns non-zero)
- Added auto-update mechanism (update subcommand: GitHub Release check/download/MD5 verify/tool version)
- Added config format versioning (config_version field with cross-version auto-migration)
- Added scan performance optimization (PII trigger pre-check + AK/SK prefix bucketing, 79% faster on plain code)
- Added config deep merge (new rules auto-preserved on version upgrade, user customizations take priority)

Fixed:
- Fixed frida detection false negatives in venv deployments (switched to find_spec)
- Fixed PII false positives from cryptographic test vectors (blacklist + path-based downweighting)
- Fixed USCC false positives (added format validation for dept/type codes)
- Fixed old config.toml overwriting new rules (shallow replace changed to deep merge)
- Fixed baksmali dependency errors discarding valid smali output (partial success now continues)

Improved:
- Unpack pipeline: 120s per-stage timeout (anti-debug resilience), failure falls back to static scan
- Log directory now follows -o output; stdout forced flush

### V1.0.10
Added:
- User workspace: config & tools auto-deployed to ~/Documents/AppInfoScanner on first run
- TOML workspace config (config.toml) with automatic migration from legacy config.py
- Credential detection (24 AK/SK rule sets) and personal/corporate PII detection (9 rule sets, ID-card & USCC checksum-validated)
- Sensitive-permission detection (49 Android / 22 iOS, Chinese risk notes) and component detection (20 Android / 22 iOS, CVE notes)
- Unified packer library (39 vendors) with three-signal shell detection (manifest class / file signatures / package-missing heuristic)
- Multi-protocol / IPv4 (with ports) / IPv6 / loopback-service extraction with adb-reverse capture hints
- Structured reports (report.json/txt/xlsx) and centralized per-task logs (logs/, newest 20 kept)
- Toolchain auto-install on macOS/Linux (Java/adb/frida) with frida version-consistency management (trio explicitly pinned)
- i18n (Chinese/English, APPINFO_LANG) and a unit-test suite (59 cases)

Fixed:
- apktool 3.x decode failure and wrong baksmali output directory
- macOS strings missing ~90% of binary strings
- Directory-mode web-scan crash, raw tracebacks on corrupt APK/IPA, and misplaced dex decompile output
- Flutter apps falsely flagged as packed, 0.0.0.0 over-filtering sibling IPs, greedy uses-permission matching
- Sniffer undefined-name regression, scan-thread queue race, history existence check, exit() bypassing error handling

Improved:
- Path handling and external commands normalized (os.path.join / subprocess argument lists)
- Two-tier public-domain filtering (126-entry suffix table); private addresses never sniffed
- Console output (noise reduction, single-line progress, [!] sensitive prefix) and regex-escaped history domains

### V1.0.9
- Updated apktool to the latest version
- Streamlined several stages
- Fixed excel export row limits
- Fixed script stuttering
- Fixed macOS Payload permission issues

### V1.0.8
- AK/SK detection
- Rule-submission entry point
- Added .gitignore
- Improved txt result output
- Fixed directory names containing spaces
- Fixed WEB page/directory scanning
- Fixed launching the app store with the default python on Windows
- Fixed empty results for iOS IPA scans

### V1.0.7
- Auto-download for APK, non-AppStore IPA and H5/HTML pages
- Suffix-based task-type auto-correction
- Improved AI-filter module, CLI parameters and config
- Improved domain filter rules
- Fixed download progress, Android dir-scan overwrite, AI filter quality
