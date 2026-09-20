# Changelog (English)

**Language**: [简体中文](update.md) | [English](update_EN.md)

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
