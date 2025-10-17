# YARA Intel Pack
[![YARA tests](https://github.com/x-pwn3d/yara-intel-pack/actions/workflows/test.yml/badge.svg)](https://github.com/x-pwn3d/yara-intel-pack/actions/workflows/test.yml)
![YARA](https://img.shields.io/badge/YARA-Intel-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)
![Status](https://img.shields.io/badge/Status-Functional-brightgreen)
![License](https://img.shields.io/badge/License-MIT-orange)


> 🧠 Test-driven YARA rulepack for detecting suspicious PowerShell, SMB uploads, and LSASS/memory-dump tooling.


**Project**: yara_intel  
**Author**: xpwn3d  
**Purpose**: A small, test-driven YARA rulepack for detecting suspicious PowerShell activity, SMB uploads and LSASS/memory-dump tooling. Designed as a standalone detection/QA module to complement a Purple Team lab (Wazuh + Sysmon).  
**Status**: Functional — rules validated against positive/negative corpora using `tools/run_tests.ps1`.

## 🧭 Quick overview

This repo contains a focused set of YARA rules + a test harness to:

- detect indicators related to:
  - PowerShell obfuscation / encoded commands,
  - suspicious download patterns,
  - malicious SMB file uploads,
  - LSASS / memory-dump tools (textual and lightweight PE heuristics),
- validate rules against curated positive and negative sample sets,
- provide an automated, repeatable QA pipeline (PowerShell) producing a compiled rules file and test summary.

The pack is intentionally modular so it can be used as:
- an offline threat-hunting/YARA intelligence pack,
- a building block to integrate agent-side scanning (Wazuh AR) or CI pipelines.

## 🎯 Detection goals & MITRE mapping

This pack targets behaviors commonly used in post-exploitation & lateral movement:

- **T1059.001 – PowerShell** (encoded commands, IEX, suspicious download patterns)
- **T1021.002 – SMB / Windows Admin Shares** (suspicious uploads to SMB shares)
- **T1003 – Credential Dumping** (mimikatz, procdump, winpmem markers and light PE heuristics)

Each rule includes metadata (author/description), consider adding more fields (created, severity, mitre tags) for production use.

## 📁 Repository structure

```scss
.
├── README.md
├── rules
│   ├── credential_dump
│   │   └── lsass.yar
│   ├── lateral_movement
│   │   └── smb_uploads.yar
│   └── powershell
│       ├── ps_obfuscation_patterns.yar
│       └── ps_suspicious_downloads.yar
├── tests
│   ├── negative
│   │   └── (benign files)
│   └── positive
│       └── (malicious test cases)
└── tools
    ├── run_tests.ps1
    └── scan_with_yara.ps1
```

## 🔎 Rules (short descriptions)

- **powershell**/**ps_suspicious_downloads.yar**: 
Detects use of ``IEX``/``Invoke-Expression``, remote download patterns and loose http/https fetching patterns (loose vs strict variants exist). Good for detecting in-place PowerShell payload retrieval.

- **powershell**/**ps_obfuscation_patterns.yar**: 
Detects simple obfuscation techniques: string concatenation, ``[char]`` conversions, long Base64 blobs (context-aware), encoded-command flags. Tuned to reduce false positives (PEM exclusion, b64 length thresholds).

- **lateral_movement**/**smb_uploads.yar**: 
Generic markers for suspicious files placed into SMB shares (filename patterns or embedded command markers). Meant to be used in conjunction with FIM/syscheck alerts (Wazuh).

- **credential_dump**/**lsass.yar**: 
Textual markers for common dumpers (``mimikatz``, ``procdump``, ``winpmem``, ``sekurlsa::``, ``logonpasswords``) plus an optional PE heuristics rule that looks at imports / small-file heuristics (use with caution).

## ✅ What the test harness does

``tools/run_tests.ps1``:

**1**. Concatenates/compiles rules into ``.\compiled_rules.yar``.  

**2**. Runs YARA on every file in ``tests/positive`` (should match ≥1 rule) and ``tests/negative`` (should not match).

**3**. Produces a colored console summary including per-file matches, false positives/negatives and YARA warnings.

This gives you a repeatable QA pipeline to tune rules and sample corpus before deploying anywhere.

## ⚙️ Prerequisites

- Windows PowerShell (tested on Windows 10/11 / PowerShell 5+).
- ``yara64.exe`` (YARA binary) accessible
-  Edit ``tools/run_tests.ps1`` and ``tools/scan_with_yara.ps1`` if your binary lives elsewhere.

## ⚠️ Windows script execution notes

If you download this repository from GitHub, PowerShell may prevent scripts from running with an error like:

```
cannot be loaded. The file ...\run_tests.ps1 is not digitally signed.
```
This is normal on Windows for scripts downloaded from the Internet. There are two safe ways to fix this:

### Option 1 – Unblock individual scripts

Run the following in PowerShell in the tools folder:

```powershell
Unblock-File .\run_tests.ps1
Unblock-File .\scan_with_yara.ps1
```
This removes the "downloaded from Internet" flag, allowing normal execution.

### Option 2 – Bypass execution policy temporarily

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\run_tests.ps1
```

- This only applies for the current PowerShell session.
- It does not modify system-wide settings.
- Recommended if you plan to run multiple scripts during testing.

> **Note**: This behavior cannot be fully bypassed in the scripts themselves, as it is enforced by Windows PowerShell’s security policies. The scripts do not need to be signed; these steps only allow them to run.

## ▶️ How to run tests (local)

Open PowerShell in ``tools`` folder:

```powershell
# default usage (assuming we have set the path to the YARA executable)
.\run_tests.ps1

# optional: override paths
.\run_tests.ps1 -RulesDir "..\rules" -PosDir "..\tests\positive" -NegDir "..\tests\negative" -YaraExe "C:\path\to\yara64.exe"
```
**Expected outcome**: compiled rules file ``.\compiled_rules.yar`` and console summary showing positives detected and negatives clean. Exit code ``0`` if no FP/FN, non-zero otherwise.

Here’s an example of a successful test harness execution showing all rules passing without false positives/negatives :

<img width="1023" height="727" alt="Capture d'écran 2025-10-17 172135" src="https://github.com/user-attachments/assets/5d037cad-f035-4ce0-ac3e-39911b2728a6" />

## ▶️ How to scan a single file (helper)


The helper script ``tools/scan_with_yara.ps1`` allows you to manually test YARA rules on a specific file or an entire directory.  
It automatically detects if the target path is a file or folder and runs YARA with recursive mode when needed.

```powershell
# Scan a single file
.\scan_with_yara.ps1 -Path "C:\yara_intel\tests\positive\evil_demo.ps1" -RulePath ".\compiled_rules.yar"

# Scan an entire directory recursively
.\scan_with_yara.ps1 -Path "C:\yara_intel\tests\positive" -RulePath ".\compiled_rules.yar"

# Optionally specify a custom YARA binary
.\scan_with_yara.ps1 -Path "C:\Samples" -RulePath ".\compiled_rules.yar" -YaraExe "C:\tools\yara\yara64.exe"

```

Example run of the on-demand scanner script (`scan_with_yara.ps1`), scanning a single file with the compiled rules:

<img width="1024" height="727" alt="Capture d'écran 2025-10-17 173147" src="https://github.com/user-attachments/assets/ca33aa17-7bf0-4a73-9717-e90f9155aff6" />



## 📌 Notes, tuning & practical tips

- **Performance**: some regexes (large base64 blobs, complex wildcards) can slow scanning. YARA warnings will tell you which strings may be expensive. Prefer bounded repeats (``.{1,200}``) and anchored patterns when possible.

- **Context-awareness**: rules that require multiple indicators (e.g., ``-EncodedCommand`` and a long base64) reduce false positives. You already use such guardrails (PEM header exclusion, b64 threshold). Good.

- **Test corpus**: keep adding realistic positives and benign negatives (certificates, manifests, installer files, vendor xml) — that’s what prevents FPs in production.

- **Rule metadata**: add ``mitre``, ``severity``, ``created``, ``source`` fields to every rule for cataloging and easier automation (e.g., dashboards).

- **PE heuristics**: ``import "pe"`` rules are powerful but may produce FPs if applied to arbitrary text files. Scope them to actual PE files only. When scanning mixed corpora, ensure you test with ``.exe`` samples.

Integration with Wazuh: optional — you already have agent-side wrapper patterns. The pack can feed Wazuh AR by having the wrapper call YARA and then execute containment logic. But keeping YARA as an offline intel pack is a valid, valuable use-case by itself.

## 🧩 Integration with Wazuh (optional)

You already have agent-side wrapper patterns.  
The pack can feed Wazuh Active Response by having the wrapper call YARA and then execute containment logic.  
However, keeping YARA as an offline intel pack is a valid, valuable use case by itself.




