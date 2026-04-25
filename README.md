# Forensic-Scanner-PRO

A fast multithreaded desktop forensic scanner for **DLL / EXE / APK / text-based files** with regex-powered secret hunting, decompilation support, severity tagging, context preview, and live progress tracking.

Built with **Python + GTK3** for Linux (tested on Kali), but can run anywhere GTK3 + Python are available.

---

# Features

## Multi-format scanning

Supports:

* DLL (`.dll`)
* EXE (`.exe`)
* APK (`.apk`)
* Other files:

  * `.txt`
  * `.json`
  * `.xml`
  * `.log`

You can enable **multiple file types at once**.

---

## Reverse engineering support

### DLL / EXE

Uses **ILSpyCmd** to decompile .NET assemblies before scanning.

### APK

Uses **apktool** to decode APK contents before scanning.

---

## Regex detection engine

Search using:

### Manual textbox regex

Examples:

```regex
api|token|key|secret
```

### regex.json file

Load structured patterns with severity labels.

Example:

```json
[
  {
    "pattern": "password",
    "matchInfo": "Critical"
  },
  {
    "pattern": "apikey",
    "matchInfo": "High"
  }
]
```

Supported severities:

* Critical
* High
* Medium
* Low
* Informational
* Manual

---

# UI Features

## Dual progress bars

### File Scan Progress

Tracks processed files.

### Results Progress

Tracks discovered matches inserted into the table.

---

## Searchable results table

Columns:

* File
* Class
* Method
* Match
* Severity

---

## Context viewer

Double-click any result to open:

* matched line
* lines before
* lines after

Selectable + copyable text.

---

## Thread control

Adjust thread count for faster scanning.

---

## Context control

Choose how many lines before/after to show (1–50).

---

## Pause / Resume

Pause long scans anytime.

---

## Cancel

Cancel running scans safely.

---

## Duplicate prevention

Prevents endless duplicate match rows.

---

# Requirements

## Python

Python 3.9+

## GTK3

```bash
sudo apt install python3-gi gir1.2-gtk-3.0
```

## ILSpyCmd (.NET DLL / EXE support)

```bash
dotnet tool install --global ilspycmd --version 8.2.0
```

If needed:

```bash
export PATH="$PATH:$HOME/.dotnet/tools"
```

Check:

```bash
ilspycmd --version
```

## APKTool (APK support)

```bash
sudo apt install apktool
```

---

# Install

```bash
git clone https://github.com/pentestrox/forensic-scanner-pro.git
cd forensic-scanner-pro
python3 scanner.py
```

---

# Usage

## 1. Select target

Choose:

* Select Folder
* Select Files

## 2. Choose file types

Tick one or more:

* DLL
* EXE
* APK
* Other

## 3. Enter regex

Example:

```regex
password|token|apikey|jwt
```

## 4. Optional: enable regex.json

Use advanced pattern packs.

## 5. Set thread count

Recommended:

* 4 = light systems
* 8 = modern CPU
* 16+ = large scans

## 6. Start Scan

Results appear live.

---

# Example Use Cases

## Bug bounty

Find:

* API keys
* hardcoded secrets
* JWT tokens
* passwords
* endpoints

## Malware triage

Scan unpacked samples for:

* URLs
* C2 strings
* credentials
* suspicious configs

## Reverse engineering

Quickly inspect .NET binaries.

## Internal auditing

Search large code dumps / backups.

---

# Example regex.json

```json
[
  {
    "pattern": "password",
    "matchInfo": "Critical"
  },
  {
    "pattern": "api[_-]?key",
    "matchInfo": "High"
  },
  {
    "pattern": "token",
    "matchInfo": "Medium"
  },
  {
    "pattern": "debug",
    "matchInfo": "Low"
  }
]
```

---

# Notes

* ILSpyCmd is required for DLL / EXE decompilation.
* APKTool is required for APK extraction.
* Large APK/DLL scans may use temporary `/tmp` storage.
* Thread count too high may slow low-RAM systems.

---

# Security / Ethics

Use only on systems, binaries, and data you own or are authorized to assess.

---

# Roadmap

Planned ideas:

* Export HTML report
* CSV export
* Dark theme
* Rule packs
* YARA integration
* Recursive archives
* Entropy detection
* PE metadata viewer

---

# Credits

Built with:

* Python
* GTK3
* ILSpyCmd
* APKTool

---

# License

MIT License
