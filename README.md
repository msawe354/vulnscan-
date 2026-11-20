# vulnscan — a basic web vulnerability scanner

[![Python](https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-pytest-informational?logo=pytest)](tests/)
[![Code style: ruff](https://img.shields.io/badge/style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Status](https://img.shields.io/badge/status-educational-orange)]()

**English** | [Русский](README.ru.md)

**vulnscan** is an educational command-line web vulnerability scanner written in
Python. It performs a lightweight security audit of a web application: it checks
HTTP security headers, looks for exposed files and directories using a built-in
wordlist, and tests HTML forms for reflected XSS using a safe, non-executable
payload. Results are printed as a readable console report and can be exported to
JSON.

The project is built as an AppSec portfolio piece and demonstrates modular
architecture, type hints, isolated checks, and network-free unit tests.

> **Educational use only.** Scan only systems you own or have written permission
> to test. See the [Disclaimer](#disclaimer).

---

## Table of contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Sample output](#sample-output)
- [What is checked](#what-is-checked)
- [Exit codes](#exit-codes)
- [Project structure](#project-structure)
- [Tests](#tests)
- [Limitations](#limitations)
- [Disclaimer](#disclaimer)
- [License](#license)

---

## Features

| Module | What it does |
| --- | --- |
| `headers` | Checks `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `Set-Cookie` flags, and version leakage. Every finding includes the risk and a remediation hint. |
| `directories` | Probes a wordlist of common paths (`.git/config`, `.env`, `admin`, `backup.zip`, `robots.txt`, etc.), classifies each response, and filters out soft-404 false positives. |
| `xss` | Parses forms with BeautifulSoup and checks whether an inert payload (`vscan<token>"'><`) is reflected unescaped. Detects the reflection context: text, attribute, or `<script>`. |
| Reporting | Colorized console report via `rich`, severity summary, and optional JSON export. |
| Safety | Timeouts, retries, response size limits, request delays, skipped password/file forms, and same-origin enforcement. |

**Additional**

- Strict URL validation with clear errors (unreachable host, timeout, TLS issues).
- CI-friendly exit codes (`--fail-on high`).
- Fully typed code (`py.typed`) with 36 pytest unit tests.
- Runs as `vulnscan ...` or `python -m vulnscan ...`.

---

## Requirements

- Python **3.10+**
- No external services; only outbound HTTP(S) access to the target you are
  authorized to test.

---

## Installation

```bash
git clone https://github.com/your-username/vulnscan.git
cd vulnscan

python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux / macOS
source .venv/bin/activate

pip install -r requirements.txt
pip install -e .
```

Verify the installation:

```bash
vulnscan --version
vulnscan --help
```

For development:

```bash
pip install -r requirements-dev.txt
```

---

## Usage

```bash
# Full scan (headers + paths + forms)
vulnscan https://example.com

# Headers and paths only
vulnscan https://example.com --no-xss

# Save a JSON report and limit the path scan
vulnscan https://example.com --json reports/example.json --max-paths 30

# Custom wordlist, more workers, polite delay
vulnscan https://example.com -w wordlists/common.txt --threads 20 --delay 0.2

# Local lab with a self-signed certificate
vulnscan https://localhost:8443 -k --timeout 5

# CI: fail with exit code 2 when a high-severity issue is found
vulnscan https://staging.example.com --fail-on high --json report.json
```

### Options

| Option | Default | Description |
| --- | --- | --- |
| `TARGET` | — | Target URL (`https://` is added automatically) |
| `-j, --json PATH` | off | Write the report to a JSON file |
| `-w, --wordlist PATH` | built-in | Path wordlist |
| `-t, --timeout SEC` | `10` | Per-request timeout |
| `--threads N` | `10` | Worker threads for path scanning (1–50) |
| `--delay SEC` | `0` | Delay between requests |
| `--max-paths N` | all | Limit the number of probed paths |
| `--max-forms N` | `10` | Maximum forms tested for XSS |
| `--no-xss` / `--no-directories` | off | Disable a module |
| `-k, --insecure` | off | Disable TLS certificate verification |
| `--proxy URL` | — | HTTP(S) proxy (e.g. Burp) |
| `--fail-on LEVEL` | `high` | Severity threshold for exit code 2 |
| `-v, --verbose` | off | Show INFO-level details |

---

## Sample output

> Runtime messages are currently in Russian; the sample below is translated for
> readability.

```text
╭───────────────────── vulnscan — basic web vulnerability scanner ─────────────────────╮
│ Target: https://example.com                                                          │
│ Started: 2026-02-11 14:02:31 MSK                                                     │
│ Duration: 6.84 s   HTTP requests: 68                                                 │
│ Version: vulnscan 1.0.0                                                              │
╰──────────────────────────────────────────────────────────────────────────────────────╯
        Severity summary
 Severity   Count
 ──────────────────
  HIGH          2  ##
  MEDIUM        4  ####
  LOW           3  ###
  INFO          5  #####
 ──────────────────
 Total        14

                                                          Findings
 #   Severity   Check          Finding                                              URL
 ───────────────────────────────────────────────────────────────────────────────────────────
 1   HIGH       directories    Exposed resource: /.env                              https://example.com/.env
 2   HIGH       directories    Exposed resource: /.git/config                       https://example.com/.git/config
 3   MEDIUM     headers        Missing Content-Security-Policy (CSP)                https://example.com/
 4   MEDIUM     headers        Missing Strict-Transport-Security (HSTS)             https://example.com/
 5   MEDIUM     headers        Missing X-Frame-Options                              https://example.com/
 6   MEDIUM     directories    Exposed resource: /admin                             https://example.com/admin
 ...

Finding details
1. [HIGH] Exposed resource: /.env
   URL: https://example.com/.env
   Risk: /.env returns HTTP 200 and is not a soft-404 page. Such files often
   contain secrets, database dumps, source code, or backups — public exposure is critical.
   Evidence: HTTP 200, 412 bytes
   Remediation: Deny access at the web-server level (deny/return 404), remove the
   file from the webroot, and keep secrets in environment variables or a secret manager.

╭──────────────────────────────────── Result ────────────────────────────────────╮
│ Critical issues found — remediation required.                                  │
│ CRITICAL: 0 | HIGH: 2 | MEDIUM: 4 | LOW: 3 | INFO: 5                           │
╰────────────────────────────────────────────────────────────────────────────────╯
```

JSON excerpt (full example in [`examples/report.json`](examples/report.json)):

```json
{
  "tool": { "name": "vulnscan", "version": "1.0.0" },
  "target": "https://example.com",
  "summary": {
    "total": 14,
    "by_severity": { "critical": 0, "high": 2, "medium": 4, "low": 3, "info": 5 }
  },
  "findings": [
    {
      "check": "directories",
      "title": "Exposed resource: /.env",
      "severity": "high",
      "url": "https://example.com/.env",
      "evidence": "HTTP 200, 412 bytes",
      "remediation": "Deny access at the web-server level (deny/return 404)…"
    }
  ]
}
```

---

## What is checked

### Security headers

| Header | Risk when missing | Severity |
| --- | --- | --- |
| `Content-Security-Policy` | No restriction on script sources; XSS and third-party widgets gain full control over the page | Medium |
| `Strict-Transport-Security` | SSL stripping, downgrade to HTTP, session theft | Medium |
| `X-Frame-Options` (or CSP `frame-ancestors`) | Clickjacking | Medium |
| `X-Content-Type-Options` | MIME sniffing: an uploaded file may execute as HTML/JS | Low |
| `Referrer-Policy` | URLs with tokens leak to external resources | Low |
| `Permissions-Policy` | Unrestricted camera/microphone/geolocation access | Info |

Additionally: HSTS `max-age`, `'unsafe-inline'` in CSP, invalid `X-Frame-Options`
values, cookie `Secure`/`HttpOnly`/`SameSite` flags, `Server`/`X-Powered-By`
fingerprinting, and plain-HTTP delivery.

### Exposed paths

The wordlist covers typical artifacts: version-control metadata, `.env` and
config files, backups and dumps, admin panels, API docs, logs, and uploads.
Each response is classified:

- `200/204` → exposed resource (High for secrets/backups, Medium otherwise);
- `401/403` → resource exists but is protected (Low);
- `301/302` to another host → possible open redirect (Low);
- `5xx` → hidden endpoint or application error (Info).

Before scanning, the tool requests three definitely nonexistent paths and
compares their responses with the findings (status + `difflib` similarity) to
avoid reporting soft-404 pages.

### Reflected XSS

The payload looks like `vscan1a2b3c4d"'><`. It contains **no** `<script>`, event
handlers, or `javascript:` URLs. The scanner reports:

- unescaped reflection → **High**;
- reflection inside `<script>` → **Critical**;
- escaped reflection (`&quot;`, `&#x27;`) → **Info** (a good sign).

Forms with `password` or `file` fields are never tested, and forms that submit
to another origin are skipped.

---

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Scan completed; no findings at or above `--fail-on` |
| `1` | Startup error: invalid URL, missing wordlist, write failure |
| `2` | Findings at or above `--fail-on` |
| `130` | Interrupted (Ctrl+C) |

---

## Project structure

```
vulnscan/
├── src/vulnscan/
│   ├── __init__.py          # package version
│   ├── __main__.py          # python -m vulnscan
│   ├── cli.py               # typer CLI, orchestration, exit codes
│   ├── models.py            # Finding / Severity / ScanReport
│   ├── http_client.py       # httpx wrapper: timeouts, retries, body limit
│   ├── py.typed             # typed-package marker
│   ├── checks/
│   │   ├── base.py          # check contract
│   │   ├── headers.py       # security header analysis
│   │   ├── directories.py   # path scanning + soft-404 detection
│   │   └── xss.py           # form parsing and reflection detection
│   ├── reporting/
│   │   ├── console.py       # rich output
│   │   └── json_report.py   # JSON export
│   ├── utils/urls.py        # URL normalization and validation
│   └── data/common.txt      # built-in wordlist (package data)
├── wordlists/common.txt     # editable wordlist (--wordlist)
├── tests/                   # pytest, no network access
├── examples/report.json     # sample JSON report
├── pyproject.toml
├── requirements.txt
├── requirements-dev.txt
├── .gitignore
├── LICENSE
├── README.md                # English (this file)
└── README.ru.md             # Russian translation
```

---

## Tests

```bash
pytest
```

Tests never touch the network: `analyze_headers` accepts a plain header mapping,
and the directory/XSS checks accept a fake client implementing the `HttpClient`
interface.

Covered:

- URL normalization and validation;
- missing/present security headers, weak CSP, short HSTS;
- form parsing, reflection-context detection, escaped output;
- wordlist parsing (comments, duplicates, BOM), soft-404, severity mapping.

---

## Limitations

- The scanner does **not** authenticate, does not execute JavaScript, and does
  not handle SPA routing, so DOM-based XSS is out of scope.
- Path discovery uses a fixed wordlist without recursion or fuzzing.
- No CSRF, SQLi, SSRF, IDOR, TLS configuration, or dependency-version checks.
- The soft-404 heuristic may misfire on pages with highly dynamic content.
- XSS findings require manual verification: the scanner detects reflection, not
  code execution.
- Redirects are followed for the header check, so headers are analyzed at the
  final URL.

For deeper testing, use dedicated tools such as OWASP ZAP, Burp Suite, nuclei,
or ffuf.

---

## Disclaimer

> **This tool is provided for educational purposes only.**
>
> Use `vulnscan` exclusively against systems you own or for which you have
> **written authorization** from the owner.
>
> Unauthorized scanning, path brute-forcing, and sending test data to third
> parties may violate the law (e.g. the U.S. Computer Fraud and Abuse Act, the
> GDPR, and local regulations) and may lead to blocking, data leaks, and legal
> liability.
>
> The author assumes no responsibility for any damage caused by the use of this
> code. By running the scanner you confirm that you act within the law and the
> permissions you have obtained.
>
> The scanner does not attempt to exploit findings, does not upload files, does
> not brute-force credentials, and does not execute JavaScript. The XSS payload
> is inert.

---

## License

Released under the [MIT License](LICENSE).

---

<p align="center"><i>Built as an AppSec portfolio project. Not a substitute for a professional penetration test.</i></p>
