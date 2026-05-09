# 🔍 Cyber Security Arsenal — Passive Reconnaissance Engine

> **Status:** Functional CLI tool · All core modules working · Seeking contributors for active-probe features

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue)](https://www.python.org)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

> ⚠️ **Legal:** For authorised security research and penetration testing only. Never run against systems you do not own or have explicit written permission to test.

---

## 🎯 What This Is

A **CLI-first, zero-subscription passive reconnaissance engine** for security researchers and penetration testers. It aggregates information that is publicly available about a target domain without sending any exploitative payloads.

**Five integrated modules:**

| Module | What it does |
|--------|-------------|
| `subdomain_enum` | Live DNS resolution of ~100 common subdomains. Finds `api.`, `dev.`, `staging.` etc. |
| `port_scan` | TCP probe of 20 well-known ports. Identifies exposed services (SSH, RDP, databases). |
| `web_fingerprint` | HTTP banner grabbing + security header analysis. Flags missing HSTS, CSP, X-Frame-Options. |
| `secret_hunter` | Shannon entropy analysis of public HTTP responses. Detects accidentally exposed API keys, tokens. |
| `dependency_audit` | Queries [OSV.dev](https://osv.dev) public API for known CVEs. No account or API key required. |

---

## ✅ What Actually Works

```bash
pip install -r requirements.txt
python src/cli.py scan --target example.com
python src/cli.py scan --target example.com --modules subdomain_enum,port_scan
python src/cli.py scan --target example.com --output report.json
python src/cli.py modules
```

- All 5 modules produce real output against live targets
- JSON report output with risk score (0–100) and signal breakdown
- Demo mode for `dependency_audit` when no `--packages` supplied (clearly flagged, excluded from risk score)
- Offline mode (`--no-network`) runs subdomain DNS only
- Full test suite: `pytest tests/` — all tests pass

---

## ❌ What We Have NOT Yet Achieved

### 1. Active Vulnerability Testing
The tool is **passive-only**. It does not:
- Send SQL injection or XSS payloads
- Test authentication bypass
- Fuzz API endpoints for business logic flaws

**Why:** Moving from passive recon to active exploitation crosses a legal and ethical line that requires explicit authorisation frameworks (like those in commercial tools such as Burp Suite Pro or Metasploit).

### 2. Authenticated Scanning
Cannot scan behind login walls — no session management, no cookie/token injection.

### 3. JavaScript-Heavy Target Support
The web fingerprinter uses raw HTTP, not a headless browser. Single-Page Applications built in React/Vue/Angular will not be analysed correctly.

### 4. OSINT Data Source Integration
No Shodan, Censys, VirusTotal, or WHOIS integration. These require API keys and paid tiers for meaningful data volumes.

### 5. Continuous Monitoring Mode
No daemon mode — it's a one-shot scan, not a continuous monitoring service.

---

## 🤝 How You Can Help

### 🔍 Security Research
- **Shodan/Censys integration:** Add optional passive enrichment from internet scan databases
- **WHOIS & certificate transparency:** Pull domain history and TLS cert logs (crt.sh)
- **Technology fingerprinting:** Improve web fingerprinting with Wappalyzer-style signatures
- **DNS zone transfer test:** Add `AXFR` attempt (with explicit permission gate)

### 🏗️ Engineering
- **Async scanning:** Replace synchronous probes with `asyncio` for 10x speed improvement on large target lists
- **Continuous monitoring daemon:** Run on a schedule, diff results, alert on new findings
- **Report templating:** HTML/PDF report generation from the JSON output
- **Plugin architecture:** Allow community-contributed modules without modifying core code

> Open an Issue or start a Discussion to contribute.

---

## 📄 License

MIT — see [LICENSE](LICENSE)
