# cyber-security-arsenal — Recon Engine

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python)](https://python.org)

A Python-native security reconnaissance engine with 6 modular scanners and a weighted risk correlator.

> **Legal Notice:** For use only against systems you own or have explicit written authorization to test.

---

## Modules

| Module | What it does |
|---|---|
| `SubdomainEnumerator` | DNS resolution of common subdomain prefixes |
| `PortScanner` | TCP probe of well-known ports |
| `WebFingerprinter` | HTTP banner + security header gap detection |
| `SecretHunter` | Shannon entropy analysis on public paths |
| `DependencyAuditor` | CVE lookup via OSV.dev API |
| `VulnerabilityCorrelator` | Weighted risk scoring across all signals |

> **Note:** This is a custom Python implementation. It does not wrap or require OWASP Nettacker or any third-party scanning framework.

## Quick Start

```bash
git clone https://github.com/GokulDubbaka/cyber-security-arsenal.git
cd cyber-security-arsenal
pip install -r requirements.txt

python src/cli.py scan --target example.com
```

## Running Tests

```bash
pip install -r requirements-dev.txt
pytest -q
```

## Test Results

`33 passed` — all modules covered with mock isolation (no live network in CI).

## License

MIT — see [LICENSE](LICENSE)
