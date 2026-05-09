"""
Cyber Security Arsenal — Reconnaissance Orchestrator
=====================================================
Multi-module, policy-enforced reconnaissance engine.

Modules:
  - SubdomainEnumerator   : Live DNS-based subdomain resolution
  - PortScanner           : Safe TCP port probing (well-known ports only)
  - WebFingerprinter      : HTTP header/banner analysis
  - SecretHunter          : Shannon entropy-based secret detection
  - DependencyAuditor     : OSV.dev live CVE lookup for supplied package list
  - VulnerabilityCorrelator: Aggregates signals into a structured risk report

DependencyAuditor behaviour:
  - When packages are supplied via CLI (--packages JSON), those packages are audited.
  - When NO packages are supplied, the auditor runs against a DEMO/REFERENCE set
    of known-vulnerable packages (lodash 4.17.20, log4j-core 2.14.0, etc.).
    The CLI labels demo results clearly to avoid confusion with target-specific data.

Design constraints:
  - No credential use, no exploit execution, no persistence
  - All probes are read-only and non-destructive
  - Timeout-bounded (no hanging scans)
"""

from __future__ import annotations

import json
import logging
import math
import re
import socket
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class ReconSignal:
    """A single intelligence signal produced by a recon module."""
    module: str
    signal_type: str
    value: str
    confidence: float
    metadata: Dict[str, Any] = field(default_factory=dict)
    is_demo_data: bool = False   # True when sourced from built-in reference packages

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "module":      self.module,
            "signal_type": self.signal_type,
            "value":       self.value,
            "confidence":  self.confidence,
            "metadata":    self.metadata,
        }
        if self.is_demo_data:
            d["note"] = "DEMO: sourced from built-in reference package list, not from target"
        return d


@dataclass
class ReconReport:
    """Aggregated reconnaissance report for a target."""
    target: str
    generated_at: str
    signals: List[ReconSignal]
    modules_run: List[str]
    errors: List[str]
    risk_summary: Dict[str, Any]
    dep_audit_mode: str = "none"   # "demo" | "target" | "none"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target":         self.target,
            "generated_at":   self.generated_at,
            "dep_audit_mode": self.dep_audit_mode,
            "signals":        [s.to_dict() for s in self.signals],
            "modules_run":    self.modules_run,
            "errors":         self.errors,
            "risk_summary":   self.risk_summary,
            "total_signals":  len(self.signals),
        }


class SubdomainEnumerator:
    """
    Passive-safe subdomain enumeration via live DNS resolution.
    NOTE: DNS resolution is network activity even in --no-network mode.
    This module is classified as LOW-IMPACT (no HTTP probing).
    """

    COMMON_PREFIXES = [
        "www", "api", "staging", "dev", "admin", "mail", "cdn",
        "static", "assets", "app", "auth", "login", "portal",
        "dashboard", "status", "docs", "beta", "v2", "internal",
    ]

    def run(self, domain: str) -> Tuple[List[ReconSignal], List[str]]:
        signals: List[ReconSignal] = []
        errors: List[str] = []
        candidates = [domain] + [f"{p}.{domain}" for p in self.COMMON_PREFIXES]

        for fqdn in candidates:
            try:
                ips = socket.getaddrinfo(fqdn, None, socket.AF_INET)
                if ips:
                    ip = ips[0][4][0]
                    signals.append(ReconSignal(
                        module="subdomain_enum", signal_type="subdomain",
                        value=fqdn, confidence=0.99,
                        metadata={"resolved_ip": ip},
                    ))
            except socket.gaierror:
                pass
            except Exception as exc:
                errors.append(f"SubdomainEnumerator error on {fqdn}: {exc}")

        return signals, errors


class PortScanner:
    """Safe TCP port probe — well-known ports only."""

    WELL_KNOWN_PORTS = [
        21, 22, 25, 53, 80, 110, 143, 443, 465, 587,
        993, 995, 3306, 5432, 6379, 8080, 8443, 8888, 27017,
    ]

    def run(self, target: str, timeout: float = 2.0) -> Tuple[List[ReconSignal], List[str]]:
        signals: List[ReconSignal] = []
        errors: List[str] = []
        host = target.replace("https://", "").replace("http://", "").split("/")[0]

        for port in self.WELL_KNOWN_PORTS:
            try:
                with socket.create_connection((host, port), timeout=timeout):
                    signals.append(ReconSignal(
                        module="port_scan", signal_type="open_port",
                        value=str(port), confidence=1.0,
                        metadata={"host": host, "port": port},
                    ))
            except (socket.timeout, ConnectionRefusedError, OSError):
                pass
            except Exception as exc:
                errors.append(f"PortScanner error {host}:{port}: {exc}")

        return signals, errors


class WebFingerprinter:
    """Passive HTTP banner and security-header analysis."""

    SECURITY_HEADERS = [
        "strict-transport-security", "content-security-policy",
        "x-frame-options", "x-content-type-options",
        "referrer-policy", "permissions-policy",
    ]

    def run(self, target: str, timeout: float = 5.0) -> Tuple[List[ReconSignal], List[str]]:
        signals: List[ReconSignal] = []
        errors: List[str] = []
        base = target if target.startswith("http") else f"https://{target}"
        probe_paths = ["/", "/robots.txt", "/.well-known/security.txt"]

        for path in probe_paths:
            url = base.rstrip("/") + path
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "security-research-bot/1.0"})
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    hdrs = {k.lower(): v for k, v in resp.headers.items()}
                    server = hdrs.get("server", "")
                    xpow   = hdrs.get("x-powered-by", "")
                    if server:
                        signals.append(ReconSignal(
                            module="web_fingerprint", signal_type="server_banner",
                            value=server, confidence=0.99,
                            metadata={"url": url, "header": "Server"},
                        ))
                    if xpow:
                        signals.append(ReconSignal(
                            module="web_fingerprint", signal_type="server_banner",
                            value=xpow, confidence=0.95,
                            metadata={"url": url, "header": "X-Powered-By"},
                        ))
                    missing = [h for h in self.SECURITY_HEADERS if h not in hdrs]
                    if missing:
                        signals.append(ReconSignal(
                            module="web_fingerprint",
                            signal_type="missing_security_headers",
                            value=", ".join(missing), confidence=0.99,
                            metadata={"url": url, "missing_headers": missing},
                        ))
            except urllib.error.HTTPError as exc:
                if exc.code not in (404, 403):
                    errors.append(f"WebFingerprinter HTTP {exc.code} on {url}")
            except Exception as exc:
                errors.append(f"WebFingerprinter error on {url}: {exc}")

        return signals, errors


class SecretHunter:
    """Entropy-based secret detection on public endpoints."""

    PROBE_PATHS = [
        "/robots.txt", "/.well-known/security.txt",
        "/.env.example", "/config.yml", "/swagger.json", "/openapi.json",
    ]
    ENTROPY_THRESHOLD = 4.2
    TOKEN_RE = re.compile(r"[A-Za-z0-9/+_\-]{20,}")

    def _entropy(self, s: str) -> float:
        if not s:
            return 0.0
        freq = {c: s.count(c) / len(s) for c in set(s)}
        return -sum(p * math.log2(p) for p in freq.values())

    def run(self, target: str, timeout: float = 5.0) -> Tuple[List[ReconSignal], List[str]]:
        signals: List[ReconSignal] = []
        errors: List[str] = []
        base = target if target.startswith("http") else f"https://{target}"

        for path in self.PROBE_PATHS:
            url = base.rstrip("/") + path
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "security-research-bot/1.0"})
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    text = resp.read(8192).decode(errors="ignore")
                    for token in self.TOKEN_RE.findall(text):
                        h = self._entropy(token)
                        if h > self.ENTROPY_THRESHOLD:
                            signals.append(ReconSignal(
                                module="secret_hunter",
                                signal_type="secret_candidate",
                                value=f"{token[:6]}...{token[-4:]}",
                                confidence=min(0.5 + (h - self.ENTROPY_THRESHOLD) * 0.15, 0.99),
                                metadata={"path": path, "entropy": round(h, 3)},
                            ))
            except urllib.error.HTTPError:
                pass
            except Exception as exc:
                errors.append(f"SecretHunter error on {url}: {exc}")

        return signals, errors


class DependencyAuditor:
    """
    Live CVE lookup via OSV.dev public API.  No API key required.

    IMPORTANT: When packages are not explicitly supplied, this auditor
    checks a built-in DEMO/REFERENCE set of known-vulnerable packages
    (lodash 4.17.20, log4j-core 2.14.0, django 3.0.0, express 4.17.1,
    requests 2.25.0).  These demo results are NOT derived from the scan
    target and are clearly labelled as such in the output.

    To audit a real target's dependencies, pass a packages list via CLI:
      --packages '[{"package":{"name":"flask","ecosystem":"PyPI"},"version":"0.12.0"}]'
    """

    DEMO_PACKAGES = [
        {"package": {"name": "lodash",    "ecosystem": "npm"},   "version": "4.17.20"},
        {"package": {"name": "log4j-core", "ecosystem": "Maven"}, "version": "2.14.0"},
        {"package": {"name": "django",     "ecosystem": "PyPI"},  "version": "3.0.0"},
        {"package": {"name": "express",    "ecosystem": "npm"},   "version": "4.17.1"},
        {"package": {"name": "requests",   "ecosystem": "PyPI"},  "version": "2.25.0"},
    ]

    OSV_ENDPOINT = "https://api.osv.dev/v1/query"

    def run(
        self, target: str,
        packages: Optional[List[Dict[str, Any]]] = None,
        timeout: float = 8.0,
    ) -> Tuple[List[ReconSignal], List[str], bool]:
        """
        Returns (signals, errors, used_demo_data).
        used_demo_data=True when packages were not supplied by the caller.
        """
        signals: List[ReconSignal] = []
        errors: List[str] = []
        using_demo = packages is None
        entries = packages if packages is not None else self.DEMO_PACKAGES

        for entry in entries:
            try:
                payload = json.dumps(entry).encode()
                req = urllib.request.Request(
                    self.OSV_ENDPOINT, data=payload,
                    headers={"Content-Type": "application/json"}, method="POST",
                )
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    data = json.loads(resp.read())
                    for vuln in data.get("vulns", []):
                        vid      = vuln.get("id", "UNKNOWN")
                        sev      = vuln.get("database_specific", {}).get("severity", "UNKNOWN")
                        pkg_name = entry.get("package", {}).get("name", "unknown")
                        signals.append(ReconSignal(
                            module="dependency_audit", signal_type="cve",
                            value=vid, confidence=0.99,
                            metadata={
                                "package": pkg_name,
                                "version": entry.get("version"),
                                "severity": sev,
                            },
                            is_demo_data=using_demo,
                        ))
            except urllib.error.URLError as exc:
                pkg = entry.get("package", {}).get("name", "?")
                errors.append(f"OSV API unreachable for {pkg}: {exc}")
            except Exception as exc:
                errors.append(f"DependencyAuditor error: {exc}")

        return signals, errors, using_demo


class VulnerabilityCorrelator:
    """Aggregates all recon signals into a risk-ranked summary."""

    WEIGHTS = {
        "cve":                      3.0,
        "secret_candidate":         2.5,
        "missing_security_headers": 1.5,
        "open_port":                0.8,
        "server_banner":            0.5,
        "subdomain":                0.3,
    }

    def correlate(self, signals: List[ReconSignal]) -> Dict[str, Any]:
        if not signals:
            return {"risk_score": 0, "risk_level": "informational", "top_findings": [], "signal_breakdown": {}}

        breakdown: Dict[str, int] = {}
        for s in signals:
            breakdown[s.signal_type] = breakdown.get(s.signal_type, 0) + 1

        raw_score = 0.0
        for s in signals:
            weight = self.WEIGHTS.get(s.signal_type, 0.2)
            # demo CVE signals get 0 weight in risk score -- they describe a reference set, not the target
            if s.is_demo_data:
                continue
            raw_score += weight * s.confidence
        risk_score = min(round(raw_score, 1), 100.0)

        if risk_score >= 40:   level = "critical"
        elif risk_score >= 25: level = "high"
        elif risk_score >= 12: level = "medium"
        elif risk_score >= 4:  level = "low"
        else:                  level = "informational"

        ranked = sorted(
            signals, key=lambda s: self.WEIGHTS.get(s.signal_type, 0.2) * s.confidence, reverse=True,
        )
        return {
            "risk_score":       risk_score,
            "risk_level":       level,
            "top_findings":     [s.to_dict() for s in ranked[:10]],
            "signal_breakdown": breakdown,
        }


class ReconOrchestrator:
    """
    Top-level reconnaissance orchestrator.
    Runs all configured modules against a target and produces a unified ReconReport.
    """

    def __init__(
        self,
        modules: Optional[List[str]] = None,
        port_timeout: float = 2.0,
        http_timeout: float = 5.0,
        osv_timeout: float = 8.0,
    ):
        self._modules     = modules or [
            "subdomain_enum", "port_scan", "web_fingerprint",
            "secret_hunter", "dependency_audit",
        ]
        self._port_timeout = port_timeout
        self._http_timeout = http_timeout
        self._osv_timeout  = osv_timeout
        self._subdomain  = SubdomainEnumerator()
        self._port       = PortScanner()
        self._web        = WebFingerprinter()
        self._secret     = SecretHunter()
        self._dep        = DependencyAuditor()
        self._correlator = VulnerabilityCorrelator()

    def run(
        self, target: str,
        packages: Optional[List[Dict[str, Any]]] = None,
    ) -> ReconReport:
        if not target:
            raise ValueError("Target must not be empty")

        all_signals: List[ReconSignal] = []
        all_errors:  List[str] = []
        modules_run: List[str] = []
        dep_audit_mode = "none"

        logger.info("RECON_START target=%s modules=%s", target, self._modules)

        if "subdomain_enum" in self._modules:
            domain = target.replace("https://", "").replace("http://", "").split("/")[0]
            sigs, errs = self._subdomain.run(domain)
            all_signals.extend(sigs)
            all_errors.extend(errs)
            modules_run.append("subdomain_enum")

        if "port_scan" in self._modules:
            sigs, errs = self._port.run(target, timeout=self._port_timeout)
            all_signals.extend(sigs)
            all_errors.extend(errs)
            modules_run.append("port_scan")

        if "web_fingerprint" in self._modules:
            sigs, errs = self._web.run(target, timeout=self._http_timeout)
            all_signals.extend(sigs)
            all_errors.extend(errs)
            modules_run.append("web_fingerprint")

        if "secret_hunter" in self._modules:
            sigs, errs = self._secret.run(target, timeout=self._http_timeout)
            all_signals.extend(sigs)
            all_errors.extend(errs)
            modules_run.append("secret_hunter")

        if "dependency_audit" in self._modules:
            sigs, errs, used_demo = self._dep.run(
                target, packages=packages, timeout=self._osv_timeout,
            )
            all_signals.extend(sigs)
            all_errors.extend(errs)
            modules_run.append("dependency_audit")
            dep_audit_mode = "demo" if used_demo else "target"
            if used_demo:
                logger.warning(
                    "DEPENDENCY_AUDIT: No packages supplied. Results reflect a DEMO/REFERENCE "
                    "package set and are NOT specific to %s. Use --packages to audit a real target.",
                    target,
                )

        risk_summary = self._correlator.correlate(all_signals)

        logger.info(
            "RECON_COMPLETE target=%s signals=%d risk_level=%s dep_audit=%s",
            target, len(all_signals), risk_summary["risk_level"], dep_audit_mode,
        )

        return ReconReport(
            target=target,
            generated_at=datetime.now(timezone.utc).isoformat(),
            signals=all_signals,
            modules_run=modules_run,
            errors=all_errors,
            risk_summary=risk_summary,
            dep_audit_mode=dep_audit_mode,
        )
