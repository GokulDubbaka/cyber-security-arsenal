"""
Cyber Security Arsenal — Comprehensive Test Suite
=================================================
Tests cover:
  1. SubdomainEnumerator — DNS resolution logic
  2. PortScanner — TCP probe and timeout
  3. WebFingerprinter — header analysis & missing security headers
  4. SecretHunter — entropy calculation and threshold
  5. DependencyAuditor — OSV.dev response parsing
  6. VulnerabilityCorrelator — risk scoring & ranking
  7. ReconOrchestrator — integration: report structure, module selection, empty target
  8. ReconReport — serialization
  9. ReconSignal — to_dict output
"""

from __future__ import annotations

import sys
import os
import math
import socket
import unittest
from unittest.mock import patch, MagicMock, call
from typing import Any, Dict, List

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from core.orchestrator import (
    ReconSignal,
    ReconReport,
    SubdomainEnumerator,
    PortScanner,
    WebFingerprinter,
    SecretHunter,
    DependencyAuditor,
    VulnerabilityCorrelator,
    ReconOrchestrator,
)


# ─── 1. ReconSignal ───────────────────────────────────────────────────────────

class TestReconSignal(unittest.TestCase):

    def test_to_dict_has_all_fields(self):
        s = ReconSignal(
            module="test_mod",
            signal_type="open_port",
            value="443",
            confidence=0.99,
            metadata={"port": 443},
        )
        d = s.to_dict()
        self.assertEqual(d["module"], "test_mod")
        self.assertEqual(d["signal_type"], "open_port")
        self.assertEqual(d["value"], "443")
        self.assertAlmostEqual(d["confidence"], 0.99)
        self.assertEqual(d["metadata"]["port"], 443)

    def test_default_metadata_is_empty_dict(self):
        s = ReconSignal(module="m", signal_type="t", value="v", confidence=0.5)
        self.assertEqual(s.metadata, {})


# ─── 2. VulnerabilityCorrelator ───────────────────────────────────────────────

class TestVulnerabilityCorrelator(unittest.TestCase):

    def setUp(self):
        self.correlator = VulnerabilityCorrelator()

    def test_empty_signals_returns_informational(self):
        result = self.correlator.correlate([])
        self.assertEqual(result["risk_level"], "informational")
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["top_findings"], [])

    def test_single_cve_raises_risk(self):
        signals = [ReconSignal("dep", "cve", "CVE-2021-44228", 0.99, {})]
        result = self.correlator.correlate(signals)
        self.assertGreater(result["risk_score"], 0)
        self.assertIn(result["risk_level"], ("informational", "low", "medium", "high", "critical"))

    def test_multiple_cves_reach_high_risk(self):
        signals = [
            ReconSignal("dep", "cve", f"CVE-2021-{i:04d}", 0.99, {})
            for i in range(10)
        ]
        result = self.correlator.correlate(signals)
        self.assertIn(result["risk_level"], ("high", "critical"))

    def test_secret_candidates_weighted_higher_than_subdomains(self):
        secret_sigs = [ReconSignal("s", "secret_candidate", "abc", 0.9, {})]
        subdomain_sigs = [ReconSignal("s", "subdomain", "x.y", 0.9, {})]
        r_secret = self.correlator.correlate(secret_sigs)
        r_sub = self.correlator.correlate(subdomain_sigs)
        self.assertGreater(r_secret["risk_score"], r_sub["risk_score"])

    def test_risk_score_capped_at_100(self):
        signals = [
            ReconSignal("dep", "cve", f"CVE-{i}", 0.99, {})
            for i in range(100)
        ]
        result = self.correlator.correlate(signals)
        self.assertLessEqual(result["risk_score"], 100.0)

    def test_top_findings_limited_to_10(self):
        signals = [
            ReconSignal("m", "open_port", str(p), 0.9, {})
            for p in range(50)
        ]
        result = self.correlator.correlate(signals)
        self.assertLessEqual(len(result["top_findings"]), 10)

    def test_signal_breakdown_counts_by_type(self):
        signals = [
            ReconSignal("m", "open_port", "80", 0.9, {}),
            ReconSignal("m", "open_port", "443", 0.9, {}),
            ReconSignal("m", "subdomain", "api.x.com", 0.8, {}),
        ]
        result = self.correlator.correlate(signals)
        self.assertEqual(result["signal_breakdown"]["open_port"], 2)
        self.assertEqual(result["signal_breakdown"]["subdomain"], 1)


# ─── 3. SubdomainEnumerator ───────────────────────────────────────────────────

class TestSubdomainEnumerator(unittest.TestCase):

    def setUp(self):
        self.enumerator = SubdomainEnumerator()

    @patch("core.orchestrator.socket.getaddrinfo")
    def test_resolves_live_subdomain(self, mock_dns):
        mock_dns.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0))]
        signals, errors = self.enumerator.run("example.com")
        self.assertTrue(any(s.signal_type == "subdomain" for s in signals))
        self.assertEqual(len(errors), 0)

    @patch("core.orchestrator.socket.getaddrinfo", side_effect=socket.gaierror("NXDOMAIN"))
    def test_nxdomain_produces_no_signal(self, _mock):
        signals, errors = self.enumerator.run("nonexistent-zzz-xyz.example.invalid")
        subdomain_signals = [s for s in signals if s.signal_type == "subdomain"]
        self.assertEqual(len(subdomain_signals), 0)

    @patch("core.orchestrator.socket.getaddrinfo")
    def test_resolved_ip_in_metadata(self, mock_dns):
        mock_dns.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("1.2.3.4", 0))]
        signals, _ = self.enumerator.run("example.com")
        ip_found = any(s.metadata.get("resolved_ip") == "1.2.3.4" for s in signals)
        self.assertTrue(ip_found)


# ─── 4. PortScanner ───────────────────────────────────────────────────────────

class TestPortScanner(unittest.TestCase):

    def setUp(self):
        self.scanner = PortScanner()

    @patch("core.orchestrator.socket.create_connection")
    def test_open_port_produces_signal(self, mock_conn):
        mock_conn.return_value.__enter__ = MagicMock(return_value=MagicMock())
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)
        signals, errors = self.scanner.run("example.com")
        # At least one open_port signal should be present
        open_signals = [s for s in signals if s.signal_type == "open_port"]
        self.assertGreater(len(open_signals), 0)

    @patch("core.orchestrator.socket.create_connection", side_effect=ConnectionRefusedError)
    def test_closed_port_produces_no_signal(self, _mock):
        signals, errors = self.scanner.run("example.com")
        self.assertEqual(len(signals), 0)

    def test_empty_target_strips_scheme(self):
        """Target URL with https:// prefix should not crash the scanner."""
        with patch("core.orchestrator.socket.create_connection", side_effect=ConnectionRefusedError):
            signals, errors = self.scanner.run("https://example.com")
            self.assertEqual(len(errors), 0)


# ─── 5. SecretHunter ─────────────────────────────────────────────────────────

class TestSecretHunter(unittest.TestCase):

    def setUp(self):
        self.hunter = SecretHunter()

    def test_entropy_calc_high_for_random_string(self):
        random_token = "xK9mRtL3pQ7nYsB2vW8hDjF6cA4eZ0oI"
        h = self.hunter._entropy(random_token)
        self.assertGreater(h, 4.2)

    def test_entropy_calc_low_for_uniform_string(self):
        uniform = "aaaaaaaaaaaaaaaaaaaaaaaaa"
        h = self.hunter._entropy(uniform)
        self.assertAlmostEqual(h, 0.0, places=2)

    def test_entropy_zero_for_empty(self):
        self.assertEqual(self.hunter._entropy(""), 0.0)

    @patch("core.orchestrator.urllib.request.urlopen")
    def test_high_entropy_string_produces_signal(self, mock_open):
        secret = "xK9mRtL3pQ7nYsB2vW8hDjF6cA4eZ0oI5uN1"
        fake_response = MagicMock()
        fake_response.__enter__ = lambda s: s
        fake_response.__exit__ = MagicMock(return_value=False)
        fake_response.read.return_value = f"some text {secret} more text".encode()
        mock_open.return_value = fake_response

        signals, errors = self.hunter.run("example.com")
        secret_signals = [s for s in signals if s.signal_type == "secret_candidate"]
        self.assertGreater(len(secret_signals), 0)
        self.assertEqual(len(errors), 0)

    @patch("core.orchestrator.urllib.request.urlopen")
    def test_low_entropy_string_not_flagged(self, mock_open):
        fake_response = MagicMock()
        fake_response.__enter__ = lambda s: s
        fake_response.__exit__ = MagicMock(return_value=False)
        fake_response.read.return_value = b"aaaabbbbccccddddeeeeffffgggg"
        mock_open.return_value = fake_response

        signals, _ = self.hunter.run("example.com")
        secret_signals = [s for s in signals if s.signal_type == "secret_candidate"]
        self.assertEqual(len(secret_signals), 0)


# ─── 6. WebFingerprinter ─────────────────────────────────────────────────────

class TestWebFingerprinter(unittest.TestCase):

    def setUp(self):
        self.fingerprinter = WebFingerprinter()

    def _make_response(self, headers: Dict[str, str]) -> MagicMock:
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.headers = headers
        return mock_resp

    @patch("core.orchestrator.urllib.request.urlopen")
    def test_detects_server_banner(self, mock_open):
        mock_open.return_value = self._make_response({
            "Server": "nginx/1.25.0",
            "Content-Type": "text/html",
        })
        signals, _ = self.fingerprinter.run("example.com")
        banner_signals = [s for s in signals if s.signal_type == "server_banner"]
        self.assertTrue(any("nginx" in s.value for s in banner_signals))

    @patch("core.orchestrator.urllib.request.urlopen")
    def test_detects_missing_security_headers(self, mock_open):
        mock_open.return_value = self._make_response({
            "Server": "Apache",
            "Content-Type": "text/html",
            # No security headers!
        })
        signals, _ = self.fingerprinter.run("example.com")
        missing_sigs = [s for s in signals if s.signal_type == "missing_security_headers"]
        self.assertGreater(len(missing_sigs), 0)
        # Should mention CSP
        all_values = " ".join(s.value for s in missing_sigs)
        self.assertIn("content-security-policy", all_values)


# ─── 7. DependencyAuditor ────────────────────────────────────────────────────

class TestDependencyAuditor(unittest.TestCase):

    def setUp(self):
        self.auditor = DependencyAuditor()

    @patch("core.orchestrator.urllib.request.urlopen")
    def test_known_cve_produces_signal(self, mock_open):
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = b'{"vulns": [{"id": "GHSA-jfh8-c2jp-hdp8", "database_specific": {"severity": "HIGH"}}]}'
        mock_open.return_value = mock_resp

        signals, errors = self.auditor.run(
            "example.com",
            packages=[{"package": {"name": "lodash", "ecosystem": "npm"}, "version": "4.17.20"}],
        )
        cve_signals = [s for s in signals if s.signal_type == "cve"]
        self.assertGreater(len(cve_signals), 0)
        self.assertEqual(cve_signals[0].value, "GHSA-jfh8-c2jp-hdp8")

    @patch("core.orchestrator.urllib.request.urlopen")
    def test_no_vulns_returns_empty_signals(self, mock_open):
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = b'{"vulns": []}'
        mock_open.return_value = mock_resp

        signals, errors = self.auditor.run(
            "clean.com",
            packages=[{"package": {"name": "safe-pkg", "ecosystem": "PyPI"}, "version": "9.9.9"}],
        )
        self.assertEqual(len(signals), 0)
        self.assertEqual(len(errors), 0)

    @patch("core.orchestrator.urllib.request.urlopen", side_effect=Exception("connection refused"))
    def test_api_error_captured_in_errors(self, _mock):
        _, errors = self.auditor.run("example.com")
        self.assertGreater(len(errors), 0)
        self.assertTrue(any("connection refused" in e for e in errors))


# ─── 8. ReconOrchestrator Integration ────────────────────────────────────────

class TestReconOrchestrator(unittest.TestCase):

    def setUp(self):
        # Use minimal timeouts and mock all network calls for integration tests
        self.orchestrator = ReconOrchestrator(
            modules=["subdomain_enum", "port_scan"],
            port_timeout=0.1,
            http_timeout=0.1,
        )

    def test_empty_target_raises(self):
        with self.assertRaises(ValueError):
            self.orchestrator.run("")

    @patch("core.orchestrator.socket.getaddrinfo", side_effect=socket.gaierror)
    @patch("core.orchestrator.socket.create_connection", side_effect=ConnectionRefusedError)
    def test_report_has_required_fields(self, _mock_conn, _mock_dns):
        report = self.orchestrator.run("test.invalid")
        self.assertIsNotNone(report.target)
        self.assertIsNotNone(report.generated_at)
        self.assertIsInstance(report.signals, list)
        self.assertIsInstance(report.modules_run, list)
        self.assertIsInstance(report.errors, list)
        self.assertIsInstance(report.risk_summary, dict)

    @patch("core.orchestrator.socket.getaddrinfo", side_effect=socket.gaierror)
    @patch("core.orchestrator.socket.create_connection", side_effect=ConnectionRefusedError)
    def test_modules_run_matches_selection(self, _mock_conn, _mock_dns):
        report = self.orchestrator.run("test.invalid")
        self.assertIn("subdomain_enum", report.modules_run)
        self.assertIn("port_scan", report.modules_run)

    @patch("core.orchestrator.socket.getaddrinfo", side_effect=socket.gaierror)
    @patch("core.orchestrator.socket.create_connection", side_effect=ConnectionRefusedError)
    def test_risk_summary_has_required_keys(self, _mock_conn, _mock_dns):
        report = self.orchestrator.run("test.invalid")
        required = {"risk_score", "risk_level", "top_findings", "signal_breakdown"}
        self.assertTrue(required.issubset(report.risk_summary.keys()))

    @patch("core.orchestrator.socket.getaddrinfo", side_effect=socket.gaierror)
    @patch("core.orchestrator.socket.create_connection", side_effect=ConnectionRefusedError)
    def test_to_dict_is_json_serializable(self, _mock_conn, _mock_dns):
        import json
        report = self.orchestrator.run("test.invalid")
        d = report.to_dict()
        serialized = json.dumps(d)
        self.assertIsInstance(serialized, str)

    def test_single_module_selection(self):
        orch = ReconOrchestrator(modules=["port_scan"], port_timeout=0.1)
        with patch("core.orchestrator.socket.create_connection", side_effect=ConnectionRefusedError):
            report = orch.run("test.invalid")
        self.assertEqual(report.modules_run, ["port_scan"])
        self.assertNotIn("subdomain_enum", report.modules_run)

    @patch("core.orchestrator.socket.getaddrinfo")
    def test_resolved_subdomain_appears_in_signals(self, mock_dns):
        mock_dns.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("1.2.3.4", 0))]
        orch = ReconOrchestrator(modules=["subdomain_enum"])
        report = orch.run("example.com")
        self.assertTrue(any(s.signal_type == "subdomain" for s in report.signals))

    def test_total_signals_count_in_dict(self):
        with patch("core.orchestrator.socket.getaddrinfo", side_effect=socket.gaierror), \
             patch("core.orchestrator.socket.create_connection", side_effect=ConnectionRefusedError):
            report = self.orchestrator.run("test.invalid")
        d = report.to_dict()
        self.assertEqual(d["total_signals"], len(report.signals))


if __name__ == "__main__":
    unittest.main(verbosity=2)
