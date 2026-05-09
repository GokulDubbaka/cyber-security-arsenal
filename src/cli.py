"""
Cyber Security Arsenal — Reconnaissance Orchestrator CLI
=========================================================
Usage:
    python src/cli.py scan --target example.com
    python src/cli.py scan --target example.com --modules subdomain_enum,port_scan
    python src/cli.py scan --target example.com --output report.json
    python src/cli.py scan --target example.com --no-network  (offline modules only)
    python src/cli.py modules  (list available modules)
"""

import argparse
import json
import logging
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from core.orchestrator import ReconOrchestrator

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)
logger = logging.getLogger("CyberCLI")


AVAILABLE_MODULES = [
    "subdomain_enum",
    "port_scan",
    "web_fingerprint",
    "secret_hunter",
    "dependency_audit",
]


def cmd_scan(args: argparse.Namespace) -> int:
    modules = AVAILABLE_MODULES
    if args.modules:
        requested = [m.strip() for m in args.modules.split(",")]
        unknown = set(requested) - set(AVAILABLE_MODULES)
        if unknown:
            print(f"[ERROR] Unknown modules: {', '.join(sorted(unknown))}", file=sys.stderr)
            print(f"[INFO]  Available: {', '.join(AVAILABLE_MODULES)}", file=sys.stderr)
            return 1
        modules = requested

    if args.no_network:
        # Only DNS-based modules work without live HTTP
        modules = [m for m in modules if m == "subdomain_enum"]
        if not modules:
            modules = []
            print("[WARN] --no-network: no offline-capable modules selected. Exiting.", file=sys.stderr)
            return 1

    print(f"\n{'='*60}")
    print(f"  CYBER SECURITY ARSENAL — Recon Engine")
    print(f"{'='*60}")
    print(f"  Target  : {args.target}")
    print(f"  Modules : {', '.join(modules)}")
    print(f"{'='*60}\n")

    orchestrator = ReconOrchestrator(
        modules=modules,
        port_timeout=args.port_timeout,
        http_timeout=args.http_timeout,
    )

    try:
        report = orchestrator.run(args.target)
    except ValueError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    report_dict = report.to_dict()

    # Pretty print summary
    summary = report.risk_summary
    print(f"  Risk Score  : {summary['risk_score']:.1f} / 100")
    print(f"  Risk Level  : {summary['risk_level'].upper()}")
    print(f"  Total Signals: {report_dict['total_signals']}")
    print(f"  Errors      : {len(report.errors)}")
    print()

    # Signal breakdown
    if summary["signal_breakdown"]:
        print("  Signal Breakdown:")
        for sig_type, count in sorted(summary["signal_breakdown"].items()):
            print(f"    {sig_type:<35} {count:>4}")
        print()

    # Top findings
    if summary["top_findings"]:
        print(f"  Top Findings ({min(5, len(summary['top_findings']))} shown):")
        for f in summary["top_findings"][:5]:
            conf = f"{f['confidence'] * 100:.0f}%"
            print(f"    [{f['signal_type']:25}] [{conf:>4}] {f['value']}")
        print()

    # Errors
    if report.errors and args.verbose:
        print("  Errors:")
        for err in report.errors:
            print(f"    [ERR] {err}")
        print()

    print(f"{'='*60}")

    # Save JSON if requested
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(report_dict, fh, indent=2)
        print(f"\n  Report saved to: {args.output}")

    return 0


def cmd_modules(_args: argparse.Namespace) -> int:
    print("\n  Available Recon Modules:")
    descriptions = {
        "subdomain_enum":   "Live DNS resolution of common subdomains (passive-safe)",
        "port_scan":        "TCP probe of well-known ports (read-only, no SYN scan)",
        "web_fingerprint":  "HTTP banner & security header analysis",
        "secret_hunter":    "Shannon entropy secret detection on public endpoints",
        "dependency_audit": "Live CVE lookup via OSV.dev (no auth required)",
    }
    for mod in AVAILABLE_MODULES:
        print(f"    {mod:<25} {descriptions[mod]}")
    print()
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Cyber Security Arsenal — Passive Reconnaissance Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # scan subcommand
    scan_p = sub.add_parser("scan", help="Run reconnaissance against a target")
    scan_p.add_argument("--target", required=True, help="Domain or IP to recon (e.g. example.com)")
    scan_p.add_argument(
        "--modules",
        default=None,
        help=f"Comma-separated modules to run. Default: all. Options: {','.join(AVAILABLE_MODULES)}",
    )
    scan_p.add_argument("--output", default=None, help="Save full JSON report to this file")
    scan_p.add_argument("--no-network", action="store_true", help="Skip all live HTTP probes")
    scan_p.add_argument("--port-timeout", type=float, default=2.0, help="TCP connect timeout per port (default: 2.0s)")
    scan_p.add_argument("--http-timeout", type=float, default=5.0, help="HTTP request timeout (default: 5.0s)")
    scan_p.add_argument("--verbose", "-v", action="store_true", help="Show full error list")

    # modules subcommand
    sub.add_parser("modules", help="List available recon modules")

    args = parser.parse_args()

    dispatch = {"scan": cmd_scan, "modules": cmd_modules}
    sys.exit(dispatch[args.command](args))


if __name__ == "__main__":
    main()
