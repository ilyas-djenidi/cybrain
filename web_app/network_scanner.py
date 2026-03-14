"""
CYBRAIN — Network Vulnerability Scanner
PFE Master 2 — Information Security
Main controller combining recon + vuln detection
"""

import socket
import os
import csv
import re
import time
from datetime import datetime
from network_recon import NetworkRecon
from network_vulns import NetworkVulnScanner
from report_generator import ReportGenerator

SEVERITY_ORDER = {
    "CRITICAL": 0, "HIGH": 1,
    "MEDIUM": 2, "LOW": 3, "INFO": 4
}


class NetworkScanner:
    """
    Full network security assessment controller.
    Combines reconnaissance + vulnerability detection
    + professional report generation.
    """

    def __init__(self, target, timeout=15):
        # Clean target — remove http:// etc
        self.target = self._clean_target(target)
        self.timeout = timeout
        self.results = []
        self.recon_data = {}
        self.report_dir = os.path.join(
            os.path.dirname(
                os.path.dirname(os.path.abspath(__file__))
            ),
            "report"
        )
        os.makedirs(self.report_dir, exist_ok=True)

    def _clean_target(self, target):
        """Extract hostname/IP from URL."""
        target = target.strip()
        # Remove protocol
        for prefix in ["https://", "http://", "ftp://"]:
            if target.startswith(prefix):
                target = target[len(prefix):]
        # Remove path
        target = target.split("/")[0]
        # Remove port
        target = target.split(":")[0]
        return target

    def _format_for_ui(self, finding):
        """Format finding for React UI display."""
        desc  = finding.get("description", "")
        fix   = finding.get("fix", "")
        evid  = finding.get("evidence", "")
        cve   = finding.get("cve", "")
        port  = finding.get("port")
        cvss  = finding.get("cvss", "")

        parts = [desc]
        if port:
            parts.append(
                f"<strong>Port:</strong> "
                f"<code>{port}/tcp</code>"
            )
        if evid:
            parts.append(
                f"<strong>Evidence:</strong>"
                f"<br><code>{evid}</code>"
            )
        if fix:
            parts.append(
                f"<strong>Remediation:</strong>"
                f"<br>{fix}"
            )
        if cve:
            parts.append(
                f"<strong>CVE/CWE:</strong> {cve}"
            )
        if cvss:
            parts.append(
                f"<strong>CVSS Score:</strong> {cvss}"
            )

        return {
            "severity": finding.get("severity", "INFO"),
            "line":     "-",
            "message":  "\n\n".join(parts),
            "code":     finding.get("title", ""),
            "file":     self.target,
        }

    def scan(self):
        """Run complete network security assessment."""
        print(
            f"\n[CYBRAIN NETWORK] Target: {self.target}"
        )
        print("[CYBRAIN NETWORK] Phase 1: Reconnaissance")

        # Phase 1: Recon
        recon = NetworkRecon(self.target, self.timeout)
        self.recon_data = recon.run_all()

        # Check if target is reachable
        ip = self.recon_data.get("dns", {}).get("ip")
        if not ip:
            self.results = [{
                "severity": "HIGH",
                "line":     "-",
                "message":  (
                    f"Cannot resolve target: "
                    f"<code>{self.target}</code><br><br>"
                    "<strong>Remediation:</strong><br>"
                    "• Verify the hostname/IP is correct<br>"
                    "• Check DNS resolution<br>"
                    "• Try scanning: "
                    "testphp.vulnweb.com or scanme.nmap.org"
                ),
                "code": "DNS Resolution Failed",
                "file": self.target,
            }]
            return self.results

        open_count = self.recon_data.get(
            "ports", {}
        ).get("total_open", 0)
        print(
            f"[CYBRAIN NETWORK] Found {open_count} "
            "open ports"
        )

        # Phase 2: Vulnerability Detection
        print(
            "[CYBRAIN NETWORK] "
            "Phase 2: Vulnerability Detection"
        )
        vuln_scanner = NetworkVulnScanner(
            self.target, self.recon_data, self.timeout
        )
        findings = vuln_scanner.scan_all()

        # Sort by severity
        findings.sort(
            key=lambda f: SEVERITY_ORDER.get(
                f.get("severity", "INFO"), 99
            )
        )

        # Add recon summary as INFO finding
        os_info = self.recon_data.get("os", {})
        dns_info = self.recon_data.get("dns", {})
        open_ports = self.recon_data.get(
            "ports", {}
        ).get("open", [])

        ports_str = ", ".join([
            f"{p['port']}/{p['service']}"
            for p in open_ports[:10]
        ])
        if len(open_ports) > 10:
            ports_str += f" (+{len(open_ports)-10} more)"

        findings.insert(0, {
            "severity":    "INFO",
            "title":       "Network Reconnaissance Summary",
            "description": (
                f"Target: {self.target} | "
                f"IP: {dns_info.get('ip','N/A')} | "
                f"OS: {os_info.get('os','Unknown')} | "
                f"Open Ports: {open_count}"
            ),
            "evidence": f"Open ports: {ports_str}",
            "fix": "",
            "cve": "",
            "cvss": "",
            "port": None,
            "target": self.target,
        })

        # Generate reports
        generator = ReportGenerator(
            self.target, findings, self.report_dir
        )
        generator.generate_all()

        # Format for UI
        self.results = [
            self._format_for_ui(f) for f in findings
        ]

        print(
            f"[CYBRAIN NETWORK] Complete: "
            f"{len(self.results)} findings"
        )
        return self.results

    def _calc_overall_risk(self):
        sevs = [r["severity"] for r in self.results]
        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if s in sevs:
                return s
        return "INFO"
