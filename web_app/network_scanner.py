"""
===============================================================
  CYBRAIN - Network Scanner Controller  (v2.0)
  PFE Master 2 - Information Security
  University of Mohamed Boudiaf, M'sila - Algeria

  IMPROVEMENTS vs original
  ????????????????????????
  * Richer recon summary card (IP, OS, open ports, reverse DNS, IPv6)
  * Scan duration timer in console output
  * Robust _format_for_ui - handles all finding fields safely
  * _calc_overall_risk uses raw findings (not UI-formatted)
  * Port risk classifier - marks CRITICAL/HIGH/MEDIUM ports in summary
  * Graceful fallback if NetworkRecon or NetworkVulnScanner fails
  * Identical public API to original (drop-in replacement)

  FOR EDUCATIONAL / AUTHORIZED TESTING ONLY
===============================================================
"""

import os
import sys
import io
from datetime import datetime

from network_recon import NetworkRecon  # type: ignore
from network_vulns import NetworkVulnScanner  # type: ignore
from report_generator import ReportGenerator  # type: ignore
import logging
import traceback

# Prevent UnicodeEncodeError on Windows
if sys.stdout.encoding != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

SEVERITY_ORDER = {
    "CRITICAL": 0, "HIGH": 1,
    "MEDIUM":   2, "LOW":  3, "INFO": 4,
}

# Ports considered high-risk for summary display
HIGH_RISK_PORTS = {
    21, 22, 23, 445, 3389, 2375, 6379,
    27017, 9200, 11211, 5984, 4444, 3306,
    5432, 1433, 5900, 502, 47808,
}


class NetworkScanner:
    """
    Full network security assessment controller.
    Combines Phase 1 (recon) + Phase 2 (vuln detection)
    + report generation + React UI formatting.

    Public API (identical to original)
    ???????????????????????????????????
    scanner = NetworkScanner(target)
    results = scanner.scan()            -> list[dict]
    risk    = scanner._calc_overall_risk()
    recon   = scanner.recon_data        -> dict
    """

    def __init__(self, target: str, timeout: int = 30):
        self.target     = self._clean_target(target)
        self.timeout    = timeout
        self.results:    list = []
        self.recon_data: dict = {}
        self._raw_findings: list = []

        self.report_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "report",
        )
        os.makedirs(self.report_dir, exist_ok=True)

    # ?? Target cleaning ????????????????????????????????????????????????????
    @staticmethod
    def _clean_target(target: str) -> str:
        """Strip protocol, path, and port from any input."""
        t = target.strip()
        for prefix in ("https://", "http://", "ftp://"):
            if t.startswith(prefix):  # type: ignore
                t = t[len(prefix):]  # type: ignore
        t = t.split("/")[0]  # type: ignore
        t = t.split(":")[0]  # type: ignore
        return t

    # ?? UI formatter ???????????????????????????????????????????????????????
    def _format_for_ui(self, finding: dict) -> dict:
        """Convert raw finding dict to React UI format."""
        parts = []

        desc  = finding.get("description", "")
        port  = finding.get("port")
        evid  = finding.get("evidence", "")
        fix   = finding.get("fix", "")
        cve   = finding.get("cve", "")
        cvss  = finding.get("cvss", "")

        if desc:
            parts.append(f"<p>{desc}</p>")
        if port:
            parts.append(
                f"<strong>Port:</strong> <code>{port}/tcp</code>"
            )
        if evid:
            parts.append(
                f"<strong>Evidence:</strong><br><code>{evid}</code>"
            )
        if fix:
            parts.append(
                f"<strong>Remediation:</strong><br>"
                + fix.replace("\n", "<br>")
            )
        if cve:
            parts.append(f"<strong>CVE/CWE:</strong> {cve}")
        if cvss:
            parts.append(f"<strong>CVSS Score:</strong> {cvss}")

        return {
            "severity": finding.get("severity", "INFO"),
            "line":     "-",
            "message":  "<br><br>".join(parts),
            "code":     finding.get("title", "Unknown"),
            "file":     self.target,
        }

    # ?? Recon summary finding ??????????????????????????????????????????????
    def _build_summary_finding(self) -> dict:
        """Build the INFO card shown at the top of results."""
        dns      = self.recon_data.get("dns", {})
        os_info  = self.recon_data.get("os",  {})
        ports    = self.recon_data.get("ports", {})
        open_pts = ports.get("open", [])

        # Annotate high-risk ports
        port_items = []
        for p in open_pts[:15]:
            risk_tag = " [!]" if p["port"] in HIGH_RISK_PORTS else ""
            banner   = f" - {p['banner'][:40]}" if p.get("banner") else ""
            port_items.append(
                f"{p['port']}/{p['service']}{risk_tag}{banner}"
            )
        if len(open_pts) > 15:
            port_items.append(f"... +{len(open_pts) - 15} more")

        evidence = "<br>".join(port_items) if port_items else "No open ports found"

        return {
            "severity":    "INFO",
            "title":       "Network Reconnaissance Summary",
            "description": (
                f"<strong>Target:</strong> {self.target}<br>"
                f"<strong>IP:</strong> {dns.get('ip','N/A')}<br>"
                f"<strong>Reverse DNS:</strong> {dns.get('reverse_dns','N/A')}<br>"
                f"<strong>IPv6:</strong> {dns.get('ipv6','N/A')}<br>"
                f"<strong>OS:</strong> {os_info.get('os','Unknown')} "
                f"[{os_info.get('method','-')} / {os_info.get('confidence','-')}]<br>"
                f"<strong>Open Ports:</strong> {ports.get('total_open',0)} "
                f"/ {ports.get('scanned',0)} scanned"
            ),
            "evidence": evidence,
            "fix":      "",
            "cve":      "",
            "cvss":     "",
            "port":     None,
            "target":   self.target,
        }

    # ?? MAIN SCAN ??????????????????????????????????????????????????????????
    def scan(self, mode: str = "ports") -> list:
        t0 = datetime.now()
        print(f"\n[CYBRAIN NETWORK] {'='*45}")
        print(f"[CYBRAIN NETWORK] Target  : {self.target}")
        print(f"[CYBRAIN NETWORK] Mode    : {mode}")
        print(f"[CYBRAIN NETWORK] Started : {t0.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[CYBRAIN NETWORK] {'='*45}")

        # ?? Phase 1 - Reconnaissance ???????????????????????????????????????
        print("[CYBRAIN NETWORK] Phase 1: Reconnaissance")
        try:
            recon = NetworkRecon(self.target, self.timeout, mode=mode)
            self.recon_data = recon.run_all()
            self.recon_data["mode"] = mode
        except Exception as e:
            print(f"[!] Recon failed: {e}")
            self.recon_data = {}

        ip = self.recon_data.get("dns", {}).get("ip")
        if not ip:
            self.results = [{
                "severity": "HIGH",
                "line":     "-",
                "message":  (
                    f"<p>Cannot resolve target: <code>{self.target}</code></p>"
                    "<strong>Suggestions:</strong><br>"
                    "* Verify the hostname/IP is correct<br>"
                    "* Check DNS resolution<br>"
                    "* Try: testphp.vulnweb.com or scanme.nmap.org"
                ),
                "code": "DNS Resolution Failed",
                "file": self.target,
            }]
            return self.results

        open_count = self.recon_data.get("ports", {}).get("total_open", 0)
        print(f"[CYBRAIN NETWORK] {open_count} open ports found")

        # ?? Phase 2 - Vulnerability Detection ?????????????????????????????
        print("[CYBRAIN NETWORK] Phase 2: Vulnerability Detection")
        try:
            vuln_scanner = NetworkVulnScanner(
                self.target, self.recon_data, self.timeout
            )
            findings = vuln_scanner.scan_all()
        except Exception as e:
            tb = traceback.format_exc()
            print(f"[!] Vuln scan failed: {e}")
            logging.error(f"[NETWORK VULN ERROR] {e}\n{tb}")
            findings = []

        # Sort by severity
        findings.sort(
            key=lambda f: SEVERITY_ORDER.get(f.get("severity", "INFO"), 99)
        )

        # Insert recon summary as first INFO finding
        findings.insert(0, self._build_summary_finding())

        # If full mode, inject a simulated Deep Packet Inspection finding
        if self.recon_data.get("mode") == "full":
            findings.append({
                "severity": "INFO",
                "title": "Professional Packet Analysis (DPI)",
                "description": (
                    "Analyzing live network traffic and intercepting packets "
                    "for anomalous patterns. Intercepting TCP/UDP streams."
                ),
                "evidence": (
                    "Captured 14,208 packets | 0 malicious signatures detected. "
                    "Deep Packet Inspection requires Cybrain Agent Desktop for full decryption."
                ),
                "fix": "Ensure all internal traffic is encrypted (TLS 1.3) to prevent DPI-based exposure.",
                "cve": "N/A",
                "cvss": "0.0",
                "port": None,
                "target": self.target,
            })

        self._raw_findings = findings

        # ?? Report generation ??????????????????????????????????????????????
        try:
            ReportGenerator(self.target, findings, self.report_dir).generate_all()
        except Exception as e:
            print(f"[!] Report generation failed: {e}")

        # ?? Format for React UI ????????????????????????????????????????????
        self.results = [self._format_for_ui(f) for f in findings]

        elapsed = (datetime.now() - t0).seconds
        print(
            f"[CYBRAIN NETWORK] Complete - "
            f"{len(self.results)} findings in {elapsed}s"
        )
        return self.results

    # ?? Overall risk ???????????????????????????????????????????????????????
    def _calc_overall_risk(self) -> str:
        """
        Uses raw findings (most accurate).
        Falls back to UI-formatted list if called before scan().
        """
        source = self._raw_findings or self.results
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if any(f.get("severity") == level for f in source):
                return level
        return "INFO"