"""
===============================================================
  CYBRAIN - Professional Report Generator  (v2.0)
  PFE Master 2 - Information Security
  University of Mohamed Boudiaf, M'sila - Algeria

  OUTPUTS
  ???????
  * vulnerability_report.md  - full Markdown report
  * findings_summary.csv     - spreadsheet export
  * executive_summary.md     - 1-page exec brief

  IMPROVEMENTS vs original
  ????????????????????????
  * Executive summary file (separate 1-pager)
  * Network findings support (port, service, cve fields)
  * Scan type auto-detection (web / network / code / apache)
  * CVSS exact scores included when available
  * Remediation roadmap sorted and numbered
  * _strip_html handles HTML entities (&amp; &lt; etc.)
  * JSON export added (machine-readable)
  * Report header includes methodology + scope

  FOR EDUCATIONAL / AUTHORIZED TESTING ONLY
===============================================================
"""

import os
import csv
import re
import json
import html
import time
from datetime import datetime

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

CVSS_RANGE = {
    "CRITICAL": "9.0-10.0",
    "HIGH":     "7.0-8.9",
    "MEDIUM":   "4.0-6.9",
    "LOW":      "0.1-3.9",
    "INFO":     "0.0",
}

EMOJI = {
    "CRITICAL": "?",
    "HIGH":     "?",
    "MEDIUM":   "?",
    "LOW":      "?",
    "INFO":     "??",
}

RISK_COLOR = {
    "CRITICAL": "CRITICAL - Immediate action required",
    "HIGH":     "HIGH - Fix within 24-48 hours",
    "MEDIUM":   "MEDIUM - Fix within 2 weeks",
    "LOW":      "LOW - Fix when convenient",
    "INFO":     "INFO - Informational",
}


class ReportGenerator:
    """
    Generates professional security assessment reports
    from any Cybrain scan module (web, network, code, apache).
    """

    def __init__(self, target: str, findings: list,
                 report_dir: str = "report",
                 scan_type: str = "auto"):
        self.target     = target
        self.report_dir = report_dir
        self.scan_type  = self._detect_scan_type(findings, scan_type)
        self.timestamp  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Sort CRITICAL -> INFO
        self.findings = sorted(
            findings,
            key=lambda f: SEVERITY_ORDER.get(f.get("severity", "INFO"), 99),
        )
        os.makedirs(report_dir, exist_ok=True)

    # ?? Scan type detection ????????????????????????????????????????????????
    def _detect_scan_type(self, findings: list, hint: str) -> str:
        if hint != "auto":
            return hint
        if not findings:
            return "web"
        # Network findings have a 'port' key
        if any("port" in f and f["port"] for f in findings):
            return "network"
        # Code findings have a 'line' key with integers
        if any(isinstance(f.get("line"), int) for f in findings):
            return "code"
        # Apache findings have apache-specific codes
        if any(f.get("code") in ("CA8","DEPRECATED","SYNTAX","HARDENING") for f in findings):
            return "apache"
        return "web"

    # ?? HTML stripping + entity decoding ??????????????????????????????????
    def _strip_html(self, text: str) -> str:
        """Remove HTML tags and decode entities."""
        clean = re.sub(r"<[^>]+>", "", str(text or ""))
        return html.unescape(clean).strip()

    # ?? Severity counts ????????????????????????????????????????????????????
    def _counts(self) -> dict:
        c = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            sev = f.get("severity", "INFO")
            c[sev] = c.get(sev, 0) + 1
        return c

    def _overall_risk(self, counts: dict) -> str:
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if counts[sev] > 0:
                return sev
        return "INFO"

    # ?? OWASP label helper ?????????????????????????????????????????????????
    def _owasp_label(self, f: dict) -> str:
        oid  = f.get("owasp_id", "")
        name = f.get("owasp_name", "")
        if oid and name:
            return f"{oid} - {name}"
        return f.get("owasp", oid or name or "N/A")

    # ?? CVSS display ???????????????????????????????????????????????????????
    def _cvss_display(self, f: dict) -> str:
        exact = f.get("cvss", "")
        sev   = f.get("severity", "INFO")
        if exact:
            return f"{exact} ({CVSS_RANGE.get(sev, 'N/A')})"
        return CVSS_RANGE.get(sev, "N/A")

    # ?? Generate all outputs ???????????????????????????????????????????????
    def generate_all(self) -> tuple:
        md_path   = self.save_markdown()
        csv_path  = self.save_csv()
        exec_path = self.save_executive_summary()
        json_path = self.save_json()
        print(f"[REPORT] MD:   {md_path}")
        print(f"[REPORT] CSV:  {csv_path}")
        print(f"[REPORT] EXEC: {exec_path}")
        print(f"[REPORT] JSON: {json_path}")
        return md_path, csv_path

    # ======================================================================
    #  MARKDOWN REPORT
    # ======================================================================
    def save_markdown(self) -> str:
        counts = self._counts()
        risk   = self._overall_risk(counts)
        total  = len(self.findings)
        path   = os.path.join(self.report_dir, "vulnerability_report.md")

        scan_labels = {
            "web":     "Web Application Vulnerability Assessment",
            "network": "Network Security Assessment",
            "code":    "Static Application Security Testing (SAST)",
            "apache":  "Apache Configuration Security Audit",
        }
        report_title = scan_labels.get(self.scan_type, "Security Assessment")

        lines = [
            f"# {report_title} Report",
            "", "---", "",
            "## Target Information", "",
            "| Field | Value |",
            "|-------|-------|",
            f"| **Target** | `{self.target}` |",
            f"| **Scan Date** | {self.timestamp} |",
            f"| **Scan Type** | {self.scan_type.upper()} |",
            f"| **Overall Risk** | **{risk}** - {RISK_COLOR[risk]} |",
            f"| **Methodology** | OWASP Testing Guide v4.2 + CWE/SANS Top 25 |",
            f"| **Framework** | OWASP Top 10 2025 |",
            f"| **Purpose** | PFE Master 2 - Information Security Research |",
            "| **Institution** | University of Mohamed Boudiaf, M'sila, Algeria |",
            "", "---", "",
            "## Executive Summary", "",
            f"A total of **{total} finding(s)** were identified during this assessment.",
            f"The overall risk level is **{risk}**.",
            "",
            "| Severity | Count | Action |",
            "|----------|-------|--------|",
            f"| {EMOJI['CRITICAL']} CRITICAL | {counts['CRITICAL']} | Fix immediately |",
            f"| {EMOJI['HIGH']} HIGH | {counts['HIGH']} | Fix within 48 hours |",
            f"| {EMOJI['MEDIUM']} MEDIUM | {counts['MEDIUM']} | Fix within 2 weeks |",
            f"| {EMOJI['LOW']} LOW | {counts['LOW']} | Fix when convenient |",
            f"| {EMOJI['INFO']} INFO | {counts['INFO']} | Informational |",
            f"| **TOTAL** | **{total}** | |",
            "", "---", "",
        ]

        # ?? Vulnerability Summary Table ????????????????????????????????????
        if self.scan_type == "network":
            lines += [
                "## Vulnerability Summary", "",
                "| # | Vulnerability | Severity | CVSS | Port | CVE/CWE |",
                "|---|--------------|----------|------|------|---------|",
            ]
            for i, f in enumerate(self.findings, 1):
                sev  = f.get("severity", "INFO")
                port = f.get("port", "-") or "-"
                cve  = f.get("cve", f.get("cwe", ""))
                lines.append(
                    f"| {i} | {f.get('title','')} | **{sev}** | "
                    f"{self._cvss_display(f)} | {port} | {cve} |"
                )
        else:
            lines += [
                "## Vulnerability Summary", "",
                "| # | Vulnerability | Severity | CVSS | CWE | OWASP 2025 |",
                "|---|--------------|----------|------|-----|-----------|",
            ]
            for i, f in enumerate(self.findings, 1):
                sev = f.get("severity", "INFO")
                lines.append(
                    f"| {i} | {f.get('title','')} | **{sev}** | "
                    f"{self._cvss_display(f)} | {f.get('cwe','')} | "
                    f"{self._owasp_label(f)} |"
                )

        lines += ["", "---", "", "## Detailed Findings", ""]

        # ?? Detailed Findings ??????????????????????????????????????????????
        for i, f in enumerate(self.findings, 1):
            sev   = f.get("severity", "INFO")
            em    = EMOJI.get(sev, "")
            title = f.get("title", f.get("code", "Unknown"))
            desc  = self._strip_html(f.get("description", f.get("message", "")))
            fix   = self._strip_html(f.get("fix", ""))
            evid  = self._strip_html(f.get("evidence", ""))

            lines += [
                f"### {em} [{i}] {title}",
                "",
                "| Field | Details |",
                "|-------|---------|",
                f"| **Severity** | {sev} |",
                f"| **CVSS** | {self._cvss_display(f)} |",
                f"| **CWE** | {f.get('cwe', 'N/A')} |",
            ]

            # Network-specific fields
            if self.scan_type == "network":
                port    = f.get("port", "-") or "-"
                service = f.get("service", "-") or "-"
                cve     = f.get("cve", "-") or "-"
                lines += [
                    f"| **Port** | {port}/tcp |",
                    f"| **Service** | {service} |",
                    f"| **CVE** | {cve} |",
                ]
            else:
                lines += [
                    f"| **OWASP 2025** | {self._owasp_label(f)} |",
                    f"| **SANS Top 25** | {f.get('sans', 'N/A')} |",
                ]

            lines += [
                f"| **Target** | `{self.target}` |",
                "",
                "**Description:**", "", desc or "N/A", "",
            ]

            if evid:
                lines += ["**Evidence:**", "", f"```\n{evid}\n```", ""]

            if fix:
                lines += ["**Remediation:**", "", fix, ""]

            lines += ["---", ""]

        # ?? Remediation Roadmap ????????????????????????????????????????????
        lines += ["## Remediation Roadmap", ""]

        roadmap = [
            ("CRITICAL", "Priority 1 - Fix Immediately"),
            ("HIGH",     "Priority 2 - Fix This Week"),
            ("MEDIUM",   "Priority 3 - Fix This Month"),
            ("LOW",      "Priority 4 - Fix When Possible"),
        ]
        for sev, label in roadmap:
            items = [f for f in self.findings if f.get("severity") == sev]
            if items:
                lines.append(f"### {label} ({sev})")
                lines.append("")
                for j, f in enumerate(items, 1):
                    title = f.get("title", f.get("code", "Unknown"))
                    cwe   = f.get("cwe", "")
                    cwe_str = f" `{cwe}`" if cwe else ""
                    lines.append(f"- [ ] **{title}**{cwe_str}")
                lines.append("")

        # ?? Conclusion ?????????????????????????????????????????????????????
        lines += [
            "---", "",
            "## Conclusion", "",
            f"This {self.scan_type.upper()} assessment of "
            f"`{self.target}` identified **{total}** security issue(s) "
            f"with an overall risk of **{risk}**.",
            "",
            "Immediate remediation is required for all CRITICAL and HIGH findings "
            "before this system is considered production-ready.",
            "",
            "**Recommended next steps:**",
            "1. Fix all CRITICAL findings within 24 hours",
            "2. Fix all HIGH findings within one week",
            "3. Re-scan after remediation to verify fixes",
            "4. Schedule periodic security assessments",
            "",
            "---",
            "",
            "*Report generated by **Cybrain Intelligence Platform** "
            f"on {self.timestamp}.*",
            "*PFE Master 2 - Information Security - "
            "University of Mohamed Boudiaf, M'sila, Algeria.*",
            "",
        ]

        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        return path

    # ======================================================================
    #  CSV EXPORT
    # ======================================================================
    def save_csv(self) -> str:
        path = os.path.join(self.report_dir, "findings_summary.csv")

        # Network findings have different fields
        if self.scan_type == "network":
            fields = ["id", "title", "severity", "cvss", "port",
                      "service", "cve", "target", "evidence", "fix"]
        else:
            fields = ["id", "title", "severity", "cvss_range",
                      "cwe", "owasp", "url", "evidence", "fix"]

        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fields)
            writer.writeheader()
            for i, f in enumerate(self.findings, 1):
                sev = f.get("severity", "INFO")
                if self.scan_type == "network":
                    writer.writerow({
                        "id":       f"VULN-{i:03d}",
                        "title":    f.get("title", ""),
                        "severity": sev,
                        "cvss":     f.get("cvss", CVSS_RANGE.get(sev, "N/A")),
                        "port":     f.get("port", "-") or "-",
                        "service":  f.get("service", "-") or "-",
                        "cve":      f.get("cve", "-") or "-",
                        "target":   self.target,
                        "evidence": self._strip_html(f.get("evidence", "")),
                        "fix":      self._strip_html(f.get("fix", "")),
                    })
                else:
                    writer.writerow({
                        "id":         f"VULN-{i:03d}",
                        "title":      f.get("title", f.get("code", "")),
                        "severity":   sev,
                        "cvss_range": self._cvss_display(f),
                        "cwe":        f.get("cwe", ""),
                        "owasp":      self._owasp_label(f),
                        "url":        self.target,
                        "evidence":   self._strip_html(f.get("evidence", "")),
                        "fix":        self._strip_html(f.get("fix", "")),
                    })
        return path

    # ======================================================================
    #  EXECUTIVE SUMMARY (1-page brief)
    # ======================================================================
    def save_executive_summary(self) -> str:
        counts = self._counts()
        risk   = self._overall_risk(counts)
        total  = len(self.findings)
        path   = os.path.join(self.report_dir, "executive_summary.md")

        critical_items = [
            f for f in self.findings if f.get("severity") == "CRITICAL"
        ]
        high_items = [
            f for f in self.findings if f.get("severity") == "HIGH"
        ]

        lines = [
            "# Executive Summary - Security Assessment",
            "",
            f"**Target:** `{self.target}`  ",
            f"**Date:** {self.timestamp}  ",
            f"**Overall Risk:** **{risk}**",
            "",
            "---",
            "",
            "## Key Metrics",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Total Findings | **{total}** |",
            f"| Critical | **{counts['CRITICAL']}** |",
            f"| High | **{counts['HIGH']}** |",
            f"| Medium | {counts['MEDIUM']} |",
            f"| Low | {counts['LOW']} |",
            "",
            "---",
            "",
        ]

        if critical_items:
            lines += ["## Critical Issues - Fix Immediately", ""]
            for f in critical_items[:5]:
                t    = f.get("title", f.get("code", "Unknown"))
                desc = self._strip_html(
                    f.get("description", f.get("message", ""))
                )[:120]
                lines.append(f"- ? **{t}** - {desc}...")
            lines.append("")

        if high_items:
            lines += ["## High Priority Issues", ""]
            for f in high_items[:5]:
                t = f.get("title", f.get("code", "Unknown"))
                lines.append(f"- ? **{t}**")
            lines.append("")

        lines += [
            "---",
            "",
            "## Recommended Immediate Actions",
            "",
            "1. **Patch CRITICAL vulnerabilities** before next deployment",
            "2. **Review HIGH findings** with development team within 48 hours",
            "3. **Re-scan** after fixes to verify remediation",
            "4. **Document** all changes in change management system",
            "",
            "---",
            "",
            f"*Generated by Cybrain - {self.timestamp}*",
            "*PFE Master 2 - University of Mohamed Boudiaf, M'sila*",
        ]

        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        return path

    # ======================================================================
    #  JSON EXPORT (machine-readable)
    # ======================================================================
    def save_json(self) -> str:
        counts = self._counts()
        risk   = self._overall_risk(counts)
        path   = os.path.join(self.report_dir, "findings.json")

        export = {
            "meta": {
                "target":    self.target,
                "scan_type": self.scan_type,
                "timestamp": self.timestamp,
                "risk":      risk,
                "counts":    counts,
                "total":     len(self.findings),
                "generator": "Cybrain v2.0",
            },
            "findings": [
                {
                    "id":          f"VULN-{i:03d}",
                    "title":       f.get("title", f.get("code", "")),
                    "severity":    f.get("severity", "INFO"),
                    "cvss":        f.get("cvss", ""),
                    "cwe":         f.get("cwe", ""),
                    "owasp_id":    f.get("owasp_id", ""),
                    "owasp_name":  f.get("owasp_name", ""),
                    "port":        f.get("port"),
                    "service":     f.get("service", ""),
                    "cve":         f.get("cve", ""),
                    "description": self._strip_html(
                                       f.get("description", f.get("message", ""))
                                   ),
                    "evidence":    self._strip_html(f.get("evidence", "")),
                    "fix":         self._strip_html(f.get("fix", "")),
                }
                for i, f in enumerate(self.findings, 1)
            ],
        }

        with open(path, "w", encoding="utf-8") as fh:
            json.dump(export, fh, indent=2, ensure_ascii=False)
        return path