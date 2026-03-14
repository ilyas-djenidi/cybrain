"""
═══════════════════════════════════════════════════════════════
  CYBRAIN — Professional Report Generator
  PFE Master 2 — Information Security
  Generates MD + CSV reports from scan findings
═══════════════════════════════════════════════════════════════
"""

import os
import csv
import re
import time

SEVERITY_ORDER = {
    "CRITICAL": 0, "HIGH": 1,
    "MEDIUM": 2, "LOW": 3, "INFO": 4
}
CVSS_MAP = {
    "CRITICAL": "9.0–10.0", "HIGH": "7.0–8.9",
    "MEDIUM": "4.0–6.9",   "LOW": "0.1–3.9",
    "INFO": "0.0"
}
EMOJI = {
    "CRITICAL": "🔴", "HIGH": "🟠",
    "MEDIUM": "🟡", "LOW": "🟢", "INFO": "ℹ️"
}


class ReportGenerator:

    def __init__(self, target_url, findings,
                 report_dir="report"):
        self.target   = target_url
        self.findings = sorted(
            findings,
            key=lambda f: SEVERITY_ORDER.get(
                f.get("severity","INFO"), 99
            )
        )
        self.report_dir = report_dir
        os.makedirs(report_dir, exist_ok=True)

    def _strip_html(self, text):
        return re.sub(r'<[^>]+>', '', str(text or ''))

    def _counts(self):
        counts = {
            "CRITICAL":0,"HIGH":0,
            "MEDIUM":0,"LOW":0,"INFO":0
        }
        for f in self.findings:
            sev = f.get("severity","INFO")
            counts[sev] = counts.get(sev,0) + 1
        return counts

    def _overall_risk(self, counts):
        for sev in ["CRITICAL","HIGH","MEDIUM","LOW"]:
            if counts[sev] > 0:
                return sev
        return "INFO"

    def generate_all(self):
        md_path  = self.save_markdown()
        csv_path = self.save_csv()
        print(f"[REPORT] Saved: {md_path}")
        print(f"[REPORT] Saved: {csv_path}")
        return md_path, csv_path

    def save_markdown(self):
        counts = self._counts()
        risk   = self._overall_risk(counts)
        total  = len(self.findings)
        path   = os.path.join(
            self.report_dir, "vulnerability_report.md"
        )

        lines = [
            "# Web Application Vulnerability Assessment Report",
            "", "---", "",
            "## Target Information", "",
            "| Field | Value |",
            "|-------|-------|",
            f"| **Target URL** | `{self.target}` |",
            f"| **Scan Date** | "
            f"{time.strftime('%Y-%m-%d %H:%M:%S')} |",
            f"| **Overall Risk** | **{risk}** |",
            "| **Methodology** | OWASP Testing Guide v4.2 |",
            "| **Purpose** | "
            "PFE Master 2 — Information Security Research |",
            "", "---", "",
            "## Executive Summary", "",
            f"A total of **{total} finding(s)** "
            "were identified.", "",
            "| Severity | Count |",
            "|----------|-------|",
            f"| 🔴 CRITICAL | {counts['CRITICAL']} |",
            f"| 🟠 HIGH | {counts['HIGH']} |",
            f"| 🟡 MEDIUM | {counts['MEDIUM']} |",
            f"| 🟢 LOW | {counts['LOW']} |",
            f"| ℹ️ INFO | {counts['INFO']} |",
            f"| **TOTAL** | **{total}** |",
            "", "---", "",
            "## Vulnerability Summary", "",
            "| # | Vulnerability | Severity | "
            "CVSS | CWE | OWASP |",
            "|---|--------------|----------|"
            "-----|-----|-------|",
        ]

        for i, f in enumerate(self.findings, 1):
            sev  = f.get("severity","INFO")
            owasp= (f.get("owasp_id","") + " " +
                    f.get("owasp_name","") or
                    f.get("owasp",""))
            lines.append(
                f"| {i} | "
                f"{f.get('title','')} | "
                f"**{sev}** | "
                f"{CVSS_MAP.get(sev,'N/A')} | "
                f"{f.get('cwe','')} | "
                f"{owasp} |"
            )

        lines += ["", "---", "", "## Detailed Findings", ""]

        for i, f in enumerate(self.findings, 1):
            sev  = f.get("severity","INFO")
            em   = EMOJI.get(sev,"")
            owasp= (f.get("owasp_id","") + ": " +
                    f.get("owasp_name","") or
                    f.get("owasp",""))
            desc = self._strip_html(
                f.get("description",
                      f.get("message",""))
            )
            fix  = self._strip_html(f.get("fix",""))
            evid = self._strip_html(f.get("evidence",""))

            lines += [
                f"### {em} [{i}] {f.get('title','')}",
                "",
                "| Field | Details |",
                "|-------|---------|",
                f"| **Severity** | {sev} |",
                f"| **CVSS Range** | "
                f"{CVSS_MAP.get(sev,'N/A')} |",
                f"| **CWE** | {f.get('cwe','')} |",
                f"| **OWASP** | {owasp} |",
                f"| **Location** | `{self.target}` |",
                "",
                "**Description:**", "", desc, "",
            ]
            if evid:
                lines += [
                    "**Evidence:**", "",
                    f"```\n{evid}\n```", ""
                ]
            if fix:
                lines += [
                    "**Remediation:**", "", fix, ""
                ]
            lines += ["---", ""]

        # Roadmap
        lines += [
            "## Remediation Roadmap", "",
            "### Priority 1 — Fix Immediately (CRITICAL)", ""
        ]
        for f in self.findings:
            if f.get("severity") == "CRITICAL":
                lines.append(f"- [ ] **{f.get('title','')}**")
        lines += [
            "", "### Priority 2 — Fix This Week (HIGH)", ""
        ]
        for f in self.findings:
            if f.get("severity") == "HIGH":
                lines.append(f"- [ ] **{f.get('title','')}**")
        lines += [
            "", "### Priority 3 — Fix This Month (MEDIUM)", ""
        ]
        for f in self.findings:
            if f.get("severity") == "MEDIUM":
                lines.append(f"- [ ] **{f.get('title','')}**")

        lines += [
            "", "---", "",
            "## Conclusion", "",
            f"This assessment identified **{total}** issues "
            f"on `{self.target}`. "
            f"Overall risk: **{risk}**.", "",
            "Immediate remediation required for all CRITICAL "
            "and HIGH findings.", "",
            "*Report generated by Cybrain Intelligence Platform "
            "— PFE Master 2 Information Security.*", "",
        ]

        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        return path

    def save_csv(self):
        path = os.path.join(
            self.report_dir, "findings_summary.csv"
        )
        fields = [
            "id","title","severity","cvss_range",
            "cwe","owasp","url","evidence","fix"
        ]
        with open(
            path, "w", newline="", encoding="utf-8"
        ) as fh:
            writer = csv.DictWriter(fh, fieldnames=fields)
            writer.writeheader()
            for i, f in enumerate(self.findings, 1):
                sev   = f.get("severity","INFO")
                owasp = (
                    f.get("owasp_id","") + " " +
                    f.get("owasp_name","") or
                    f.get("owasp","")
                )
                writer.writerow({
                    "id":         f"VULN-{i:03d}",
                    "title":      f.get("title",""),
                    "severity":   sev,
                    "cvss_range": CVSS_MAP.get(sev,"N/A"),
                    "cwe":        f.get("cwe",""),
                    "owasp":      owasp,
                    "url":        self.target,
                    "evidence":   self._strip_html(
                                    f.get("evidence","")
                                  ),
                    "fix":        self._strip_html(
                                    f.get("fix","")
                                  ),
                })
        return path
