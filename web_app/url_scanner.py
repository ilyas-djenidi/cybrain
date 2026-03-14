"""
CYBRAIN — Master URL Scanner
Integrates OWASP Top 10 + Additional Checks + Report Generation
"""

import requests
import re
import json
import time
import os
import urllib3
from urllib.parse import urlparse, urlencode, urlunparse
from owasp_checks import OWASPChecker
from report_generator import ReportGenerator

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/122.0.0.0 Safari/537.36"
)


class UrlScanner:

    def __init__(self, target_url):
        self.target_url = target_url.strip()
        if not self.target_url.startswith(
            ('http://', 'https://')
        ):
            self.target_url = 'http://' + self.target_url
        self.target_url = (
            self.target_url.split('#')[0].rstrip('/')
        )
        self.results = []
        self.timeout = 25
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": BROWSER_UA,
            "Accept": (
                "text/html,application/xhtml+xml,"
                "application/xml;q=0.9,*/*;q=0.8"
            ),
            "Accept-Language": "en-US,en;q=0.9",
        })
        self.report_dir = os.path.join(
            os.path.dirname(
                os.path.dirname(os.path.abspath(__file__))
            ),
            "report"
        )
        os.makedirs(self.report_dir, exist_ok=True)

    def _get(self, url, **kw):
        try:
            return self.session.get(
                url, timeout=self.timeout,
                verify=False, allow_redirects=True, **kw
            )
        except Exception as e:
            print(f"[GET ERROR] {url}: {e}")
            return None

    def _format_for_ui(self, finding):
        """Convert any finding dict to UI format."""
        desc = finding.get(
            "description", finding.get("message", "")
        )
        fix  = finding.get("fix", "")
        evid = finding.get("evidence", "")
        cwe  = finding.get("cwe", "")
        owasp_id   = finding.get("owasp_id", "")
        owasp_name = finding.get("owasp_name", "")
        owasp      = (
            finding.get("owasp") or
            f"{owasp_id} {owasp_name}".strip()
        )

        parts = [desc]
        if evid:
            parts.append(
                f"<strong>Evidence:</strong>"
                f"<br><code>{evid}</code>"
            )
        if fix:
            parts.append(
                f"<strong>Recommendation:</strong>"
                f"<br>{fix}"
            )
        if cwe:
            parts.append(
                f"<strong>CWE:</strong> "
                f"<a href='https://cwe.mitre.org/"
                f"data/definitions/"
                f"{cwe.replace('CWE-','')}'"
                f" target='_blank'>{cwe}</a>"
            )
        if owasp:
            parts.append(
                f"<strong>OWASP:</strong> {owasp}"
            )

        return {
            "severity": finding.get("severity", "INFO"),
            "line":     "-",
            "message":  "\n\n".join(parts),
            "code":     finding.get(
                "title",
                finding.get("code", "")
            ),
            "file":     self.target_url,
        }

    def scan(self):
        print(
            f"[CYBRAIN SCANNER] Target: {self.target_url}"
        )

        # Connectivity check with retries
        resp = self._get(self.target_url)
        if resp is None:
            if "://www." not in self.target_url:
                alt = self.target_url.replace(
                    "://", "://www."
                )
                resp = self._get(alt)
                if resp:
                    self.target_url = alt

        if resp is None and self.target_url.startswith(
            "http://"
        ):
            alt = self.target_url.replace(
                "http://", "https://"
            )
            resp = self._get(alt)
            if resp:
                self.target_url = alt

        if resp is None:
            self.results = [{
                "severity": "HIGH",
                "line":     "-",
                "message":  (
                    "Could not reach target after multiple "
                    "attempts.<br><br>"
                    "<strong>Recommendation:</strong><br>"
                    "Try: http://testphp.vulnweb.com or "
                    "https://demo.testfire.net"
                ),
                "code": "Connection Error",
                "file": self.target_url,
            }]
            return self.results

        print(
            f"[CYBRAIN SCANNER] Connected: "
            f"{resp.status_code}"
        )

        # Run full OWASP Top 10
        checker = OWASPChecker(
            self.target_url, self.session, self.timeout
        )
        all_findings = checker.run_all()

        # Deduplicate by title
        seen  = set()
        dedup = []
        for f in all_findings:
            key = f.get("title","")
            if key not in seen:
                seen.add(key)
                dedup.append(f)

        # Sort by severity
        order = {
            "CRITICAL":0,"HIGH":1,
            "MEDIUM":2,"LOW":3,"INFO":4
        }
        dedup.sort(
            key=lambda f: order.get(
                f.get("severity","INFO"), 99
            )
        )

        # Generate professional reports
        generator = ReportGenerator(
            self.target_url, dedup, self.report_dir
        )
        generator.generate_all()

        # Format for React UI
        self.results = [
            self._format_for_ui(f) for f in dedup
        ]

        print(
            f"[CYBRAIN SCANNER] Complete: "
            f"{len(self.results)} findings"
        )
        return self.results

    def _calc_overall_risk(self):
        sevs = [r["severity"] for r in self.results]
        for s in ["CRITICAL","HIGH","MEDIUM","LOW"]:
            if s in sevs:
                return s
        return "INFO"
