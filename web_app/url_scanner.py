"""
═══════════════════════════════════════════════════════════════
  CYBRAIN — URL Scanner Orchestrator
  Integrates OWASPChecker + ReportGenerator
  PFE Master 2 — Information Security
═══════════════════════════════════════════════════════════════
"""

import requests
import time
import os
from datetime import datetime
from owasp_checks import OWASPChecker
from report_generator import ReportGenerator

class UrlScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        if not self.target_url.startswith(('http://', 'https://')):
            self.target_url = 'http://' + self.target_url
            
        self.session = requests.Session()
        self.session.verify = False
        # Initial connection check with retry
        self.connected = self._check_connection()

    def _check_connection(self):
        retries = 2
        for i in range(retries):
            try:
                resp = self.session.get(
                    self.target_url, 
                    timeout=10, 
                    allow_redirects=True
                )
                self.target_url = resp.url.rstrip('/')
                return True
            except Exception as e:
                print(f"[!] Connection attempt {i+1} failed: {e}")
                time.sleep(1)
        return False

    def scan(self):
        if not self.connected:
            return [{
                "severity": "CRITICAL",
                "title": "Target Unreachable",
                "description": "Could not establish connection to the target URL.",
                "target": self.target_url
            }]

        print(f"\n[CYBRAIN] SCAN START: {self.target_url}")
        print(f"[CYBRAIN] Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        checker = OWASPChecker(self.target_url, self.session)
        findings = checker.run_all()

        # Deduplicate and sort findings
        seen_titles = set()
        unique_findings = []
        
        severity_map = {
            "CRITICAL": 4,
            "HIGH": 3,
            "MEDIUM": 2,
            "LOW": 1,
            "INFO": 0
        }

        for f in findings:
            if f['title'] not in seen_titles:
                unique_findings.append(f)
                seen_titles.add(f['title'])

        # Sort by severity high to low
        unique_findings.sort(
            key=lambda x: severity_map.get(x['severity'], 0), 
            reverse=True
        )

        print(f"[CYBRAIN] SCAN COMPLETE: {len(unique_findings)} unique findings")
        
        # Save report
        try:
            report_dir = os.path.join(
                os.path.dirname(
                    os.path.dirname(os.path.abspath(__file__))
                ),
                "report"
            )
            os.makedirs(report_dir, exist_ok=True)
            generator = ReportGenerator(
                self.target_url,
                unique_findings,
                report_dir
            )
            generator.generate_all()
        except Exception as e:
            print(f"[!] Report generation failed: {e}")

        # Format for UI (matching expected standard)
        formatted_results = []
        for f in unique_findings:
            # Build HTML message for UI display
            message_html = (
                f"<p>{f['description']}</p>"
                f"<strong>Evidence:</strong><br><code>{f.get('evidence', 'N/A')}</code><br><br>"
                f"<strong>Recommendation:</strong><br>{f.get('fix', 'N/A')}<br><br>"
                f"<strong>CWE:</strong> <a href='https://cwe.mitre.org/data/definitions/{f.get('cwe','').replace('CWE-','')}.html' target='_blank'>{f.get('cwe','N/A')}</a><br>"
                f"<strong>OWASP 2025:</strong> {f.get('owasp_id', 'N/A')} — {f.get('owasp_name', 'N/A')}<br>"
                f"<strong>CVSS Score:</strong> {f.get('cvss', 'N/A')}<br>"
                f"<strong>SANS/CWE Top 25:</strong> {f.get('sans', 'N/A')}"
            )
            
            formatted_results.append({
                "severity": f['severity'],
                "code": f['title'],
                "message": message_html,
                "file": self.target_url,
                "line": "-"
            })

        self.last_findings = formatted_results
        return formatted_results

    def _calc_overall_risk(self):
        """Calculate overall risk based on findings."""
        # This mirrors the logic in app.py for consistency
        # although app.py also tries to call it directly.
        # We'll implement a robust version here.
        try:
            # We need to re-scan findings if they aren't stored, 
            # or just use a default if called before scan.
            # But usually it's called after scan().
            # Let's just return a default for now if no findings, 
            # or better, store findings in self.
            if hasattr(self, 'last_findings'):
                sevs = [f['severity'] for f in self.last_findings]
                for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                    if s in sevs:
                        return s
            return 'INFO'
        except:
            return 'INFO'

if __name__ == "__main__":
    import sys
    url = sys.argv[1] if len(sys.argv) > 1 else "http://testphp.vulnweb.com"
    scanner = UrlScanner(url)
    results = scanner.scan()
    print(f"Found {len(results)} vulnerabilities")
