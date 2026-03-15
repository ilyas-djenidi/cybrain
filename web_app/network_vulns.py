"""
CYBRAIN — Network Vulnerability Detection Module
PFE Master 2 — Information Security
Checks: Dangerous services, weak configs, known CVEs
"""

import socket
import re
import requests
import urllib3
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Known vulnerable service versions
VULNERABLE_VERSIONS = {
    "openssh": [
        ("7.2", "CVE-2016-6515", "CRITICAL",
         "OpenSSH 7.2 — Auth bypass"),
        ("6.6", "CVE-2014-1692", "HIGH",
         "OpenSSH 6.6 — Memory corruption"),
    ],
    "apache": [
        ("2.4.49", "CVE-2021-41773", "CRITICAL",
         "Path traversal RCE"),
        ("2.4.50", "CVE-2021-42013", "CRITICAL",
         "Path traversal RCE bypass"),
        ("2.2",    "CVE-2017-7679", "HIGH",
         "mod_mime buffer overflow"),
    ],
    "nginx": [
        ("1.16", "CVE-2019-9511", "HIGH",
         "HTTP/2 DoS"),
    ],
    "vsftpd": [
        ("2.3.4", "CVE-2011-2523", "CRITICAL",
         "Backdoor command execution"),
    ],
    "openssl": [
        ("1.0.1", "CVE-2014-0160", "CRITICAL",
         "Heartbleed — memory leak"),
        ("3.0.0", "CVE-2022-0778", "HIGH",
         "Infinite loop DoS"),
    ],
    "proftpd": [
        ("1.3.5", "CVE-2015-3306", "CRITICAL",
         "mod_copy unauthenticated file copy"),
    ],
    "mysql": [
        ("5.5", "CVE-2012-2122", "CRITICAL",
         "Authentication bypass"),
    ],
}

# Dangerous default credentials
DEFAULT_CREDS = {
    21:   [("anonymous",""),("ftp","ftp"),("admin","admin")],
    22:   [("root","root"),("admin","admin"),("test","test")],
    23:   [("admin","admin"),("root","root"),("cisco","cisco")],
    3306: [("root",""),("root","root"),("admin","admin")],
    5432: [("postgres","postgres"),("admin","admin")],
    6379: [("",""),("admin","admin")],
    27017:[("admin","admin"),("root","root")],
    9200: [("elastic",""),("admin","admin")],
}


class NetworkVulnScanner:
    """
    Phase 2: Vulnerability Detection
    Analyzes open ports for security issues
    """

    def __init__(self, target, recon_results,
                 timeout=10):
        self.target  = target
        self.recon   = recon_results
        self.timeout = timeout
        self.findings = []

    def _add(self, severity, title, description,
             port=None, service=None, evidence="",
             fix="", cve="", cvss=""):
        self.findings.append({
            "severity":    severity,
            "title":       title,
            "description": description,
            "port":        port,
            "service":     service,
            "evidence":    evidence,
            "fix":         fix,
            "cve":         cve,
            "cvss":        cvss,
            "target":      self.target,
            "category":    "Network",
        })

    def scan_all(self):
        """Run all network vulnerability checks."""
        print("[NETWORK VULN] Starting checks...")
        open_ports = self.recon.get(
            "ports", {}
        ).get("open", [])

        for port_info in open_ports:
            port    = port_info["port"]
            service = port_info["service"]
            banner  = port_info.get("banner", "")

            # Check each service
            self._check_dangerous_ports(
                port, service, banner
            )
            self._check_service_version(
                port, service, banner
            )
            self._check_unencrypted_services(
                port, service
            )
            self._check_default_credentials(
                port, service
            )

        # Global checks
        self._check_firewall_rules(open_ports)
        self._check_smb_vulnerabilities()
        self._check_rdp_vulnerabilities()
        self._check_ftp_vulnerabilities()
        self._check_ssh_configuration()
        self._check_database_exposure()
        self._check_web_services()
        self._check_nosql_exposure()
        self._check_management_interfaces()
        self._check_snmp()

        print(
            f"[NETWORK VULN] Done. "
            f"{len(self.findings)} issues found."
        )
        return self.findings

    # ── DANGEROUS PORTS ──────────────────────────────────────
    def _check_dangerous_ports(self, port, service, banner):
        dangerous = {
            9200: ("CRITICAL",
                   "Elasticsearch Exposed Without Auth",
                   "Elasticsearch on 9200. Default has "
                   "no auth — all indices readable/writable.",
                   "Enable X-Pack security. "
                   "Bind to localhost. "
                   "Add firewall rules.",
                   "CVE-2014-3120", "10.0"),
            2375: ("CRITICAL",
                   "Docker API Exposed (Unauthenticated)",
                   "Docker daemon API port 2375 is exposed without TLS. "
                   "Full container management, host filesystem access, "
                   "and container escape to host RCE possible.",
                   "Disable plain HTTP Docker API:\n"
                   "Remove -H tcp://0.0.0.0:2375 from dockerd\n"
                   "Use TLS-secured socket (port 2376) only.",
                   "CVE-2019-5736", "10.0"),
            2376: ("HIGH",
                   "Docker TLS API Exposed",
                   "Docker TLS API on 2376 exposed. If TLS certs "
                   "are misconfigured, unauthorized access possible.",
                   "Verify TLS certificates are properly configured.\n"
                   "Restrict access to trusted IPs only.",
                   "CWE-284", "8.1"),
            11211:("CRITICAL",
                   "Memcached Exposed (Amplification Attack Risk)",
                   "Memcached on 11211 accessible without auth. "
                   "Used in DDoS amplification attacks (51,000x). "
                   "All cached data readable and writable.",
                   "Bind to 127.0.0.1 only.\n"
                   "Block UDP port 11211 at firewall.\n"
                   "Enable SASL authentication.",
                   "CVE-2018-1000115", "10.0"),
            5984: ("CRITICAL",
                   "CouchDB Exposed Without Auth",
                   "CouchDB admin interface on 5984 accessible. "
                   "Default install has no authentication. "
                   "All databases readable, RCE via _node API.",
                   "Enable CouchDB authentication.\n"
                   "Bind to localhost only.\n"
                   "Block port 5984 externally.",
                   "CVE-2017-12635", "9.8"),
            50070:("HIGH",
                   "Hadoop NameNode Web UI Exposed",
                   "Hadoop NameNode on 50070 accessible. "
                   "Exposes HDFS file system, cluster info, "
                   "and potentially allows file read/write.",
                   "Enable Kerberos authentication.\n"
                   "Restrict access with firewall rules.",
                   "CWE-284", "8.1"),
            10000:("HIGH",
                   "Webmin Admin Panel Exposed",
                   "Webmin on 10000 is accessible. "
                   "Known critical vulnerabilities exist. "
                   "Full server administration possible.",
                   "Update Webmin immediately.\n"
                   "Restrict to trusted IPs only.\n"
                   "Disable if not needed.",
                   "CVE-2019-15107", "9.8"),
            9092: ("HIGH",
                   "Apache Kafka Exposed",
                   "Kafka broker on 9092 without authentication. "
                   "All topics readable/writable. "
                   "Can inject malicious messages into pipelines.",
                   "Enable Kafka SASL/SSL authentication.\n"
                   "Bind to internal network only.\n"
                   "Use ACLs for topic access control.",
                   "CWE-287", "8.1"),
            15672:("HIGH",
                   "RabbitMQ Management UI Exposed",
                   "RabbitMQ management interface on 15672. "
                   "Default credentials guest:guest often active. "
                   "Full message queue access and admin control.",
                   "Change default credentials immediately.\n"
                   "Restrict management UI to localhost.\n"
                   "Enable TLS for all connections.",
                   "CWE-521", "8.8"),
            4848: ("HIGH",
                   "GlassFish Admin Console Exposed",
                   "GlassFish admin console on 4848 accessible. "
                   "Known RCE vulnerabilities. "
                   "Full application server control.",
                   "Update GlassFish to latest version.\n"
                   "Restrict admin console to localhost.\n"
                   "Change default admin password.",
                   "CVE-2011-2260", "9.8"),
            8888: ("MEDIUM",
                   "Jupyter Notebook Exposed",
                   "Jupyter Notebook on 8888 accessible. "
                   "If no token/password configured, "
                   "arbitrary Python code execution possible.",
                   "Set Jupyter password: jupyter notebook password\n"
                   "Bind to localhost: c.NotebookApp.ip='127.0.0.1'\n"
                   "Never expose Jupyter to internet.",
                   "CWE-284", "9.0"),
            2181: ("HIGH",
                   "Zookeeper Exposed Without Auth",
                   "Zookeeper on 2181 accessible. "
                   "Stores Kafka/Hadoop cluster config. "
                   "Data readable, cluster disruption possible.",
                   "Enable Zookeeper authentication (SASL).\n"
                   "Restrict access with firewall rules.\n"
                   "Bind to internal network only.",
                   "CWE-287", "7.5"),
            161:  ("MEDIUM",
                   "SNMP Service Exposed",
                   "SNMP on port 161 accessible. "
                   "Community string 'public' often default. "
                   "Network device info and config readable.",
                   "Change SNMP community strings.\n"
                   "Use SNMPv3 with authentication.\n"
                   "Restrict SNMP access by IP.",
                   "CWE-287", "7.5"),
            873:  ("HIGH",
                   "Rsync Exposed Without Auth",
                   "Rsync on 873 accessible. "
                   "May allow anonymous file read/write access "
                   "to synced directories.",
                   "Require rsync authentication.\n"
                   "Restrict access with hosts allow.\n"
                   "Disable if not needed.",
                   "CWE-284", "8.1"),
            4444: ("CRITICAL",
                   "Metasploit Default Port Open",
                   "Port 4444 open — default Metasploit "
                   "meterpreter handler port. "
                   "May indicate active compromise.",
                   "Investigate immediately — possible breach.\n"
                   "Check for unauthorized processes.\n"
                   "Run forensic analysis.",
                   "CWE-200", "10.0"),
        }

        if port in dangerous:
            sev, title, desc, fix, cwe, cvss = (
                dangerous[port]
            )
            self._add(
                sev, title, desc,
                port=port, service=service,
                evidence=f"Port {port}/tcp open — {service}",
                fix=fix, cve=cwe, cvss=cvss
            )

    # ── VERSION VULNERABILITY CHECK ──────────────────────────
    def _check_service_version(self, port, service,
                                banner):
        if not banner:
            return
        banner_lower = banner.lower()

        for software, vulns in VULNERABLE_VERSIONS.items():
            if software not in banner_lower:
                continue
            # Extract version number
            ver_match = re.search(
                r"(\d+\.\d+[\.\d]*)", banner
            )
            if not ver_match:
                continue
            version = ver_match.group(1)

            for vuln_ver, cve, sev, desc in vulns:
                if version.startswith(vuln_ver):
                    self._add(
                        sev,
                        f"Vulnerable Version: {software} "
                        f"{version} ({cve})",
                        f"{desc}. Version {version} is "
                        "affected by this CVE. "
                        "Immediate patching required.",
                        port=port, service=service,
                        evidence=(
                            f"Banner: {banner[:100]} | "
                            f"Version: {version}"
                        ),
                        fix=f"Update {software} to the "
                            "latest stable version. "
                            f"Check: https://nvd.nist.gov/"
                            f"vuln/detail/{cve}",
                        cve=cve, cvss="9.8"
                    )

    # ── UNENCRYPTED SERVICES ─────────────────────────────────
    def _check_unencrypted_services(self, port, service):
        unencrypted = {
            21:  "FTP — use SFTP/FTPS",
            23:  "Telnet — use SSH",
            25:  "SMTP — enforce STARTTLS",
            80:  "HTTP — redirect to HTTPS",
            110: "POP3 — use POP3S (995)",
            143: "IMAP — use IMAPS (993)",
        }
        if port in unencrypted:
            self._add(
                "MEDIUM",
                f"Unencrypted Protocol on Port {port}",
                f"{service} transmits data in plaintext. "
                "Credentials and sensitive data can be "
                "intercepted by network sniffing (Wireshark).",
                port=port, service=service,
                evidence=(
                    f"Port {port}/tcp open — "
                    "no encryption"
                ),
                fix=unencrypted[port],
                cve="CWE-319", cvss="5.9"
            )

    # ── DEFAULT CREDENTIALS ──────────────────────────────────
    def _check_default_credentials(self, port, service):
        ip = self.recon.get("dns", {}).get(
            "ip", self.target
        )
        if port not in DEFAULT_CREDS:
            return

        # Only test anonymous FTP (safe)
        if port == 21:
            try:
                sock = socket.socket(
                    socket.AF_INET, socket.SOCK_STREAM
                )
                sock.settimeout(5)
                sock.connect((ip, port))
                banner = sock.recv(1024).decode(
                    errors="ignore"
                )
                # Send anonymous login
                sock.send(b"USER anonymous\r\n")
                resp1 = sock.recv(1024).decode(
                    errors="ignore"
                )
                sock.send(b"PASS anonymous@test.com\r\n")
                resp2 = sock.recv(1024).decode(
                    errors="ignore"
                )
                sock.close()
                if "230" in resp2:  # 230 = Login successful
                    self._add(
                        "HIGH",
                        "FTP Anonymous Login Enabled",
                        "FTP server allows anonymous access. "
                        "Anyone can connect without credentials "
                        "and potentially read/write files.",
                        port=port, service="FTP",
                        evidence=(
                            "USER anonymous + PASS anonymous"
                            " → 230 Login successful"
                        ),
                        fix="Disable anonymous FTP in "
                            "vsftpd.conf: "
                            "anonymous_enable=NO",
                        cve="CWE-287", cvss="7.5"
                    )
            except Exception:
                pass

    # ── FIREWALL ANALYSIS ────────────────────────────────────
    def _check_firewall_rules(self, open_ports):
        """Analyze if proper firewall rules are in place."""
        port_numbers = [p["port"] for p in open_ports]
        sensitive_exposed = [
            p for p in port_numbers
            if p in [22, 23, 3306, 5432, 6379,
                     27017, 9200, 1433, 3389]
        ]
        if len(sensitive_exposed) > 3:
            self._add(
                "HIGH",
                "Insufficient Firewall Rules",
                f"{len(sensitive_exposed)} sensitive ports "
                "are exposed to the network. A properly "
                "configured firewall should restrict access "
                "to management and database ports.",
                evidence=(
                    f"Exposed sensitive ports: "
                    f"{sensitive_exposed}"
                ),
                fix="Implement firewall rules:\n"
                    "- Allow only necessary ports\n"
                    "- Restrict DB ports to app servers\n"
                    "- Restrict SSH to known IPs\n"
                    "- Block all by default\n"
                    "iptables -A INPUT -p tcp "
                    "--dport 3306 -s trusted_ip -j ACCEPT",
                cve="CWE-284", cvss="7.5"
            )

    # ── SMB VULNERABILITIES ──────────────────────────────────
    def _check_smb_vulnerabilities(self):
        open_ports = self.recon.get(
            "ports", {}
        ).get("open", [])
        port_nums = [p["port"] for p in open_ports]

        if 445 in port_nums:
            # Test SMBv1 (EternalBlue)
            ip = self.recon.get(
                "dns", {}
            ).get("ip", self.target)
            try:
                sock = socket.socket(
                    socket.AF_INET, socket.SOCK_STREAM
                )
                sock.settimeout(5)
                sock.connect((ip, 445))
                # SMB negotiate protocol request
                smb_neg = (
                    b"\x00\x00\x00\x85"  # NetBIOS
                    b"\xff\x53\x4d\x42"  # SMB header
                    b"\x72\x00\x00\x00"
                    b"\x00\x18\x53\xc8"
                    b"\x00\x00\x00\x00"
                    b"\x00\x00\x00\x00"
                    b"\x00\x00\x00\x00"
                    b"\x00\x00\xff\xfe"
                    b"\x00\x00\x00\x00"
                )
                sock.send(smb_neg)
                response = sock.recv(1024)
                sock.close()

                if len(response) > 4:
                    self._add(
                        "CRITICAL",
                        "SMB Service Responding (EternalBlue Risk)",
                        "SMB port 445 is open and responding. "
                        "If SMBv1 is enabled, vulnerable to "
                        "EternalBlue (MS17-010) — the exploit "
                        "used by WannaCry and NotPetya ransomware. "
                        "Unauthenticated RCE possible.",
                        port=445, service="SMB",
                        evidence=(
                            "Port 445 open + SMB response "
                            f"({len(response)} bytes)"
                        ),
                        fix="1. Apply MS17-010 patch\n"
                            "2. Disable SMBv1:\n"
                            "   Set-SmbServerConfiguration "
                            "   -EnableSMB1Protocol $false\n"
                            "3. Block port 445 externally\n"
                            "4. Enable Windows Defender",
                        cve="CVE-2017-0144",
                        cvss="9.8"
                    )
            except Exception:
                pass

    # ── RDP VULNERABILITIES ──────────────────────────────────
    def _check_rdp_vulnerabilities(self):
        open_ports = self.recon.get(
            "ports", {}
        ).get("open", [])
        port_nums = [p["port"] for p in open_ports]

        if 3389 in port_nums:
            self._add(
                "CRITICAL",
                "RDP Exposed — BlueKeep/DejaBlue Risk",
                "RDP port 3389 is publicly accessible. "
                "Vulnerable to:\n"
                "• BlueKeep (CVE-2019-0708) — pre-auth RCE\n"
                "• DejaBlue (CVE-2019-1181/1182)\n"
                "• Brute force attacks\n"
                "• Credential stuffing\n"
                "Attackers actively scan for exposed RDP.",
                port=3389, service="RDP",
                evidence="Port 3389/tcp open",
                fix="1. Restrict to VPN/trusted IPs only\n"
                    "2. Enable Network Level Auth (NLA)\n"
                    "3. Apply KB4499175 patch\n"
                    "4. Enable Account Lockout Policy\n"
                    "5. Use MFA for RDP",
                cve="CVE-2019-0708",
                cvss="9.8"
            )

    # ── FTP VULNERABILITIES ──────────────────────────────────
    def _check_ftp_vulnerabilities(self):
        open_ports = self.recon.get(
            "ports", {}
        ).get("open", [])

        for p in open_ports:
            if p["port"] == 21:
                banner = p.get("banner", "")
                # Check for vsftpd 2.3.4 backdoor
                if "vsftpd 2.3.4" in banner.lower():
                    self._add(
                        "CRITICAL",
                        "vsftpd 2.3.4 Backdoor (CVE-2011-2523)",
                        "vsftpd 2.3.4 is installed. This version "
                        "contains a deliberately planted backdoor. "
                        "Sending ':)' as username triggers a "
                        "shell on port 6200.",
                        port=21, service="FTP",
                        evidence=f"Banner: {banner}",
                        fix="Immediately upgrade vsftpd to "
                            "latest version: "
                            "apt-get install vsftpd",
                        cve="CVE-2011-2523",
                        cvss="10.0"
                    )

    # ── SSH CONFIGURATION ────────────────────────────────────
    def _check_ssh_configuration(self):
        open_ports = self.recon.get(
            "ports", {}
        ).get("open", [])

        for p in open_ports:
            if p["port"] == 22:
                banner = p.get("banner", "")

                # Check SSH version
                if banner:
                    ver_match = re.search(
                        r"SSH-[\d.]+-OpenSSH_([\d.]+)",
                        banner
                    )
                    if ver_match:
                        version = ver_match.group(1)
                        major = float(
                            ".".join(version.split(".")[:2])
                        )
                        if major < 8.0:
                            self._add(
                                "MEDIUM",
                                f"OpenSSH {version} — Update Recommended",
                                f"OpenSSH {version} may have known "
                                "vulnerabilities. Version 8.0+ is "
                                "recommended.",
                                port=22, service="SSH",
                                evidence=f"SSH banner: {banner}",
                                fix="Update OpenSSH: "
                                    "apt-get upgrade openssh-server",
                                cve="CWE-1104",
                                cvss="5.9"
                            )

                # SSH root login warning
                self._add(
                    "MEDIUM",
                    "SSH Exposed — Brute Force Risk",
                    "SSH port 22 is publicly accessible. "
                    "Exposed SSH is constantly scanned by "
                    "automated bots attempting brute force.",
                    port=22, service="SSH",
                    evidence="Port 22/tcp open",
                    fix="1. Change SSH port from 22\n"
                        "2. Disable root login: "
                        "PermitRootLogin no\n"
                        "3. Use key-based auth only: "
                        "PasswordAuthentication no\n"
                        "4. Install fail2ban\n"
                        "5. Restrict to known IPs",
                    cve="CWE-307",
                    cvss="5.9"
                )
                break

    # ── DATABASE EXPOSURE ────────────────────────────────────
    def _check_database_exposure(self):
        open_ports = self.recon.get(
            "ports", {}
        ).get("open", [])
        db_ports = {
            3306: "MySQL/MariaDB",
            5432: "PostgreSQL",
            1433: "MSSQL",
            1521: "Oracle DB",
        }
        for p in open_ports:
            if p["port"] in db_ports:
                db_name = db_ports[p["port"]]
                self._add(
                    "CRITICAL",
                    f"{db_name} Exposed to Network",
                    f"{db_name} on port {p['port']} is "
                    "accessible from the network. Database "
                    "servers should NEVER be directly "
                    "accessible. Risk of data breach, "
                    "brute force, and injection attacks.",
                    port=p["port"], service=db_name,
                    evidence=(
                        f"Port {p['port']}/tcp open — "
                        f"{db_name}"
                    ),
                    fix=f"Bind {db_name} to 127.0.0.1\n"
                        "Use firewall to block external access\n"
                        "Connect only through app server\n"
                        "Enable authentication\n"
                        "Use encrypted connections (SSL/TLS)",
                    cve="CWE-284",
                    cvss="9.8"
                )

    # ── WEB SERVICES ─────────────────────────────────────────
    def _check_web_services(self):
        open_ports = self.recon.get(
            "ports", {}
        ).get("open", [])
        ip = self.recon.get(
            "dns", {}
        ).get("ip", self.target)

        for p in open_ports:
            if p["port"] in [80, 8080, 8888]:
                # Check for HTTP (not HTTPS)
                self._add(
                    "HIGH",
                    f"Unencrypted HTTP on Port {p['port']}",
                    "Web service running without TLS. "
                    "All traffic including session tokens "
                    "and passwords sent in plaintext.",
                    port=p["port"], service="HTTP",
                    evidence=f"Port {p['port']}/tcp open HTTP",
                    fix="Configure HTTPS with TLS 1.2+\n"
                        "Redirect all HTTP to HTTPS\n"
                        "Get free cert: certbot --nginx",
                    cve="CWE-319",
                    cvss="7.5"
                )

    # ── NoSQL EXPOSURE ───────────────────────────────────────
    def _check_nosql_exposure(self):
        open_ports = self.recon.get(
            "ports", {}
        ).get("open", [])
        ip = self.recon.get(
            "dns", {}
        ).get("ip", self.target)
        nosql_ports = {
            6379:  "Redis",
            27017: "MongoDB",
            9200:  "Elasticsearch",
            9300:  "Elasticsearch (cluster)",
            7474:  "Neo4j",
            8086:  "InfluxDB",
            5984:  "CouchDB",
        }
        for p in open_ports:
            if p["port"] in nosql_ports:
                db = nosql_ports[p["port"]]
                # Try unauthenticated access
                try:
                    if p["port"] == 9200:
                        r = requests.get(
                            f"http://{ip}:9200/",
                            timeout=5
                        )
                        if r.status_code == 200:
                            self._add(
                                "CRITICAL",
                                f"{db} Unauthenticated Access",
                                f"{db} accessible without "
                                "authentication. All data readable.",
                                port=p["port"],
                                service=db,
                                evidence=(
                                    f"HTTP 200 from "
                                    f"{ip}:{p['port']}"
                                ),
                                fix=f"Enable {db} security. "
                                    "Bind to localhost. "
                                    "Add firewall rules.",
                                cve="CWE-284",
                                cvss="10.0"
                            )
                except Exception:
                    pass

    # ── MANAGEMENT INTERFACES ────────────────────────────────
    def _check_management_interfaces(self):
        open_ports = self.recon.get(
            "ports", {}
        ).get("open", [])
        ip = self.recon.get(
            "dns", {}
        ).get("ip", self.target)

        mgmt_paths = [
            "/phpmyadmin", "/phpMyAdmin",
            "/adminer", "/admin",
            "/manager/html",  # Tomcat
            "/wp-admin",      # WordPress
            "/jenkins",       # Jenkins
            "/grafana",       # Grafana
            "/kibana",        # Kibana
        ]

        for p in open_ports:
            if p["port"] not in [80, 443, 8080, 8443]:
                continue
            scheme = "https" if p["port"] in [
                443, 8443
            ] else "http"

            for path in mgmt_paths:
                try:
                    url = (
                        f"{scheme}://{ip}"
                        f":{p['port']}{path}"
                    )
                    r = requests.get(
                        url, timeout=5, verify=False
                    )
                    if r.status_code in [200, 401, 403]:
                        self._add(
                            "HIGH",
                            f"Management Interface Exposed: "
                            f"{path}",
                            f"Admin/management panel found at "
                            f"{url}. Exposed management interfaces "
                            "are prime targets for attackers.",
                            port=p["port"],
                            service=f"HTTP ({path})",
                            evidence=(
                                f"GET {url} → "
                                f"{r.status_code}"
                            ),
                            fix="Move admin panels behind VPN\n"
                                "Restrict access by IP\n"
                                "Enable MFA for admin access\n"
                                "Change default paths",
                            cve="CWE-284",
                            cvss="7.5"
                        )
                        break
                except Exception:
                    pass

    def _check_snmp(self):
        """Check SNMP for default community strings."""
        open_ports = self.recon.get(
            "ports", {}
        ).get("open", [])
        port_nums = [p["port"] for p in open_ports]

        if 161 not in port_nums:
            return

        ip = self.recon.get(
            "dns", {}
        ).get("ip", self.target)

        # Try default community strings via UDP
        try:
            import socket
            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_DGRAM
            )
            sock.settimeout(3)

            # SNMP v1 GET request for sysDescr OID
            # Community string: "public"
            snmp_get = bytes([
                0x30, 0x26,          # SEQUENCE
                0x02, 0x01, 0x00,    # version: 1
                0x04, 0x06,          # community string length
                0x70, 0x75, 0x62,    # "pub"
                0x6c, 0x69, 0x63,    # "lic"
                0xa0, 0x19,          # GetRequest PDU
                0x02, 0x04, 0x00, 0x00, 0x00, 0x01,
                0x02, 0x01, 0x00,
                0x02, 0x01, 0x00,
                0x30, 0x0b,
                0x30, 0x09,
                0x06, 0x05,
                0x2b, 0x06, 0x01, 0x02, 0x01,
                0x05, 0x00,
            ])

            sock.sendto(snmp_get, (ip, 161))
            response, _ = sock.recvfrom(1024)
            sock.close()

            if response and len(response) > 10:
                self._add(
                    "HIGH",
                    "SNMP Default Community String 'public'",
                    "SNMP service responds to default community "
                    "string 'public'. Network device information "
                    "including interfaces, routing tables, and "
                    "system details are readable.",
                    port=161, service="SNMP",
                    evidence=(
                        f"SNMP GET with community='public' "
                        f"→ {len(response)} byte response"
                    ),
                    fix=(
                        "Change SNMP community strings.\n"
                        "Upgrade to SNMPv3 with auth+encryption.\n"
                        "Restrict SNMP to management hosts only:\n"
                        "iptables -A INPUT -p udp --dport 161 "
                        "-s mgmt_ip -j ACCEPT\n"
                        "iptables -A INPUT -p udp "
                        "--dport 161 -j DROP"
                    ),
                    cve="CWE-287",
                    cvss="7.5"
                )
        except Exception:
            pass
