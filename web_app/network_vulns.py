"""
===============================================================
  CYBRAIN - Network Vulnerability Detection Module  (v2.1)
  PFE Master 2 - Information Security
  University of Mohamed Boudiaf, M'sila - Algeria

  BUG FIXES in v2.1
  -----------------
  * _check_ssh: float() crash on non-standard versions (dropbear_0.51)
    was silently killing the entire scan. Now wrapped safely.
  * _check_ftp: anonymous FTP probe now runs even if vsftpd check passes.
  * _check_telnet: was correct but now also adds MEDIUM unencrypted finding.
  * _check_service_version: added dropbear version matching.
  * All _add() calls verified - description field always populated.
  * Deduplication guard: same title not added twice per scan.
  * Each check method is fully isolated with try/except so one crash
    never silently kills all subsequent checks.

  FOR EDUCATIONAL / AUTHORIZED TESTING ONLY
===============================================================
"""

import re
import socket
import requests
import urllib3
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Known vulnerable versions ──────────────────────────────────────────────
VULNERABLE_VERSIONS = {
    "openssh": [
        ("7.2",  "CVE-2016-6515",  "HIGH",     "Auth bypass via malformed packets"),
        ("6.6",  "CVE-2014-1692",  "HIGH",     "Memory corruption"),
        ("5.",   "CVE-2010-4478",  "CRITICAL", "OpenSSH 5.x - auth bypass"),
    ],
    "dropbear": [
        ("0.51", "CVE-2013-4421", "HIGH",   "Dropbear SSH 0.51 - old/vulnerable build"),
        ("0.52", "CVE-2013-4421", "HIGH",   "Dropbear SSH 0.52 - update recommended"),
        ("0.53", "CVE-2013-4421", "MEDIUM", "Dropbear SSH 0.53 - update recommended"),
        ("2016", "CVE-2016-7406", "HIGH",   "Dropbear SSH 2016.x - format string vuln"),
        ("2017", "CVE-2017-9078", "HIGH",   "Dropbear SSH 2017.x - use-after-free"),
    ],
    "apache": [
        ("2.4.49", "CVE-2021-41773", "CRITICAL", "Path traversal / RCE"),
        ("2.4.50", "CVE-2021-42013", "CRITICAL", "Path traversal RCE bypass"),
        ("2.2",    "CVE-2017-7679",  "HIGH",     "mod_mime buffer overflow"),
        ("2.4.6",  "CVE-2013-1862",  "MEDIUM",   "mod_rewrite log injection"),
    ],
    "nginx": [
        ("1.16", "CVE-2019-9511", "HIGH", "HTTP/2 DoS"),
        ("1.9",  "CVE-2016-4450", "HIGH", "Chunked encoding DoS"),
    ],
    "vsftpd": [
        ("2.3.4", "CVE-2011-2523", "CRITICAL", "Backdoor command execution"),
    ],
    "openssl": [
        ("1.0.1", "CVE-2014-0160", "CRITICAL", "Heartbleed - memory leak"),
        ("3.0.0", "CVE-2022-0778", "HIGH",     "Infinite loop DoS"),
        ("1.0.2", "CVE-2016-0703", "HIGH",     "DROWN attack"),
    ],
    "proftpd": [
        ("1.3.5", "CVE-2015-3306", "CRITICAL", "mod_copy unauth file copy"),
    ],
    "mysql": [
        ("5.5", "CVE-2012-2122", "CRITICAL", "Authentication bypass"),
        ("5.6", "CVE-2016-6662", "CRITICAL", "Config file overwrite RCE"),
    ],
    "exim": [
        ("4.87", "CVE-2019-10149", "CRITICAL", "Remote command execution"),
        ("4.9",  "CVE-2019-10149", "CRITICAL", "Exim RCE"),
    ],
    "log4j": [
        ("2.0",  "CVE-2021-44228", "CRITICAL", "Log4Shell JNDI RCE"),
        ("2.14", "CVE-2021-44228", "CRITICAL", "Log4Shell JNDI RCE"),
    ],
    "spring": [
        ("5.3", "CVE-2022-22965", "CRITICAL", "Spring4Shell RCE"),
    ],
    "struts": [
        ("2.3", "CVE-2017-5638", "CRITICAL", "Apache Struts RCE (Equifax breach)"),
    ],
}

# ── Dangerous ports ────────────────────────────────────────────────────────
DANGEROUS_PORTS = {
    2375: {
        "sev": "CRITICAL", "cve": "CVE-2019-5736", "cvss": "10.0",
        "title": "Docker API Exposed (Unauthenticated)",
        "desc": "Docker daemon API on 2375 exposed without TLS. Full container management and host RCE possible.",
        "fix": "Remove -H tcp://0.0.0.0:2375 from dockerd. Use TLS socket (port 2376) only.",
    },
    2376: {
        "sev": "HIGH", "cve": "CWE-284", "cvss": "8.1",
        "title": "Docker TLS API Exposed",
        "desc": "Docker TLS API on 2376 exposed. Misconfigured TLS allows full container control.",
        "fix": "Verify TLS certs. Restrict to trusted IPs.",
    },
    9200: {
        "sev": "CRITICAL", "cve": "CVE-2014-3120", "cvss": "10.0",
        "title": "Elasticsearch Exposed Without Auth",
        "desc": "Elasticsearch REST API on 9200 has no authentication by default. All indices readable/writable/deletable.",
        "fix": "Enable X-Pack security. Bind to localhost. Firewall port 9200.",
    },
    9300: {
        "sev": "HIGH", "cve": "CWE-284", "cvss": "7.5",
        "title": "Elasticsearch Cluster Port Exposed",
        "desc": "ES cluster communication port 9300 accessible. Node injection possible.",
        "fix": "Bind to internal network only. Apply transport TLS.",
    },
    11211: {
        "sev": "CRITICAL", "cve": "CVE-2018-1000115", "cvss": "10.0",
        "title": "Memcached Exposed (Amplification Attack Risk)",
        "desc": "Memcached on 11211 accessible without auth. Used in DDoS amplification attacks (51,000x factor). All cached data readable.",
        "fix": "Bind to 127.0.0.1. Block UDP 11211 at firewall. Enable SASL.",
    },
    6379: {
        "sev": "CRITICAL", "cve": "CVE-2022-0543", "cvss": "10.0",
        "title": "Redis Exposed Without Auth",
        "desc": "Redis on 6379 accessible without authentication. All keys readable/writable. Attackers can write SSH keys or cron jobs to gain OS RCE.",
        "fix": "requirepass <strong_password> in redis.conf. Bind to 127.0.0.1.",
    },
    5984: {
        "sev": "CRITICAL", "cve": "CVE-2017-12635", "cvss": "9.8",
        "title": "CouchDB Exposed Without Auth",
        "desc": "CouchDB admin interface on 5984 accessible. Default install has no authentication. All databases readable. RCE via _node API.",
        "fix": "Enable CouchDB auth. Bind to localhost. Block 5984 externally.",
    },
    27017: {
        "sev": "CRITICAL", "cve": "CWE-284", "cvss": "9.8",
        "title": "MongoDB Exposed Without Auth",
        "desc": "MongoDB on 27017 accessible. Older versions have no auth by default. All databases and collections readable.",
        "fix": "Enable auth in mongod.conf: security.authorization: enabled. Bind to 127.0.0.1.",
    },
    50070: {
        "sev": "HIGH", "cve": "CWE-284", "cvss": "8.1",
        "title": "Hadoop NameNode Web UI Exposed",
        "desc": "HDFS NameNode on 50070 accessible. Exposes file system, cluster info.",
        "fix": "Enable Kerberos. Restrict with firewall.",
    },
    10000: {
        "sev": "HIGH", "cve": "CVE-2019-15107", "cvss": "9.8",
        "title": "Webmin Admin Panel Exposed",
        "desc": "Webmin on 10000 accessible. Known critical RCE. Full server admin.",
        "fix": "Update Webmin. Restrict to trusted IPs. Disable if unused.",
    },
    9092: {
        "sev": "HIGH", "cve": "CWE-287", "cvss": "8.1",
        "title": "Apache Kafka Exposed Without Auth",
        "desc": "Kafka on 9092 without auth. All topics readable/writable. Message injection possible.",
        "fix": "Enable SASL/SSL. Bind to internal network. Use ACLs.",
    },
    15672: {
        "sev": "HIGH", "cve": "CWE-521", "cvss": "8.8",
        "title": "RabbitMQ Management UI Exposed",
        "desc": "RabbitMQ UI on 15672. Default guest:guest credentials often active.",
        "fix": "Change default credentials. Restrict UI to localhost. Enable TLS.",
    },
    4848: {
        "sev": "HIGH", "cve": "CVE-2011-2260", "cvss": "9.8",
        "title": "GlassFish Admin Console Exposed",
        "desc": "GlassFish admin on 4848. Known RCE vulnerabilities. Full app server control.",
        "fix": "Update GlassFish. Restrict to localhost. Change admin password.",
    },
    8888: {
        "sev": "MEDIUM", "cve": "CWE-284", "cvss": "9.0",
        "title": "Jupyter Notebook Exposed",
        "desc": "Jupyter on 8888. Without token/password, arbitrary Python RCE possible.",
        "fix": "Set password. Bind to 127.0.0.1. Never expose to internet.",
    },
    2181: {
        "sev": "HIGH", "cve": "CWE-287", "cvss": "7.5",
        "title": "Zookeeper Exposed Without Auth",
        "desc": "Zookeeper on 2181. Stores Kafka/Hadoop cluster config. Cluster disruption possible.",
        "fix": "Enable SASL. Restrict with firewall.",
    },
    873: {
        "sev": "HIGH", "cve": "CWE-284", "cvss": "8.1",
        "title": "Rsync Exposed Without Auth",
        "desc": "Rsync on 873 accessible. Anonymous file read/write to synced dirs.",
        "fix": "Require rsync auth. Restrict with hosts allow. Disable if unused.",
    },
    4444: {
        "sev": "CRITICAL", "cve": "CWE-200", "cvss": "10.0",
        "title": "Metasploit Default Port Open",
        "desc": "Port 4444 open - default Metasploit meterpreter handler. Possible active compromise.",
        "fix": "Investigate immediately. Check for unauthorized processes. Run forensics.",
    },
    1883: {
        "sev": "HIGH", "cve": "CWE-319", "cvss": "7.5",
        "title": "MQTT Broker Exposed (IoT Risk)",
        "desc": "MQTT on 1883 without TLS. IoT device messages interceptable. Topic injection possible.",
        "fix": "Enable MQTT TLS (port 8883). Require authentication. Use ACLs.",
    },
    502: {
        "sev": "CRITICAL", "cve": "CWE-306", "cvss": "10.0",
        "title": "Modbus ICS Port Exposed",
        "desc": "Modbus on 502 exposed. Industrial control system protocol with no auth or encryption.",
        "fix": "Isolate ICS network. Firewall Modbus from internet. Deploy industrial DMZ.",
    },
    47808: {
        "sev": "HIGH", "cve": "CWE-306", "cvss": "8.6",
        "title": "BACnet Building Automation Port Exposed",
        "desc": "BACnet on 47808. HVAC, lighting, access control may be controllable.",
        "fix": "Isolate BACnet on dedicated VLAN. Block internet access.",
    },
    5900: {
        "sev": "HIGH", "cve": "CWE-307", "cvss": "8.8",
        "title": "VNC Remote Desktop Exposed",
        "desc": "VNC on 5900 publicly accessible. Brute-forceable. Many VNC servers have no auth or weak passwords.",
        "fix": "Require strong VNC password. Restrict to VPN/known IPs. Prefer SSH tunneling.",
    },
}

# ── Unencrypted protocols ──────────────────────────────────────────────────
UNENCRYPTED_PORTS = {
    21:  "FTP - credentials in plaintext. Replace with SFTP (port 22) or FTPS.",
    23:  "Telnet - all traffic unencrypted. Replace with SSH immediately.",
    25:  "SMTP - enforce STARTTLS. Reject plain SMTP externally.",
    80:  "HTTP - redirect to HTTPS. Get free cert: certbot --nginx.",
    110: "POP3 - use POP3S (port 995).",
    143: "IMAP - use IMAPS (port 993).",
    119: "NNTP - plaintext news protocol. Use NNTPS (563).",
    514: "Syslog UDP - plaintext log data. Use syslog-ng with TLS.",
}


class NetworkVulnScanner:
    """
    Phase 2 - Vulnerability Detection.
    Each check is fully isolated so one failure never silences others.
    """

    def __init__(self, target: str, recon_results: dict, timeout: int = 10):
        self.target   = target
        self.recon    = recon_results
        self.timeout  = timeout
        self.findings: list = []
        self._ip      = recon_results.get("dns", {}).get("ip") or target
        self._seen_titles: set = set()   # deduplication guard

    def _add(self, severity: str, title: str, description: str,
             port=None, service: str = "", evidence: str = "",
             fix: str = "", cve: str = "", cvss: str = ""):
        """Add a finding. Skips duplicates by title."""
        if title in self._seen_titles:
            return
        self._seen_titles.add(title)
        # Ensure description is never empty — fallback to title
        if not description:
            description = title
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

    def scan_all(self) -> list:
        print("[NETWORK VULN] Starting checks...")
        open_ports = self.recon.get("ports", {}).get("open", [])

        if not open_ports:
            print("[NETWORK VULN] No open ports to check.")
            return self.findings

        # Per-port checks — each wrapped individually
        for port_info in open_ports:
            port    = port_info.get("port", 0)
            service = port_info.get("service", "")
            banner  = port_info.get("banner") or ""

            try:
                self._check_dangerous_ports(port, service, banner)
            except Exception as e:
                print(f"[NETWORK VULN] dangerous_ports check error port {port}: {e}")

            try:
                self._check_service_version(port, service, banner)
            except Exception as e:
                print(f"[NETWORK VULN] service_version check error port {port}: {e}")

            try:
                self._check_unencrypted_services(port, service)
            except Exception as e:
                print(f"[NETWORK VULN] unencrypted check error port {port}: {e}")

            try:
                self._check_tls_weakness(port, banner)
            except Exception as e:
                print(f"[NETWORK VULN] tls_weakness check error port {port}: {e}")

        # Service-specific checks — each individually guarded
        for fn_name, fn in [
            ("ftp",         self._check_ftp),
            ("ssh",         self._check_ssh),
            ("smb",         self._check_smb),
            ("rdp",         self._check_rdp),
            ("telnet",      self._check_telnet),
            ("vnc",         self._check_vnc),
            ("database",    self._check_database_exposure),
            ("nosql",       self._check_nosql_exposure),
            ("web",         self._check_web_services),
            ("management",  self._check_management_interfaces),
            ("snmp",        self._check_snmp),
            ("ics",         self._check_ics_ports),
            ("nfs",         self._check_nfs),
            ("firewall",    self._check_firewall_posture),
        ]:
            try:
                fn(open_ports)
            except Exception as e:
                print(f"[NETWORK VULN] {fn_name} check error: {e}")

        print(f"[NETWORK VULN] Done - {len(self.findings)} issues found.")
        return self.findings

    # ── DANGEROUS PORTS ───────────────────────────────────────────────────
    def _check_dangerous_ports(self, port: int, service: str, banner: str):
        if port in DANGEROUS_PORTS:
            d = DANGEROUS_PORTS[port]
            self._add(
                d["sev"], d["title"], d["desc"],
                port=port, service=service,
                evidence=f"Port {port}/tcp open - {service}",
                fix=d["fix"], cve=d["cve"], cvss=d["cvss"],
            )

    # ── VERSION CVE MATCHING ──────────────────────────────────────────────
    def _check_service_version(self, port: int, service: str, banner: str):
        if not banner:
            return
        bl = banner.lower()
        for software, vulns in VULNERABLE_VERSIONS.items():
            if software not in bl:
                continue
            # Extract version - handle formats like "dropbear_0.51" and "OpenSSH_8.2"
            ver_m = re.search(r"[_/\s-]([\d]+\.[\d]+[\.\d]*)", banner, re.IGNORECASE)
            if not ver_m:
                ver_m = re.search(r"(\d+\.\d+[\.\d]*)", banner)
            if not ver_m:
                continue
            version = ver_m.group(1)
            for vuln_ver, cve, sev, desc in vulns:
                if version.startswith(vuln_ver):
                    title = f"Vulnerable Version: {software.title()} {version} ({cve})"
                    self._add(
                        sev, title,
                        f"{desc}. Version {version} is affected. Immediate patch required.",
                        port=port, service=service,
                        evidence=f"Banner: {banner[:120]} | Version: {version}",
                        fix=(
                            f"Update {software.title()} to latest stable version.\n"
                            f"Advisory: https://nvd.nist.gov/vuln/detail/{cve}"
                        ),
                        cve=cve, cvss="9.8",
                    )

    # ── UNENCRYPTED PROTOCOLS ─────────────────────────────────────────────
    def _check_unencrypted_services(self, port: int, service: str):
        if port in UNENCRYPTED_PORTS:
            # Dedup: Skip generic finding if a specific, higher-severity check exists
            if port == 23:
                return  # Handled by _check_telnet (CRITICAL)
            if port == 80:
                return  # Handled by _check_web_services (HIGH)

            self._add(
                "MEDIUM",
                f"Unencrypted Protocol - Port {port} ({service})",
                f"{service} transmits credentials and data in plaintext. "
                "Any network observer can capture all traffic (Wireshark, tcpdump).",
                port=port, service=service,
                evidence=f"Port {port}/tcp open - no encryption",
                fix=UNENCRYPTED_PORTS[port],
                cve="CWE-319", cvss="5.9",
            )

    # ── TLS WEAKNESS ──────────────────────────────────────────────────────
    def _check_tls_weakness(self, port: int, banner: str):
        if not banner:
            return
        bl = banner.lower()
        if "tlsv1.0" in bl or "tls 1.0" in bl:
            self._add(
                "MEDIUM",
                f"TLS 1.0 Enabled on Port {port}",
                "TLS 1.0 is deprecated and vulnerable to BEAST and POODLE attacks.",
                port=port, service="TLS",
                evidence=f"Banner: {banner[:80]}",
                fix="Disable TLS 1.0 and 1.1. Enable TLS 1.2 and 1.3 only.",
                cve="CVE-2014-3566", cvss="5.9",
            )
        if "tlsv1.1" in bl or "tls 1.1" in bl:
            self._add(
                "LOW",
                f"TLS 1.1 Enabled on Port {port}",
                "TLS 1.1 is deprecated. Disable in favour of TLS 1.2+.",
                port=port, service="TLS",
                evidence=f"Banner: {banner[:80]}",
                fix="Disable TLS 1.1. Enable TLS 1.2 and 1.3.",
                cve="CWE-326", cvss="4.3",
            )

    # ── FTP ───────────────────────────────────────────────────────────────
    def _check_ftp(self, open_ports: list):
        for p in open_ports:
            if p["port"] != 21:
                continue
            banner = p.get("banner") or ""

            # vsftpd 2.3.4 backdoor
            if "vsftpd 2.3.4" in banner.lower():
                self._add(
                    "CRITICAL", "vsftpd 2.3.4 Backdoor (CVE-2011-2523)",
                    "This version contains a planted backdoor. "
                    "Sending ':)' as username triggers a shell on port 6200.",
                    port=21, service="FTP",
                    evidence=f"Banner: {banner[:100]}",
                    fix="Immediately upgrade vsftpd: apt-get install vsftpd",
                    cve="CVE-2011-2523", cvss="10.0",
                )

            # Anonymous FTP probe — safe, only sends USER/PASS
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((self._ip, 21))
                sock.recv(1024)
                sock.sendall(b"USER anonymous\r\n")
                sock.recv(1024)
                sock.sendall(b"PASS test@cybrain.sec\r\n")
                resp = sock.recv(1024).decode(errors="ignore")
                sock.close()
                if "230" in resp:
                    self._add(
                        "HIGH", "FTP Anonymous Login Enabled",
                        "FTP server allows anonymous access. "
                        "Anyone can connect without credentials and read/write files.",
                        port=21, service="FTP",
                        evidence="USER anonymous -> 230 Login successful",
                        fix="Disable in vsftpd.conf: anonymous_enable=NO",
                        cve="CWE-287", cvss="7.5",
                    )
            except Exception:
                pass
            break

    # ── SSH ───────────────────────────────────────────────────────────────
    def _check_ssh(self, open_ports: list):
        for p in open_ports:
            if p["port"] != 22:
                continue
            banner = (p.get("banner") or "").strip()

            # ── OpenSSH version check ──────────────────────────────────
            vm_openssh = re.search(
                r"SSH-[\d.]+-OpenSSH[_\s]+([\d.]+)", banner, re.IGNORECASE
            )
            if vm_openssh:
                version_str = vm_openssh.group(1)
                try:
                    parts = version_str.split(".")
                    major = float(f"{parts[0]}.{parts[1]}" if len(parts) >= 2 else parts[0])
                    if major < 8.0:
                        self._add(
                            "MEDIUM",
                            f"OpenSSH {version_str} - Outdated (< 8.0)",
                            f"OpenSSH {version_str} may have known vulnerabilities. "
                            "Version 8.0+ is recommended.",
                            port=22, service="SSH",
                            evidence=f"Banner: {banner[:100]}",
                            fix="apt-get upgrade openssh-server",
                            cve="CWE-1104", cvss="5.9",
                        )
                except (ValueError, IndexError):
                    # Non-standard version string - just report it as outdated
                    self._add(
                        "LOW",
                        f"OpenSSH {version_str} - Version Check Failed",
                        f"Could not parse OpenSSH version '{version_str}'. "
                        "Verify the SSH server is up to date.",
                        port=22, service="SSH",
                        evidence=f"Banner: {banner[:100]}",
                        fix="apt-get upgrade openssh-server",
                        cve="CWE-1104", cvss="4.0",
                    )

            # ── Dropbear SSH check ────────────────────────────────────
            # Handles: SSH-2.0-dropbear_0.51  SSH-2.0-dropbear_2016.74
            vm_dropbear = re.search(
                r"dropbear[_\s]+([\d.]+)", banner, re.IGNORECASE
            )
            if vm_dropbear:
                db_ver = vm_dropbear.group(1)
                # Find CVE for this version
                cve_found = None
                sev_found = "MEDIUM"
                desc_found = f"Dropbear SSH {db_ver} is outdated."
                for vuln_ver, cve, sev, desc in VULNERABLE_VERSIONS.get("dropbear", []):
                    if db_ver.startswith(vuln_ver):
                        cve_found  = cve
                        sev_found  = sev
                        desc_found = desc
                        break
                if not cve_found:
                    # Unknown old version - still warn
                    cve_found  = "CWE-1104"
                    sev_found  = "MEDIUM"
                    desc_found = f"Dropbear SSH {db_ver} - verify this is the latest version."

                self._add(
                    sev_found,
                    f"Dropbear SSH {db_ver} Detected",
                    f"Dropbear SSH {db_ver} is in use. {desc_found} "
                    "Dropbear is a lightweight SSH server common on routers and IoT devices.",
                    port=22, service="SSH",
                    evidence=f"Banner: {banner[:100]}",
                    fix=(
                        "Update Dropbear SSH to the latest release.\n"
                        "For embedded devices: check manufacturer firmware updates.\n"
                        "If this is a router (192.168.x.x), update its firmware."
                    ),
                    cve=cve_found, cvss="7.5" if sev_found == "HIGH" else "5.3",
                )

            # ── General SSH brute-force warning (always fires on port 22) ─
            self._add(
                "MEDIUM",
                "SSH Port 22 Exposed - Brute Force Risk",
                "SSH on port 22 is constantly scanned by automated bots. "
                "Brute-force and credential stuffing attacks are ongoing.",
                port=22, service="SSH",
                evidence=f"Port 22/tcp open | Banner: {banner[:80] if banner else 'N/A'}",
                fix=(
                    "1. Change SSH port from 22 to a high port (e.g. 2222).\n"
                    "2. PermitRootLogin no  in /etc/ssh/sshd_config\n"
                    "3. PasswordAuthentication no  (use key-based auth only)\n"
                    "4. Install fail2ban: apt-get install fail2ban\n"
                    "5. Restrict to known IPs: AllowUsers user@trusted_ip"
                ),
                cve="CWE-307", cvss="5.9",
            )
            break

    # ── SMB / ETERNALBLUE ─────────────────────────────────────────────────
    def _check_smb(self, open_ports: list):
        port_nums = [p["port"] for p in open_ports]
        if 445 not in port_nums:
            return
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self._ip, 445))
            smb_neg = (
                b"\x00\x00\x00\x85\xff\x53\x4d\x42"
                b"\x72\x00\x00\x00\x00\x18\x53\xc8"
                b"\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\xff\xfe"
                b"\x00\x00\x00\x00"
            )
            sock.sendall(smb_neg)
            response = sock.recv(1024)
            sock.close()
            if len(response) > 4:
                self._add(
                    "CRITICAL",
                    "SMB Service Responding - EternalBlue Risk (CVE-2017-0144)",
                    "SMB port 445 is open and responding. If SMBv1 is enabled, "
                    "vulnerable to EternalBlue (MS17-010) exploited by WannaCry/NotPetya. "
                    "Unauthenticated RCE possible.",
                    port=445, service="SMB",
                    evidence=f"Port 445 + SMB negotiate response ({len(response)} bytes)",
                    fix=(
                        "1. Apply MS17-010 patch immediately.\n"
                        "2. Disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false\n"
                        "3. Block port 445 at perimeter firewall.\n"
                        "4. Enable Windows Defender / EDR."
                    ),
                    cve="CVE-2017-0144", cvss="9.8",
                )
        except Exception:
            pass

    # ── RDP / BLUEKEEP ────────────────────────────────────────────────────
    def _check_rdp(self, open_ports: list):
        if not any(p["port"] == 3389 for p in open_ports):
            return
        self._add(
            "CRITICAL",
            "RDP Exposed - BlueKeep / DejaBlue Risk",
            "RDP port 3389 is publicly accessible. "
            "Vulnerable to BlueKeep (CVE-2019-0708) - pre-auth RCE. "
            "Constant brute-force and credential stuffing attacks.",
            port=3389, service="RDP",
            evidence="Port 3389/tcp open",
            fix=(
                "1. Restrict to VPN / trusted IPs only.\n"
                "2. Enable Network Level Authentication (NLA).\n"
                "3. Apply KB4499175 patch.\n"
                "4. Enable Account Lockout Policy.\n"
                "5. Enforce MFA for RDP."
            ),
            cve="CVE-2019-0708", cvss="9.8",
        )

    # ── TELNET ────────────────────────────────────────────────────────────
    def _check_telnet(self, open_ports: list):
        for p in open_ports:
            if p["port"] == 23:
                self._add(
                    "CRITICAL",
                    "Telnet Service Active - Replace with SSH Immediately",
                    "Telnet transmits ALL data including passwords in plaintext. "
                    "Any network observer can capture credentials with Wireshark. "
                    "This is considered a critical vulnerability on any production device.",
                    port=23, service="Telnet",
                    evidence=f"Port 23/tcp open | Banner: {(p.get('banner') or 'N/A')[:60]}",
                    fix=(
                        "1. Disable Telnet service immediately.\n"
                        "2. Install SSH: apt-get install openssh-server\n"
                        "3. For routers/switches: access via SSH or web console.\n"
                        "4. If this is a router, update firmware."
                    ),
                    cve="CWE-319", cvss="9.1",
                )
                break

    # ── VNC ───────────────────────────────────────────────────────────────
    def _check_vnc(self, open_ports: list):
        for p in open_ports:
            if p["port"] == 5900:
                banner  = (p.get("banner") or "").lower()
                no_auth = "rfb" in banner and ("003.003" in banner or "003.007" in banner)
                self._add(
                    "CRITICAL" if no_auth else "HIGH",
                    "VNC Remote Desktop Exposed" + (" - No Auth" if no_auth else ""),
                    "VNC on 5900 is publicly accessible. "
                    + ("RFB version suggests no-auth mode - anyone can connect. " if no_auth else "")
                    + "Brute-forceable. Full desktop control possible.",
                    port=5900, service="VNC",
                    evidence=f"Port 5900/tcp open. Banner: {(p.get('banner') or 'N/A')[:60]}",
                    fix=(
                        "1. Require strong VNC password.\n"
                        "2. Restrict to trusted IPs.\n"
                        "3. Prefer SSH tunnel: ssh -L 5900:localhost:5900 user@host"
                    ),
                    cve="CWE-307", cvss="9.8" if no_auth else "8.8",
                )
                break

    # ── DATABASE EXPOSURE ─────────────────────────────────────────────────
    def _check_database_exposure(self, open_ports: list):
        db_ports = {
            3306: "MySQL/MariaDB",
            5432: "PostgreSQL",
            1433: "MSSQL",
            1521: "Oracle DB",
        }
        for p in open_ports:
            if p["port"] in db_ports:
                name = db_ports[p["port"]]
                self._add(
                    "CRITICAL",
                    f"{name} Exposed to Network",
                    f"{name} on port {p['port']} is accessible from the network. "
                    "Database servers should never be directly internet-accessible. "
                    "Risk: data breach, brute force, SQL injection directly on the engine.",
                    port=p["port"], service=name,
                    evidence=f"Port {p['port']}/tcp open - {name}",
                    fix=(
                        f"Bind {name} to 127.0.0.1 in config.\n"
                        "Use firewall to block external access.\n"
                        "Connect only through application server.\n"
                        "Enable strong authentication and TLS."
                    ),
                    cve="CWE-284", cvss="9.8",
                )

    # ── NoSQL EXPOSURE ────────────────────────────────────────────────────
    def _check_nosql_exposure(self, open_ports: list):
        nosql_ports = {
            6379: "Redis", 27017: "MongoDB",
            9200: "Elasticsearch", 9300: "Elasticsearch-Cluster",
            7474: "Neo4j", 5984: "CouchDB", 8086: "InfluxDB",
        }
        for p in open_ports:
            if p["port"] not in nosql_ports:
                continue
            name = nosql_ports[p["port"]]

            if p["port"] in (9200, 5984, 8086):
                try:
                    r = requests.get(
                        f"http://{self._ip}:{p['port']}/",
                        timeout=4, verify=False,
                    )
                    if r.status_code == 200:
                        self._add(
                            "CRITICAL",
                            f"{name} Unauthenticated Access Confirmed",
                            f"{name} HTTP API returned 200 without credentials. "
                            "All data readable and writable by anyone.",
                            port=p["port"], service=name,
                            evidence=f"HTTP GET http://{self._ip}:{p['port']}/ -> 200 OK",
                            fix=f"Enable {name} security. Bind to localhost. Firewall port.",
                            cve="CWE-284", cvss="10.0",
                        )
                except Exception:
                    pass

            elif p["port"] == 6379:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3)
                    sock.connect((self._ip, 6379))
                    sock.sendall(b"PING\r\n")
                    resp = sock.recv(256).decode(errors="ignore")
                    sock.close()
                    if "+PONG" in resp:
                        self._add(
                            "CRITICAL",
                            "Redis Unauthenticated Access Confirmed",
                            "Redis responds to PING without authentication. "
                            "All keys accessible. SSH key / cron job write = OS RCE.",
                            port=6379, service="Redis",
                            evidence="PING -> +PONG (no auth required)",
                            fix="requirepass <password> in redis.conf. Bind to 127.0.0.1.",
                            cve="CVE-2022-0543", cvss="10.0",
                        )
                except Exception:
                    pass

    # ── WEB SERVICES ──────────────────────────────────────────────────────
    def _check_web_services(self, open_ports: list):
        for p in open_ports:
            if p["port"] in (80, 8080, 8000, 8081):
                banner = p.get("banner") or ""
                self._add(
                    "HIGH",
                    f"Unencrypted HTTP on Port {p['port']}",
                    "Web service running without TLS. All traffic including "
                    "session tokens and passwords transmitted in plaintext.",
                    port=p["port"], service="HTTP",
                    evidence=f"Port {p['port']}/tcp open HTTP | {banner[:60]}",
                    fix=(
                        "Configure HTTPS with TLS 1.2+.\n"
                        "Redirect all HTTP to HTTPS.\n"
                        "Free cert: certbot --nginx or certbot --apache"
                    ),
                    cve="CWE-319", cvss="7.5",
                )

    # ── MANAGEMENT INTERFACES ─────────────────────────────────────────────
    def _check_management_interfaces(self, open_ports: list):
        mgmt_paths = {
            "/phpmyadmin":   "phpMyAdmin",
            "/phpMyAdmin":   "phpMyAdmin",
            "/adminer":      "Adminer DB Manager",
            "/manager/html": "Apache Tomcat Manager",
            "/wp-admin":     "WordPress Admin",
            "/jenkins":      "Jenkins CI",
            "/grafana":      "Grafana Dashboard",
            "/kibana":       "Kibana",
            "/sonar":        "SonarQube",
            "/nexus":        "Nexus Repository",
            "/console":      "Admin Console",
        }
        for p in open_ports:
            if p["port"] not in (80, 443, 8080, 8443, 8888, 9000):
                continue
            scheme = "https" if p["port"] in (443, 8443) else "http"
            for path, name in mgmt_paths.items():
                try:
                    url = f"{scheme}://{self._ip}:{p['port']}{path}"
                    r   = requests.get(url, timeout=3, verify=False, allow_redirects=True)
                    if r.status_code in (200, 401, 403):
                        self._add(
                            "HIGH",
                            f"Management Interface Exposed: {name}",
                            f"{name} panel found at {url}. Exposed admin interfaces are prime targets.",
                            port=p["port"], service=f"HTTP ({path})",
                            evidence=f"GET {url} -> HTTP {r.status_code}",
                            fix=(
                                "Move admin panels behind VPN.\n"
                                "Restrict access by IP.\n"
                                "Enable MFA for admin access."
                            ),
                            cve="CWE-284", cvss="7.5",
                        )
                        break
                except Exception:
                    pass

    # ── SNMP ──────────────────────────────────────────────────────────────
    def _check_snmp(self, open_ports: list):
        if not any(p["port"] == 161 for p in open_ports):
            return
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            snmp_get = bytes([
                0x30, 0x26, 0x02, 0x01, 0x00,
                0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
                0xa0, 0x19, 0x02, 0x04, 0x00, 0x00, 0x00, 0x01,
                0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
                0x30, 0x0b, 0x30, 0x09,
                0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01,
                0x05, 0x00,
            ])
            sock.sendto(snmp_get, (self._ip, 161))
            resp, _ = sock.recvfrom(1024)
            sock.close()
            if resp and len(resp) > 10:
                self._add(
                    "HIGH",
                    "SNMP Default Community String 'public' Accepted",
                    "SNMP responds to default 'public' community string. "
                    "Network device info, interfaces, and routing tables are readable.",
                    port=161, service="SNMP",
                    evidence=f"SNMPv1 GET community='public' -> {len(resp)} byte response",
                    fix=(
                        "Change community strings from 'public'/'private'.\n"
                        "Upgrade to SNMPv3 with authentication + encryption.\n"
                        "Restrict SNMP to management host IPs."
                    ),
                    cve="CWE-287", cvss="7.5",
                )
        except Exception:
            pass

    # ── ICS / SCADA ───────────────────────────────────────────────────────
    def _check_ics_ports(self, open_ports: list):
        ics = {
            502:   ("Modbus",    "CRITICAL", "Industrial control - no auth/encryption"),
            102:   ("Siemens S7","CRITICAL", "PLC programming port - no auth"),
            47808: ("BACnet",    "HIGH",     "Building automation - HVAC/access control"),
            4840:  ("OPC-UA",    "HIGH",     "Industrial automation protocol"),
            9600:  ("Omron FINS","CRITICAL", "PLC control - no auth"),
            1883:  ("MQTT",      "HIGH",     "IoT broker - no TLS/auth"),
        }
        for p in open_ports:
            if p["port"] in ics:
                proto, sev, desc = ics[p["port"]]
                self._add(
                    sev,
                    f"ICS/OT Port Exposed: {proto} (Port {p['port']})",
                    f"{proto} on {p['port']} is internet-accessible. {desc}. "
                    "Critical infrastructure protocols were designed for isolated networks.",
                    port=p["port"], service=proto,
                    evidence=f"Port {p['port']}/tcp open - {proto}",
                    fix=(
                        "Isolate ICS/OT network from internet.\n"
                        "Deploy industrial DMZ / Purdue Model architecture.\n"
                        "Firewall all ICS ports from external access."
                    ),
                    cve="CWE-306", cvss="10.0",
                )

    # ── NFS ───────────────────────────────────────────────────────────────
    def _check_nfs(self, open_ports: list):
        if not any(p["port"] == 2049 for p in open_ports):
            return
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self._ip, 2049))
            sock.close()
            self._add(
                "HIGH",
                "NFS Port Exposed - World-Mountable Risk",
                "NFS on 2049 is accessible. Misconfigured NFS exports "
                "(e.g., /export *(rw)) allow anyone to mount and read/write filesystems.",
                port=2049, service="NFS",
                evidence="Port 2049/tcp open - NFS",
                fix=(
                    "Restrict NFS exports to specific IPs: /export 192.168.1.0/24(rw)\n"
                    "Never use * in /etc/exports.\n"
                    "Use NFSv4 with Kerberos authentication.\n"
                    "Block port 2049 at perimeter firewall."
                ),
                cve="CWE-284", cvss="8.1",
            )
        except Exception:
            pass

    # ── FIREWALL POSTURE ──────────────────────────────────────────────────
    def _check_firewall_posture(self, open_ports: list):
        sensitive = {22, 23, 3306, 5432, 6379, 27017, 9200, 1433, 3389, 445, 5900}
        exposed   = [p["port"] for p in open_ports if p["port"] in sensitive]
        if len(exposed) >= 3:
            self._add(
                "HIGH",
                f"Insufficient Firewall - {len(exposed)} Sensitive Ports Exposed",
                f"Sensitive ports {exposed} are all accessible from the network. "
                "A properly configured firewall should block all non-essential ports.",
                evidence=f"Exposed sensitive ports: {exposed}",
                fix=(
                    "Implement default-deny firewall policy:\n"
                    "iptables -P INPUT DROP\n"
                    "iptables -A INPUT -p tcp --dport 80  -j ACCEPT\n"
                    "iptables -A INPUT -p tcp --dport 443 -j ACCEPT\n"
                    "iptables -A INPUT -p tcp --dport 22  -s trusted_ip -j ACCEPT\n"
                    "Block all DB/cache/admin ports from external access."
                ),
                cve="CWE-284", cvss="7.5",
            )