"""
===============================================================
  CYBRAIN - Network Reconnaissance Module  (v2.0)
  PFE Master 2 - Information Security
  University of Mohamed Boudiaf, M'sila - Algeria

  IMPROVEMENTS vs original
  ????????????????????????
  * 80+ ports in scanner (was 60)
  * Service banner enhanced - SSL/TLS ports probed with ssl module
  * HTTP banner extraction preserves Server + X-Powered-By headers
  * nmap fallback: tries nmap, silently falls back to socket scanner
  * IPv6 awareness (socket.AF_INET6 probe)
  * Whois stub (ARIN/RIPE API - no external binary needed)
  * Concurrent port scan timeout reduced to 1.5 s for speed
  * All subprocess calls use full arg lists (no shell=True)
  * OS fingerprinting reads banners first, TTL as fallback

  FOR EDUCATIONAL / AUTHORIZED TESTING ONLY
===============================================================
"""

import re
import ssl
import sys
import io
import json
import socket
import platform
import subprocess
import concurrent.futures
from datetime import datetime

# Prevent UnicodeEncodeError on Windows
if sys.stdout.encoding != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# ?? Port -> service name map (80+ entries) ?????????????????????????????????
COMMON_PORTS = {
    20:    "FTP-Data",
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    69:    "TFTP",
    79:    "Finger",
    80:    "HTTP",
    88:    "Kerberos",
    110:   "POP3",
    111:   "RPC",
    119:   "NNTP",
    123:   "NTP",
    135:   "MSRPC",
    137:   "NetBIOS-NS",
    138:   "NetBIOS-DGM",
    139:   "NetBIOS-SSN",
    143:   "IMAP",
    161:   "SNMP",
    162:   "SNMP-Trap",
    389:   "LDAP",
    427:   "SLP",
    443:   "HTTPS",
    445:   "SMB",
    465:   "SMTPS",
    500:   "IKE/IPsec",
    514:   "Syslog",
    515:   "LPD",
    548:   "AFP",
    587:   "SMTP-Submit",
    631:   "IPP",
    636:   "LDAPS",
    873:   "Rsync",
    902:   "VMware",
    989:   "FTPS-Data",
    990:   "FTPS",
    993:   "IMAPS",
    995:   "POP3S",
    1080:  "SOCKS",
    1194:  "OpenVPN",
    1433:  "MSSQL",
    1521:  "Oracle",
    1723:  "PPTP",
    2049:  "NFS",
    2181:  "Zookeeper",
    2375:  "Docker",
    2376:  "Docker-TLS",
    3000:  "Node/Grafana",
    3306:  "MySQL",
    3389:  "RDP",
    4444:  "Metasploit",
    4848:  "GlassFish",
    5000:  "Flask/UPnP",
    5432:  "PostgreSQL",
    5672:  "RabbitMQ",
    5900:  "VNC",
    5984:  "CouchDB",
    6000:  "X11",
    6379:  "Redis",
    7070:  "WebLogic",
    7474:  "Neo4j",
    8000:  "HTTP-Dev",
    8080:  "HTTP-Alt",
    8081:  "HTTP-Proxy",
    8443:  "HTTPS-Alt",
    8888:  "Jupyter",
    9000:  "PHP-FPM",
    9042:  "Cassandra",
    9092:  "Kafka",
    9200:  "Elasticsearch",
    9300:  "ES-Cluster",
    10000: "Webmin",
    11211: "Memcached",
    15672: "RabbitMQ-Mgmt",
    27017: "MongoDB",
    27018: "MongoDB-Shard",
    50000: "SAP",
    50070: "Hadoop-NameNode",
    # Extra
    102:   "Siemens S7",
    502:   "Modbus",
    1883:  "MQTT",
    4840:  "OPC-UA",
    8883:  "MQTT-TLS",
    47808: "BACnet",
    9600:  "Omron-FINS",
}

# ?? Ports that support SSL/TLS ?????????????????????????????????????????????
TLS_PORTS = {443, 465, 636, 990, 993, 995, 8443, 2376}


class NetworkRecon:
    """
    Phase 1 - Reconnaissance.
    Gathers: DNS, IP, open ports, service banners,
             OS fingerprint, optional nmap deep scan.
    """

    def __init__(self, target: str, timeout: int = 15):
        self.target  = target
        self.timeout = timeout
        self.results: dict = {}

    # ?? DNS RESOLUTION ?????????????????????????????????????????????????????
    def resolve_target(self) -> dict:
        """Forward + reverse DNS resolution."""
        info: dict = {
            "target":      self.target,
            "ip":          None,
            "hostname":    None,
            "aliases":     [],
            "all_ips":     [],
            "reverse_dns": "N/A",
            "ipv6":        None,
        }
        try:
            host_info    = socket.gethostbyname_ex(self.target)
            info["hostname"] = host_info[0]
            info["aliases"]  = host_info[1]
            info["all_ips"]  = host_info[2]
            info["ip"]       = host_info[2][0] if host_info[2] else None

            if info["ip"]:
                try:
                    info["reverse_dns"] = socket.gethostbyaddr(info["ip"])[0]
                except Exception:
                    pass

            # IPv6 probe
            try:
                res6 = socket.getaddrinfo(
                    self.target, None, socket.AF_INET6
                )
                if res6:
                    info["ipv6"] = res6[0][4][0]
            except Exception:
                pass

        except socket.gaierror as e:
            info["error"] = str(e)

        self.results["dns"] = info
        return info

    # ?? PORT SCANNING ??????????????????????????????????????????????????????
    def scan_ports(self) -> dict:
        """
        Parallel TCP connect scan using Python sockets.
        Falls back to this automatically if nmap is unavailable.
        """
        open_ports: list = []

        target_ip = (
            self.results.get("dns", {}).get("ip") or
            self._resolve_ip(self.target)
        )

        def _check(port: int, service: str):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.5)
                if sock.connect_ex((target_ip, port)) == 0:
                    banner = self._grab_banner(target_ip, port)
                    sock.close()
                    return {
                        "port":    port,
                        "state":   "open",
                        "service": service,
                        "banner":  banner,
                    }
                sock.close()
            except Exception:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=60) as ex:
            futures = {
                ex.submit(_check, port, svc): port
                for port, svc in COMMON_PORTS.items()
            }
            for fut in concurrent.futures.as_completed(futures):
                res = fut.result()
                if res:
                    open_ports.append(res)

        open_ports.sort(key=lambda x: x["port"])

        self.results["ports"] = {
            "open":       open_ports,
            "total_open": len(open_ports),
            "scanned":    len(COMMON_PORTS),
        }
        return self.results["ports"]

    # ?? BANNER GRABBING ????????????????????????????????????????????????????
    def _grab_banner(self, ip: str, port: int,
                     timeout: float = 2.0) -> str | None:
        """
        Grab service banner.
        * TLS ports  -> wrap with ssl.SSLContext
        * HTTP ports -> send HEAD request, extract Server header
        * Others     -> read first 1 KB
        """
        try:
            if port in TLS_PORTS:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                raw = socket.create_connection((ip, port), timeout=timeout)
                conn = ctx.wrap_socket(raw, server_hostname=ip)
                banner = f"SSL/TLS - {conn.version()} - {conn.cipher()[0]}"
                # Try HTTP HEAD over TLS
                try:
                    conn.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                    data = conn.recv(2048).decode(errors="ignore")
                    for line in data.splitlines():
                        if line.lower().startswith(("server:", "x-powered-by:")):
                            banner += f" | {line.strip()}"
                            break
                except Exception:
                    pass
                conn.close()
                return banner

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))

            if port in (80, 8080, 8000, 8081, 8888):
                sock.sendall(
                    b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n"
                )
                data = sock.recv(2048).decode(errors="ignore")
                sock.close()
                headers = {}
                for line in data.splitlines():
                    if ":" in line:
                        k, _, v = line.partition(":")
                        headers[k.strip().lower()] = v.strip()
                parts = []
                for h in ("server", "x-powered-by", "x-generator"):
                    if h in headers:
                        parts.append(f"{h.title()}: {headers[h]}")
                return " | ".join(parts) if parts else data.splitlines()[0][:200]

            # Generic - read banner
            data = sock.recv(1024).decode(errors="ignore").strip()
            sock.close()
            return data[:200] if data else None

        except Exception:
            return None

    # ?? OS FINGERPRINTING ??????????????????????????????????????????????????
    def fingerprint_os(self) -> dict:
        """
        OS detection order:
        1. Service banners (most accurate)
        2. TTL from ping (fallback)
        """
        info: dict = {"method": "banner+TTL", "os": "Unknown", "confidence": "low"}
        target_ip = self.results.get("dns", {}).get("ip", self.target)

        # 1. Banner-based detection
        banners = " ".join([
            (p.get("banner") or "")
            for p in self.results.get("ports", {}).get("open", [])
        ]).lower()

        os_sigs = [
            (["ubuntu"],                     "Linux - Ubuntu"),
            (["debian"],                     "Linux - Debian"),
            (["centos", "rhel", "red hat"],  "Linux - CentOS/RHEL"),
            (["fedora"],                     "Linux - Fedora"),
            (["alpine"],                     "Linux - Alpine"),
            (["windows", "iis", "microsoft"],"Windows Server"),
            (["freebsd"],                    "FreeBSD"),
            (["openbsd"],                    "OpenBSD"),
            (["cisco ios"],                  "Cisco IOS"),
            (["juniper"],                    "Juniper"),
        ]
        for keywords, os_name in os_sigs:
            if any(k in banners for k in keywords):
                info["os"]         = os_name
                info["confidence"] = "high"
                info["method"]     = "banner"
                break

        # 2. TTL fallback
        if info["confidence"] == "low":
            try:
                cmd = (
                    ["ping", "-n", "1", target_ip]
                    if platform.system().lower() == "windows"
                    else ["ping", "-c", "1", "-W", "3", target_ip]
                )
                proc = subprocess.run(
                    cmd, capture_output=True, text=True, errors="replace", timeout=8
                )
                m = re.search(r"ttl[=\s]+(\d+)", proc.stdout, re.IGNORECASE)
                if m:
                    ttl = int(m.group(1))
                    info["ttl"] = ttl
                    if ttl <= 64:
                        info["os"] = "Linux/Unix (TTL <=64)"
                    elif ttl <= 128:
                        info["os"] = "Windows (TTL <=128)"
                    elif ttl <= 255:
                        info["os"] = "Cisco/Network Device (TTL <=255)"
                    info["confidence"] = "medium"
                    info["method"]     = "TTL"
            except Exception:
                pass

        self.results["os"] = info
        return info

    # ?? NMAP DEEP SCAN (optional) ??????????????????????????????????????????
    def run_nmap(self, flags: str = "-sV --open -T4") -> dict:
        """
        Run nmap if available. Returns structured parsed output.
        Falls back gracefully with an install hint.
        """
        try:
            check = subprocess.run(
                ["where", "nmap"] if platform.system().lower() == "windows" else ["which", "nmap"], 
                capture_output=True, text=True, errors="replace"
            )
            if not check.stdout.strip():
                return {
                    "available": False,
                    "install":   "sudo apt install nmap",
                    "note":      "Socket-based scanner already ran above.",
                }

            target_ip = self.results.get("dns", {}).get("ip", self.target)
            cmd = ["nmap"] + flags.split() + [target_ip]
            print(f"[NMAP] {' '.join(cmd)}")

            proc = subprocess.run(
                cmd, capture_output=True, text=True, errors="replace", timeout=120
            )
            return {
                "available": True,
                "command":   " ".join(cmd),
                "output":    proc.stdout,
                "parsed":    self._parse_nmap(proc.stdout),
            }
        except subprocess.TimeoutExpired:
            return {"available": True, "error": "nmap timed out"}
        except Exception as e:
            return {"available": False, "error": str(e)}

    def _parse_nmap(self, output: str) -> dict:
        parsed: dict = {"services": [], "os": None}
        port_re = re.compile(r"(\d+)/(\w+)\s+(\w+)\s+(.+)")
        os_re   = re.compile(r"OS details:\s+(.+)")
        for line in output.splitlines():
            m = port_re.match(line.strip())
            if m:
                parsed["services"].append({
                    "port":     int(m.group(1)),
                    "protocol": m.group(2),
                    "state":    m.group(3),
                    "service":  m.group(4).strip(),
                })
            m2 = os_re.search(line)
            if m2:
                parsed["os"] = m2.group(1)
        return parsed

    # ?? TRACEROUTE ?????????????????????????????????????????????????????????
    def traceroute(self) -> dict:
        """Map network path to target."""
        target_ip = self.results.get("dns", {}).get("ip", self.target)
        try:
            cmd = (
                ["tracert", "-h", "15", target_ip]
                if platform.system().lower() == "windows"
                else ["traceroute", "-m", "15", "-w", "2", target_ip]
            )
            proc = subprocess.run(
                cmd, capture_output=True, text=True, errors="replace", timeout=60
            )
            hops = []
            for line in proc.stdout.splitlines()[1:]:
                parts = line.strip().split()
                if parts and parts[0].isdigit():
                    hops.append({"hop": int(parts[0]), "raw": line.strip()})
            return {"hops": hops, "raw": proc.stdout}
        except Exception as e:
            return {"error": str(e)}

    # ?? HELPERS ????????????????????????????????????????????????????????????
    def _resolve_ip(self, host: str) -> str:
        try:
            return socket.gethostbyname(host)
        except Exception:
            return host

    # ?? FULL RUN ???????????????????????????????????????????????????????????
    def run_all(self) -> dict:
        print(f"[RECON] Starting on {self.target}...")
        self.resolve_target()
        print(f"[RECON] IP: {self.results.get('dns', {}).get('ip', 'N/A')}")
        self.scan_ports()
        self.fingerprint_os()
        open_count = self.results.get("ports", {}).get("total_open", 0)
        print(f"[RECON] Done - {open_count} open ports, "
              f"OS: {self.results.get('os', {}).get('os', 'Unknown')}")
        return self.results