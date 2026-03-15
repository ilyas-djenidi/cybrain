"""
CYBRAIN — Network Reconnaissance Module
PFE Master 2 — Information Security
Tools: nmap, socket, ping, traceroute, DNS
"""

import socket
import subprocess
import platform
import re
import json
import concurrent.futures
from datetime import datetime


class NetworkRecon:
    """
    Phase 1: Reconnaissance
    Gathers intelligence about the target network/host
    """

    def __init__(self, target, timeout=15):
        self.target  = target
        self.timeout = timeout
        self.results = {}

    # ── DNS RESOLUTION ──────────────────────────────────────
    def resolve_target(self):
        """Resolve hostname to IP and get DNS info."""
        info = {
            "target":   self.target,
            "ip":       None,
            "hostname": None,
            "aliases":  [],
            "all_ips":  [],
        }
        try:
            # Forward DNS
            host_info = socket.gethostbyname_ex(self.target)
            info["hostname"] = host_info[0]
            info["aliases"]  = host_info[1]
            info["all_ips"]  = host_info[2]
            info["ip"]       = host_info[2][0] if host_info[2] else None

            # Reverse DNS
            if info["ip"]:
                try:
                    rev = socket.gethostbyaddr(info["ip"])
                    info["reverse_dns"] = rev[0]
                except Exception:
                    info["reverse_dns"] = "N/A"

        except socket.gaierror as e:
            info["error"] = str(e)

        self.results["dns"] = info
        return info

    # ── PORT SCANNING ────────────────────────────────────────
    def scan_ports(self, port_range="common"):
        """
        Scan ports using Python sockets (no nmap needed).
        Falls back to nmap if available.
        """
        # Common ports to scan
        common_ports = {
            21:   "FTP",
            22:   "SSH",
            23:   "Telnet",
            25:   "SMTP",
            53:   "DNS",
            80:   "HTTP",
            110:  "POP3",
            111:  "RPC",
            135:  "MSRPC",
            139:  "NetBIOS",
            143:  "IMAP",
            443:  "HTTPS",
            445:  "SMB",
            993:  "IMAPS",
            995:  "POP3S",
            1433: "MSSQL",
            1521: "Oracle",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            6379: "Redis",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt",
            8888: "HTTP-Dev",
            9200: "Elasticsearch",
            27017:"MongoDB",
            20:   "FTP-Data",
            69:   "TFTP",
            79:   "Finger",
            88:   "Kerberos",
            119:  "NNTP",
            123:  "NTP",
            161:  "SNMP",
            162:  "SNMP-Trap",
            389:  "LDAP",
            427:  "SLP",
            465:  "SMTPS",
            514:  "Syslog",
            515:  "LPD",
            548:  "AFP",
            587:  "SMTP-Submit",
            631:  "IPP",
            636:  "LDAPS",
            873:  "Rsync",
            902:  "VMware",
            989:  "FTPS-Data",
            990:  "FTPS",
            1080: "SOCKS",
            1194: "OpenVPN",
            1723: "PPTP",
            2049: "NFS",
            2181: "Zookeeper",
            2375: "Docker",
            2376: "Docker-TLS",
            3000: "Node/Grafana",
            4444: "Metasploit",
            4848: "GlassFish",
            5000: "Flask/UPnP",
            5672: "RabbitMQ",
            5984: "CouchDB",
            6000: "X11",
            7070: "WebLogic",
            7474: "Neo4j",
            8000: "HTTP-Dev",
            8081: "HTTP-Proxy",
            8888: "Jupyter",
            9000: "PHP-FPM",
            9042: "Cassandra",
            9092: "Kafka",
            9300: "ES-Cluster",
            10000:"Webmin",
            11211:"Memcached",
            15672:"RabbitMQ-Mgmt",
            27018:"MongoDB-Shard",
            50000:"SAP",
            50070:"Hadoop",
        }

        open_ports   = []
        closed_ports = []

        target_ip = self.results.get("dns", {}).get("ip")
        if not target_ip:
            try:
                target_ip = socket.gethostbyname(self.target)
            except Exception:
                target_ip = self.target

        def check_port(port, service):
            try:
                sock = socket.socket(
                    socket.AF_INET, socket.SOCK_STREAM
                )
                sock.settimeout(2)  # 2 seconds per port
                result = sock.connect_ex((target_ip, port))
                sock.close()
                if result == 0:
                    # Try banner grab
                    banner = self._grab_banner(
                        target_ip, port
                    )
                    return {
                        "port":    port,
                        "state":   "open",
                        "service": service,
                        "banner":  banner,
                    }
            except Exception:
                pass
            return None

        # Parallel port scanning
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=50
        ) as executor:
            futures = {
                executor.submit(check_port, port, svc): port
                for port, svc in common_ports.items()
            }
            for future in concurrent.futures.as_completed(
                futures
            ):
                result = future.result()
                if result:
                    open_ports.append(result)

        # Sort by port number
        open_ports.sort(key=lambda x: x["port"])

        self.results["ports"] = {
            "open":  open_ports,
            "total_open": len(open_ports),
            "scanned": len(common_ports),
        }
        return self.results["ports"]

    def _grab_banner(self, ip, port, timeout=2):
        """Grab service banner for version detection."""
        try:
            sock = socket.socket(
                socket.AF_INET, socket.SOCK_STREAM
            )
            sock.settimeout(timeout)
            sock.connect((ip, port))
            # Send HTTP request for web ports
            if port in [80, 8080, 8888]:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port == 443:
                sock.close()
                return "SSL/TLS"
            banner = sock.recv(1024).decode(
                errors="ignore"
            ).strip()
            sock.close()
            return banner[:200] if banner else None
        except Exception:
            return None

    # ── NMAP INTEGRATION ─────────────────────────────────────
    def run_nmap(self, flags="-sV -sC --open -T4"):
        """
        Run nmap if available on the system.
        Requires: sudo apt install nmap
        """
        try:
            # Check if nmap exists
            check = subprocess.run(
                ["which", "nmap"],
                capture_output=True, text=True
            )
            if not check.stdout.strip():
                return {"error": "nmap not installed",
                        "install": "sudo apt install nmap"}

            target_ip = self.results.get(
                "dns", {}
            ).get("ip", self.target)

            cmd = ["nmap"] + flags.split() + [target_ip]
            print(f"[NMAP] Running: {' '.join(cmd)}")

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )

            return {
                "command": " ".join(cmd),
                "output":  proc.stdout,
                "errors":  proc.stderr,
                "parsed":  self._parse_nmap_output(
                    proc.stdout
                ),
            }
        except subprocess.TimeoutExpired:
            return {"error": "nmap scan timed out"}
        except Exception as e:
            return {"error": str(e)}

    def _parse_nmap_output(self, output):
        """Parse nmap text output into structured data."""
        parsed = {
            "hosts":    [],
            "os":       None,
            "services": [],
        }
        port_pattern = re.compile(
            r"(\d+)/(\w+)\s+(\w+)\s+(.+)"
        )
        os_pattern = re.compile(
            r"OS details: (.+)"
        )
        for line in output.splitlines():
            pm = port_pattern.match(line.strip())
            if pm:
                parsed["services"].append({
                    "port":     int(pm.group(1)),
                    "protocol": pm.group(2),
                    "state":    pm.group(3),
                    "service":  pm.group(4).strip(),
                })
            om = os_pattern.search(line)
            if om:
                parsed["os"] = om.group(1)
        return parsed

    # ── OS FINGERPRINTING ────────────────────────────────────
    def fingerprint_os(self):
        """Basic OS detection via TTL and banner analysis."""
        info = {"method": "TTL analysis", "os": "Unknown"}
        target_ip = self.results.get(
            "dns", {}
        ).get("ip", self.target)

        try:
            if platform.system().lower() == "windows":
                cmd = ["ping", "-n", "1", target_ip]
            else:
                cmd = ["ping", "-c", "1", target_ip]

            proc = subprocess.run(
                cmd, capture_output=True,
                text=True, timeout=10
            )
            output = proc.stdout

            # TTL-based OS detection
            ttl_match = re.search(
                r"ttl[=\s]+(\d+)", output, re.IGNORECASE
            )
            if ttl_match:
                ttl = int(ttl_match.group(1))
                info["ttl"] = ttl
                if ttl <= 64:
                    info["os"] = "Linux/Unix"
                elif ttl <= 128:
                    info["os"] = "Windows"
                elif ttl <= 255:
                    info["os"] = "Cisco/Network Device"

        except Exception as e:
            info["error"] = str(e)

        # Check banners for OS hints
        banners = []
        for port_info in self.results.get(
            "ports", {}
        ).get("open", []):
            if port_info.get("banner"):
                banners.append(port_info["banner"])

        for banner in banners:
            b = banner.lower()
            if "ubuntu" in b or "debian" in b:
                info["os"] = "Linux (Ubuntu/Debian)"
            elif "centos" in b or "rhel" in b:
                info["os"] = "Linux (CentOS/RHEL)"
            elif "windows" in b or "iis" in b:
                info["os"] = "Windows Server"
            elif "freebsd" in b:
                info["os"] = "FreeBSD"

        self.results["os"] = info
        return info

    # ── TRACEROUTE ───────────────────────────────────────────
    def traceroute(self):
        """Run traceroute to map network path."""
        target_ip = self.results.get(
            "dns", {}
        ).get("ip", self.target)
        try:
            if platform.system().lower() == "windows":
                cmd = ["tracert", "-h", "15", target_ip]
            else:
                cmd = ["traceroute", "-m", "15", target_ip]

            proc = subprocess.run(
                cmd, capture_output=True,
                text=True, timeout=60
            )
            hops = []
            for line in proc.stdout.splitlines()[1:]:
                parts = line.strip().split()
                if parts and parts[0].isdigit():
                    hops.append({
                        "hop": int(parts[0]),
                        "raw": line.strip()
                    })
            return {"hops": hops, "raw": proc.stdout}
        except Exception as e:
            return {"error": str(e)}

    def run_all(self):
        """Run complete reconnaissance."""
        print(f"[RECON] Starting on {self.target}...")
        self.resolve_target()
        self.scan_ports()
        self.fingerprint_os()
        print(
            f"[RECON] Done. "
            f"{self.results['ports']['total_open']} "
            "open ports found."
        )
        return self.results
