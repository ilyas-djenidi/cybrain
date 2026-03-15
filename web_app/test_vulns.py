
import sys
import os

# Add web_app to path
sys.path.append(r'c:\Users\HP\Desktop\misconfiguration_datasets-master\web_app')

from network_vulns import NetworkVulnScanner

mock_recon = {
    "dns": {"ip": "127.0.0.1"},
    "ports": {
        "open": [
            {"port": 21, "service": "ftp", "banner": "220 vsFTPd 2.3.4"},
            {"port": 22, "service": "ssh", "banner": "SSH-2.0-OpenSSH_7.2"},
            {"port": 23, "service": "telnet", "banner": "Telnet prompt"},
            {"port": 80, "service": "http", "banner": "Apache/2.4.49"}
        ],
        "total_open": 4,
        "scanned": 100
    }
}

try:
    print("Testing NetworkVulnScanner...")
    scanner = NetworkVulnScanner("127.0.0.1", mock_recon)
    findings = scanner.scan_all()
    print(f"Success! Found {len(findings)} issues.")
    for f in findings:
        print(f"- {f['severity']}: {f['title']}")
except Exception as e:
    import traceback
    print(f"FAILED: {e}")
    traceback.print_exc()
