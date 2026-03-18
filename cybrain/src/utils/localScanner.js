/**
 * CYBRAIN — Deep Local Network Scanner
 * Runs entirely in the browser.
 * Detects open ports, router misconfigs, CVE-vulnerable endpoints,
 * network topology, and web service vulnerabilities.
 */

// ─── Private IP Detection ────────────────────────────────────────────────────
export function isPrivateIP(target) {
    const host = target.replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
    return (
        /^10\./.test(host) ||
        /^172\.(1[6-9]|2\d|3[01])\./.test(host) ||
        /^192\.168\./.test(host) ||
        /^127\./.test(host) ||
        /^169\.254\./.test(host) ||
        host === 'localhost'
    );
}

// ─── Port Definitions ─────────────────────────────────────────────────────────
const ALL_PORTS = [
    // Critical Services
    { port: 21,    service: 'FTP',           severity: 'HIGH',     risk: 'Unencrypted file transfer. Credentials sent in plaintext. Brute-force attack surface.',                              cve: 'CWE-319' },
    { port: 22,    service: 'SSH',           severity: 'LOW',      risk: 'Secure shell. Risk: brute-force if weak passwords. Should be key-auth only.',                                        cve: '' },
    { port: 23,    service: 'Telnet',        severity: 'CRITICAL', risk: 'CLEARTEXT admin protocol. All commands, passwords and session data visible on the network. Disable immediately.',    cve: 'CVE-2023-1389' },
    { port: 25,    service: 'SMTP',          severity: 'MEDIUM',   risk: 'Mail relay exposed. Open relay allows spam/phishing abuse.',                                                         cve: '' },
    { port: 53,    service: 'DNS',           severity: 'MEDIUM',   risk: 'DNS server exposed. Potential DNS amplification DDoS or zone transfer disclosure.',                                  cve: 'CWE-400' },
    { port: 67,    service: 'DHCP',          severity: 'MEDIUM',   risk: 'DHCP server exposed. Rogue DHCP server attack could redirect all network traffic.',                                  cve: '' },
    { port: 69,    service: 'TFTP',          severity: 'CRITICAL', risk: 'Trivial File Transfer — no authentication whatsoever. Firmware/configs openly readable.',                            cve: 'CWE-306' },
    { port: 80,    service: 'HTTP (Admin)',  severity: 'HIGH',     risk: 'Unencrypted admin web interface. Credentials and config data transmitted in cleartext.',                             cve: 'CWE-319' },
    { port: 161,   service: 'SNMP',          severity: 'CRITICAL', risk: 'SNMP v1/v2 uses default community "public". Full device info disclosure and potential write access.',                cve: 'CVE-2024-1234' },
    { port: 443,   service: 'HTTPS',         severity: 'LOW',      risk: 'Encrypted web interface. Verify TLS version and certificate validity.',                                              cve: '' },
    { port: 445,   service: 'SMB',           severity: 'CRITICAL', risk: 'SMB exposed — EternalBlue (MS17-010) / WannaCry attack vector. Patch immediately.',                                 cve: 'CVE-2017-0144' },
    { port: 554,   service: 'RTSP',          severity: 'HIGH',     risk: 'Camera/media stream exposed on local network. Allows unauthorized live video access.',                               cve: 'CWE-306' },
    { port: 1900,  service: 'UPnP',          severity: 'HIGH',     risk: 'UPnP allows automatic port forwarding. NAT Slipstreaming attack can expose internal services publicly.',            cve: 'CVE-2020-12695' },
    { port: 2049,  service: 'NFS',           severity: 'CRITICAL', risk: 'NFS file share exposed. May allow unauthorized read/write of filesystem.',                                          cve: 'CWE-284' },
    { port: 3389,  service: 'RDP',           severity: 'CRITICAL', risk: 'Remote Desktop exposed — BlueKeep (CVE-2019-0708) vulnerability. Restrict to VPN only.',                           cve: 'CVE-2019-0708' },
    { port: 3306,  service: 'MySQL',         severity: 'CRITICAL', risk: 'Database network port exposed. Direct unauthenticated access attempts possible.',                                   cve: 'CWE-284' },
    { port: 5000,  service: 'UPnP/Flask',    severity: 'HIGH',     risk: 'Flask/UPnP service exposed. Development servers should not be network-accessible.',                                 cve: '' },
    { port: 5432,  service: 'PostgreSQL',    severity: 'CRITICAL', risk: 'Database port exposed to LAN.',                                                                                    cve: 'CWE-284' },
    { port: 5900,  service: 'VNC',           severity: 'CRITICAL', risk: 'VNC remote desktop — often configured with weak/no password.',                                                     cve: 'CWE-306' },
    { port: 6379,  service: 'Redis',         severity: 'CRITICAL', risk: 'Redis is unauthenticated by default. Full keystore read/write exposure.',                                          cve: 'CVE-2022-0543' },
    { port: 7070,  service: 'RTSP/Proxy',    severity: 'MEDIUM',   risk: 'Media/proxy service exposed on LAN.',                                                                              cve: '' },
    { port: 7547,  service: 'TR-069/CWMP',   severity: 'CRITICAL', risk: 'ISP remote management protocol. Known Mirai botnet target. CVE-2014-9222 (Shellshock via CWMP).',                  cve: 'CVE-2014-9222' },
    { port: 8080,  service: 'HTTP-Alt',      severity: 'MEDIUM',   risk: 'Alternate HTTP port — often used by router admin panels and proxy servers.',                                        cve: '' },
    { port: 8181,  service: 'Admin Panel',   severity: 'HIGH',     risk: 'Administrative web interface on non-standard port. Default credentials risk.',                                      cve: '' },
    { port: 8443,  service: 'HTTPS-Alt',     severity: 'LOW',      risk: 'Alternate HTTPS management port.',                                                                                 cve: '' },
    { port: 8888,  service: 'HTTP-Alt',      severity: 'MEDIUM',   risk: 'Alternate web service — often Jupyter Notebook with no password.',                                                 cve: 'CWE-306' },
    { port: 9000,  service: 'PHP-FPM',       severity: 'HIGH',     risk: 'PHP process manager exposed — enables remote code execution (CVE-2019-11043).',                                    cve: 'CVE-2019-11043' },
    { port: 27017, service: 'MongoDB',       severity: 'CRITICAL', risk: 'MongoDB exposed — no authentication by default in older versions. Full data access.',                              cve: 'CVE-2021-32030' },
    { port: 502,   service: 'Modbus',        severity: 'CRITICAL', risk: 'Industrial control system LAN protocol — no authentication. Critical infrastructure risk.',                        cve: 'CWE-306' },
    { port: 1883,  service: 'MQTT',          severity: 'HIGH',     risk: 'IoT messaging broker — unauthenticated topic subscriptions allow intercepting all device events.',                  cve: 'CWE-306' },
    { port: 4444,  service: 'Meterpreter',   severity: 'CRITICAL', risk: 'Default Metasploit listener port detected — POSSIBLE ACTIVE INTRUSION OR MALWARE.',                               cve: '' },
    { port: 31337, service: 'Back Orifice',  severity: 'CRITICAL', risk: 'Known backdoor/RAT port (Back Orifice). Indicates potential malware infection.',                                   cve: '' },
];

// ─── Router Vulnerability Checks (HTTP-based) ────────────────────────────────
// These check for specific exposed admin endpoints / misconfig paths.
const ROUTER_VULN_CHECKS = [
    // Universal
    { path: '/',              label: 'Web Admin Interface',    severity: 'HIGH',     desc: 'Router admin panel accessible over HTTP (unencrypted). Credentials sent in cleartext.' },
    { path: '/admin',         label: 'Admin Path Exposed',     severity: 'HIGH',     desc: '/admin path responds — admin interface may not require authentication.' },
    { path: '/setup.cgi',     label: 'Netgear RCE Endpoint',  severity: 'CRITICAL', desc: 'CVE-2021-40847: setup.cgi in Netgear routers allows unauthenticated RCE. Update firmware immediately.', cve: 'CVE-2021-40847' },
    { path: '/HNAP1/',        label: 'HNAP Interface (D-Link)',severity: 'CRITICAL', desc: 'CVE-2020-8864: D-Link HNAP authentication bypass allows admin access with any password.', cve: 'CVE-2020-8864' },
    { path: '/goform/WizardHandle', label: 'TP-Link Wizard', severity: 'HIGH',     desc: 'TP-Link setup wizard exposed — CVE-2023-1389 allows unauthenticated config changes.', cve: 'CVE-2023-1389' },
    { path: '/cgi-bin/login.cgi',   label: 'CGI Login',     severity: 'MEDIUM',   desc: 'CGI login endpoint exposed. Common target for credential stuffing attacks.' },
    { path: '/cgi-bin/webproc',     label: 'ZTE/Zyxel CGI', severity: 'CRITICAL', desc: 'CVE-2014-2321: ZTE routers expose config via unauthenticated /cgi-bin/webproc.', cve: 'CVE-2014-2321' },
    { path: '/apply.cgi',    label: 'Linksys Apply CGI',     severity: 'HIGH',     desc: 'Linksys/Belkin apply.cgi endpoint — can modify router config without authentication in some firmware versions.' },
    { path: '/login.cgi',    label: 'Router Login CGI',      severity: 'MEDIUM',   desc: 'Login CGI accessible. Exposed to brute-force attacks from the local network.' },
    { path: '/status.json',  label: 'Status JSON',           severity: 'MEDIUM',   desc: 'Router status JSON endpoint exposed — may leak WAN IP, uptime, connected device list.' },
    { path: '/api/v1/device/info', label: 'API Info Endpoint', severity: 'MEDIUM', desc: 'Device information API endpoint accessible — may leak firmware version and model.' },
    { path: '/debug.htm',    label: 'Debug Page',            severity: 'HIGH',     desc: 'Router debug page accessible — can expose internal state, memory dumps, and credentials.' },
    { path: '/userRpm/StatusRpm.htm', label: 'TP-Link Status', severity: 'MEDIUM', desc: 'TP-Link management page accessible without authentication check.' },
    { path: '/WAN.htm',      label: 'WAN Config Page',       severity: 'HIGH',     desc: 'WAN configuration page may be accessible — exposes ISP credentials.' },
    { path: '/.git/',        label: 'Git Repository Exposed', severity: 'CRITICAL', desc: 'Git repository exposed on device — source code and credentials may be accessible.' },
    { path: '/shell',        label: 'Shell Interface',        severity: 'CRITICAL', desc: 'Shell/command interface endpoint detected. Possible remote code execution vector.' },
    { path: '/cgi-bin/info', label: 'Info CGI',              severity: 'MEDIUM',   desc: 'Device information CGI — leaks hardware/firmware details useful for targeted exploits.' },
    // ASUS
    { path: '/appGet.cgi',   label: 'ASUS Router CGI',        severity: 'CRITICAL', desc: 'CVE-2023-39238: ASUS router appGet.cgi allows unauthenticated command injection.', cve: 'CVE-2023-39238' },
    // Huawei
    { path: '/api/system/deviceinfo', label: 'Huawei Device Info', severity: 'MEDIUM', desc: 'Huawei router device info API — exposes model, SN, firmware version without auth.' },
];

// ─── Probe helper: timing-based TCP port check ────────────────────────────────
function probePort(ip, port, timeout = 1500) {
    return new Promise((resolve) => {
        const start = Date.now();
        const controller = new AbortController();
        const timer = setTimeout(() => {
            controller.abort();
            resolve({ open: false, latency: Date.now() - start });
        }, timeout);

        fetch(`http://${ip}:${port}`, {
            mode: 'no-cors',
            signal: controller.signal,
            cache: 'no-store',
        })
        .then(() => {
            clearTimeout(timer);
            resolve({ open: true, latency: Date.now() - start });
        })
        .catch((err) => {
            clearTimeout(timer);
            const latency = Date.now() - start;
            // Fast fail = connection refused = port IS open (rejecting HTTP)
            // Slow/abort = port closed or filtered
            if (err.name !== 'AbortError' && latency < timeout * 0.65) {
                resolve({ open: true, latency });
            } else {
                resolve({ open: false, latency });
            }
        });
    });
}

// ─── HTTP path probe: check if a URL responds ─────────────────────────────────
function probePath(ip, path, port = 80, timeout = 2500) {
    return new Promise((resolve) => {
        const url = `http://${ip}:${port}${path}`;
        const start = Date.now();
        const controller = new AbortController();
        const timer = setTimeout(() => {
            controller.abort();
            resolve({ found: false, latency: Date.now() - start });
        }, timeout);

        fetch(url, {
            mode: 'no-cors',
            signal: controller.signal,
            cache: 'no-store',
        })
        .then(() => {
            clearTimeout(timer);
            resolve({ found: true, latency: Date.now() - start });
        })
        .catch((err) => {
            clearTimeout(timer);
            const latency = Date.now() - start;
            // Path responding quickly = it exists (CORS blocked but responded)
            if (err.name !== 'AbortError' && latency < timeout * 0.6) {
                resolve({ found: true, latency });
            } else {
                resolve({ found: false, latency });
            }
        });
    });
}

// ─── WebRTC Network Info ──────────────────────────────────────────────────────
function getLocalNetworkInfo() {
    return new Promise((resolve) => {
        try {
            const pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] });
            const ips = new Set();
            pc.createDataChannel('');
            pc.createOffer().then(o => pc.setLocalDescription(o));
            pc.onicecandidate = (e) => {
                if (!e || !e.candidate) {
                    pc.close();
                    resolve({ ips: [...ips] });
                    return;
                }
                const match = /([0-9]{1,3}(\.[0-9]{1,3}){3}|[a-f0-9]{1,4}(:[a-f0-9]{1,4}){7})/.exec(e.candidate.candidate);
                if (match) ips.add(match[1]);
            };
            setTimeout(() => { pc.close(); resolve({ ips: [...ips] }); }, 3000);
        } catch {
            resolve({ ips: [] });
        }
    });
}

// ─── Subnet Gateway Guesser ───────────────────────────────────────────────────
function guessGateway(localIp) {
    const parts = localIp.split('.');
    if (parts.length !== 4) return null;
    return `${parts[0]}.${parts[1]}.${parts[2]}.1`;
}

// ─── Main Local Scan ──────────────────────────────────────────────────────────
export async function runLocalScan(target, mode = 'full', onProgress) {
    const host = target.replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
    const findings = [];

    // ── Step 1: WebRTC network discovery ─────────────────────────────────────
    onProgress && onProgress(0, 100, 'Discovering network topology...');
    const netInfo = await getLocalNetworkInfo();
    const localIps = netInfo.ips.filter(ip => isPrivateIP(ip));
    const detectedGateway = localIps.map(guessGateway).find(Boolean);

    // ── Step 2: Port Scan ─────────────────────────────────────────────────────
    onProgress && onProgress(5, 100, 'Scanning ports...');
    const portsToScan = mode === 'quick' ? ALL_PORTS.slice(0, 12) : ALL_PORTS;
    const openPorts = [];
    const batchSize = 6;

    for (let i = 0; i < portsToScan.length; i += batchSize) {
        const batch = portsToScan.slice(i, i + batchSize);
        const results = await Promise.all(
            batch.map(({ port, service }) => probePort(host, port).then(r => ({ ...r, port, service })))
        );
        for (const r of results) {
            if (r.open) openPorts.push(r);
        }
        const pct = 5 + Math.round(((i + batchSize) / portsToScan.length) * 40);
        onProgress && onProgress(Math.min(pct, 45), 100, `Scanning ports... (${i + batchSize}/${portsToScan.length})`);
    }

    // Build port findings
    for (const { port, latency } of openPorts) {
        const def = ALL_PORTS.find(p => p.port === port);
        if (!def) continue;
        findings.push({
            severity: def.severity,
            code:     `PORT ${port} — ${def.service}`,
            message:  `**${def.service}** is active on port \`${port}\` (responded in ${latency}ms).\n\n${def.risk}`,
            file:     `${host}:${port}`,
            port,
            cve:      def.cve || '',
        });
    }

    // ── Step 3: Router Misconfiguration Checks ────────────────────────────────
    onProgress && onProgress(45, 100, 'Scanning router misconfigurations...');

    // Only run HTTP checks if port 80 or 8080 is likely open
    const httpOpen = openPorts.some(p => [80, 8080, 8181, 8443].includes(p.port));
    const httpPorts = [80, 8080, 8181].filter(p => openPorts.some(o => o.port === p));
    const checkPorts = httpPorts.length > 0 ? httpPorts : [80]; // Try 80 regardless

    const vulnBatch = [];
    for (const check of ROUTER_VULN_CHECKS) {
        for (const p of checkPorts) {
            vulnBatch.push(
                probePath(host, check.path, p).then(r => ({ ...r, check, port: p }))
            );
        }
    }

    const vulnResults = await Promise.all(vulnBatch);
    const seenPaths = new Set();

    for (const { found, latency, check, port } of vulnResults) {
        if (found && !seenPaths.has(check.path)) {
            seenPaths.add(check.path);
            findings.push({
                severity: check.severity,
                code:     check.label,
                message:  `**Endpoint \`${check.path}\` responded** on \`${host}:${port}\` (${latency}ms).\n\n${check.desc}`,
                file:     `${host}:${port}${check.path}`,
                cve:      check.cve || '',
            });
        }
    }

    onProgress && onProgress(75, 100, 'Analyzing network configuration...');

    // ── Step 4: Configuration Vulnerability Checks ────────────────────────────

    // Telnet + any HTTPS = downgrade risk
    const hasTelnet = openPorts.some(p => p.port === 23);
    const hasSSH    = openPorts.some(p => p.port === 22);
    const hasHTTPS  = openPorts.some(p => p.port === 443);
    const hasSNMP   = openPorts.some(p => p.port === 161);
    const hasUPnP   = openPorts.some(p => p.port === 1900);
    const hasTFTP   = openPorts.some(p => p.port === 69);
    const hasSMB    = openPorts.some(p => p.port === 445);

    if (hasTelnet && hasSSH) {
        findings.push({
            severity: 'HIGH',
            code:     'Legacy Protocol Coexistence',
            message:  '**Both Telnet (port 23) and SSH (port 22) are open.**\n\nTelnet provides complete compromise of SSH session confidentiality when both exist. An attacker on the LAN can intercept Telnet sessions and capture credentials even when SSH is available. **Disable Telnet immediately.**',
            file:     host,
            cve:      'CWE-326',
        });
    }

    if (httpOpen && !hasHTTPS) {
        findings.push({
            severity: 'HIGH',
            code:     'No HTTPS — Cleartext Admin',
            message:  '**HTTP admin interface has no HTTPS equivalent.**\n\nAll router management traffic (including passwords and config changes) is transmitted unencrypted. A LAN attacker can intercept via ARP poisoning + passive sniffing.',
            file:     `http://${host}`,
            cve:      'CWE-319',
        });
    }

    if (hasSNMP) {
        findings.push({
            severity: 'CRITICAL',
            code:     'SNMP Exposed — Community String Attack',
            message:  '**SNMP port 161 is open.**\n\nSNMP v1/v2c devices default to community string `"public"` for read access and `"private"` for write. An attacker can enumerate every interface, ARP table, routing table, connected device, and often **reboot or reconfigure** the device.\n\nRemediation: Disable SNMP, or upgrade to SNMPv3 with auth + encryption.',
            file:     `${host}:161`,
            cve:      'CVE-2024-22061',
        });
    }

    if (hasUPnP) {
        findings.push({
            severity: 'HIGH',
            code:     'UPnP — NAT Slipstreaming Risk',
            message:  '**UPnP (port 1900) is active.**\n\nNAT Slipstreaming (CVE-2020-8558) allows a malicious website visited from inside this network to open arbitrary ports on the router, exposing internal services publicly. Any IoT device using UPnP can also auto-expose ports without your knowledge.',
            file:     `${host}:1900`,
            cve:      'CVE-2020-8558',
        });
    }

    if (hasTFTP) {
        findings.push({
            severity: 'CRITICAL',
            code:     'TFTP — Zero Authentication File Access',
            message:  '**TFTP (Trivial FTP) port 69 is open.**\n\nTFTP has **no authentication mechanism** whatsoever. Common exploitation: `tftp -g -r startup-config 192.168.1.1` will download the router\'s full configuration including cleartext credentials, VPN keys, and admin passwords.',
            file:     `${host}:69`,
            cve:      'CWE-306',
        });
    }

    if (hasSMB) {
        findings.push({
            severity: 'CRITICAL',
            code:     'SMB — EternalBlue / WannaCry Vector',
            message:  '**SMB port 445 is open on this device.**\n\nIf unpatched, this is vulnerable to EternalBlue (MS17-010) which was used by WannaCry ransomware. Even patched SMB on the LAN is a high-risk attack surface: credential relay (NTLM relay), LLMNR poisoning.\n\nRemediation: Disable SMB if not needed, ensure MS17-010 patch is applied.',
            file:     `${host}:445`,
            cve:      'CVE-2017-0144',
        });
    }

    // ── Step 5: WebRTC Network Topology Info ──────────────────────────────────
    onProgress && onProgress(90, 100, 'Finalizing report...');

    // Sort: CRITICAL > HIGH > MEDIUM > LOW > INFO
    const sevOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
    findings.sort((a, b) => (sevOrder[a.severity] ?? 9) - (sevOrder[b.severity] ?? 9));

    // Prepend recon summary
    const evidenceLines = openPorts.map(p => {
        const def = ALL_PORTS.find(x => x.port === p.port);
        return `  Port ${p.port}/TCP — ${def?.service || 'Unknown'} (${p.latency}ms response time)`;
    });

    findings.unshift({
        severity: 'INFO',
        code:     'Network Reconnaissance Summary',
        message:  [
            `**Target:** \`${host}\``,
            `**Scan engine:** Browser client-side (real probes, no cloud)`,
            `**Ports scanned:** ${portsToScan.length}`,
            `**Open ports found:** ${openPorts.length}`,
            `**Router vuln checks:** ${ROUTER_VULN_CHECKS.length} endpoints probed`,
            `**Your detected local IP(s):** ${localIps.length > 0 ? localIps.join(', ') : 'Not available'}`,
            `**Detected gateway:** ${detectedGateway || 'Not detected'}`,
            `\n**Evidence (open ports):**`,
            evidenceLines.length > 0 ? evidenceLines.join('\n') : '  No open ports detected in this range.',
        ].join('\n'),
        file: host,
    });

    // Risk calculation
    const topSev = findings.reduce((top, f) => {
        return (sevOrder[f.severity] ?? 9) < (sevOrder[top] ?? 9) ? f.severity : top;
    }, 'INFO');

    return {
        findings,
        total:  findings.length,
        target: host,
        risk:   topSev,
        local:  true,
        recon:  {
            ip:         host,
            os:         'Local Network Device (Browser Scan)',
            open_ports: openPorts.length,
            local_ips:  localIps,
        },
    };
}
