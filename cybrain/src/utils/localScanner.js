/**
 * CYBRAIN — Client-Side Local Network Scanner
 * Runs entirely in the browser for private/LAN IP addresses.
 * Uses timing-based port detection (fetch + AbortController).
 */

// ─── Private IP Detection ───────────────────────────────────────────────────
export function isPrivateIP(target) {
    // Strip protocol/path
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

// ─── Common Ports with Service Names ─────────────────────────────────────────
const COMMON_PORTS = [
    { port: 21,   service: 'FTP',          severity: 'HIGH',   risk: 'Unencrypted file transfer — credentials exposed in plaintext.' },
    { port: 22,   service: 'SSH',          severity: 'LOW',    risk: 'Secure shell. Brute-force risk if weak credentials.' },
    { port: 23,   service: 'Telnet',       severity: 'CRITICAL', risk: 'CLEARTEXT PROTOCOL — all traffic including passwords are visible on the network.' },
    { port: 25,   service: 'SMTP',         severity: 'MEDIUM', risk: 'Mail transfer. Open relay may allow spam/phishing abuse.' },
    { port: 53,   service: 'DNS',          severity: 'MEDIUM', risk: 'DNS exposed. Potential zone transfer or amplification DDoS vector.' },
    { port: 67,   service: 'DHCP',         severity: 'MEDIUM', risk: 'DHCP server. Rogue DHCP attacks possible.' },
    { port: 80,   service: 'HTTP',         severity: 'MEDIUM', risk: 'Unencrypted web interface. Credentials and data exposed in plaintext.' },
    { port: 443,  service: 'HTTPS',        severity: 'LOW',    risk: 'Encrypted web interface. Check certificate validity.' },
    { port: 445,  service: 'SMB',          severity: 'CRITICAL', risk: 'SMB exposed — EternalBlue/WannaCry attack vector. Patch immediately.' },
    { port: 554,  service: 'RTSP',         severity: 'HIGH',   risk: 'Camera/media stream exposed. Potential unauthorized surveillance.' },
    { port: 1900, service: 'UPnP',         severity: 'HIGH',   risk: 'UPnP allows automatic port forwarding — NAT Slipstreaming attack possible.' },
    { port: 3389, service: 'RDP',          severity: 'CRITICAL', risk: 'Remote Desktop exposed — BlueKeep vulnerability. Restrict to VPN only.' },
    { port: 3306, service: 'MySQL',        severity: 'CRITICAL', risk: 'Database port exposed to network — unauthorized data access risk.' },
    { port: 5432, service: 'PostgreSQL',   severity: 'CRITICAL', risk: 'Database port exposed to network.' },
    { port: 5900, service: 'VNC',          severity: 'CRITICAL', risk: 'VNC remote desktop often uses weak/no passwords.' },
    { port: 6379, service: 'Redis',        severity: 'CRITICAL', risk: 'Redis is unauthenticated by default — full data exposure.' },
    { port: 7547, service: 'TR-069 (CWMP)',severity: 'CRITICAL', risk: 'ISP management protocol — known Mirai botnet target on routers.' },
    { port: 8080, service: 'HTTP-Alt',     severity: 'MEDIUM', risk: 'Alternate HTTP port — often used by admin panels and proxy servers.' },
    { port: 8181, service: 'Admin Panel',  severity: 'HIGH',   risk: 'Administrative interface. Default credentials risk.' },
    { port: 8443, service: 'HTTPS-Alt',    severity: 'LOW',    risk: 'Alternate HTTPS port.' },
    { port: 8888, service: 'HTTP-Alt',     severity: 'MEDIUM', risk: 'Alternate web interface, may expose admin panel.' },
    { port: 9000, service: 'PHP-FPM',      severity: 'HIGH',   risk: 'PHP process manager exposed — remote code execution risk.' },
    { port: 27017,service: 'MongoDB',      severity: 'CRITICAL', risk: 'MongoDB exposed to network — no authentication by default.' },
    { port: 502,  service: 'Modbus',       severity: 'CRITICAL', risk: 'Industrial control system protocol — no authentication.' },
    { port: 1883, service: 'MQTT',         severity: 'HIGH',   risk: 'IoT messaging brokerexposed — unauthenticated subscriptions possible.' },
    { port: 4444, service: 'Metasploit',   severity: 'CRITICAL', risk: 'Default Metasploit listener port — possible active intrusion.' },
    { port: 31337,service: 'Back Orifice', severity: 'CRITICAL', risk: 'Known malware/backdoor port.' },
];

// ─── Port Probe via Timing Attack ─────────────────────────────────────────────
// Browsers can't truly "connect" to arbitrary TCP ports,
// but we can detect OPEN ports via FAST response (CORS rejection) vs.
// SLOW/timeout (port closed or filtered).
function probePort(ip, port, timeout = 1500) {
    return new Promise((resolve) => {
        const start = Date.now();
        const controller = new AbortController();
        const timer = setTimeout(() => {
            controller.abort();
            resolve({ open: false, latency: Date.now() - start });
        }, timeout);

        // Use fetch with no-cors — connection refused comes back almost instantly (<200ms),
        // while closed/filtered ports timeout at ~1500ms.
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
            // Fast failure (< threshold) = connection refused = PORT IS OPEN (but rejecting HTTP)
            // Slow failure / abort = port is CLOSED or FILTERED
            if (err.name !== 'AbortError' && latency < timeout * 0.7) {
                resolve({ open: true, latency });
            } else {
                resolve({ open: false, latency });
            }
        });
    });
}

// ─── Full Local Scan ──────────────────────────────────────────────────────────
export async function runLocalScan(target, mode = 'full', onProgress) {
    const host = target.replace(/^https?:\/\//, '').split('/')[0].split(':')[0];

    // Choose port list based on mode
    const portsToScan = mode === 'quick'
        ? COMMON_PORTS.slice(0, 10)
        : COMMON_PORTS;

    const openPorts = [];
    const findings = [];
    let scanned = 0;

    // Scan ports in batches of 5 for speed
    const batchSize = 5;
    for (let i = 0; i < portsToScan.length; i += batchSize) {
        const batch = portsToScan.slice(i, i + batchSize);
        const results = await Promise.all(
            batch.map(({ port, service }) => probePort(host, port).then(r => ({ ...r, port, service })))
        );
        for (const r of results) {
            if (r.open) openPorts.push(r);
        }
        scanned += batch.length;
        if (onProgress) onProgress(scanned, portsToScan.length);
    }

    // Build findings for open ports
    for (const { port, latency } of openPorts) {
        const def = COMMON_PORTS.find(p => p.port === port);
        if (!def) continue;

        findings.push({
            severity: def.severity,
            code:     `PORT ${port} OPEN — ${def.service}`,
            message:  `**${def.service}** is active on port ${port} (response in ${latency}ms).\n\n${def.risk}`,
            file:     `${host}:${port}`,
            port,
        });
    }

    // Severity downgrades — if HTTPS is open alongside HTTP, lower HTTP to MEDIUM
    const hasHttps = openPorts.some(p => p.port === 443);
    if (hasHttps) {
        const http = findings.find(f => f.port === 80);
        if (http && http.severity === 'HIGH') http.severity = 'MEDIUM';
    }

    // Add recon summary
    findings.unshift({
        severity: 'INFO',
        code:     'Local Reconnaissance Summary',
        message:  `Target: ${host}\nScanned from: Browser (client-side)\nPorts checked: ${portsToScan.length}\nOpen ports found: ${openPorts.length}\nScan mode: ${mode.toUpperCase()}\n\nEvidence:\n${openPorts.length > 0 ? openPorts.map(p => `  Port ${p.port} (${p.service}) — responded in ${p.latency}ms`).join('\n') : 'No open ports detected in this range.'}`,
        file:     host,
    });

    // Risk calculation
    const sevOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
    const topSev = findings.reduce((top, f) => {
        return (sevOrder[f.severity] ?? 9) < (sevOrder[top] ?? 9) ? f.severity : top;
    }, 'INFO');

    return {
        findings,
        total: findings.length,
        target: host,
        risk: topSev,
        local: true,
        recon: {
            ip: host,
            os: 'Local Network Device (Browser Scan)',
            open_ports: openPorts.length,
        },
    };
}
