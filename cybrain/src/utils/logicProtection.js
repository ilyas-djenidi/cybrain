/**
 * CYBRAIN LOGIC PROTECTION
 * 
 * This file documents the protected backend files.
 * These are NEVER modified by frontend changes.
 * 
 * Protected files:
 *   - web_app/app.py                    Flask routes
 *   - web_app/url_scanner.py            12 vuln checks
 *   - web_app/detect_apache_misconf.py  14 Apache rules
 *   - src/hooks/useScanner.js           API hook
 */

// API endpoints — in production points to the Render backend
const BACKEND = import.meta.env.VITE_API_URL || 'http://127.0.0.1:5000';

export const API_ENDPOINTS = {
    ANALYZE:         `${BACKEND}/analyze`,
    SCAN_URL:        `${BACKEND}/scan_url`,
    DOWNLOAD_REPORT: `${BACKEND}/download_report`,
};

// Severity order — matches url_scanner.py output
export const SEVERITY_ORDER = {
    CRITICAL: 0,
    HIGH:     1,
    MEDIUM:   2,
    LOW:      3,
    INFO:     4,
};

// Severity colors — used in ResultsPanel and SeverityBadge
export const SEVERITY_STYLES = {
    CRITICAL: {
        bg:     '#000000',
        border: '#ef4444',
        text:   '#ef4444',
        badge:  'bg-red-500/20 text-red-400 border-red-500/40',
    },
    HIGH: {
        bg:     '#000000',
        border: '#f97316',
        text:   '#f97316',
        badge:  'bg-orange-500/20 text-orange-400 border-orange-500/40',
    },
    MEDIUM: {
        bg:     '#000000',
        border: '#eab308',
        text:   '#eab308',
        badge:  'bg-yellow-500/20 text-yellow-400 border-yellow-500/40',
    },
    LOW: {
        bg:     '#000000',
        border: '#22c55e',
        text:   '#22c55e',
        badge:  'bg-green-500/20 text-green-400 border-green-500/40',
    },
};

// Sort findings by severity — mirrors backend output order
export const sortBySeverity = (findings) => {
    return [...findings].sort(
        (a, b) =>
            (SEVERITY_ORDER[a.severity] ?? 9) -
            (SEVERITY_ORDER[b.severity] ?? 9)
    );
};

// Format a finding message for display
export const formatFinding = (finding) => {
    const parts = [finding.message || ''];
    if (finding.fix)
        parts.push(
            `<strong>Recommendation:</strong><br>${finding.fix}`
        );
    if (finding.evidence)
        parts.push(
            `<strong>Evidence:</strong><br><code>${finding.evidence}</code>`
        );
    if (finding.cwe)
        parts.push(`<strong>CWE:</strong> ${finding.cwe}`);
    if (finding.owasp)
        parts.push(`<strong>OWASP:</strong> ${finding.owasp}`);
    return parts.join('\n\n');
};
