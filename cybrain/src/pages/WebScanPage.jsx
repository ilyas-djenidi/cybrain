import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import axios from 'axios';
import SeverityBadge from '../components/SeverityBadge';
import { sortBySeverity } from '../utils/logicProtection';

const SAFE_TARGETS = [
    'http://testphp.vulnweb.com',
    'https://demo.testfire.net',
    'http://zero.webappsecurity.com',
    'https://juice-shop.herokuapp.com',
];

const WebScanPage = () => {
    const [url, setUrl]           = useState('');
    const [loading, setLoading]   = useState(false);
    const [findings, setFindings] = useState([]);
    const [expanded, setExpanded] = useState({});
    const [aiAnalysis, setAiAnalysis] = useState('');
    const [analyzing, setAnalyzing]   = useState(false);
    const [risk, setRisk]             = useState(null);

    const handleScan = async () => {
        if (!url.trim()) return;
        let clean = url.split('#')[0].trim();
        if (!clean.startsWith('http')) {
            clean = 'http://' + clean;
        }
        setLoading(true);
        setFindings([]);
        setAiAnalysis('');
        setRisk(null);
        try {
            const { data } = await axios.post(
                '/scan_url',
                { url: clean },
                {
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    timeout: 480000  // 8 minutes
                }
            );
            // Handle both response key formats
            const raw = data.findings || data.results || [];
            const sorted = sortBySeverity(raw);
            setFindings(sorted);
            setRisk(data.risk || 'INFO');
        } catch(e) {
            console.error('[SCAN ERROR]', e);
            if (e.code === 'ECONNREFUSED' || e.response?.status === 502) {
                setFindings([{
                    severity: 'HIGH',
                    code: 'Backend Offline',
                    message: (
                        'Flask backend is not running.<br><br>' +
                        '<strong>Fix:</strong><br>' +
                        '1. Open terminal in web_app/ folder<br>' +
                        '2. Run: <code>python app.py</code><br>' +
                        '3. Verify it says "Running on port 5000"<br>' +
                        '4. Then try scanning again'
                    ),
                    file: clean,
                }]);
            } else {
                setFindings([{
                    severity: 'HIGH',
                    code: 'Scan Error',
                    message: `Error: ${e.message}`,
                    file: clean,
                }]);
            }
        } finally {
            setLoading(false);
        }
    };

    const handleAiAnalysis = async () => {
        if (!findings.length) return;
        setAnalyzing(true);
        try {
            const { data } = await axios.post(
                '/api/analyze_findings',
                {
                    findings,
                    target:    url,
                    scan_type: 'web'
                }
            );
            setAiAnalysis(data.analysis);
        } catch(e) {
            setAiAnalysis('AI analysis failed: ' + e.message);
        } finally {
            setAnalyzing(false);
        }
    };

    const counts = findings.reduce((acc, f) => {
        acc[f.severity] = (acc[f.severity] || 0) + 1;
        return acc;
    }, {});

    return (
        <div className="min-h-screen bg-black
                        content-section pt-24 pb-16
                        px-4 md:px-12">
            <div className="max-w-6xl mx-auto">

                {/* Header */}
                <motion.div
                    initial={{ opacity:0, y:20 }}
                    animate={{ opacity:1, y:0 }}
                    className="mb-10"
                >
                    <a href="/"
                       className="text-cyan-500/60 text-[10px]
                                  font-orbitron tracking-widest
                                  uppercase hover:text-cyan-400
                                  transition-colors mb-6
                                  inline-flex items-center gap-2">
                        ← Back to Home
                    </a>
                    <h1 className="font-orbitron font-black
                                   text-3xl md:text-5xl text-white
                                   tracking-wider mb-3">
                        WEB <span className="text-cyan-400">
                            VULNERABILITY
                        </span> SCANNER
                    </h1>
                    <p className="text-gray-500 font-inter
                                  text-xs md:text-sm max-w-2xl leading-relaxed">
                        Pure Python security analysis engine.
                        100% offline & local remediation.
                    </p>
                </motion.div>

                {/* Scanner Input */}
                <div className="scanner-glass p-4 md:p-8 mb-8
                                rounded-3xl">
                    <div className="flex flex-col md:flex-row gap-4 mb-6">
                        <input
                            value={url}
                            onChange={e =>
                                setUrl(e.target.value)
                            }
                            onKeyDown={e =>
                                e.key==='Enter' &&
                                handleScan()
                            }
                            placeholder="https://target.com"
                            className="flex-1 bg-black/40
                                       border border-white/10
                                       rounded-2xl px-6 py-4
                                       text-gray-300 font-mono
                                       text-sm focus:outline-none
                                       focus:border-cyan-500/50
                                       transition-all shadow-inner"
                        />
                        <motion.button
                            onClick={handleScan}
                            disabled={loading}
                            whileHover={{ scale: 1.02 }}
                            whileTap={{ scale: 0.98 }}
                            className="px-10 py-4 bg-cyan-500/10
                                       border border-cyan-500/50
                                       text-cyan-400
                                       font-orbitron text-xs
                                       tracking-widest uppercase
                                       rounded-2xl
                                       hover:bg-cyan-500
                                       hover:text-black
                                       transition-all
                                       disabled:opacity-50"
                        >
                            {loading ? (
                                <div className="flex items-center gap-2">
                                    <div className="w-2 h-2 bg-black rounded-full animate-bounce" />
                                    <span>Scanning...</span>
                                </div>
                            ) : '▶ Start Scan'}
                        </motion.button>
                    </div>

                    {/* Quick targets */}
                </div>

                {/* Loading State */}
                {loading && (
                    <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        className="scanner-glass rounded-3xl
                                   p-8 text-center mb-8 border border-cyan-500/20"
                    >
                        {/* Animated scan line */}
                        <div className="relative h-1 bg-gray-800
                                        rounded-full overflow-hidden
                                        mb-6 max-w-sm mx-auto">
                            <motion.div
                                className="absolute inset-y-0 left-0
                                           w-1/3 bg-gradient-to-r
                                           from-transparent
                                           via-cyan-400 to-transparent"
                                animate={{ x: ['-100%', '400%'] }}
                                transition={{
                                    duration:  2,
                                    repeat:    Infinity,
                                    ease:      'linear',
                                }}
                            />
                        </div>

                        {/* Bouncing dots */}
                        <div className="flex items-center
                                        justify-center gap-2 mb-4">
                            {[0,1,2,3,4].map(i => (
                                <div
                                    key={i}
                                    className="w-2 h-2 bg-cyan-400
                                               rounded-full
                                               animate-bounce"
                                    style={{
                                        animationDelay: `${i * 0.15}s`
                                    }}
                                />
                            ))}
                        </div>

                        <p className="font-orbitron text-cyan-400
                                      text-sm font-bold
                                      tracking-[0.2em] uppercase mb-2">
                            OWASP 2025 Scan Running
                        </p>
                        <p className="text-gray-500 text-xs
                                      font-inter mb-4">
                            Testing 100+ vulnerability payloads
                            across 10 OWASP categories...
                        </p>

                        {/* What's being tested */}
                        <div className="grid grid-cols-2 gap-2
                                        max-w-md mx-auto text-left">
                            {[
                                'A01 Broken Access Control',
                                'A02 Misconfiguration',
                                'A03 Supply Chain',
                                'A04 Cryptographic Failures',
                                'A05 Injection (SQLi/XSS)',
                                'A06 Insecure Design',
                                'A07 Auth Failures',
                                'A08 Integrity Failures',
                                'A09 Logging Failures',
                                'A10 Exception Handling',
                            ].map((check, i) => (
                                <div
                                    key={i}
                                    className="flex items-center
                                               gap-1.5"
                                >
                                    <div className="w-1 h-1
                                                   bg-cyan-500/50
                                                   rounded-full
                                                   flex-shrink-0"/>
                                    <span className="text-gray-600
                                                     text-[10px]
                                                     font-inter">
                                        {check}
                                    </span>
                                </div>
                            ))}
                        </div>

                        <p className="text-gray-700 text-[10px]
                                      font-inter mt-4">
                            Estimated time: 1-3 minutes (Multithreaded)
                        </p>
                    </motion.div>
                )}

                {/* Results */}
                {findings.length > 0 && (
                    <motion.div
                        initial={{ opacity:0 }}
                        animate={{ opacity:1 }}
                    >
                        {/* Summary Cards */}
                        <div className="grid grid-cols-2
                                        md:grid-cols-5
                                        gap-4 mb-8">
                            {[
                                ['CRITICAL','#ef4444'],
                                ['HIGH','#f97316'],
                                ['MEDIUM','#eab308'],
                                ['LOW','#22c55e'],
                                ['TOTAL','#00f5d4'],
                            ].map(([sev, color]) => (
                                <div key={sev}
                                     className="scanner-glass
                                                rounded-2xl p-5
                                                text-center border border-white/5">
                                    <div
                                        className="text-3xl
                                                   font-orbitron
                                                   font-black mb-1"
                                        style={{ color }}
                                    >
                                        {sev === 'TOTAL'
                                            ? findings.length
                                            : counts[sev] || 0}
                                    </div>
                                    <div className="text-[10px]
                                                   text-gray-500
                                                   font-orbitron
                                                   tracking-wider uppercase">
                                        {sev}
                                    </div>
                                </div>
                            ))}
                        </div>

                        {/* AI Analysis Block */}
                        <div className="scanner-glass
                                        rounded-3xl p-6 md:p-8 mb-8 border border-purple-500/20">
                            <div className="flex items-center
                                            justify-between
                                            flex-wrap gap-6 mb-6">
                                <div>
                                    <h3 className="font-orbitron
                                                   text-base
                                                   text-purple-400
                                                   font-bold
                                                   tracking-wider
                                                   mb-2 flex items-center gap-2">
                                        <span className="text-xl">🤖</span> AI SECURITY AUDIT
                                    </h3>
                                    <p className="text-gray-500
                                                  text-xs
                                                  font-inter">
                                        Cybrain Offline Engine • Deterministic remediation & expert advice
                                    </p>
                                </div>
                                <button
                                    onClick={handleAiAnalysis}
                                    disabled={analyzing}
                                    className="px-8 py-3
                                               bg-purple-500/10
                                               border border-purple-500/40
                                               text-purple-400
                                               font-orbitron
                                               text-xs
                                               tracking-widest
                                               uppercase
                                               rounded-2xl
                                               hover:bg-purple-500
                                               hover:text-black
                                               transition-all
                                               disabled:opacity-50"
                                >
                                    {analyzing
                                        ? '⟳ Analyzing...'
                                        : '✦ Launch AI Audit'}
                                </button>
                            </div>
                            
                            <AnimatePresence>
                                {aiAnalysis && (
                                    <motion.div 
                                        initial={{ opacity:0, height:0 }}
                                        animate={{ opacity:1, height:'auto' }}
                                        className="mt-6 p-6
                                                   bg-black/40
                                                   border
                                                   border-purple-500/20
                                                   rounded-2xl shadow-inner">
                                        <div className="text-gray-400
                                                        text-sm
                                                        font-inter
                                                        whitespace-pre-wrap
                                                        leading-relaxed
                                                        prose prose-invert prose-sm">
                                            {aiAnalysis}
                                        </div>
                                    </motion.div>
                                )}
                            </AnimatePresence>
                        </div>

                        {/* Findings List */}
                        <div className="space-y-4">
                            <div className="flex items-center justify-between px-2 mb-2">
                                <h2 className="font-orbitron text-xs text-gray-500 tracking-[0.2em] uppercase">Vulnerability Feed</h2>
                                <span className="text-[10px] text-gray-600 font-inter tracking-wider">Sorted by Severity</span>
                            </div>
                            {findings.map((f, i) => (
                                <motion.div
                                    key={i}
                                    initial={{
                                        opacity:0, y:10
                                    }}
                                    animate={{
                                        opacity:1, y:0
                                    }}
                                    transition={{
                                        delay: i * 0.02
                                    }}
                                    className={`
                                        rounded-2xl overflow-hidden
                                        border transition-all duration-300
                                        ${f.severity==='CRITICAL'
                                            ? 'border-red-500/30 bg-red-500/5 hover:border-red-500/50'
                                            : f.severity==='HIGH'
                                            ? 'border-orange-500/30 bg-orange-500/5 hover:border-orange-500/50'
                                            : f.severity==='MEDIUM'
                                            ? 'border-yellow-500/30 bg-yellow-500/5 hover:border-yellow-500/50'
                                            : 'border-green-500/30 bg-green-500/5 hover:border-green-500/50'
                                        }
                                    `}
                                >
                                    <button
                                        onClick={() =>
                                            setExpanded(p => ({
                                                ...p,
                                                [i]: !p[i]
                                            }))
                                        }
                                        className="w-full p-5
                                                   flex items-center
                                                   gap-4 text-left"
                                    >
                                        <SeverityBadge
                                            severity={f.severity}
                                        />
                                        <span className="font-orbitron
                                                         text-xs
                                                         font-bold
                                                         text-white/90
                                                         tracking-wider
                                                         flex-1">
                                            {f.code}
                                        </span>
                                        <span className={`text-xs transition-transform duration-300 ${expanded[i] ? 'rotate-180' : ''}`}>
                                            ▼
                                        </span>
                                    </button>
                                    <AnimatePresence>
                                        {expanded[i] && (
                                            <motion.div
                                                initial={{ height: 0, opacity: 0 }}
                                                animate={{ height: 'auto', opacity: 1 }}
                                                exit={{ height: 0, opacity: 0 }}
                                                className="overflow-hidden"
                                            >
                                                <div className="px-5 pb-6 pt-2 border-t border-white/5 mt-2">
                                                    <div
                                                        className="text-gray-400
                                                                   text-sm
                                                                   font-inter
                                                                   leading-relaxed
                                                                   whitespace-pre-wrap"
                                                        dangerouslySetInnerHTML={{
                                                            __html: f.message
                                                        }}
                                                    />
                                                </div>
                                            </motion.div>
                                        )}
                                    </AnimatePresence>
                                </motion.div>
                            ))}
                        </div>

                        {/* Export */}
                        <div className="mt-10 flex flex-wrap gap-4">
                            <a
                                href="/download_report"
                                className="font-orbitron text-xs
                                           tracking-widest uppercase
                                           px-8 py-4 bg-white/5 border
                                           border-white/10
                                           text-white/60
                                           hover:bg-cyan-500
                                           hover:text-black hover:border-cyan-500
                                           transition-all
                                           rounded-2xl"
                            >
                                Download Markdown Report →
                            </a>
                        </div>
                    </motion.div>
                )}
            </div>
        </div>
    );
};

export default WebScanPage;
