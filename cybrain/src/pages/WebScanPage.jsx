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
    const [apiKey, setApiKey]         = useState(
        localStorage.getItem('openrouter_key') || ''
    );

    const handleScan = async () => {
        if (!url.trim()) return;
        let clean = url.split('#')[0];
        if (!clean.startsWith('http')) {
            clean = 'http://' + clean;
        }
        setLoading(true);
        setFindings([]);
        setAiAnalysis('');
        try {
            const { data } = await axios.post(
                '/scan_url',
                { url: clean },
                { headers: {'Content-Type':'application/json'}}
            );
            const sorted = sortBySeverity(
                data.findings || []
            );
            setFindings(sorted);
        } catch(e) {
            console.error(e);
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
                    scan_type: 'web',
                    api_key:   apiKey,
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
                        px-6 md:px-12">
            <div className="max-w-6xl mx-auto">

                {/* Header */}
                <motion.div
                    initial={{ opacity:0, y:20 }}
                    animate={{ opacity:1, y:0 }}
                    className="mb-10"
                >
                    <a href="/"
                       className="text-cyan-500/60 text-xs
                                  font-orbitron tracking-widest
                                  uppercase hover:text-cyan-400
                                  transition-colors mb-4
                                  inline-block">
                        ← Back to Home
                    </a>
                    <h1 className="font-orbitron font-black
                                   text-4xl text-white
                                   tracking-wider mb-2">
                        WEB <span className="text-cyan-400">
                            VULNERABILITY
                        </span> SCANNER
                    </h1>
                    <p className="text-gray-500 font-inter
                                  text-sm">
                        Full OWASP Top 10 assessment with
                        AI-powered analysis and remediation
                    </p>
                </motion.div>

                {/* Scanner Input */}
                <div className="scanner-glass p-6 mb-6
                                rounded-2xl">
                    <div className="flex gap-3 mb-4">
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
                                       border border-gray-700
                                       rounded-xl px-4 py-3
                                       text-gray-300 font-mono
                                       text-sm focus:outline-none
                                       focus:border-cyan-500/50
                                       transition-all"
                        />
                        <motion.button
                            onClick={handleScan}
                            disabled={loading}
                            whileHover={{ scale: 1.02 }}
                            whileTap={{ scale: 0.98 }}
                            className="px-8 py-3 border
                                       border-cyan-500/50
                                       text-cyan-400
                                       font-orbitron text-xs
                                       tracking-widest uppercase
                                       rounded-xl
                                       hover:bg-cyan-500
                                       hover:text-black
                                       transition-all
                                       disabled:opacity-50"
                        >
                            {loading ? '⟳ Scanning...'
                                     : '▶ Scan'}
                        </motion.button>
                    </div>

                    {/* Quick targets */}
                    <div className="flex flex-wrap gap-2">
                        <span className="text-gray-600
                                         text-xs font-orbitron
                                         tracking-widest
                                         uppercase">
                            Safe targets:
                        </span>
                        {SAFE_TARGETS.map(t => (
                            <button
                                key={t}
                                onClick={() => setUrl(t)}
                                className="text-xs text-cyan-500/60
                                           hover:text-cyan-400
                                           font-mono transition-colors
                                           bg-cyan-500/5
                                           border border-cyan-500/10
                                           px-2 py-1 rounded"
                            >
                                {t.replace('https://','')
                                  .replace('http://','')}
                            </button>
                        ))}
                    </div>
                </div>

                {/* Results */}
                {findings.length > 0 && (
                    <motion.div
                        initial={{ opacity:0 }}
                        animate={{ opacity:1 }}
                    >
                        {/* Summary Cards */}
                        <div className="grid grid-cols-2
                                        md:grid-cols-5
                                        gap-3 mb-6">
                            {[
                                ['CRITICAL','#ef4444'],
                                ['HIGH','#f97316'],
                                ['MEDIUM','#eab308'],
                                ['LOW','#22c55e'],
                                ['TOTAL','#00f5d4'],
                            ].map(([sev, color]) => (
                                <div key={sev}
                                     className="scanner-glass
                                                rounded-xl p-4
                                                text-center">
                                    <div
                                        className="text-2xl
                                                   font-orbitron
                                                   font-black mb-1"
                                        style={{ color }}
                                    >
                                        {sev === 'TOTAL'
                                            ? findings.length
                                            : counts[sev] || 0}
                                    </div>
                                    <div className="text-xs
                                                   text-gray-500
                                                   font-orbitron
                                                   tracking-wider">
                                        {sev}
                                    </div>
                                </div>
                            ))}
                        </div>

                        {/* AI Analysis Button */}
                        <div className="scanner-glass
                                        rounded-xl p-4 mb-6">
                            <div className="flex items-center
                                            justify-between
                                            flex-wrap gap-4">
                                <div>
                                    <h3 className="font-orbitron
                                                   text-sm
                                                   text-white
                                                   font-bold
                                                   tracking-wider
                                                   mb-1">
                                        🤖 AI SECURITY ANALYSIS
                                    </h3>
                                    <p className="text-gray-500
                                                  text-xs
                                                  font-inter">
                                        Deep analysis by Llama 3.3
                                        70B via OpenRouter (free)
                                    </p>
                                </div>
                                <div className="flex gap-3
                                                items-center">
                                    <input
                                        value={apiKey}
                                        onChange={e => {
                                            setApiKey(
                                                e.target.value
                                            );
                                            localStorage.setItem(
                                                'openrouter_key',
                                                e.target.value
                                            );
                                        }}
                                        placeholder="sk-or-v1-..."
                                        type="password"
                                        className="bg-black/40
                                                   border
                                                   border-gray-700
                                                   rounded-lg
                                                   px-3 py-2
                                                   text-gray-400
                                                   text-xs
                                                   font-mono
                                                   w-48
                                                   focus:outline-none
                                                   focus:border-purple-500/50"
                                    />
                                    <button
                                        onClick={handleAiAnalysis}
                                        disabled={analyzing}
                                        className="px-4 py-2
                                                   border
                                                   border-purple-500/50
                                                   text-purple-400
                                                   font-orbitron
                                                   text-xs
                                                   tracking-widest
                                                   uppercase
                                                   rounded-lg
                                                   hover:bg-purple-500
                                                   hover:text-black
                                                   transition-all
                                                   disabled:opacity-50"
                                    >
                                        {analyzing
                                            ? '⟳ Analyzing...'
                                            : '✦ Analyze'}
                                    </button>
                                </div>
                            </div>
                            {aiAnalysis && (
                                <div className="mt-4 p-4
                                               bg-purple-500/5
                                               border
                                               border-purple-500/20
                                               rounded-xl">
                                    <pre className="text-gray-300
                                                    text-xs
                                                    font-inter
                                                    whitespace-pre-wrap
                                                    leading-relaxed">
                                        {aiAnalysis}
                                    </pre>
                                </div>
                            )}
                        </div>

                        {/* Findings List */}
                        <div className="space-y-3">
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
                                        delay: i * 0.03
                                    }}
                                    className={`
                                        rounded-xl overflow-hidden
                                        border-l-4
                                        ${f.severity==='CRITICAL'
                                            ? 'border-red-500 bg-red-500/5'
                                            : f.severity==='HIGH'
                                            ? 'border-orange-500 bg-orange-500/5'
                                            : f.severity==='MEDIUM'
                                            ? 'border-yellow-500 bg-yellow-500/5'
                                            : 'border-green-500 bg-green-500/5'
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
                                        className="w-full p-4
                                                   flex items-center
                                                   gap-3 text-left"
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
                                        <span className="text-gray-600
                                                         text-xs">
                                            {expanded[i]
                                                ? '▲' : '▼'}
                                        </span>
                                    </button>
                                    <AnimatePresence>
                                        {expanded[i] && (
                                            <motion.div
                                                initial={{
                                                    height:0,
                                                    opacity:0
                                                }}
                                                animate={{
                                                    height:'auto',
                                                    opacity:1
                                                }}
                                                exit={{
                                                    height:0,
                                                    opacity:0
                                                }}
                                                className="px-4 pb-4"
                                            >
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
                                            </motion.div>
                                        )}
                                    </AnimatePresence>
                                </motion.div>
                            ))}
                        </div>

                        {/* Export */}
                        <div className="mt-6 flex gap-3">
                            <a
                                href="/download_report"
                                className="font-orbitron text-xs
                                           tracking-widest uppercase
                                           px-6 py-3 border
                                           border-cyan-500/40
                                           text-cyan-400
                                           hover:bg-cyan-500
                                           hover:text-black
                                           transition-all
                                           rounded-xl"
                            >
                                Export Report →
                            </a>
                        </div>
                    </motion.div>
                )}
            </div>
        </div>
    );
};

export default WebScanPage;
