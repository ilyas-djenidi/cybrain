import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import axios from 'axios';
import SeverityBadge from '../components/SeverityBadge';
import { sortBySeverity } from '../utils/logicProtection';

const NetworkScanPage = () => {
    const [target, setTarget] = useState('');
    const [scanType, setScanType] = useState('full');
    const [loading, setLoading] = useState(false);
    const [results, setResults] = useState(null);
    const [aiAnalysis, setAiAnalysis] = useState('');
    const [analyzing, setAnalyzing]   = useState(false);
    const [apiKey, setApiKey]         = useState(
        localStorage.getItem('openrouter_key') || ''
    );

    const handleScan = async () => {
        if (!target.trim()) return;
        let clean = target.replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
        setLoading(true);
        setResults(null);
        setAiAnalysis('');
        try {
            const { data } = await axios.post(
                '/scan_network',
                { target: clean, scan_type: scanType },
                { headers: {'Content-Type':'application/json'}}
            );
            setResults(data);
        } catch(e) {
            console.error(e);
        } finally {
            setLoading(false);
        }
    };

    const handleAiAnalysis = async () => {
        if (!results) return;
        setAnalyzing(true);
        try {
            const { data } = await axios.post(
                '/api/analyze_findings',
                {
                    findings:  results.vulnerabilities || [],
                    target:    target,
                    scan_type: 'network',
                    api_key:   apiKey,
                    context:   JSON.stringify(results.hosts)
                }
            );
            setAiAnalysis(data.analysis);
        } catch(e) {
            setAiAnalysis('AI analysis failed: ' + e.message);
        } finally {
            setAnalyzing(false);
        }
    };

    const scanTypes = [
        { id: 'full',  label: 'Full Scan',  desc: 'Ports + Vulns + OS' },
        { id: 'ports', label: 'Port Scan',  desc: 'Open ports only' },
        { id: 'quick', label: 'Quick Scan', desc: 'Top 10 ports' },
    ];

    return (
        <div className="min-h-screen bg-black content-section pt-24 pb-16 px-6 md:px-12">
            <div className="max-w-6xl mx-auto">
                {/* Header */}
                <motion.div initial={{ opacity:0, y:20 }} animate={{ opacity:1, y:0 }} className="mb-10">
                    <a href="/" className="text-cyan-500/60 text-xs font-orbitron tracking-widest uppercase hover:text-cyan-400 mb-4 inline-block">← Back</a>
                    <h1 className="font-orbitron font-black text-4xl text-white tracking-wider mb-2">
                        NETWORK <span className="text-cyan-400">RECON</span>
                    </h1>
                    <p className="text-gray-500 font-inter text-sm">
                        Enterprise-grade port scanning, service detection, and network vulnerability analysis.
                    </p>
                </motion.div>

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                    {/* Left - Input */}
                    <div className="space-y-6">
                        <div className="scanner-glass rounded-xl p-6">
                            <label className="font-orbitron text-[10px] text-gray-500 tracking-[0.2em] uppercase mb-4 block">Target Host / IP</label>
                            <input
                                value={target}
                                onChange={e => setTarget(e.target.value)}
                                onKeyDown={e => e.key === 'Enter' && handleScan()}
                                placeholder="scanme.nmap.org"
                                className="w-full bg-black/40 border border-gray-700 rounded-xl px-4 py-3 text-gray-300 font-mono text-sm focus:outline-none focus:border-cyan-500/50 transition-all mb-6"
                            />

                            <label className="font-orbitron text-[10px] text-gray-500 tracking-[0.2em] uppercase mb-4 block">Scan Type</label>
                            <div className="grid grid-cols-1 gap-3">
                                {scanTypes.map(type => (
                                    <button
                                        key={type.id}
                                        onClick={() => setScanType(type.id)}
                                        className={`p-4 rounded-xl border text-left transition-all duration-300 ${
                                            scanType === type.id
                                                ? 'border-cyan-500/60 bg-cyan-500/10 text-cyan-400'
                                                : 'border-gray-700/50 bg-black/20 text-gray-500 hover:border-gray-600'
                                        }`}
                                    >
                                        <div className="font-orbitron text-xs font-bold tracking-wider mb-1">{type.label}</div>
                                        <div className="text-[10px] font-inter opacity-70">{type.desc}</div>
                                    </button>
                                ))}
                            </div>
                        </div>

                        {/* API Key */}
                        <div className="scanner-glass rounded-xl p-4">
                            <p className="text-gray-500 text-xs font-orbitron tracking-widest uppercase mb-2">OpenRouter API Key (For AI Analysis)</p>
                            <input
                                value={apiKey}
                                onChange={e => {
                                    setApiKey(e.target.value);
                                    localStorage.setItem('openrouter_key', e.target.value);
                                }}
                                placeholder="sk-or-v1-..."
                                type="password"
                                className="w-full bg-black/40 border border-gray-700 rounded-lg px-3 py-2 text-gray-400 text-xs font-mono focus:outline-none focus:border-cyan-500/50"
                            />
                        </div>

                        <motion.button
                            onClick={handleScan}
                            disabled={loading || !target.trim()}
                            className={`w-full py-4 font-orbitron font-bold text-sm tracking-[0.2em] uppercase rounded-xl transition-all duration-300 border ${
                                loading || !target.trim() ? 'border-gray-700 text-gray-600' : 'border-cyan-500/50 text-cyan-400 hover:bg-cyan-500 hover:text-black'
                            }`}
                        >
                            {loading ? '⟳ SCANNING...' : '▶ LAUNCH NETWORK SCAN'}
                        </motion.button>
                    </div>

                    {/* Right - Results */}
                    <div className="space-y-6">
                        {results ? (
                            <>
                                {/* AI Analysis Toggle */}
                                <div className="scanner-glass rounded-xl p-4">
                                    <div className="flex items-center justify-between mb-4">
                                        <h3 className="font-orbitron text-xs text-purple-400 font-bold tracking-widest uppercase">🤖 AI ATTACK SURFACE ANALYSIS</h3>
                                        <button onClick={handleAiAnalysis} disabled={analyzing} className="px-4 py-2 border border-purple-500/50 text-purple-400 font-orbitron text-[10px] tracking-widest uppercase rounded-lg hover:bg-purple-500 hover:text-black transition-all">
                                            {analyzing ? 'ANALYZING...' : 'RUN AI AUDIT'}
                                        </button>
                                    </div>
                                    {aiAnalysis && (
                                        <div className="p-4 bg-purple-500/5 border border-purple-500/20 rounded-xl max-h-60 overflow-y-auto">
                                            <pre className="text-gray-300 text-[11px] font-inter whitespace-pre-wrap leading-relaxed">{aiAnalysis}</pre>
                                        </div>
                                    )}
                                </div>

                                {/* Host Results */}
                                {results.hosts?.map((host, hi) => (
                                    <div key={hi} className="scanner-glass rounded-xl p-6 border border-cyan-500/20">
                                        <div className="flex justify-between items-center mb-4">
                                            <div>
                                                <div className="text-white font-orbitron font-bold text-lg">{host.ip}</div>
                                                <div className="text-gray-500 text-xs font-mono">{host.hostname}</div>
                                            </div>
                                            <div className="text-cyan-400 font-orbitron text-[10px] border border-cyan-500/30 px-2 py-1 rounded">OS: {host.os || 'Unknown'}</div>
                                        </div>

                                        <div className="space-y-3">
                                            {host.ports?.map((port, pi) => (
                                                <div key={pi} className="flex items-center justify-between p-3 bg-black/40 rounded-lg border border-gray-800">
                                                    <div className="flex items-center gap-4">
                                                        <span className="font-mono text-cyan-400 text-sm w-12">{port.port}</span>
                                                        <div>
                                                            <div className="text-white text-xs font-bold uppercase tracking-wider">{port.service}</div>
                                                            <div className="text-gray-600 text-[10px] font-mono">{port.product} {port.version}</div>
                                                        </div>
                                                    </div>
                                                    <span className={`text-[10px] font-orbitron px-2 py-1 rounded ${port.state === 'open' ? 'text-green-400 border border-green-500/30' : 'text-red-400'}`}>
                                                        {port.state.toUpperCase()}
                                                    </span>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                ))}
                            </>
                        ) : (
                            <div className="scanner-glass rounded-xl p-12 text-center border-2 border-dashed border-gray-800">
                                <div className="text-4xl mb-4 opacity-20">🌐</div>
                                <p className="text-gray-600 font-orbitron text-sm tracking-wider">Target information will appear here</p>
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default NetworkScanPage;
