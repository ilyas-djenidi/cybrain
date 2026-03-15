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
            console.error('[NETWORK SCAN ERROR]', e);
            if (e.code === 'ECONNREFUSED' || e.response?.status === 502) {
                setResults({
                    vulnerabilities: [{
                        severity: 'HIGH',
                        code: 'Backend Offline',
                        message: 'Flask backend is not running. Start <code>app.py</code> in the web_app folder.'
                    }]
                });
            }
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
                    findings:  results.findings || results.vulnerabilities || [],
                    target:    target,
                    scan_type: 'network',
                    context:   JSON.stringify(results.recon || results.hosts || {})
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
        { id: 'full',  label: 'Deep Infiltration',  desc: 'Ports + Vulns + OS Detection' },
        { id: 'ports', label: 'Port Discovery',  desc: 'Identify active services' },
        { id: 'quick', label: 'Surveillance Scan', desc: 'Top common ports only' },
    ];

    return (
        <div className="min-h-screen bg-black content-section pt-24 pb-16 px-4 md:px-12">
            <div className="max-w-6xl mx-auto">
                {/* Header */}
                <motion.div initial={{ opacity:0, y:20 }} animate={{ opacity:1, y:0 }} className="mb-10">
                    <a href="/" className="text-cyan-500/60 text-[10px] font-orbitron tracking-widest uppercase hover:text-cyan-400 mb-6 inline-flex items-center gap-2">← Back to Command Center</a>
                    <h1 className="font-orbitron font-black text-3xl md:text-5xl text-white tracking-wider mb-3">
                        NETWORK <span className="text-cyan-400">RECON</span>
                    </h1>
                    <p className="text-gray-500 font-inter text-xs md:text-sm max-w-2xl leading-relaxed">
                        Enterprise-grade discovery engine. Surface vulnerabilities and scan the perimeter powered by Gemini 1.5 expert analysis.
                    </p>
                </motion.div>

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-10 items-start">
                    {/* Left - Input */}
                    <div className="space-y-8">
                        <div className="scanner-glass rounded-3xl p-6 md:p-10 border border-white/5 shadow-2xl">
                            <label className="font-orbitron text-[10px] text-gray-500 tracking-[0.25em] uppercase mb-5 block">Host Target Information</label>
                            <input
                                value={target}
                                onChange={e => setTarget(e.target.value)}
                                onKeyDown={e => e.key === 'Enter' && handleScan()}
                                placeholder="192.168.1.1 or scanme.nmap.org"
                                className="w-full bg-black/40 border border-white/10 rounded-2xl px-6 py-4 text-gray-300 font-mono text-sm focus:outline-none focus:border-cyan-500/50 transition-all mb-10 shadow-inner"
                            />

                            <label className="font-orbitron text-[10px] text-gray-500 tracking-[0.25em] uppercase mb-5 block">Operational Mode</label>
                            <div className="grid grid-cols-1 gap-4">
                                {scanTypes.map(type => (
                                    <button
                                        key={type.id}
                                        onClick={() => setScanType(type.id)}
                                        className={`p-5 rounded-2xl border text-left transition-all duration-500 group ${
                                            scanType === type.id
                                                ? 'border-cyan-500/60 bg-cyan-500/10 text-cyan-400 shadow-lg shadow-cyan-500/5'
                                                : 'border-white/5 bg-white/[0.01] text-gray-600 hover:border-white/10'
                                        }`}
                                    >
                                        <div className="font-orbitron text-xs font-bold tracking-widest mb-1 group-hover:text-gray-300 transition-colors">{type.label}</div>
                                        <div className="text-[10px] font-inter opacity-60 group-hover:opacity-100 transition-opacity">{type.desc}</div>
                                    </button>
                                ))}
                            </div>
                        </div>

                        <motion.button
                            onClick={handleScan}
                            disabled={loading || !target.trim()}
                            whileHover={{ scale: 1.01 }}
                            whileTap={{ scale: 0.99 }}
                            className={`w-full py-5 font-orbitron font-bold text-xs tracking-[0.3em] uppercase rounded-2xl transition-all duration-300 border flex items-center justify-center gap-3 shadow-xl ${
                                loading || !target.trim() 
                                    ? 'border-white/5 bg-white/5 text-gray-600' 
                                    : 'border-cyan-500/40 text-cyan-400 bg-cyan-500/5 hover:bg-cyan-500 hover:text-black hover:border-cyan-500'
                            }`}
                        >
                            {loading ? (
                                <>
                                    <span className="animate-spin text-lg">⟳</span>
                                    <span>SYNCHRONIZING RECON...</span>
                                </>
                            ) : (
                                <>
                                    <span>▶ EXECUTE SCAN SEQUENCE</span>
                                </>
                            )}
                        </motion.button>
                    </div>

                    {/* Right - Results */}
                    <div className="space-y-8">
                        {(results?.findings || results?.vulnerabilities) ? (
                            <motion.div 
                                initial={{ opacity:0, x:20 }}
                                animate={{ opacity:1, x:0 }}
                                className="space-y-6"
                            >
                                {/* AI Analysis Toggle */}
                                <div className="scanner-glass rounded-3xl p-6 md:p-8 border border-purple-500/20 shadow-2xl shadow-purple-500/5">
                                    <div className="flex items-center justify-between flex-wrap gap-6 mb-6">
                                        <div>
                                            <h3 className="font-orbitron text-xs text-purple-400 font-bold tracking-[0.2em] uppercase mb-1">🤖 AI SURFACE AUDIT</h3>
                                            <p className="text-[10px] text-gray-500 font-inter">Deep analysis of the network attack surface</p>
                                        </div>
                                        <button 
                                            onClick={handleAiAnalysis} 
                                            disabled={analyzing} 
                                            className="px-6 py-2.5 bg-purple-500/10 border border-purple-500/40 text-purple-400 font-orbitron text-[10px] tracking-widest uppercase rounded-xl hover:bg-purple-500 hover:text-black transition-all disabled:opacity-30"
                                        >
                                            {analyzing ? 'AUDITING...' : 'RUN AI AUDIT'}
                                        </button>
                                    </div>
                                    <AnimatePresence>
                                        {aiAnalysis && (
                                            <motion.div 
                                                initial={{ opacity:0, height:0 }}
                                                animate={{ opacity:1, height:'auto' }}
                                                className="p-6 bg-black/40 border border-purple-500/20 rounded-2xl shadow-inner overflow-hidden"
                                            >
                                                <pre className="text-gray-300 text-[11px] font-inter whitespace-pre-wrap leading-relaxed max-h-80 overflow-y-auto custom-scrollbar">{aiAnalysis}</pre>
                                            </motion.div>
                                        )}
                                    </AnimatePresence>
                                </div>

                                {/* Host Results */}
                                <div className="space-y-6">
                                    <h2 className="font-orbitron text-[10px] text-gray-500 tracking-[0.3em] uppercase px-2">Discovery Logs</h2>
                                    {(results.recon?.hosts || results.hosts || []).map((host, hi) => (
                                        <motion.div 
                                            key={hi} 
                                            initial={{ opacity:0, y:20 }}
                                            animate={{ opacity:1, y:0 }}
                                            transition={{ delay: hi * 0.1 }}
                                            className="scanner-glass rounded-3xl p-6 md:p-8 border border-white/5 shadow-xl"
                                        >
                                            <div className="flex justify-between items-start flex-wrap gap-4 mb-8">
                                                <div>
                                                    <div className="text-white font-orbitron font-bold text-xl md:text-2xl tracking-wider mb-1">{host.ip}</div>
                                                    <div className="text-gray-500 text-[10px] font-mono tracking-wider">{host.hostname || 'UNRESOLVED HOSTNAME'}</div>
                                                </div>
                                                <div className="text-cyan-400 font-orbitron text-[9px] border border-cyan-500/20 bg-cyan-500/5 px-4 py-2 rounded-full tracking-widest uppercase">
                                                    OS: {host.os || 'Unknown Signature'}
                                                </div>
                                            </div>

                                            <div className="grid grid-cols-1 gap-3">
                                                {host.ports?.map((port, pi) => (
                                                    <div key={pi} className="flex items-center justify-between p-4 bg-white/[0.02] rounded-2xl border border-white/5 group hover:border-cyan-500/30 transition-all duration-300">
                                                        <div className="flex items-center gap-6">
                                                            <span className="font-mono text-cyan-400 text-sm w-14 font-bold tracking-tighter">{port.port}</span>
                                                            <div>
                                                                <div className="text-gray-200 text-[10px] font-orbitron font-bold uppercase tracking-widest mb-1 group-hover:text-cyan-400 transition-colors">{port.service}</div>
                                                                <div className="text-gray-600 text-[9px] font-mono uppercase opacity-70 group-hover:opacity-100 transition-opacity">{port.product || 'Unknown Service'} {port.version}</div>
                                                            </div>
                                                        </div>
                                                        <span className={`text-[9px] font-orbitron px-3 py-1.5 rounded-full border transition-all ${
                                                            port.state === 'open' 
                                                                ? 'text-green-400 border-green-500/20 bg-green-500/5' 
                                                                : 'text-red-400 border-red-500/20 bg-red-500/5'
                                                        }`}>
                                                            {port.state.toUpperCase()}
                                                        </span>
                                                    </div>
                                                ))}
                                                {(!host.ports || host.ports.length === 0) && (
                                                    <div className="text-center py-8 border border-dashed border-white/5 rounded-2xl">
                                                        <p className="text-gray-700 font-orbitron text-[10px] tracking-widest uppercase">No open services found</p>
                                                    </div>
                                                )}
                                            </div>
                                        </motion.div>
                                    ))}
                                </div>
                            </motion.div>
                        ) : !loading ? (
                            <div className="scanner-glass rounded-3xl p-16 text-center border-2 border-dashed border-white/5 h-full flex flex-col justify-center min-h-[400px]">
                                <div className="text-6xl mb-6 opacity-20">📡</div>
                                <p className="text-gray-600 font-orbitron text-xs tracking-[0.3em] uppercase">
                                    Reconnaissance Passive
                                </p>
                                <p className="text-gray-700 font-inter text-xs mt-3">Target data will appear here after synchronization</p>
                            </div>
                        ) : null}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default NetworkScanPage;
