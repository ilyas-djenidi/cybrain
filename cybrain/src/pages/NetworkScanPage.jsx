import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import axios from 'axios';
import SeverityBadge from '../components/SeverityBadge';

/**
 * CYBRAIN — Network Reconnaissance Page
 * Enterprise-grade perimeter scanning & service discovery
 */

const NetworkScanPage = () => {
    const [target, setTarget] = useState('');
    const [scanMode, setScanMode] = useState('full');
    const [loading, setLoading] = useState(false);
    const [results, setResults] = useState(null);
    const [error, setError] = useState(null);
    const [aiAnalysis, setAiAnalysis] = useState('');
    const [analyzing, setAnalyzing] = useState(false);

    // Common safe targets FORMERLY here — now removed as requested

    const scanModes = [
        { 
            id: 'full', 
            label: 'Deep Infiltration', 
            desc: 'Comprehensive scan (Ports + Services + OS)', 
            icon: '🔍',
            color: 'cyan'
        },
        { 
            id: 'ports', 
            label: 'Port Discovery', 
            desc: 'Identify all active entry points', 
            icon: '⚡',
            color: 'blue'
        },
        { 
            id: 'quick', 
            label: 'Surveillance Mode', 
            desc: 'Rapid scan of common top 100 ports', 
            icon: '📡',
            color: 'purple'
        }
    ];

    const handleExecuteScan = async () => {
        if (!target.trim()) return;
        
        let discoveryTarget = target.trim()
            .replace(/^https?:\/\//, '')
            .split('/')[0]
            .split(':')[0];

        setLoading(true);
        setResults(null);
        setError(null);
        setAiAnalysis('');

        try {
            // Using a long timeout for network scans (3 minutes)
            const { data } = await axios.post(
                '/scan_network',
                { target: discoveryTarget, mode: scanMode },
                { 
                    headers: { 'Content-Type': 'application/json' },
                    timeout: 480000 
                }
            );
            
            if (data.findings && data.findings.length > 0) {
                setResults(data);
            } else {
                setError("No services or vulnerabilities discovered on target.");
            }
        } catch (e) {
            console.error('[NETWORK RECON ERROR]', e);
            if (e.response?.status === 502) {
                setError("<strong>502 Bad Gateway</strong>: Backend is offline or crashing. Check Flask logs.");
            } else if (e.code === 'ECONNABORTED') {
                setError("<strong>Scan Timeout</strong>: The target took too long to respond (3 min limit).");
            } else {
                setError(`<strong>Error</strong>: ${e.response?.data?.error || e.message}`);
            }
        } finally {
            setLoading(false);
        }
    };

    const runAiSurfaceAudit = async () => {
        if (!results) return;
        setAnalyzing(true);
        try {
            const { data } = await axios.post('/api/analyze_findings', {
                findings: results.findings,
                target: target,
                scan_type: 'network'
            });
            setAiAnalysis(data.analysis);
        } catch (e) {
            setAiAnalysis("AI Surface Audit failed: " + e.message);
        } finally {
            setAnalyzing(false);
        }
    };

    const cleanMessage = (msg) => {
        if (!msg) return '';
        return msg
            .replace(/\n\n/g, '<br><br>')
            .replace(/\n/g, '<br>')
            .replace(
                /`([^`]+)`/g,
                '<code style="background:rgba(0,245,212,0.08);' +
                'border:1px solid rgba(0,245,212,0.2);' +
                'padding:2px 8px;border-radius:4px;' +
                'font-family:monospace;font-size:11px;' +
                'color:#00f5d4;white-space:nowrap">$1</code>'
            )
            .replace(
                /\*\*(.*?)\*\*/g,
                '<strong style="color:#e5e7eb">$1</strong>'
            );
    };

    const getSeverityCount = (sev) => {
        if (!results?.findings) return 0;
        return results.findings.filter(f => f.severity === sev).length;
    };

    return (
        <div className="min-h-screen bg-black text-white pt-24 pb-20 px-4 md:px-12">
            <div className="max-w-7xl mx-auto">
                
                {/* Header Section */}
                <motion.div 
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="mb-12"
                >
                    <a href="/" className="text-cyan-500/60 text-[10px] font-orbitron tracking-widest uppercase hover:text-cyan-400 mb-6 inline-flex items-center gap-2 transition-colors">
                        ← Back
                    </a>
                    <div className="flex flex-col md:flex-row md:items-end justify-between gap-6">
                        <div>
                            <h1 className="font-orbitron font-black text-4xl md:text-6xl tracking-tighter mb-4">
                                NETWORK <span className="text-cyan-400">RECON</span>
                            </h1>
                            <p className="text-gray-500 font-inter text-sm max-w-2xl leading-relaxed">
                                Powered by Cybrain high-speed static analysis & offline intelligence.
                            </p>
                        </div>
                        {/* Quick Targets REMOVED as requested */}
                    </div>
                </motion.div>

                <div className="grid grid-cols-1 lg:grid-cols-12 gap-10">
                    
                    {/* Left Column: Input & Modes */}
                    <div className="lg:col-span-4 space-y-6">
                        <div className="bg-[#0a0a0a] border border-white/10 rounded-3xl p-8 shadow-2xl">
                            <label className="font-orbitron text-[10px] text-gray-500 tracking-[0.2em] uppercase mb-4 block">Target Hostname / IP</label>
                            <div className="relative mb-8">
                                <input 
                                    value={target}
                                    onChange={e => setTarget(e.target.value)}
                                    onKeyDown={e => e.key === 'Enter' && handleExecuteScan()}
                                    placeholder="e.g. scanme.nmap.org"
                                    className="w-full bg-black border border-white/10 rounded-2xl px-6 py-4 text-cyan-400 font-mono text-sm focus:outline-none focus:border-cyan-500 transition-all shadow-inner"
                                />
                                <div className="absolute right-4 top-4 text-cyan-500/30 animate-pulse">📡</div>
                            </div>

                            {/* Hint text only — no buttons */}
                            <p className="text-gray-700 text-xs font-mono mt-[-20px] mb-8">
                                e.g. scanme.nmap.org · 192.168.1.x · testphp.vulnweb.com
                            </p>

                            <label className="font-orbitron text-[10px] text-gray-500 tracking-[0.2em] uppercase mb-4 block">Operational Mode</label>
                            <div className="space-y-3">
                                {scanModes.map(mode => (
                                    <button
                                        key={mode.id}
                                        onClick={() => setScanMode(mode.id)}
                                        className={`w-full p-4 rounded-2xl border text-left transition-all duration-300 flex items-start gap-4 group ${
                                            scanMode === mode.id
                                                ? 'border-cyan-500/50 bg-cyan-500/10 text-white'
                                                : 'border-white/5 bg-white/[0.02] text-gray-500 hover:border-white/20'
                                        }`}
                                    >
                                        <span className="text-xl mt-1">{mode.icon}</span>
                                        <div>
                                            <div className={`font-orbitron text-[10px] font-bold tracking-wider mb-0.5 ${scanMode === mode.id ? 'text-cyan-400' : 'text-gray-400'}`}>
                                                {mode.label}
                                            </div>
                                            <div className="text-[10px] opacity-60 leading-tight">{mode.desc}</div>
                                        </div>
                                    </button>
                                ))}
                            </div>

                            <button
                                onClick={handleExecuteScan}
                                disabled={loading || !target.trim()}
                                className={`w-full mt-10 py-5 font-orbitron font-bold text-xs tracking-[0.3em] uppercase rounded-2xl transition-all duration-300 border flex items-center justify-center gap-3 ${
                                    loading || !target.trim() 
                                        ? 'border-white/5 bg-white/5 text-gray-600' 
                                        : 'border-cyan-500/50 text-cyan-400 bg-cyan-500/5 hover:bg-cyan-500 hover:text-black shadow-lg shadow-cyan-500/20'
                                }`}
                            >
                                {loading ? (
                                    <>
                                        <div className="flex gap-1">
                                            <span className="w-1.5 h-1.5 bg-cyan-400 rounded-full animate-bounce" style={{animationDelay: '0s'}}></span>
                                            <span className="w-1.5 h-1.5 bg-cyan-400 rounded-full animate-bounce" style={{animationDelay: '0.2s'}}></span>
                                            <span className="w-1.5 h-1.5 bg-cyan-400 rounded-full animate-bounce" style={{animationDelay: '0.4s'}}></span>
                                        </div>
                                        <span>INITIALIZING...</span>
                                    </>
                                ) : (
                                    <>
                                        <span>▶ START SEQUENCE</span>
                                    </>
                                )}
                            </button>
                        </div>
                    </div>

                    {/* Right Column: Results */}
                    <div className="lg:col-span-8">
                        {error && (
                            <motion.div initial={{ opacity:0 }} animate={{ opacity:1 }} className="bg-red-500/10 border border-red-500/30 rounded-2xl p-6 text-red-400 text-xs font-inter mb-6">
                                <span dangerouslySetInnerHTML={{ __html: error }} />
                            </motion.div>
                        )}

                        <AnimatePresence mode="wait">
                            {results ? (
                                <motion.div 
                                    initial={{ opacity:0, x:20 }} 
                                    animate={{ opacity:1, x:0 }}
                                    exit={{ opacity:0 }}
                                    className="space-y-8"
                                >
                                    {/* Summary Stats */}
                                    <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
                                        {[
                                            { label: 'CRITICAL', color: 'bg-red-500', count: getSeverityCount('CRITICAL') },
                                            { label: 'HIGH', color: 'bg-orange-500', count: getSeverityCount('HIGH') },
                                            { label: 'MEDIUM', color: 'bg-yellow-500', count: getSeverityCount('MEDIUM') },
                                            { label: 'LOW', color: 'bg-blue-500', count: getSeverityCount('LOW') },
                                            { label: 'INFO', color: 'bg-gray-500', count: getSeverityCount('INFO') },
                                        ].map(stat => (
                                            <div key={stat.label} className="bg-[#0a0a0a] border border-white/5 rounded-2xl p-4 text-center">
                                                <div className={`w-2 h-2 rounded-full ${stat.color} mx-auto mb-2 shadow-lg shadow-${stat.color.split('-')[1]}-500/50`}></div>
                                                <div className="text-2xl font-orbitron font-black">{stat.count}</div>
                                                <div className="text-[8px] text-gray-600 font-orbitron tracking-widest">{stat.label}</div>
                                            </div>
                                        ))}
                                    </div>

                                    {/* AI Surface Audit Card */}
                                    <div className="bg-gradient-to-br from-purple-500/10 to-transparent border border-purple-500/20 rounded-3xl p-8">
                                        <div className="flex items-center justify-between mb-8">
                                            <div>
                                                <h3 className="font-orbitron font-bold text-sm text-purple-400 tracking-widest uppercase mb-1 flex items-center gap-2">
                                                    🤖 OFFLINE SURFACE AUDIT
                                                </h3>
                                                <p className="text-[10px] text-gray-500">Expert interpretation of infrastructure risk</p>
                                            </div>
                                            <button 
                                                onClick={runAiSurfaceAudit}
                                                disabled={analyzing}
                                                className="px-6 py-2.5 bg-purple-500/10 border border-purple-500/30 rounded-xl text-[10px] font-orbitron text-purple-400 hover:bg-purple-500 hover:text-black transition-all disabled:opacity-30"
                                            >
                                                {analyzing ? 'AUDITING...' : 'RUN OFFLINE AUDIT'}
                                            </button>
                                        </div>
                                        {aiAnalysis && (
                                            <motion.div initial={{ opacity:0 }} animate={{ opacity:1 }} className="bg-black/50 border border-purple-500/10 rounded-2xl p-6">
                                                <pre className="text-gray-300 text-[11px] font-inter leading-relaxed whitespace-pre-wrap max-h-96 overflow-y-auto custom-scrollbar">
                                                    {aiAnalysis}
                                                </pre>
                                            </motion.div>
                                        )}
                                    </div>

                                    {/* Recon Data */}
                                    {results.recon && (
                                        <div className="bg-[#0a0a0a] border border-white/10 rounded-3xl p-8">
                                            <h3 className="font-orbitron text-[10px] text-gray-500 tracking-[0.2em] uppercase mb-6 flex items-center gap-2">
                                                <span className="text-cyan-500">⦿</span> RECONNAISSANCE SUMMARY
                                            </h3>
                                            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                                                <div className="bg-white/[0.02] border border-white/5 rounded-2xl p-4">
                                                    <div className="text-[8px] text-gray-600 font-orbitron mb-1 uppercase">Resolved IP</div>
                                                    <div className="text-sm font-mono text-cyan-400">{results.recon.ip || 'Unknown'}</div>
                                                </div>
                                                <div className="bg-white/[0.02] border border-white/5 rounded-2xl p-4">
                                                    <div className="text-[8px] text-gray-600 font-orbitron mb-1 uppercase">OS Detection</div>
                                                    <div className="text-sm font-inter text-gray-300">{results.recon.os || 'Unknown Signature'}</div>
                                                </div>
                                                <div className="bg-white/[0.02] border border-white/5 rounded-2xl p-4">
                                                    <div className="text-[8px] text-gray-600 font-orbitron mb-1 uppercase">Open Ports</div>
                                                    <div className="text-sm font-inter text-gray-300">{results.recon.open_ports} detected</div>
                                                </div>
                                            </div>
                                        </div>
                                    )}

                                    {/* Vulnerabilities List */}
                                    <div className="space-y-4">
                                        <h3 className="font-orbitron text-[10px] text-gray-500 tracking-[0.2em] uppercase px-4">FINDINGS LOG</h3>
                                        {results.findings.map((finding, idx) => (
                                            <motion.div 
                                                key={idx}
                                                initial={{ opacity: 0, y: 10 }}
                                                animate={{ opacity: 1, y: 0 }}
                                                transition={{ delay: idx * 0.05 }}
                                                className={`border rounded-2xl p-6 hover:border-white/10 transition-all group ${
                                                    finding.severity === 'CRITICAL'
                                                        ? 'border-red-500 bg-red-500/5'
                                                        : finding.severity === 'HIGH'
                                                        ? 'border-orange-500 bg-orange-500/5'
                                                        : finding.severity === 'MEDIUM'
                                                        ? 'border-yellow-500 bg-yellow-500/5'
                                                        : finding.severity === 'LOW'
                                                        ? 'border-green-500 bg-green-500/5'
                                                        : 'border-cyan-500/40 bg-cyan-500/5'  // INFO
                                                }`}
                                            >
                                                <div className="flex items-start justify-between gap-4 mb-4">
                                                    <div className="flex items-center gap-4">
                                                        <SeverityBadge severity={finding.severity} />
                                                        <h4 className="font-orbitron font-bold text-sm tracking-tight text-gray-200 group-hover:text-cyan-400 transition-colors uppercase">
                                                            {finding.code}
                                                        </h4>
                                                    </div>
                                                    <div className="text-[10px] font-mono text-gray-600">{finding.file}</div>
                                                </div>
                                                <div 
                                                    className="text-[11px] text-gray-500 font-inter leading-relaxed findings-content"
                                                    dangerouslySetInnerHTML={{
                                                        __html: cleanMessage(finding.message)
                                                    }}
                                                />
                                            </motion.div>
                                        ))}
                                    </div>

                                    {/* Footer Actions */}
                                    <div className="flex justify-between items-center py-10 border-t border-white/5 mt-10">
                                        <div className="flex gap-6">
                                            <a href="/scan/apache" className="text-[10px] font-orbitron text-gray-600 hover:text-cyan-400 transition-all uppercase">Config Scanner</a>
                                            <a href="/scan/code" className="text-[10px] font-orbitron text-gray-600 hover:text-cyan-400 transition-all uppercase">Code Analyzer</a>
                                        </div>
                                        <button className="px-8 py-3 bg-white/5 border border-white/10 rounded-2xl text-[10px] font-orbitron text-gray-400 hover:border-green-500/50 hover:text-green-400 transition-all uppercase flex items-center gap-2">
                                            <span>📥</span> EXPORT MD REPORT
                                        </button>
                                    </div>
                                </motion.div>
                            ) : loading ? (
                                <motion.div
                                    initial={{ opacity: 0 }}
                                    animate={{ opacity: 1 }}
                                    className="scanner-glass rounded-3xl
                                               p-12 text-center mb-8 border border-cyan-500/20"
                                >
                                    {/* Animated scan line */}
                                    <div className="relative h-1 bg-gray-800
                                                    rounded-full overflow-hidden
                                                    mb-8 max-w-sm mx-auto">
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
                                                    justify-center gap-2 mb-6">
                                        {[0,1,2,3,4].map(i => (
                                            <div
                                                key={i}
                                                className="w-2.5 h-2.5 bg-cyan-400
                                                           rounded-full
                                                           animate-bounce"
                                                style={{
                                                    animationDelay: `${i * 0.15}s`
                                                }}
                                            />
                                        ))}
                                    </div>

                                    <h3 className="font-orbitron text-cyan-400
                                                  text-lg font-black
                                                  tracking-[0.3em] uppercase mb-4">
                                        SYNCHRONIZING RECON DATA
                                    </h3>
                                    <p className="text-gray-500 text-xs
                                                  font-inter mb-8 max-w-md mx-auto">
                                        Intercepting network packets and mapping target surface. 
                                        Performing deep service enumeration across 75+ critical ports.
                                    </p>

                                    {/* What's being tested */}
                                    <div className="grid grid-cols-2 gap-3
                                                    max-w-lg mx-auto text-left py-6 border-y border-white/5">
                                        {[
                                            'TCP Port Discovery',
                                            'Banner Grabbing',
                                            'OS Fingerprinting',
                                            'SNMP Community Enumeration',
                                            'Docker API Check',
                                            'Database Accessibility',
                                            'Management Interfaces',
                                            'Message Queue Vulnerabilities',
                                            'Key-Value Store Exposure',
                                            'Metasploit Indicator Check',
                                        ].map((check, i) => (
                                            <div
                                                key={i}
                                                className="flex items-center
                                                           gap-2"
                                            >
                                                <div className="w-1 h-1
                                                               bg-cyan-500/50
                                                               rounded-full
                                                               flex-shrink-0"/>
                                                <span className="text-gray-600
                                                                 text-[10px]
                                                                 font-orbitron uppercase tracking-widest">
                                                    {check}
                                                </span>
                                            </div>
                                        ))}
                                    </div>

                                    <div className="mt-8 font-mono text-[10px] text-cyan-500/50 uppercase tracking-widest animate-pulse">
                                        [ INTERCEPTING ] PORT_SCAN :: ATTACK_VECTOR_RECOGNITION
                                    </div>
                                    <p className="text-gray-700 text-[10px]
                                                  font-inter mt-4">
                                        Estimated time: 1-2 minutes (High-Speed)
                                    </p>
                                </motion.div>
                            ) : (
                                <div className="h-[600px] flex flex-col items-center justify-center text-center p-20 border-2 border-dashed border-white/5 rounded-3xl">
                                    <div className="text-6xl mb-10 opacity-20">📡</div>
                                    <h3 className="font-orbitron font-black text-xl tracking-[0.3em] text-gray-800 mb-4">AWAITING TARGET DATA</h3>
                                    <p className="text-gray-700 font-inter text-xs max-w-xs">
                                        Input a target IP or hostname to begin automated perimeter reconnaissance.
                                    </p>
                                </div>
                            )}
                        </AnimatePresence>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default NetworkScanPage;
