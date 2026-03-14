import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import axios from 'axios';
import SeverityBadge from '../components/SeverityBadge';
import { sortBySeverity } from '../utils/logicProtection';

const ApacheScanPage = () => {
    const [content, setContent] = useState('');
    const [loading, setLoading] = useState(false);
    const [fixing,  setFixing]  = useState(false);
    const [findings, setFindings] = useState([]);
    const [fixResult, setFixResult] = useState(null);
    const [expanded, setExpanded] = useState({});
    const [apiKey, setApiKey]     = useState(
        localStorage.getItem('openrouter_key') || ''
    );

    const handleAnalyze = async () => {
        if (!content.trim()) return;
        setLoading(true);
        setFindings([]);
        setFixResult(null);
        try {
            const { data } = await axios.post(
                '/detect_apache_misconf',
                { config: content },
                { headers: {'Content-Type':'application/json'}}
            );
            const sorted = sortBySeverity(data.findings || []);
            setFindings(sorted);
        } catch(e) {
            console.error(e);
        } finally {
            setLoading(false);
        }
    };

    const handleFix = async () => {
        if (!content.trim()) return;
        setFixing(true);
        try {
            const { data } = await axios.post(
                '/fix_config',
                {
                    config:   content,
                    api_key:  apiKey,
                }
            );
            setFixResult(data);
        } catch(e) {
            console.error(e);
        } finally {
            setFixing(false);
        }
    };

    const downloadFixed = () => {
        if (!fixResult?.fixed_config) return;
        const blob = new Blob([fixResult.fixed_config], { type: 'text/plain' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'fixed_httpd.conf';
        a.click();
    };

    const counts = findings.reduce((acc, f) => {
        acc[f.severity] = (acc[f.severity] || 0) + 1;
        return acc;
    }, {});

    return (
        <div className="min-h-screen bg-black content-section pt-24 pb-16 px-6 md:px-12">
            <div className="max-w-6xl mx-auto">
                {/* Header */}
                <motion.div initial={{ opacity:0, y:20 }} animate={{ opacity:1, y:0 }} className="mb-10">
                    <a href="/" className="text-cyan-500/60 text-xs font-orbitron tracking-widest uppercase hover:text-cyan-400 mb-4 inline-block">← Back</a>
                    <h1 className="font-orbitron font-black text-4xl text-white tracking-wider mb-2">
                        APACHE <span className="text-cyan-400">CONFIG</span> AUDIT
                    </h1>
                    <p className="text-gray-500 font-inter text-sm">
                        Deep scan Apache configurations for security breaches and misconfigurations.
                    </p>
                </motion.div>

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    {/* Left - Input */}
                    <div className="space-y-4">
                        <div className="scanner-glass rounded-xl p-6">
                            <label className="text-gray-400 text-[10px] font-orbitron font-bold tracking-[0.2em] uppercase mb-4 block">
                                Configuration Stream
                            </label>
                            <textarea
                                value={content}
                                onChange={(e) => setContent(e.target.value)}
                                placeholder="Paste httpd.conf or .htaccess logic here..."
                                className="w-full bg-black/40 border border-gray-800 rounded-xl p-6 text-gray-300 font-mono text-sm resize-none h-96 focus:outline-none focus:border-cyan-400/50 transition-colors"
                            />
                        </div>

                        {/* API Key for Fix */}
                        <div className="scanner-glass rounded-xl p-4">
                            <p className="text-gray-500 text-xs font-orbitron tracking-widest uppercase mb-2">
                                OpenRouter API Key (For AI Fix)
                            </p>
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

                        <button
                            onClick={handleAnalyze}
                            disabled={!content.trim() || loading}
                            className="w-full py-4 bg-gradient-to-r from-cyan-400 to-purple-500 text-black font-orbitron font-black tracking-widest uppercase rounded-xl hover:shadow-[0_0_25px_rgba(0,245,212,0.4)] transition-all disabled:opacity-50"
                        >
                            {loading ? 'PROCESSING...' : 'ANALYZE CONFIGURATION'}
                        </button>
                    </div>

                    {/* Right - Results */}
                    <div className="space-y-4">
                        {findings.length > 0 ? (
                            <>
                                {/* Stats */}
                                <div className="grid grid-cols-3 gap-3">
                                    {['CRITICAL', 'HIGH', 'MEDIUM'].map(sev => (
                                        <div key={sev} className="scanner-glass rounded-xl p-4 text-center">
                                            <div className={`text-xl font-orbitron font-black ${
                                                sev==='CRITICAL' ? 'text-red-500' : sev==='HIGH' ? 'text-orange-500' : 'text-yellow-500'
                                            }`}>
                                                {counts[sev] || 0}
                                            </div>
                                            <div className="text-[10px] text-gray-500 font-orbitron tracking-widest uppercase">
                                                {sev}
                                            </div>
                                        </div>
                                    ))}
                                </div>

                                {/* AI Fix Button */}
                                <motion.button
                                    onClick={handleFix}
                                    disabled={fixing}
                                    className="w-full py-3 border border-green-500/50 text-green-400 font-orbitron text-xs tracking-widest uppercase rounded-xl hover:bg-green-500 hover:text-black transition-all disabled:opacity-50"
                                >
                                    {fixing ? '✦ GENERATING AI FIX...' : '✦ GENERATE SECURE CONFIG'}
                                </motion.button>

                                {/* Findings */}
                                <div className="space-y-2 max-h-[500px] overflow-y-auto pr-2">
                                    {findings.map((f, i) => (
                                        <div key={i} className={`rounded-xl border-l-4 p-4 ${
                                            f.severity==='CRITICAL' ? 'border-red-500 bg-red-500/5' : f.severity==='HIGH' ? 'border-orange-500 bg-orange-500/5' : 'border-yellow-500 bg-yellow-500/5'
                                        }`}>
                                            <div className="flex items-center gap-3 mb-2">
                                                <SeverityBadge severity={f.severity} />
                                                <span className="font-orbitron font-bold text-white/90 text-[10px] tracking-wider uppercase">
                                                    Rule ID: {f.code}
                                                </span>
                                            </div>
                                            <p className="text-gray-400 text-sm font-inter leading-relaxed" 
                                               dangerouslySetInnerHTML={{ __html: f.message }} />
                                        </div>
                                    ))}
                                </div>

                                {/* Fixed Result */}
                                {fixResult && (
                                    <div className="scanner-glass rounded-xl p-4 border border-green-500/20">
                                        <div className="flex items-center justify-between mb-3">
                                            <p className="font-orbitron text-green-400 text-[10px] tracking-widest uppercase">
                                                ✓ SECURE CONFIG READY
                                            </p>
                                            <button onClick={downloadFixed} className="text-[10px] font-orbitron tracking-widest uppercase px-3 py-1.5 border border-green-500/50 text-green-400 hover:bg-green-500 hover:text-black rounded-lg transition-all">
                                                DOWNLOAD
                                            </button>
                                        </div>
                                        <pre className="text-[10px] text-gray-500 font-mono bg-black/40 rounded-lg p-3 max-h-40 overflow-auto">
                                            {fixResult.fixed_config}
                                        </pre>
                                    </div>
                                )}
                            </>
                        ) : (
                            <div className="scanner-glass rounded-xl p-12 text-center border-2 border-dashed border-gray-800">
                                <div className="text-4xl mb-4 opacity-20">🛡️</div>
                                <p className="text-gray-600 font-orbitron text-sm tracking-wider">
                                    Paste configuration content to start security audit
                                </p>
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default ApacheScanPage;
