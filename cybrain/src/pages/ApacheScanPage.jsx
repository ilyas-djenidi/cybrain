import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import axios from 'axios';
import SeverityBadge from '../components/SeverityBadge';
import { sortBySeverity } from '../utils/logicProtection';

const ApacheScanPage = () => {
    const [content, setContent] = useState('');
    const [file, setFile]       = useState(null);
    const [loading, setLoading] = useState(false);
    const [fixing,  setFixing]  = useState(false);
    const [findings, setFindings] = useState([]);
    const [fixResult, setFixResult] = useState(null);
    const [expanded, setExpanded] = useState({});

    const handleFileChange = (e) => {
        const selected = e.target.files[0];
        if (selected) {
            setFile(selected);
            setContent(''); // Clear manual text if file is chosen
        }
    };

    const handleAnalyze = async () => {
        if (!content.trim() && !file) return;
        setLoading(true);
        setFindings([]);
        setFixResult(null);
        try {
            let data;
            if (file) {
                const formData = new FormData();
                formData.append('file', file);
                const res = await axios.post('/analyze', formData, {
                    headers: { 'Content-Type': 'multipart/form-data' }
                });
                data = res.data;
            } else {
                const res = await axios.post(
                    '/analyze',
                    { content: content },
                    { headers: {'Content-Type':'application/json'}}
                );
                data = res.data;
            }

            const raw = data.findings || data.results || [];
            const sorted = sortBySeverity(raw);
            setFindings(sorted);
        } catch(e) {
            console.error('[APACHE SCAN ERROR]', e);
            if (e.code === 'ECONNREFUSED' || e.response?.status === 502) {
                setFindings([{
                    severity: 'HIGH',
                    code: 'Backend Offline',
                    message: 'Flask backend is not running. Start <code>app.py</code> in the web_app folder.'
                }]);
            }
        } finally {
            setLoading(false);
        }
    };

    const handleFix = async () => {
        if (!content.trim() && !file) return;
        setFixing(true);
        try {
            const payload = file ? { config: await file.text() } : { config: content };
            const { data } = await axios.post('/fix_config', payload);
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
        <div className="min-h-screen bg-black content-section pt-24 pb-16 px-4 md:px-12">
            <div className="max-w-6xl mx-auto">
                {/* Header */}
                <motion.div initial={{ opacity:0, y:20 }} animate={{ opacity:1, y:0 }} className="mb-10">
                    <a href="/" className="text-cyan-500/60 text-[10px] font-orbitron tracking-widest uppercase hover:text-cyan-400 mb-6 inline-flex items-center gap-2">← Back to Dashboard</a>
                    <h1 className="font-orbitron font-black text-3xl md:text-5xl text-white tracking-wider mb-3">
                        APACHE <span className="text-cyan-400">CONFIG</span> AUDIT
                    </h1>
                    <p className="text-gray-500 font-inter text-xs md:text-sm max-w-2xl leading-relaxed">
                        Deep scan Apache web server configurations for security breaches, misconfigurations, and hardening opportunities powered by Gemini AI.
                    </p>
                </motion.div>

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 items-start">
                    {/* Left - Input */}
                    <div className="space-y-6">
                        <div className="scanner-glass rounded-3xl p-6 md:p-8 border border-white/5">
                            <div className="flex items-center justify-between mb-5">
                                <label className="text-gray-500 text-[10px] font-orbitron font-bold tracking-[0.2em] uppercase">
                                    {file ? `File: ${file.name}` : 'Configuration Stream'}
                                </label>
                                <div className="flex gap-2">
                                    {file && (
                                        <button 
                                            onClick={() => {setFile(null); setContent('');}}
                                            className="text-[9px] font-orbitron text-red-400/60 hover:text-red-400 uppercase tracking-widest"
                                        >
                                            [ Clear File ]
                                        </button>
                                    )}
                                    <label className="cursor-pointer px-4 py-2 bg-white/5 border border-white/10 text-cyan-400 font-orbitron text-[9px] tracking-widest uppercase rounded-xl hover:bg-cyan-500 hover:text-black transition-all">
                                        Upload Config
                                        <input 
                                            type="file" 
                                            className="hidden" 
                                            onChange={handleFileChange}
                                            accept=".conf,.htaccess,text/plain"
                                        />
                                    </label>
                                </div>
                            </div>
                            <textarea
                                value={file ? 'File uploaded: ' + file.name + '\n\n(Edit text to override file)' : content}
                                onChange={(e) => {
                                    setContent(e.target.value);
                                    if (file) setFile(null); // Switching back to manual text
                                }}
                                placeholder="Paste your httpd.conf, .htaccess or virtual host settings here..."
                                className="w-full bg-black/40 border border-white/10 rounded-2xl p-6 text-gray-300 font-mono text-sm resize-none h-[400px] md:h-[500px] focus:outline-none focus:border-cyan-400/50 transition-all shadow-inner"
                            />
                        </div>

                        <button
                            onClick={handleAnalyze}
                            disabled={!content.trim() || loading}
                            className="w-full py-5 bg-gradient-to-r from-cyan-500/80 to-purple-600/80 text-white font-orbitron font-black tracking-[0.2em] text-xs uppercase rounded-2xl hover:shadow-[0_0_40px_rgba(0,245,212,0.2)] transition-all disabled:opacity-30 border border-white/10 hover:border-cyan-500/50"
                        >
                            {loading ? '⟳ EXECUTING AUDIT...' : '▶ DISPATCH AUDIT'}
                        </button>
                    </div>

                    {/* Right - Results */}
                    <div className="space-y-6">
                        {findings.length > 0 ? (
                            <motion.div 
                                initial={{ opacity:0, x:20 }}
                                animate={{ opacity:1, x:0 }}
                                className="space-y-6"
                            >
                                {/* Stats */}
                                <div className="grid grid-cols-3 gap-4">
                                    {['CRITICAL', 'HIGH', 'MEDIUM'].map(sev => (
                                        <div key={sev} className="scanner-glass rounded-2xl p-5 text-center border border-white/5 shadow-lg">
                                            <div className={`text-2xl font-orbitron font-black mb-1 ${
                                                sev==='CRITICAL' ? 'text-red-500' : sev==='HIGH' ? 'text-orange-500' : 'text-yellow-500'
                                            }`}>
                                                {counts[sev] || 0}
                                            </div>
                                            <div className="text-[9px] text-gray-500 font-orbitron tracking-widest uppercase">
                                                {sev}
                                            </div>
                                        </div>
                                    ))}
                                </div>

                                {/* AI Fix Button */}
                                <motion.button
                                    onClick={handleFix}
                                    disabled={fixing}
                                    whileHover={{ scale: 1.02 }}
                                    className="w-full py-4 border border-green-500/40 bg-green-500/5 text-green-400 font-orbitron text-[10px] tracking-[0.2em] uppercase rounded-2xl hover:bg-green-500 hover:text-black transition-all disabled:opacity-30 shadow-lg shadow-green-500/5"
                                >
                                    {fixing ? '✦ HARROWING SECURE LOGIC...' : '✦ GENERATE HARDENED CONFIG'}
                                </motion.button>

                                {/* Findings */}
                                <div className="space-y-3 max-h-[450px] md:max-h-[600px] overflow-y-auto pr-2 custom-scrollbar">
                                    {findings.map((f, i) => (
                                        <div key={i} className={`rounded-2xl border-l-4 p-5 transition-all duration-300 ${
                                            f.severity==='CRITICAL' ? 'border-red-500 bg-red-500/5' : f.severity==='HIGH' ? 'border-orange-500 bg-orange-500/5' : 'border-yellow-500 bg-yellow-500/5'
                                        }`}>
                                            <div className="flex items-center gap-3 mb-3">
                                                <SeverityBadge severity={f.severity} />
                                                <span className="font-orbitron font-bold text-white/90 text-[10px] tracking-wider uppercase opacity-70">
                                                    Rule Code: {f.code}
                                                </span>
                                            </div>
                                            <p className="text-gray-400 text-sm font-inter leading-relaxed" 
                                               dangerouslySetInnerHTML={{ __html: f.message }} />
                                        </div>
                                    ))}
                                </div>

                                {/* Fixed Result */}
                                <AnimatePresence>
                                    {fixResult && (
                                        <motion.div 
                                            initial={{ opacity:0, y:20 }}
                                            animate={{ opacity:1, y:0 }}
                                            className="scanner-glass rounded-2xl p-6 border border-green-500/20 shadow-xl shadow-green-500/5"
                                        >
                                            <div className="flex items-center justify-between mb-4">
                                                <p className="font-orbitron text-green-400 text-[10px] tracking-widest uppercase flex items-center gap-2">
                                                    <span className="text-base text-green-500">✓</span> Hardened Config Ready
                                                </p>
                                                <button onClick={downloadFixed} className="text-[9px] font-orbitron tracking-widest uppercase px-4 py-2 border border-green-500/50 text-green-400 hover:bg-green-500 hover:text-black rounded-xl transition-all">
                                                    Download .conf
                                                </button>
                                            </div>
                                            <pre className="text-[10px] text-gray-500 font-mono bg-black/60 rounded-xl p-5 max-h-52 overflow-auto border border-white/5">
                                                {fixResult.fixed_config}
                                            </pre>
                                        </motion.div>
                                    )}
                                </AnimatePresence>
                            </motion.div>
                        ) : !loading ? (
                            <div className="scanner-glass rounded-3xl p-16 text-center border-2 border-dashed border-white/5 h-full flex flex-col justify-center min-h-[400px]">
                                <div className="text-6xl mb-6 opacity-20">🛡️</div>
                                <p className="text-gray-600 font-orbitron text-xs tracking-[0.2em] uppercase">
                                    Audit Engine Standby
                                </p>
                                <p className="text-gray-700 font-inter text-xs mt-3">Provide configuration stream to scan for leaks</p>
                            </div>
                        ) : null}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default ApacheScanPage;
