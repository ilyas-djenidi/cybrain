import React, { useState, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import axios from 'axios';
import SeverityBadge from '../components/SeverityBadge';

const SUPPORTED = [
    'Python (.py)', 'PHP (.php)',
    'JavaScript (.js)', 'TypeScript (.ts)',
    'Java (.java)', 'C# (.cs)',
    'SQL (.sql)', 'Go (.go)',
    'Ruby (.rb)', 'C/C++ (.c/.cpp)',
];

const CodeScanPage = () => {
    const [file, setFile]         = useState(null);
    const [code, setCode]         = useState('');
    const [filename, setFilename] = useState('');
    const [loading, setLoading]   = useState(false);
    const [fixing,  setFixing]    = useState(false);
    const [result,  setResult]    = useState(null);
    const [fixResult, setFixResult] = useState(null);
    const [mode, setMode]         = useState('upload');
    const fileRef = useRef();

    const handleFileChange = (e) => {
        const f = e.target.files[0];
        if (!f) return;
        setFile(f);
        setFilename(f.name);
        const reader = new FileReader();
        reader.onload = ev => setCode(ev.target.result);
        reader.readAsText(f);
    };

    const handleScan = async () => {
        const content = code.trim();
        const fname   = filename || 'code.txt';
        if (!content) return;
        setLoading(true);
        setResult(null);
        setFixResult(null);
        try {
            const { data } = await axios.post(
                '/analyze_code',
                {
                    code:     content,
                    filename: fname
                },
                {
                    headers: {
                        'Content-Type': 'application/json'
                    }
                }
            );
            // Handle consistent finding keys
            setResult({
                ...data,
                findings: data.findings || []
            });
        } catch(e) {
            console.error('[CODE SCAN ERROR]', e);
            if (e.code === 'ECONNREFUSED' || e.response?.status === 502) {
                setResult({
                    filename: fname,
                    language: 'Error',
                    lines: 0,
                    findings: [{
                        severity: 'HIGH',
                        code: 'Backend Offline',
                        message: 'Flask backend is not running. Please start <code>app.py</code>.'
                    }]
                });
            }
        } finally {
            setLoading(false);
        }
    };

    const handleFix = async () => {
        if (!result) return;
        setFixing(true);
        try {
            const { data } = await axios.post(
                '/fix_code',
                {
                    code:     code,
                    filename: filename
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
        if (!fixResult?.fixed_code) return;
        const blob = new Blob(
            [fixResult.fixed_code],
            { type: 'text/plain' }
        );
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `fixed_${filename}`;
        a.click();
    };

    return (
        <div className="min-h-screen bg-black
                        content-section pt-24 pb-16
                        px-4 md:px-12">
            <div className="max-w-6xl mx-auto">

                {/* Header */}
                <div className="mb-10">
                    <a href="/"
                       className="text-cyan-500/60 text-[10px]
                                  font-orbitron tracking-widest
                                  uppercase hover:text-cyan-400
                                  mb-6 inline-flex items-center gap-2">
                        ← Back to Cockpit
                    </a>
                    <h1 className="font-orbitron font-black
                                   text-3xl md:text-5xl text-white
                                   tracking-wider mb-3">
                        CODE <span className="text-purple-400">
                            VULNERABILITY
                        </span> SCANNER
                    </h1>
                    <p className="text-gray-500 text-xs md:text-sm
                                  font-inter max-w-2xl leading-relaxed">
                        Upload any source file for deep static analysis. 
                        Gemini 1.5 detect vulnerabilities and generates
                        hardened versions of your code.
                    </p>
                </div>

                <div className="grid grid-cols-1
                                lg:grid-cols-2 gap-8 items-start">

                    {/* Left — Input */}
                    <div className="space-y-6">

                        {/* Mode Toggle */}
                        <div className="flex gap-2 scanner-glass
                                        rounded-2xl p-1.5 border border-white/5">
                            {['upload','paste'].map(m => (
                                <button
                                    key={m}
                                    onClick={() => setMode(m)}
                                    className={`flex-1 py-3
                                        font-orbitron text-[10px]
                                        tracking-widest uppercase
                                        rounded-xl transition-all duration-300
                                        ${mode === m
                                            ? 'bg-purple-500/20 text-purple-400 border border-purple-500/30'
                                            : 'text-gray-500 hover:text-gray-300'
                                        }`}
                                >
                                    {m === 'upload'
                                        ? '↑ Upload File'
                                        : '⌨ Paste Code'}
                                </button>
                            ))}
                        </div>

                        {mode === 'upload' ? (
                            <div
                                onClick={() =>
                                    fileRef.current?.click()
                                }
                                className="scanner-glass
                                           rounded-3xl p-10 md:p-16
                                           text-center
                                           cursor-pointer
                                           border-2
                                           border-dashed
                                           border-purple-500/20
                                           hover:border-purple-500/50
                                           transition-all group"
                            >
                                <input
                                    ref={fileRef}
                                    type="file"
                                    onChange={handleFileChange}
                                    className="hidden"
                                    accept=".py,.php,.js,.ts,.java,.cs,.sql,.go,.rb,.c,.cpp,.jsx,.tsx"
                                />
                                <div className="text-5xl mb-4 group-hover:scale-110 transition-transform">
                                    📄
                                </div>
                                <p className="text-gray-400
                                              font-orbitron
                                              text-sm
                                              tracking-wider
                                              mb-3">
                                    {filename || 'Drop code file here'}
                                </p>
                                <div className="flex flex-wrap justify-center gap-2 opacity-40">
                                    {SUPPORTED.slice(0, 4).map(s => (
                                        <span key={s} className="text-[10px] text-gray-500 font-mono italic">{s}</span>
                                    ))}
                                    <span className="text-[10px] text-gray-500 font-mono italic">...</span>
                                </div>
                            </div>
                        ) : (
                            <div className="space-y-4">
                                <input
                                    value={filename}
                                    onChange={e =>
                                        setFilename(e.target.value)
                                    }
                                    placeholder="filename.py"
                                    className="w-full bg-black/40
                                               border border-white/10
                                               rounded-xl px-4 py-3
                                               text-gray-400 text-xs
                                               font-mono
                                               focus:outline-none
                                               focus:border-purple-500/50"
                                />
                                <textarea
                                    value={code}
                                    onChange={e =>
                                        setCode(e.target.value)
                                    }
                                    placeholder="Paste your source code here..."
                                    rows={16}
                                    className="w-full bg-black/40
                                               border border-white/10
                                               rounded-2xl p-6
                                               text-gray-300
                                               font-mono text-xs
                                               leading-relaxed
                                               focus:outline-none
                                               focus:border-purple-500/50
                                               resize-none"
                                />
                            </div>
                        )}

                        {/* Scan Button */}
                        <motion.button
                            onClick={handleScan}
                            disabled={loading || !code.trim()}
                            whileHover={{ scale: 1.01 }}
                            whileTap={{ scale: 0.99 }}
                            className="w-full py-5
                                       font-orbitron font-bold
                                       text-xs tracking-[0.25em]
                                       uppercase rounded-2xl
                                       border transition-all duration-300
                                       bg-purple-500/10
                                       border-purple-500/50
                                       text-purple-400
                                       hover:bg-purple-500
                                       hover:text-black
                                       disabled:opacity-30
                                       disabled:cursor-not-allowed
                                       shadow-[0_0_30px_rgba(168,85,247,0.1)]"
                        >
                            {loading
                                ? '⟳ Analyzing Syntax...'
                                : '▶ Launch Code Audit'
                            }
                        </motion.button>
                    </div>

                    {/* Right — Results */}
                    <div className="space-y-6">
                        <AnimatePresence mode="wait">
                            {result ? (
                                <motion.div 
                                    key="results"
                                    initial={{ opacity:0, x:20 }}
                                    animate={{ opacity:1, x:0 }}
                                    className="space-y-6"
                                >
                                    {/* Stats */}
                                    <div className="scanner-glass
                                                    rounded-2xl p-6 border border-white/5">
                                        <div className="flex items-center
                                                        justify-between
                                                        flex-wrap gap-4">
                                            <div>
                                                <p className="font-orbitron
                                                               text-white
                                                               font-bold
                                                               text-base
                                                               tracking-wider mb-1">
                                                    {result.filename}
                                                </p>
                                                <div className="flex items-center gap-3">
                                                    <span className="text-[10px] bg-purple-500/10 text-purple-400 px-2 py-0.5 rounded font-orbitron uppercase border border-purple-500/20">{result.language}</span>
                                                    <span className="text-gray-500 text-xs font-inter">{result.lines} lines • {result.findings.length} findings</span>
                                                </div>
                                            </div>
                                            {result.can_fix && (
                                                <motion.button
                                                    onClick={handleFix}
                                                    disabled={fixing}
                                                    whileHover={{scale:1.05}}
                                                    className="px-6 py-2.5
                                                               bg-green-500/10
                                                               border
                                                               border-green-500/50
                                                               text-green-400
                                                               font-orbitron
                                                               text-[10px]
                                                               tracking-widest
                                                               uppercase
                                                               rounded-xl
                                                               hover:bg-green-500
                                                               hover:text-black
                                                               transition-all
                                                               disabled:opacity-50"
                                                >
                                                    {fixing
                                                        ? '⟳ Fixing...'
                                                        : '🔧 Apply AI Patch'}
                                                </motion.button>
                                            )}
                                        </div>
                                    </div>

                                    {/* Findings Scroll View */}
                                    <div className="space-y-3
                                                    max-h-[400px]
                                                    overflow-y-auto pr-2 custom-scrollbar">
                                        {result.findings.map(
                                            (f, i) => (
                                            <div key={i}
                                                 className={`rounded-xl p-4
                                                    border-l-4 text-xs transition-all duration-300
                                                    ${f.severity==='CRITICAL'
                                                        ? 'border-red-500 bg-red-500/5'
                                                        : f.severity==='HIGH'
                                                        ? 'border-orange-500 bg-orange-500/5'
                                                        : 'border-yellow-500 bg-yellow-500/5'
                                                    }`}
                                            >
                                                <div className="flex
                                                                items-center
                                                                gap-3 mb-3">
                                                    <SeverityBadge
                                                        severity={
                                                            f.severity
                                                        }
                                                    />
                                                    <span className="font-orbitron
                                                                     font-bold
                                                                     text-white/90
                                                                     tracking-wider">
                                                        {f.code}
                                                    </span>
                                                    <span className="text-gray-600
                                                                     ml-auto font-inter text-[10px]">
                                                        Line {f.line}
                                                    </span>
                                                </div>
                                                <div
                                                    className="text-gray-400
                                                               leading-relaxed
                                                               font-inter"
                                                    dangerouslySetInnerHTML={{
                                                        __html: f.message
                                                    }}
                                                />
                                            </div>
                                        ))}
                                    </div>

                                    {/* AI Analysis */}
                                    {result.ai_analysis && (
                                        <div className="scanner-glass
                                                        rounded-2xl p-6 border border-purple-500/20 shadow-lg shadow-purple-500/5">
                                            <p className="font-orbitron
                                                           text-purple-400
                                                           text-[10px]
                                                           tracking-[0.2em]
                                                           uppercase mb-4 flex items-center gap-2">
                                                <span className="text-base">✦</span> AI Strategic Review
                                            </p>
                                            <div className="text-gray-400
                                                            text-xs
                                                            font-inter
                                                            whitespace-pre-wrap
                                                            leading-relaxed
                                                            max-h-64
                                                            overflow-y-auto pr-2 custom-scrollbar">
                                                {result.ai_analysis}
                                            </div>
                                        </div>
                                    )}

                                    {/* Fixed Code Output */}
                                    {fixResult && (
                                        <motion.div 
                                            initial={{ opacity:0, y:20 }}
                                            animate={{ opacity:1, y:0 }}
                                            className="scanner-glass
                                                        rounded-2xl p-6
                                                        border
                                                        border-green-500/30 shadow-lg shadow-green-500/5">
                                            <div className="flex items-center
                                                            justify-between
                                                            flex-wrap gap-4
                                                            mb-4">
                                                <p className="font-orbitron
                                                               text-green-400
                                                               text-[10px]
                                                               tracking-widest
                                                               uppercase">
                                                    ✓ Hardened Version Created
                                                </p>
                                                <button
                                                    onClick={downloadFixed}
                                                    className="text-[9px]
                                                               font-orbitron
                                                               tracking-widest
                                                               uppercase
                                                               px-4 py-2
                                                               bg-green-500/10
                                                               border
                                                               border-green-500/50
                                                               text-green-400
                                                               hover:bg-green-500
                                                               hover:text-black
                                                               rounded-lg
                                                               transition-all"
                                                >
                                                    ↓ Download Fixed File
                                                </button>
                                            </div>
                                            {fixResult.fixed_code && (
                                                <pre className="text-gray-400
                                                                text-[10px]
                                                                font-mono
                                                                bg-black/60
                                                                rounded-xl
                                                                p-5
                                                                max-h-60
                                                                overflow-auto border border-white/5">
                                                    {fixResult.fixed_code
                                                        .slice(0, 1500)}
                                                    {fixResult.fixed_code
                                                        .length > 1500
                                                        && '\n... (truncated for preview)'}
                                                </pre>
                                            )}
                                        </motion.div>
                                    )}
                                </motion.div>
                            ) : !loading ? (
                                <motion.div 
                                    key="placeholder"
                                    initial={{ opacity:0 }}
                                    animate={{ opacity:1 }}
                                    className="scanner-glass
                                                rounded-3xl p-16
                                                text-center border border-white/5 h-full flex flex-col justify-center min-h-[400px]">
                                    <div className="text-6xl mb-6 opacity-20">
                                        🛡️
                                    </div>
                                    <p className="text-gray-600
                                                  font-orbitron
                                                  text-xs
                                                  tracking-[0.2em] uppercase">
                                        Code analysis engine idle
                                    </p>
                                    <p className="text-gray-700 font-inter text-xs mt-3">Upload your script to visualize attack vectors</p>
                                </motion.div>
                            ) : null}
                        </AnimatePresence>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default CodeScanPage;
