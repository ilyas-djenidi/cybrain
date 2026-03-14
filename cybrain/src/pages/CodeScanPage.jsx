import React, { useState, useRef } from 'react';
import { motion } from 'framer-motion';
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
    const [apiKey, setApiKey]     = useState(
        localStorage.getItem('openrouter_key') || ''
    );
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
                    filename: fname,
                    api_key:  apiKey,
                },
                {
                    headers: {
                        'Content-Type': 'application/json'
                    }
                }
            );
            setResult(data);
        } catch(e) {
            console.error(e);
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
                    filename: filename,
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
                        px-6 md:px-12">
            <div className="max-w-6xl mx-auto">

                {/* Header */}
                <div className="mb-10">
                    <a href="/"
                       className="text-cyan-500/60 text-xs
                                  font-orbitron tracking-widest
                                  uppercase hover:text-cyan-400
                                  mb-4 inline-block">
                        ← Back
                    </a>
                    <h1 className="font-orbitron font-black
                                   text-4xl text-white
                                   tracking-wider mb-2">
                        CODE <span className="text-purple-400">
                            VULNERABILITY
                        </span> SCANNER
                    </h1>
                    <p className="text-gray-500 text-sm
                                  font-inter">
                        Upload any code file. AI detects
                        vulnerabilities and generates
                        a fixed version.
                    </p>
                </div>

                <div className="grid grid-cols-1
                                lg:grid-cols-2 gap-6">

                    {/* Left — Input */}
                    <div className="space-y-4">

                        {/* Mode Toggle */}
                        <div className="flex gap-2 scanner-glass
                                        rounded-xl p-1">
                            {['upload','paste'].map(m => (
                                <button
                                    key={m}
                                    onClick={() => setMode(m)}
                                    className={`flex-1 py-2
                                        font-orbitron text-xs
                                        tracking-widest uppercase
                                        rounded-lg transition-all
                                        ${mode === m
                                            ? 'bg-purple-500/20 text-purple-400 border border-purple-500/40'
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
                                           rounded-xl p-12
                                           text-center
                                           cursor-pointer
                                           border-2
                                           border-dashed
                                           border-purple-500/30
                                           hover:border-purple-500/60
                                           transition-all"
                            >
                                <input
                                    ref={fileRef}
                                    type="file"
                                    onChange={handleFileChange}
                                    className="hidden"
                                    accept=".py,.php,.js,.ts,.java,.cs,.sql,.go,.rb,.c,.cpp,.jsx,.tsx"
                                />
                                <div className="text-4xl mb-3">
                                    📄
                                </div>
                                <p className="text-gray-400
                                              font-orbitron
                                              text-sm
                                              tracking-wider
                                              mb-2">
                                    {filename || 'Drop code file here'}
                                </p>
                                <p className="text-gray-600
                                              text-xs font-inter">
                                    {SUPPORTED.join(' • ')}
                                </p>
                            </div>
                        ) : (
                            <div className="space-y-2">
                                <input
                                    value={filename}
                                    onChange={e =>
                                        setFilename(e.target.value)
                                    }
                                    placeholder="filename.py"
                                    className="w-full bg-black/40
                                               border border-gray-700
                                               rounded-lg px-3 py-2
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
                                    placeholder="Paste your code here..."
                                    rows={16}
                                    className="w-full bg-black/40
                                               border border-gray-700
                                               rounded-xl p-4
                                               text-gray-300
                                               font-mono text-xs
                                               leading-relaxed
                                               focus:outline-none
                                               focus:border-purple-500/50
                                               resize-none"
                                />
                            </div>
                        )}

                        {/* API Key */}
                        <div className="scanner-glass
                                        rounded-xl p-4">
                            <p className="text-gray-500 text-xs
                                          font-orbitron
                                          tracking-widest
                                          uppercase mb-2">
                                OpenRouter API Key (Free)
                            </p>
                            <input
                                value={apiKey}
                                onChange={e => {
                                    setApiKey(e.target.value);
                                    localStorage.setItem(
                                        'openrouter_key',
                                        e.target.value
                                    );
                                }}
                                placeholder="sk-or-v1-... (get free key at openrouter.ai)"
                                type="password"
                                className="w-full bg-black/40
                                           border border-gray-700
                                           rounded-lg px-3 py-2
                                           text-gray-400 text-xs
                                           font-mono
                                           focus:outline-none
                                           focus:border-purple-500/50"
                            />
                        </div>

                        {/* Scan Button */}
                        <motion.button
                            onClick={handleScan}
                            disabled={loading || !code.trim()}
                            whileHover={{ scale: 1.02 }}
                            whileTap={{ scale: 0.98 }}
                            className="w-full py-4
                                       font-orbitron font-bold
                                       text-sm tracking-[0.2em]
                                       uppercase rounded-xl
                                       border transition-all
                                       border-purple-500/50
                                       text-purple-400
                                       hover:bg-purple-500
                                       hover:text-black
                                       disabled:opacity-40
                                       disabled:cursor-not-allowed"
                        >
                            {loading
                                ? '⟳ ANALYZING CODE...'
                                : '▶ SCAN FOR VULNERABILITIES'
                            }
                        </motion.button>
                    </div>

                    {/* Right — Results */}
                    <div className="space-y-4">
                        {result && (
                            <>
                                {/* Stats */}
                                <div className="scanner-glass
                                                rounded-xl p-4">
                                    <div className="flex items-center
                                                    justify-between
                                                    flex-wrap gap-3">
                                        <div>
                                            <p className="font-orbitron
                                                           text-white
                                                           font-bold
                                                           text-sm
                                                           tracking-wider">
                                                {result.filename}
                                            </p>
                                            <p className="text-gray-500
                                                           text-xs
                                                           font-inter">
                                                {result.language} •
                                                {result.lines} lines •
                                                {result.total} issues
                                            </p>
                                        </div>
                                        {result.can_fix && (
                                            <motion.button
                                                onClick={handleFix}
                                                disabled={fixing}
                                                whileHover={{scale:1.05}}
                                                className="px-4 py-2
                                                           border
                                                           border-green-500/50
                                                           text-green-400
                                                           font-orbitron
                                                           text-xs
                                                           tracking-widest
                                                           uppercase
                                                           rounded-lg
                                                           hover:bg-green-500
                                                           hover:text-black
                                                           transition-all
                                                           disabled:opacity-50"
                                            >
                                                {fixing
                                                    ? '⟳ Fixing...'
                                                    : '🔧 Fix Code'}
                                            </motion.button>
                                        )}
                                    </div>
                                </div>

                                {/* Static Findings */}
                                <div className="space-y-2
                                                max-h-80
                                                overflow-y-auto">
                                    {result.findings.map(
                                        (f, i) => (
                                        <div key={i}
                                             className={`rounded-lg p-3
                                                border-l-4 text-xs
                                                ${f.severity==='CRITICAL'
                                                    ? 'border-red-500 bg-red-500/5'
                                                    : f.severity==='HIGH'
                                                    ? 'border-orange-500 bg-orange-500/5'
                                                    : 'border-yellow-500 bg-yellow-500/5'
                                                }`}
                                        >
                                            <div className="flex
                                                            items-center
                                                            gap-2 mb-1">
                                                <SeverityBadge
                                                    severity={
                                                        f.severity
                                                    }
                                                />
                                                <span className="font-orbitron
                                                                 font-bold
                                                                 text-white/80
                                                                 tracking-wider">
                                                    {f.code}
                                                </span>
                                                <span className="text-gray-600
                                                                 ml-auto">
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
                                                    rounded-xl p-4">
                                        <p className="font-orbitron
                                                       text-purple-400
                                                       text-xs
                                                       tracking-widest
                                                       uppercase mb-3">
                                            🤖 AI Deep Analysis
                                        </p>
                                        <pre className="text-gray-400
                                                        text-xs
                                                        font-inter
                                                        whitespace-pre-wrap
                                                        leading-relaxed
                                                        max-h-64
                                                        overflow-y-auto">
                                            {result.ai_analysis}
                                        </pre>
                                    </div>
                                )}

                                {/* Fixed Code */}
                                {fixResult && (
                                    <div className="scanner-glass
                                                    rounded-xl p-4
                                                    border
                                                    border-green-500/20">
                                        <div className="flex items-center
                                                        justify-between
                                                        mb-3">
                                            <p className="font-orbitron
                                                           text-green-400
                                                           text-xs
                                                           tracking-widest
                                                           uppercase">
                                                ✓ Fixed Code Ready
                                            </p>
                                            <button
                                                onClick={downloadFixed}
                                                className="text-xs
                                                           font-orbitron
                                                           tracking-widest
                                                           uppercase
                                                           px-4 py-2
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
                                                            text-xs
                                                            font-mono
                                                            bg-black/40
                                                            rounded-lg
                                                            p-3
                                                            max-h-48
                                                            overflow-auto">
                                                {fixResult.fixed_code
                                                    .slice(0, 1000)}
                                                {fixResult.fixed_code
                                                    .length > 1000
                                                    && '\n... (download for full file)'}
                                            </pre>
                                        )}
                                    </div>
                                )}
                            </>
                        )}

                        {!result && !loading && (
                            <div className="scanner-glass
                                            rounded-xl p-12
                                            text-center">
                                <div className="text-4xl mb-4">
                                    🔍
                                </div>
                                <p className="text-gray-600
                                              font-orbitron
                                              text-sm
                                              tracking-wider">
                                    Upload a code file to
                                    begin analysis
                                </p>
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default CodeScanPage;
