import React, { useState } from 'react';

const ConfigTab = ({ onAnalyze, loading }) => {
    const [content, setContent] = useState('');

    const handleAnalyze = () => {
        if (!content.trim() || loading) return;
        onAnalyze(content);
    };

    return (
        <div className="space-y-6">
            <div className="space-y-2">
                <label className="text-gray-400 text-[10px] font-orbitron font-bold tracking-[0.2em] uppercase">
                    Apache Configuration Stream
                </label>
                <textarea
                    value={content}
                    onChange={(e) => setContent(e.target.value)}
                    placeholder="Paste httpd.conf or .htaccess logic here..."
                    className="w-full bg-black/40 border border-gray-800 rounded-xl p-6 text-gray-300 font-mono text-sm resize-none h-64 focus:outline-none focus:border-cyan-400/50 transition-colors"
                ></textarea>
            </div>
            
            <button
                onClick={handleAnalyze}
                disabled={!content.trim() || loading}
                className="w-full py-4 bg-gradient-to-r from-cyan-400 to-purple-500 text-black font-orbitron font-black tracking-widest uppercase rounded-xl hover:shadow-[0_0_25px_rgba(0,245,212,0.4)] transition-all active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed"
            >
                {loading ? 'PROCESSING...' : 'ANALYZE CONFIGURATION'}
            </button>
        </div>
    );
};

export default ConfigTab;
