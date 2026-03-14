import React, { useState } from 'react';
import { Globe } from 'lucide-react';

const UrlTab = ({ onScan, loading }) => {
    const [url, setUrl] = useState('');

    const handleScan = () => {
        if (!url.trim() || loading) return;
        onScan(url);
    };

    return (
        <div className="space-y-8">
            <div className="space-y-4">
                <label className="text-gray-400 text-[10px] font-orbitron font-bold tracking-[0.2em] uppercase">
                    Target URL Exposure
                </label>
                
                <div className="relative group">
                    <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none text-gray-600 group-focus-within:text-cyan-400 transition-colors">
                        <Globe size={18} />
                    </div>
                    <input
                        type="url"
                        value={url}
                        onChange={(e) => setUrl(e.target.value)}
                        placeholder="https://testphp.vulnweb.com"
                        className="w-full bg-black/40 border border-gray-800 rounded-xl pl-12 pr-6 py-4 text-gray-300 font-inter text-base focus:outline-none focus:border-cyan-400/50 transition-colors placeholder:text-gray-700"
                    />
                </div>
                
                <p className="text-gray-600 text-[10px] font-light leading-relaxed">
                    Note: Scanning third-party websites without authorization is illegal. Only scan targets you own or have explicit permission to test.
                </p>
            </div>
            
            <button
                onClick={handleScan}
                disabled={!url.trim() || loading}
                className="w-full py-4 bg-transparent border border-cyan-400 text-cyan-400 font-orbitron font-black tracking-widest uppercase rounded-xl hover:bg-cyan-400 hover:text-black transition-all duration-300 active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed overflow-hidden relative group"
            >
                <span className="relative z-10">{loading ? 'SCANNING...' : 'TEST VULNERABILITIES'}</span>
                {/* Button Glow Effect */}
                <div className="absolute inset-0 bg-cyan-400 scale-x-0 group-hover:scale-x-0 transition-transform origin-left"></div>
            </button>
        </div>
    );
};

export default UrlTab;
