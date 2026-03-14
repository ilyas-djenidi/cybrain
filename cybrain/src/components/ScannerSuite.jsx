import React, { useState } from 'react';
import { useScanner } from '../hooks/useScanner';
import ConfigTab from './tabs/ConfigTab';
import UploadTab from './tabs/UploadTab';
import UrlTab from './tabs/UrlTab';
import NetworkTab from './tabs/NetworkTab';
import ResultsPanel from './ResultsPanel';
import ScanProgress from './ScanProgress';

const ScannerSuite = ({ activeTabProp }) => {
    const [activeTab, setActiveTab] = useState('config');
    const { findings, loading, error, total, scanUrl, scanNetwork, analyzeConfig, analyzeFile } = useScanner();

    // Sync external tab changes
    React.useEffect(() => {
        if (activeTabProp) setActiveTab(activeTabProp);
    }, [activeTabProp]);

    const tabs = [
        { id: 'config', label: 'Config Analysis' },
        { id: 'upload', label: 'Upload File' },
        { id: 'url', label: 'Scan URL' },
        { id: 'network', label: 'Network Scan' }
    ];

    return (
        <div className="max-w-4xl mx-auto">
            {/* Tabs Navigation */}
            <div className="flex justify-center gap-4 md:gap-8 mb-10">
                {tabs.map(tab => (
                    <button
                        key={tab.id}
                        onClick={() => setActiveTab(tab.id)}
                        className={`font-orbitron text-[10px] md:text-sm font-bold tracking-widest uppercase py-2 transition-all border-b-2 ${
                            activeTab === tab.id 
                            ? 'text-cyan-400 border-cyan-400 drop-shadow-[0_0_8px_rgba(0,245,212,0.5)]' 
                            : 'text-gray-500 border-transparent hover:text-gray-300'
                        }`}
                    >
                        {tab.label}
                    </button>
                ))}
            </div>

            {/* Panel Container */}
            <div className="bg-white/5 backdrop-blur-xl border border-cyan-500/20 rounded-2xl p-6 md:p-10 shadow-2xl overflow-hidden relative">
                {/* Background Decor */}
                <div className="absolute top-0 right-0 w-32 h-32 bg-cyan-400/5 blur-3xl rounded-full -mr-16 -mt-16"></div>
                <div className="absolute bottom-0 left-0 w-32 h-32 bg-purple-500/5 blur-3xl rounded-full -ml-16 -mb-16"></div>

                {/* Tab Content */}
                <div className="relative z-10">
                    {activeTab === 'config' && <ConfigTab onAnalyze={analyzeConfig} loading={loading} />}
                    {activeTab === 'upload' && <UploadTab onUpload={analyzeFile} loading={loading} />}
                    {activeTab === 'url' && <UrlTab onScan={scanUrl} loading={loading} />}
                    {activeTab === 'network' && <NetworkTab onScan={scanNetwork} loading={loading} />}
                </div>

                {/* error message */}
                {error && (
                    <div className="mt-6 p-4 bg-red-500/10 border border-red-500/30 rounded-xl text-red-400 text-sm">
                        <span className="font-bold">Intelligence Link Failed:</span> {error}
                    </div>
                )}
            </div>

            {/* Progress and Results */}
            <ScanProgress loading={loading} />
            
            {!loading && findings.length > 0 && (
                <ResultsPanel findings={findings} total={total} />
            )}
        </div>
    );
};

export default ScannerSuite;
