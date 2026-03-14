import React, { useState } from 'react';
import { motion } from 'framer-motion';

const NetworkTab = ({ onScan, loading }) => {
    const [target, setTarget] = useState('');
    const [scanType, setScanType] = useState('full');

    const handleScan = () => {
        if (!target.trim()) return;
        // Strip http:// — network scanner needs hostname/IP
        let clean = target
            .replace(/^https?:\/\//, '')
            .split('/')[0]
            .split(':')[0];
        onScan(clean, scanType);
    };

    const scanTypes = [
        {
            id: 'full',
            label: 'Full Scan',
            desc: 'Ports + Vulns + OS'
        },
        {
            id: 'ports',
            label: 'Port Scan',
            desc: 'Open ports only'
        },
        {
            id: 'quick',
            label: 'Quick Scan',
            desc: 'Top 10 ports'
        },
    ];

    return (
        <div className="space-y-6">
            {/* Header */}
            <div>
                <h3 className="font-orbitron font-bold
                               text-white text-lg
                               tracking-wider mb-2">
                    NETWORK VULNERABILITY SCAN
                </h3>
                <p className="text-gray-500 text-sm
                              font-inter">
                    Scan ports, detect services, and identify
                    network-level vulnerabilities.
                    <span className="text-cyan-500/60
                                     ml-2 text-xs">
                        Test on: scanme.nmap.org
                    </span>
                </p>
            </div>

            {/* Target Input */}
            <div className="space-y-2">
                <label className="font-orbitron text-xs
                                  text-gray-500
                                  tracking-widest uppercase">
                    Target Host / IP
                </label>
                <div className="flex gap-3">
                    <input
                        type="text"
                        value={target}
                        onChange={e =>
                            setTarget(e.target.value)
                        }
                        onKeyDown={e =>
                            e.key === 'Enter' && handleScan()
                        }
                        placeholder="scanme.nmap.org or 192.168.1.1"
                        className="flex-1 bg-black/40
                                   border border-gray-700/50
                                   rounded-xl px-4 py-3
                                   text-gray-300 font-mono
                                   text-sm placeholder-gray-600
                                   focus:outline-none
                                   focus:border-cyan-500/50
                                   focus:ring-1
                                   focus:ring-cyan-500/20
                                   transition-all"
                    />
                </div>
            </div>

            {/* Scan Type */}
            <div className="space-y-2">
                <label className="font-orbitron text-xs
                                  text-gray-500
                                  tracking-widest uppercase">
                    Scan Type
                </label>
                <div className="grid grid-cols-3 gap-3">
                    {scanTypes.map(type => (
                        <button
                            key={type.id}
                            onClick={() =>
                                setScanType(type.id)
                            }
                            className={`p-3 rounded-xl
                                border text-left
                                transition-all duration-300
                                ${scanType === type.id
                                    ? 'border-cyan-500/60 bg-cyan-500/10 text-cyan-400'
                                    : 'border-gray-700/50 bg-black/20 text-gray-500 hover:border-gray-600'
                                }`}
                        >
                            <div className="font-orbitron
                                           text-xs
                                           font-bold
                                           tracking-wider
                                           mb-1">
                                {type.label}
                            </div>
                            <div className="text-xs
                                           font-inter
                                           opacity-70">
                                {type.desc}
                            </div>
                        </button>
                    ))}
                </div>
            </div>

            {/* What We Check */}
            <div className="bg-black/20 rounded-xl p-4
                            border border-gray-800/50">
                <p className="font-orbitron text-xs
                              text-gray-500
                              tracking-widest uppercase
                              mb-3">
                    Checks Performed
                </p>
                <div className="grid grid-cols-2 gap-2">
                    {[
                        "Port Scanning (27 ports)",
                        "Service Detection",
                        "OS Fingerprinting",
                        "Banner Grabbing",
                        "SMB / EternalBlue",
                        "RDP / BlueKeep",
                        "Default Credentials",
                        "Unencrypted Services",
                        "Database Exposure",
                        "NoSQL Exposure",
                        "Firewall Analysis",
                        "CVE Matching",
                    ].map((check, i) => (
                        <div key={i}
                             className="flex items-center
                                        gap-2 text-xs
                                        text-gray-500
                                        font-inter">
                            <div className="w-1.5 h-1.5
                                           rounded-full
                                           bg-cyan-500/50
                                           flex-shrink-0"/>
                            {check}
                        </div>
                    ))}
                </div>
            </div>

            {/* Warning */}
            <div className="flex items-start gap-3 p-4
                            bg-yellow-500/5
                            border border-yellow-500/20
                            rounded-xl">
                <span className="text-yellow-500 text-lg
                                 flex-shrink-0">
                    ⚠
                </span>
                <p className="text-yellow-500/70 text-xs
                              font-inter leading-relaxed">
                    Only scan systems you own or have
                    explicit written permission to test.
                    Authorized targets: scanme.nmap.org,
                    testphp.vulnweb.com, localhost.
                </p>
            </div>

            {/* Scan Button */}
            <motion.button
                onClick={handleScan}
                disabled={loading || !target.trim()}
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
                className={`w-full py-4 font-orbitron
                           font-bold text-sm
                           tracking-[0.2em] uppercase
                           rounded-xl transition-all
                           duration-300 border
                           ${loading || !target.trim()
                               ? 'border-gray-700 text-gray-600 cursor-not-allowed'
                               : 'border-cyan-500/50 text-cyan-400 hover:bg-cyan-500 hover:text-black'
                           }`}
            >
                {loading
                    ? '⟳ SCANNING NETWORK...'
                    : '▶ LAUNCH NETWORK SCAN'
                }
            </motion.button>
        </div>
    );
};

export default NetworkTab;
