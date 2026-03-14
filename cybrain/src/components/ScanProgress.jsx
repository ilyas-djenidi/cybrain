import React from 'react';
import { motion } from 'framer-motion';

const ScanProgress = ({ loading }) => {
    if (!loading) return null;

    return (
        <div className="flex flex-col items-center justify-center py-12 space-y-6">
            <div className="relative">
                <div className="w-20 h-20 rounded-full border-4 border-cyan-400/20 border-t-cyan-400 animate-spin"></div>
                <div className="absolute inset-0 flex items-center justify-center">
                    <div className="w-12 h-12 bg-cyan-400/10 rounded-full animate-pulse ring-2 ring-cyan-400/50"></div>
                </div>
            </div>
            <div className="text-center">
                <h3 className="font-orbitron text-cyan-400 font-bold tracking-widest mb-2">SCANNING TARGET...</h3>
                <p className="text-gray-500 text-sm font-light">Establishing intelligence bridge and running security heuristics.</p>
            </div>
            
            <div className="w-full max-w-md bg-gray-800 h-1 rounded-full overflow-hidden">
                <motion.div 
                    initial={{ x: '-100%' }}
                    animate={{ x: '100%' }}
                    transition={{ repeat: Infinity, duration: 1.5, ease: "linear" }}
                    className="w-1/2 h-full bg-gradient-to-r from-transparent via-cyan-400 to-transparent"
                />
            </div>
        </div>
    );
};

export default ScanProgress;
