import React from 'react';
import { motion } from 'framer-motion';

const ReportPage = () => {
    return (
        <div className="min-h-screen bg-black content-section pt-24 pb-16 px-6 md:px-12">
            <div className="max-w-6xl mx-auto">
                {/* Header */}
                <motion.div initial={{ opacity:0, y:20 }} animate={{ opacity:1, y:0 }} className="mb-10 text-center">
                    <a href="/" className="text-cyan-500/60 text-xs font-orbitron tracking-widest uppercase hover:text-cyan-400 mb-4 inline-block">← Back to Home</a>
                    <h1 className="font-orbitron font-black text-4xl text-white tracking-wider mb-2">
                        SCAN <span className="text-cyan-400">REPORTS</span>
                    </h1>
                    <p className="text-gray-500 font-inter text-sm">
                        View and download your historical security assessments.
                    </p>
                </motion.div>

                <div className="scanner-glass rounded-2xl p-12 text-center border-2 border-dashed border-gray-800">
                    <div className="text-5xl mb-6 opacity-30">📋</div>
                    <h3 className="font-orbitron text-white font-bold text-xl mb-3 tracking-widest">NO REPORTS FOUND</h3>
                    <p className="text-gray-600 max-w-md mx-auto font-inter text-sm mb-8">
                        You haven't generated any reports yet. Complete a scan to see your detailed results here.
                    </p>
                    <a href="/" className="px-8 py-3 bg-cyan-500 text-black font-orbitron font-bold text-xs tracking-[0.2em] rounded-xl hover:shadow-[0_0_20px_rgba(0,245,212,0.5)] transition-all">
                        START NEW SCAN
                    </a>
                </div>
            </div>
        </div>
    );
};

export default ReportPage;
