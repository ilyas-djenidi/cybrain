import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Navbar from './components/Navbar';
import HeroSection from './components/HeroSection';
import TabCards from './components/TabCards';
import AboutSection from './components/AboutSection';
import WebScanPage from './pages/WebScanPage';
import ApacheScanPage from './pages/ApacheScanPage';
import CodeScanPage from './pages/CodeScanPage';
import NetworkScanPage from './pages/NetworkScanPage';
import ReportPage from './pages/ReportPage';
import ChatBot from './components/ChatBot';

function HomePage() {
    const handleCardSelect = (tabId) => {
        const routesMap = {
            'web':     '/scan/web',
            'config':  '/scan/apache',
            'upload':  '/scan/code',
            'network': '/scan/network',
            'url':     '/scan/web'
        };
        if (routesMap[tabId]) {
            window.location.href = routesMap[tabId];
        }
    };

    return (
        <div className="min-h-screen bg-black">
            {/* 1. HERO SECTION */}
            <HeroSection />

            <div className="content-section">
                
                {/* 1. CYBER INTELLIGENCE CARDS */}
                <section id="scanner" className="py-28 px-6 md:px-12 scroll-mt-20">
                    <div className="max-w-7xl mx-auto">
                        <div className="text-center mb-16">
                            <p className="font-orbitron text-xs tracking-[0.4em]
                                          uppercase text-cyan-500/60 mb-4">
                                Intelligence Suite
                            </p>
                            <h2 className="font-orbitron font-black text-3xl
                                           md:text-4xl text-white tracking-[0.15em]">
                                CYBER{' '}
                                <span className="text-cyan-400 text-glow-cyan">
                                    INTELLIGENCE
                                </span>
                            </h2>
                            <div className="h-px w-32 bg-gradient-to-r
                                            from-transparent via-cyan-400
                                            to-transparent mx-auto mt-6" />
                            <p className="mt-6 text-gray-500 text-sm
                                          font-inter max-w-sm mx-auto
                                          tracking-widest leading-relaxed uppercase">
                                Select an entry point to begin your
                                professional security analysis.
                            </p>
                        </div>

                        <div className="flex justify-center">
                            <TabCards onSelect={handleCardSelect} />
                        </div>
                    </div>
                </section>

                {/* 2. ABOUT SERVICE SECTION */}
                <AboutSection />

                {/* 3. AI COMMAND SECTION */}
                <section className="py-24 px-6 bg-gradient-to-b from-transparent to-cyan-900/10">
                    <div className="max-w-7xl mx-auto flex flex-col items-center text-center">
                        <motion.div
                            initial={{ opacity: 0, y: 20 }}
                            whileInView={{ opacity: 1, y: 0 }}
                            transition={{ duration: 0.8 }}
                            className="mb-12"
                        >
                            <h1 className="font-orbitron font-black text-4xl md:text-5xl text-white tracking-widest mb-4">
                                CYBRAIN <span className="text-cyan-400 text-glow-cyan">COMMAND</span>
                            </h1>
                            <p className="text-gray-500 font-orbitron text-xs tracking-[0.5em] uppercase">
                                AI-Powered Security Intelligence Orchestrator
                            </p>
                            <div className="h-px w-32 bg-gradient-to-r from-transparent via-cyan-400 to-transparent mx-auto mt-6" />
                        </motion.div>

                        <motion.div
                            initial={{ opacity: 0, scale: 0.98 }}
                            whileInView={{ opacity: 1, scale: 1 }}
                            transition={{ duration: 1 }}
                            className="w-full"
                        >
                            <ChatBot position="inline" />
                        </motion.div>
                    </div>
                </section>

                {/* FOOTER */}
                <footer className="border-t border-white/5 py-12 px-6">
                    <div className="max-w-7xl mx-auto flex flex-col
                                    md:flex-row items-center justify-between
                                    gap-4">
                        <p className="font-orbitron text-[10px] text-gray-600
                                      tracking-[0.3em] uppercase">
                            © 2026 CYBRAIN Intelligence Platform
                        </p>
                        <p className="font-orbitron text-[10px] text-gray-700
                                      tracking-[0.2em] uppercase">
                            PFE Master 2 — Information Security
                        </p>
                    </div>
                </footer>
            </div>
        </div>
    );
}

function App() {
    return (
        <BrowserRouter>
            <div className="min-h-screen bg-black">
                <Navbar />
                <Routes>
                    <Route path="/" element={<HomePage />} />
                    <Route path="/scan/web" element={<WebScanPage />} />
                    <Route path="/scan/apache" element={<ApacheScanPage />} />
                    <Route path="/scan/code" element={<CodeScanPage />} />
                    <Route path="/scan/network" element={<NetworkScanPage />} />
                    <Route path="/reports" element={<ReportPage />} />
                </Routes>
                <ChatBot position="fixed" />
            </div>
        </BrowserRouter>
    );
}

export default App;
