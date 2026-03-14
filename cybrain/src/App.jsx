import React, { useState } from 'react';
import Navbar from './components/Navbar';
import HeroSection from './components/HeroSection';
import ScannerSuite from './components/ScannerSuite';
import TabCards from './components/TabCards';

function App() {
    const [scannerTab, setScannerTab] = useState('config');

    const handleCardSelect = (tabId) => {
        setScannerTab(tabId);
        setTimeout(() => {
            document.getElementById('scanner')?.scrollIntoView({
                behavior: 'smooth'
            });
        }, 100);
    };

    return (
        <div className="min-h-screen bg-black">
            <Navbar />

            {/* HERO — no dot pattern, has 3D Spline */}
            <HeroSection />

            {/* ALL CONTENT BELOW HERO — black + blue dot pattern */}
            <div className="content-section">

                {/* CYBER INTELLIGENCE CARDS SECTION */}
                <section className="py-28 px-6 md:px-12">
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
                                          font-inter max-w-md mx-auto
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

                {/* DIVIDER */}
                <div className="max-w-7xl mx-auto px-6 md:px-12">
                    <div className="h-px bg-gradient-to-r from-transparent
                                    via-cyan-500/30 to-transparent" />
                </div>

                {/* SCANNER SUITE SECTION */}
                <section id="scanner" className="py-28 px-6 md:px-12">
                    <div className="max-w-7xl mx-auto">
                        <div className="text-center mb-16">
                            <p className="font-orbitron text-xs tracking-[0.4em]
                                          uppercase text-purple-400/60 mb-4">
                                Active Scanning
                            </p>
                            <h2 className="font-orbitron font-black text-4xl
                                           text-white tracking-[0.15em]">
                                SECURITY{' '}
                                <span className="text-purple-400">SUITE</span>
                            </h2>
                            <div className="h-px w-32 bg-gradient-to-r
                                            from-transparent via-purple-500
                                            to-transparent mx-auto mt-6" />
                        </div>

                        <ScannerSuite activeTabProp={scannerTab} />
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

export default App;
