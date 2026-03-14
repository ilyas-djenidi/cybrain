import React from 'react';
import { motion } from 'framer-motion';
import logo from '../assets/cybrain_logo.png';

const HeroSection = () => {
    return (
        <section className="h-screen w-full relative overflow-hidden bg-black">

            {/* Spline 3D Background */}
            <div className="absolute inset-0 z-0">
                <iframe
                    src="https://my.spline.design/boxeshover-moTMLK3GQFBGQDftEiPF6OlW"
                    frameBorder="0"
                    width="100%"
                    height="100%"
                    className="w-full h-full border-none"
                    style={{ pointerEvents: 'auto' }}
                />
            </div>

            {/* Dark overlay for readability */}
            <div className="absolute inset-0 z-[1] bg-black/30 pointer-events-none" />

            {/* Hero Content — left aligned matching navbar */}
            <div className="absolute inset-0 z-10 pointer-events-none
                            flex flex-col justify-center
                            px-6 md:px-12 max-w-7xl mx-auto w-full
                            pt-20">
                <motion.div
                    initial={{ opacity: 0, y: 30 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 1, ease: 'easeOut' }}
                    className="max-w-2xl"
                >

                    {/* Main headline */}
                    <motion.h1
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ duration: 0.9, delay: 0.4 }}
                        className="font-orbitron font-black leading-tight"
                    >
                        <span className="block text-white text-4xl md:text-6xl
                                         tracking-tight">
                            INTELLIGENT
                        </span>
                        <span className="block text-cyan-400 text-xl md:text-3xl
                                         tracking-[0.3em] mt-2 uppercase">
                            Security Platform
                        </span>
                    </motion.h1>

                    {/* Subtitle */}
                    <motion.p
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        transition={{ duration: 1, delay: 0.7 }}
                        className="mt-6 text-gray-400 text-sm md:text-base
                                   font-inter font-light tracking-wide
                                   border-l-2 border-purple-500/60 pl-5
                                   max-w-md leading-relaxed"
                    >
                        Protecting your digital frontier with AI-powered{' '}
                        <span className="text-cyan-400 font-medium italic">
                            Cybrain
                        </span>{' '}
                        intelligence.
                    </motion.p>

                    {/* CTA */}
                    <motion.div
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ duration: 0.8, delay: 1 }}
                        className="mt-10 pointer-events-auto"
                    >
                        <a
                            href="#scanner"
                            className="inline-flex items-center gap-3
                                       px-8 py-3 bg-cyan-500/10
                                       border border-cyan-500/50 text-cyan-400
                                       font-orbitron font-bold text-xs
                                       tracking-[0.3em] uppercase rounded-sm
                                       hover:bg-cyan-500 hover:text-black
                                       transition-all duration-300"
                        >
                            INITIALIZE SCAN
                            <span className="text-base">→</span>
                        </a>
                    </motion.div>
                </motion.div>
            </div>

            {/* Bottom gradient fade into sections */}
            <div className="absolute bottom-0 left-0 w-full h-48 z-[2]
                            bg-gradient-to-t from-black to-transparent" />
        </section>
    );
};

export default HeroSection;
