import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import AnimatedCubes from './AnimatedCubes';

const HeroSection = () => {
    const [isMobile, setIsMobile] = useState(false);

    useEffect(() => {
        const checkMobile = () => setIsMobile(window.innerWidth < 768);
        checkMobile();
        window.addEventListener('resize', checkMobile);
        return () => window.removeEventListener('resize', checkMobile);
    }, []);

    return (
        <section className="h-screen w-full relative overflow-hidden bg-black">

            {/* Background Layer */}
            <div className="absolute inset-0 z-0">
                {isMobile ? (
                    <AnimatedCubes />
                ) : (
                    <iframe
                        src="https://my.spline.design/boxeshover-moTMLK3GQFBGQDftEiPF6OlW"
                        frameBorder="0"
                        width="100%"
                        height="100%"
                        className="w-full h-full border-none"
                        style={{ pointerEvents: 'auto' }}
                    />
                )}
            </div>

            {/* Dark overlay for readability */}
            <div className="absolute inset-0 z-[1] bg-black/40 pointer-events-none" />

            {/* Hero Content */}
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
                        <span className="block text-white text-4xl md:text-6xl lg:text-7xl
                                         tracking-tight">
                            INTELLIGENT
                        </span>
                        <span className="block text-cyan-400 text-xl md:text-3xl lg:text-4xl
                                         tracking-[0.3em] mt-2 uppercase">
                            Security Platform
                        </span>
                    </motion.h1>

                    {/* Subtitle */}
                    <motion.p
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        transition={{ duration: 1, delay: 0.7 }}
                        className="mt-6 text-gray-400 text-sm md:text-base lg:text-lg
                                   font-inter font-light tracking-wide
                                   border-l-2 border-purple-500/60 pl-5
                                   max-w-md leading-relaxed"
                    >
                        Protecting your digital frontier with AI-powered{' '}
                        <span className="text-cyan-400 font-medium italic">
                            Cybrain
                        </span>{' '}
                        intelligence and Gemini 2.0 Flash
expert analysis.
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
                                       px-10 py-4 bg-cyan-500/10
                                       border border-cyan-500/50 text-cyan-400
                                       font-orbitron font-bold text-xs md:text-sm
                                       tracking-[0.2em] uppercase rounded-xl
                                       hover:bg-cyan-500 hover:text-black
                                       transition-all duration-300 
                                       shadow-[0_0_30px_rgba(0,245,212,0.15)]"
                        >
                            INITIALIZE SCAN →
                        </a>
                    </motion.div>
                </motion.div>
            </div>

            {/* Scroll Indicator */}
            <motion.div 
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: 2 }}
                className="absolute bottom-10 left-1/2 -translate-x-1/2 z-20 flex flex-col items-center gap-2"
            >
                <span className="text-[10px] font-orbitron text-gray-500 tracking-[0.3em] uppercase">Scroll</span>
                <div className="w-[1px] h-12 bg-gradient-to-b from-cyan-500/60 to-transparent relative overflow-hidden">
                    <motion.div 
                        animate={{ y: [0, 48] }}
                        transition={{ duration: 2, repeat: Infinity, ease: 'easeInOut' }}
                        className="absolute top-0 left-0 w-full h-1/3 bg-cyan-400"
                    />
                </div>
            </motion.div>

            {/* Bottom gradient fade */}
            <div className="absolute bottom-0 left-0 w-full h-48 z-[2]
                            bg-gradient-to-t from-black to-transparent" />
        </section>
    );
};

export default HeroSection;
