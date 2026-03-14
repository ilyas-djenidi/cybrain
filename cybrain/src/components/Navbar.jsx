import React, { useEffect, useState } from 'react';
import logo from '../assets/cybrain_logo.png';

const Navbar = () => {
    const [scrolled, setScrolled] = useState(false);

    useEffect(() => {
        const onScroll = () => setScrolled(window.scrollY > 50);
        window.addEventListener('scroll', onScroll);
        return () => window.removeEventListener('scroll', onScroll);
    }, []);

    return (
        <nav className="fixed top-0 left-0 w-full z-[100] transition-all duration-500 h-16 flex items-center bg-transparent mt-4"
        >
            <div className="w-full px-6 md:px-12 flex items-center justify-between">

                {/* LOGO — bigger size popping out of the fixed nav */}
                <a href="/" className="flex items-center gap-3 group relative z-10">
                    <img
                        src={logo}
                        alt="Cybrain"
                        className="h-24 w-auto object-contain
                                   drop-shadow-[0_0_20px_rgba(0,245,212,0.6)]
                                   hover:drop-shadow-[0_0_30px_rgba(0,245,212,0.9)]
                                   transition-all duration-300 transform group-hover:scale-105"
                    />
                </a>

                {/* NAV LINKS */}
                <div className="flex items-center gap-8">
                    <a
                        href="#scanner"
                        className="font-orbitron text-xs font-bold tracking-[0.15em]
                                   uppercase px-5 py-2 border border-cyan-500/50
                                   text-cyan-400 hover:bg-cyan-500 hover:text-black
                                   transition-all duration-300 rounded-sm"
                    >
                        Launch →
                    </a>
                </div>
            </div>
        </nav>
    );
};

export default Navbar;
