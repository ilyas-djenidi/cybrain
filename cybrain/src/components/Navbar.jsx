import React, { useEffect, useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import logo from '../assets/cybrain_logo.png';

const Navbar = () => {
    const [scrolled, setScrolled] = useState(false);
    const location = useLocation();

    useEffect(() => {
        const onScroll = () => setScrolled(window.scrollY > 20);
        window.addEventListener('scroll', onScroll);
        return () => window.removeEventListener('scroll', onScroll);
    }, []);

    const isPricingPage = location.pathname === '/pricing';

    return (
        <nav 
            className={`fixed top-0 left-0 w-full z-[100] transition-all duration-500 h-[72px] flex items-center ${
                scrolled || isPricingPage ? 'bg-black/80 backdrop-blur-xl border-b border-white/5' : 'bg-transparent'
            }`}
        >
            <div className="w-full px-6 md:px-12 flex items-center justify-between">

                {/* LOGO */}
                <Link to="/" className="flex items-center gap-3 group relative z-10">
                    <img
                        src={logo}
                        alt="Cybrain"
                        className="h-10 md:h-12 lg:h-14 w-auto object-contain
                                   drop-shadow-[0_0_15px_rgba(0,245,212,0.4)]
                                   hover:drop-shadow-[0_0_25px_rgba(0,245,212,0.7)]
                                   transition-all duration-300 transform group-hover:scale-105"
                    />
                </Link>

                {/* NAV LINKS */}
                <div className="flex items-center gap-4 md:gap-8">
                    <Link
                        to="/scan/web"
                        className="font-orbitron text-[10px] md:text-xs font-bold tracking-[0.2em]
                                   uppercase text-gray-400 hover:text-cyan-400
                                   transition-all duration-300"
                    >
                        SCANNER
                    </Link>
                    <Link
                        to="/pricing"
                        className={`font-orbitron text-[10px] md:text-xs font-bold tracking-[0.2em]
                                   uppercase transition-all duration-300 ${
                                       isPricingPage ? 'text-cyan-400' : 'text-gray-400 hover:text-cyan-400'
                                   }`}
                    >
                        PRICING
                    </Link>
                    
                    <Link
                        to="/pricing"
                        className="font-orbitron text-[10px] md:text-xs font-bold tracking-[0.2em]
                                   uppercase px-4 md:px-6 py-2 bg-cyan-500/10 
                                   border border-cyan-500/50 text-cyan-400
                                   hover:bg-cyan-500 hover:text-black
                                   transition-all duration-300 rounded-lg hidden sm:block"
                    >
                        GET PRO
                    </Link>

                    <Link
                        to="/login"
                        className="font-orbitron text-[10px] md:text-xs font-bold tracking-[0.2em]
                                   uppercase text-white/40 hover:text-white
                                   transition-all duration-300"
                    >
                        LOGIN
                    </Link>
                </div>
            </div>
        </nav>
    );
};

export default Navbar;
