import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import logo from '../assets/cybrain_logo.png';

const Navbar = () => {
    const location = useLocation();
    const isPricingPage = location.pathname === '/pricing';

    return (
        <nav className="fixed top-0 left-0 w-full z-[100] h-[72px] flex items-center bg-transparent">
            <div className="w-full px-6 md:px-12 flex items-center justify-between">

                {/* LOGO — larger but navbar height stays 72px */}
                <Link to="/" className="flex items-center gap-3 group relative z-10">
                    <img
                        src={logo}
                        alt="Cybrain"
                        className="h-16 md:h-20 lg:h-24 w-auto object-contain
                                   drop-shadow-[0_0_20px_rgba(0,245,212,0.5)]
                                   hover:drop-shadow-[0_0_35px_rgba(0,245,212,0.8)]
                                   transition-all duration-300 transform group-hover:scale-105"
                    />
                </Link>

                {/* NAV LINKS */}
                <div className="flex items-center gap-5 md:gap-8">
                    <Link
                        to="/scan/web"
                        className="font-orbitron text-[10px] md:text-xs font-bold tracking-[0.2em]
                                   uppercase text-gray-400 hover:text-cyan-400
                                   transition-all duration-300"
                    >
                        SCANNER
                    </Link>
                    <Link
                        to="/reports"
                        className="font-orbitron text-[10px] md:text-xs font-bold tracking-[0.2em]
                                   uppercase text-gray-400 hover:text-cyan-400
                                   transition-all duration-300 hidden md:block"
                    >
                        REPORTS
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
