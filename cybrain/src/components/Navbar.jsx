import React, { useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { Menu, X } from 'lucide-react';
import logo from '../assets/cybrain_logo.png';

const Navbar = () => {
    const location = useLocation();
    const isPricingPage = location.pathname === '/pricing';
    const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

    return (
        <>
            <nav className="fixed top-0 left-0 w-full z-[100] h-[72px] flex items-center bg-transparent">
                
                {/* Desktop Layout */}
                <div className="hidden md:flex w-full px-12 items-center justify-between">
                    <Link to="/" className="flex items-center gap-3 group relative z-10">
                        <img
                            src={logo}
                            alt="Cybrain"
                            className="h-20 lg:h-24 w-auto object-contain
                                       drop-shadow-[0_0_20px_rgba(0,245,212,0.5)]
                                       hover:drop-shadow-[0_0_35px_rgba(0,245,212,0.8)]
                                       transition-all duration-300 transform group-hover:scale-105"
                        />
                    </Link>
                    <div className="flex items-center gap-8">
                        <Link
                            to="/scan/web"
                            className="font-orbitron text-xs font-bold tracking-[0.2em]
                                       uppercase text-gray-400 hover:text-cyan-400
                                       transition-all duration-300"
                        >
                            SCANNER
                        </Link>

                        <Link
                            to="/pricing"
                            className={`font-orbitron text-xs font-bold tracking-[0.2em]
                                       uppercase transition-all duration-300 ${
                                           isPricingPage ? 'text-cyan-400' : 'text-gray-400 hover:text-cyan-400'
                                       }`}
                        >
                            PRICING
                        </Link>
                        <Link
                            to="/login"
                            className="font-orbitron text-xs font-bold tracking-[0.2em]
                                       uppercase text-white/40 hover:text-white
                                       transition-all duration-300"
                        >
                            LOGIN
                        </Link>
                    </div>
                </div>

                {/* Mobile Layout */}
                <div className="flex md:hidden w-full px-6 items-center justify-between relative">
                    {/* Left: Hamburger */}
                    <button 
                        onClick={() => setIsMobileMenuOpen(true)}
                        className="text-gray-400 hover:text-cyan-400 z-10 transition-colors"
                    >
                        <Menu className="w-8 h-8" />
                    </button>

                    {/* Center: Logo */}
                    <div className="absolute left-1/2 -translate-x-1/2 z-0">
                        <Link to="/">
                            <img
                                src={logo}
                                alt="Cybrain"
                                className="h-16 w-auto object-contain
                                           drop-shadow-[0_0_20px_rgba(0,245,212,0.5)]"
                            />
                        </Link>
                    </div>

                    {/* Right: Scan Button */}
                    <Link 
                        to="/scan/web"
                        className="z-10 font-orbitron text-[10px] font-bold tracking-[0.2em]
                                   uppercase px-4 py-2 bg-cyan-500/10 text-cyan-400
                                   border border-cyan-500/50 rounded-lg hover:bg-cyan-500
                                   hover:text-black transition-all"
                    >
                        SCAN
                    </Link>
                </div>
            </nav>

            {/* Mobile Side Menu Overlay */}
            {isMobileMenuOpen && (
                <div className="fixed inset-0 z-[200] flex md:hidden">
                    {/* Backdrop */}
                    <div 
                        className="fixed inset-0 bg-black/80 backdrop-blur-sm"
                        onClick={() => setIsMobileMenuOpen(false)} 
                    />
                    
                    {/* Sidebar */}
                    <div className="w-64 h-full bg-[#050505] border-r border-white/10 relative z-10 p-6 flex flex-col gap-8 shadow-[0_0_30px_rgba(0,245,212,0.1)]">
                        <div className="flex justify-between items-center mb-4">
                            <span className="font-orbitron font-bold text-cyan-400 tracking-[0.2em] uppercase text-xs">
                                MENU
                            </span>
                            <button 
                                onClick={() => setIsMobileMenuOpen(false)} 
                                className="text-gray-400 hover:text-white transition-colors"
                            >
                                <X className="w-6 h-6" />
                            </button>
                        </div>
                        
                        <div className="flex flex-col gap-6">
                            <Link 
                                to="/" 
                                onClick={() => setIsMobileMenuOpen(false)} 
                                className="font-orbitron text-xs font-bold tracking-[0.2em] uppercase text-gray-400 hover:text-cyan-400"
                            >
                                HOME
                            </Link>
                            <Link 
                                to="/scan/web" 
                                onClick={() => setIsMobileMenuOpen(false)} 
                                className="font-orbitron text-xs font-bold tracking-[0.2em] uppercase text-gray-400 hover:text-cyan-400"
                            >
                                SCAN WEB
                            </Link>
                            <Link 
                                to="/scan/network" 
                                onClick={() => setIsMobileMenuOpen(false)} 
                                className="font-orbitron text-xs font-bold tracking-[0.2em] uppercase text-gray-400 hover:text-cyan-400"
                            >
                                SCAN NETWORK
                            </Link>
                            <Link 
                                to="/scan/code" 
                                onClick={() => setIsMobileMenuOpen(false)} 
                                className="font-orbitron text-xs font-bold tracking-[0.2em] uppercase text-gray-400 hover:text-cyan-400"
                            >
                                CODE CHECK
                            </Link>
                            <Link 
                                to="/scan/apache" 
                                onClick={() => setIsMobileMenuOpen(false)} 
                                className="font-orbitron text-xs font-bold tracking-[0.2em] uppercase text-gray-400 hover:text-cyan-400"
                            >
                                MISCONFIG CHECK
                            </Link>

                            <Link 
                                to="/pricing" 
                                onClick={() => setIsMobileMenuOpen(false)} 
                                className={`font-orbitron text-xs font-bold tracking-[0.2em] uppercase ${isPricingPage ? 'text-cyan-400' : 'text-gray-400 hover:text-cyan-400'}`}
                            >
                                PRICING
                            </Link>
                            <Link 
                                to="/login" 
                                onClick={() => setIsMobileMenuOpen(false)} 
                                className="font-orbitron text-xs font-bold tracking-[0.2em] uppercase text-gray-400 hover:text-cyan-400 mt-8"
                            >
                                LOGIN
                            </Link>
                        </div>
                    </div>
                </div>
            )}
        </>
    );
};

export default Navbar;
