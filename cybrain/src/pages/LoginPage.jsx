import React from 'react';
import { motion } from 'framer-motion';
import { Github, Mail, Lock, User, ArrowRight } from 'lucide-react';

const LoginPage = () => {
    return (
        <div className="min-h-screen bg-black flex items-center justify-center p-6 relative overflow-hidden">
            {/* Background Glows */}
            <div className="absolute top-1/4 -left-24 w-96 h-96 bg-cyan-500/10 rounded-full blur-[120px]" />
            <div className="absolute bottom-1/4 -right-24 w-96 h-96 bg-purple-500/10 rounded-full blur-[120px]" />

            <motion.div 
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                className="w-full max-w-md relative z-10"
            >
                <div className="bg-white/[0.03] backdrop-blur-2xl border border-white/10 p-8 md:p-10 rounded-3xl shadow-2xl">
                    <div className="text-center mb-10">
                        <h1 className="font-orbitron font-black text-3xl text-white tracking-widest mb-2">
                            CYBRAIN <span className="text-cyan-400 text-glow-cyan">COMMAND</span>
                        </h1>
                        <p className="text-gray-500 font-inter text-sm tracking-wide">
                            Enter your credentials to access the orchestrator.
                        </p>
                    </div>

                    <form className="space-y-6">
                        <div className="space-y-2">
                            <label className="text-[10px] font-orbitron text-gray-500 tracking-[0.2em] uppercase ml-1">Email Address</label>
                            <div className="relative group">
                                <Mail className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-600 group-focus-within:text-cyan-400 transition-colors" />
                                <input 
                                    type="email" 
                                    placeholder="operator@cybrain.io"
                                    className="w-full bg-black/40 border border-white/5 rounded-xl py-3.5 pl-12 pr-4 text-white placeholder:text-gray-700 focus:outline-none focus:border-cyan-500/50 focus:bg-black/60 transition-all font-inter text-sm"
                                />
                            </div>
                        </div>

                        <div className="space-y-2">
                            <label className="text-[10px] font-orbitron text-gray-500 tracking-[0.2em] uppercase ml-1">Access Token</label>
                            <div className="relative group">
                                <Lock className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-600 group-focus-within:text-cyan-400 transition-colors" />
                                <input 
                                    type="password" 
                                    placeholder="••••••••••••"
                                    className="w-full bg-black/40 border border-white/5 rounded-xl py-3.5 pl-12 pr-4 text-white placeholder:text-gray-700 focus:outline-none focus:border-cyan-500/50 focus:bg-black/60 transition-all font-inter text-sm"
                                />
                            </div>
                        </div>

                        <button 
                            type="button"
                            className="w-full py-4 bg-cyan-500 text-black font-orbitron font-bold text-xs tracking-[0.2em] uppercase rounded-xl hover:bg-cyan-400 transition-all duration-300 shadow-[0_0_20px_rgba(0,245,212,0.3)] flex items-center justify-center gap-2"
                        >
                            Log In 
                            <ArrowRight className="w-4 h-4" />
                        </button>
                    </form>

                    <div className="mt-10">
                        <div className="relative flex items-center justify-center mb-8">
                            <div className="absolute inset-0 flex items-center">
                                <div className="w-full border-t border-white/5"></div>
                            </div>
                            <span className="relative px-4 bg-transparent text-[10px] font-orbitron text-gray-600 tracking-[0.2em] uppercase">Third-Party Auth</span>
                        </div>

                        <div className="grid grid-cols-2 gap-4">
                            <button className="flex items-center justify-center gap-3 py-3 bg-white/[0.02] border border-white/5 rounded-xl hover:bg-white/[0.05] hover:border-white/10 transition-all text-white font-inter text-sm group">
                                <Github className="w-5 h-5 text-gray-400 group-hover:text-white transition-colors" />
                                GitHub
                            </button>
                            <button className="flex items-center justify-center gap-3 py-3 bg-white/[0.02] border border-white/5 rounded-xl hover:bg-white/[0.05] hover:border-white/10 transition-all text-white font-inter text-sm group">
                                <img src="https://www.gstatic.com/images/branding/product/1x/gsa_512dp.png" className="w-4 h-4 opacity-70 group-hover:opacity-100 transition-opacity filter grayscale group-hover:grayscale-0" alt="Google" />
                                Google
                            </button>
                        </div>
                    </div>

                    <div className="mt-10 text-center">
                        <p className="text-gray-600 font-inter text-xs tracking-wide">
                            New operative? {' '}
                            <a href="/register" className="text-cyan-400 hover:underline">Request Access</a>
                        </p>
                    </div>
                </div>

                <div className="mt-8 text-center flex flex-col gap-2">
                    <p className="text-[10px] font-orbitron text-gray-700 tracking-[0.3em] uppercase">
                        Enterprise Security Intelligence
                    </p>
                    <a href="/" className="text-gray-600 text-[10px] font-orbitron tracking-widest hover:text-gray-400 transition-colors">
                        ← RETURN TO DOCK
                    </a>
                </div>
            </motion.div>
        </div>
    );
};

export default LoginPage;
