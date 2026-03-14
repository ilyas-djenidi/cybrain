import React from 'react';
import { motion } from 'framer-motion';
import { Github, Mail, Lock, User, ArrowRight, ShieldCheck } from 'lucide-react';

const RegisterPage = () => {
    return (
        <div className="min-h-screen bg-black flex items-center justify-center p-6 relative overflow-hidden">
            {/* Background Glows */}
            <div className="absolute top-1/4 -right-24 w-96 h-96 bg-purple-500/10 rounded-full blur-[120px]" />
            <div className="absolute bottom-1/4 -left-24 w-96 h-96 bg-cyan-500/10 rounded-full blur-[120px]" />

            <motion.div 
                initial={{ opacity: 0, scale: 0.98 }}
                animate={{ opacity: 1, scale: 1 }}
                className="w-full max-w-md relative z-10"
            >
                <div className="bg-white/[0.03] backdrop-blur-2xl border border-white/10 p-8 md:p-10 rounded-3xl shadow-2xl">
                    <div className="text-center mb-10">
                        <div className="w-16 h-16 bg-cyan-500/10 border border-cyan-500/20 rounded-2xl flex items-center justify-center mx-auto mb-6 shadow-[0_0_30px_rgba(0,245,212,0.1)]">
                            <ShieldCheck className="w-8 h-8 text-cyan-400" />
                        </div>
                        <h1 className="font-orbitron font-black text-2xl text-white tracking-widest mb-2 uppercase">
                            Register Operative
                        </h1>
                        <p className="text-gray-500 font-inter text-sm tracking-wide">
                            Join the next generation of security auditing.
                        </p>
                    </div>

                    <form className="space-y-5">
                        <div className="space-y-2">
                            <label className="text-[10px] font-orbitron text-gray-500 tracking-[0.2em] uppercase ml-1">Full Identity</label>
                            <div className="relative group">
                                <User className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-600 group-focus-within:text-cyan-400 transition-colors" />
                                <input 
                                    type="text" 
                                    placeholder="Agent 0x42"
                                    className="w-full bg-black/40 border border-white/5 rounded-xl py-3.5 pl-12 pr-4 text-white placeholder:text-gray-700 focus:outline-none focus:border-cyan-500/50 focus:bg-black/60 transition-all font-inter text-sm"
                                />
                            </div>
                        </div>

                        <div className="space-y-2">
                            <label className="text-[10px] font-orbitron text-gray-500 tracking-[0.2em] uppercase ml-1">Email Address</label>
                            <div className="relative group">
                                <Mail className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-600 group-focus-within:text-cyan-400 transition-colors" />
                                <input 
                                    type="email" 
                                    placeholder="agent@cybrain.io"
                                    className="w-full bg-black/40 border border-white/5 rounded-xl py-3.5 pl-12 pr-4 text-white placeholder:text-gray-700 focus:outline-none focus:border-cyan-500/50 focus:bg-black/60 transition-all font-inter text-sm"
                                />
                            </div>
                        </div>

                        <div className="space-y-2">
                            <label className="text-[10px] font-orbitron text-gray-500 tracking-[0.2em] uppercase ml-1">Secure Passphrase</label>
                            <div className="relative group">
                                <Lock className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-600 group-focus-within:text-cyan-400 transition-colors" />
                                <input 
                                    type="password" 
                                    placeholder="••••••••••••"
                                    className="w-full bg-black/40 border border-white/5 rounded-xl py-3.5 pl-12 pr-4 text-white placeholder:text-gray-700 focus:outline-none focus:border-cyan-500/50 focus:bg-black/60 transition-all font-inter text-sm"
                                />
                            </div>
                        </div>

                        <div className="pt-4">
                            <button 
                                type="button"
                                className="w-full py-4 bg-gradient-to-r from-cyan-600 to-purple-600 text-white font-orbitron font-bold text-xs tracking-[0.2em] uppercase rounded-xl hover:from-cyan-500 hover:to-purple-500 transition-all duration-300 shadow-[0_0_20px_rgba(0,245,212,0.2)] flex items-center justify-center gap-2"
                            >
                                Create Account
                                <ArrowRight className="w-4 h-4" />
                            </button>
                        </div>
                    </form>

                    <div className="mt-8 pt-8 border-t border-white/5 text-center">
                        <p className="text-gray-600 font-inter text-xs tracking-wide">
                            Already registered? {' '}
                            <a href="/login" className="text-cyan-400 hover:underline">Log In Here</a>
                        </p>
                    </div>
                </div>

                <div className="mt-8 text-center">
                    <a href="/" className="text-gray-600 text-[10px] font-orbitron tracking-widest hover:text-gray-400 transition-colors">
                        ← BACK TO HOME
                    </a>
                </div>
            </motion.div>
        </div>
    );
};

export default RegisterPage;
