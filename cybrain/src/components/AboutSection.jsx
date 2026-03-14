import React from 'react';
import { motion } from 'framer-motion';
import { Shield, Zap, Search, Lock, Cpu, Globe } from 'lucide-react';

const ServiceCard = ({ icon: Icon, title, desc, delay }) => (
    <motion.div
        initial={{ opacity: 0, y: 20 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true }}
        transition={{ duration: 0.6, delay }}
        className="group relative p-8 rounded-2xl bg-white/5 border border-white/10 hover:border-cyan-500/30 transition-all duration-500 overflow-hidden"
    >
        {/* Glow Background */}
        <div className="absolute -inset-1 bg-gradient-to-r from-cyan-500/0 via-cyan-500/0 to-cyan-500/0 group-hover:from-cyan-500/5 group-hover:via-purple-500/5 group-hover:to-cyan-500/5 transition-all duration-1000 blur-2xl opacity-0 group-hover:opacity-100" />
        
        <div className="relative z-10">
            <div className="w-12 h-12 rounded-xl bg-cyan-500/10 flex items-center justify-center mb-6 group-hover:scale-110 transition-transform duration-500 border border-cyan-500/20">
                <Icon className="w-6 h-6 text-cyan-400" />
            </div>
            <h3 className="font-orbitron font-bold text-xl text-white mb-4 tracking-wider group-hover:text-cyan-400 transition-colors">
                {title}
            </h3>
            <p className="text-gray-400 font-inter text-sm leading-relaxed tracking-wide">
                {desc}
            </p>
        </div>

        {/* Bottom line animation */}
        <div className="absolute bottom-0 left-0 h-[2px] w-0 bg-gradient-to-r from-cyan-500 to-purple-500 group-hover:w-full transition-all duration-700" />
    </motion.div>
);

const AboutSection = () => {
    const services = [
        {
            icon: Shield,
            title: "Autonomous Auditing",
            desc: "Advanced AI algorithms perform non-invasive penetration testing and vulnerability discovery across your entire digital surface.",
            delay: 0.1
        },
        {
            icon: Cpu,
            title: "Neural Threat Analysis",
            desc: "Leveraging Llama 3.3 70B intelligence to classify complex threats and provide context-aware remediation strategies in seconds.",
            delay: 0.2
        },
        {
            icon: Zap,
            title: "Real-time Hardening",
            desc: "Instantly generate secure configuration patterns and code fixes tailored to your specific environment and security policies.",
            delay: 0.3
        },
        {
            icon: Search,
            title: "Deep Reconnaissance",
            desc: "Multi-layered network mapping and service discovery to identify shadow IT and exposed assets before attackers do.",
            delay: 0.4
        },
        {
            icon: Lock,
            title: "Compliance Mastery",
            desc: "Align your infrastructure with OWASP Top 10, NIST, and ISO standards using automated validation frameworks.",
            delay: 0.5
        },
        {
            icon: Globe,
            title: "Global Intelligence",
            desc: "Continuous synchronization with zero-day databases and threat feeds ensures your protection is always one step ahead.",
            delay: 0.6
        }
    ];

    return (
        <section id="services" className="py-24 px-6 md:px-12 relative overflow-hidden">
            {/* Background elements */}
            <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] bg-cyan-500/5 rounded-full blur-[120px] pointer-events-none" />
            
            <div className="max-w-7xl mx-auto relative z-10">
                <div className="flex flex-col md:flex-row items-end justify-between mb-20 gap-8">
                    <div className="max-w-2xl">
                        <motion.p 
                            initial={{ opacity: 0 }}
                            whileInView={{ opacity: 1 }}
                            className="font-orbitron text-xs tracking-[0.4em] uppercase text-cyan-500/70 mb-4"
                        >
                            Orchestrating Security
                        </motion.p>
                        <motion.h2 
                            initial={{ opacity: 0, x: -30 }}
                            whileInView={{ opacity: 1, x: 0 }}
                            className="font-orbitron font-black text-4xl md:text-5xl text-white tracking-widest leading-tight"
                        >
                            THE <span className="text-cyan-400 text-glow-cyan">CYBRAIN</span> SOLUTION
                        </motion.h2>
                    </div>
                    <motion.div 
                        initial={{ opacity: 0, y: 20 }}
                        whileInView={{ opacity: 1, y: 0 }}
                        className="max-w-md"
                    >
                        <p className="text-gray-500 font-inter text-sm md:text-base leading-relaxed tracking-wide">
                            We provide enterprise-grade security intelligence that evolves 
                            with the threat landscape, transforming reactive posture into 
                            proactive dominance.
                        </p>
                    </motion.div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 md:gap-8">
                    {services.map((s, i) => (
                        <ServiceCard key={i} {...s} />
                    ))}
                </div>

                {/* Bottom CTA or Badge */}
                <motion.div 
                    initial={{ opacity: 0 }}
                    whileInView={{ opacity: 1 }}
                    className="mt-24 flex flex-col items-center justify-center p-12 rounded-3xl border border-white/5 bg-gradient-to-b from-white/[0.02] to-transparent text-center"
                >
                    <div className="h-px w-24 bg-cyan-500/30 mb-8" />
                    <h3 className="font-orbitron text-2xl text-white mb-4 tracking-[0.2em]">READY FOR DEPLOYMENT</h3>
                    <p className="text-gray-500 font-inter text-sm max-w-lg mb-8 tracking-wide">
                        Experience the next generation of security auditing. Deploy Cybrain 
                        to your infrastructure and gain immediate visibility.
                    </p>
                    <a 
                        href="#scanner" 
                        className="px-10 py-4 bg-cyan-500/20 border border-cyan-500/50 text-cyan-400 font-orbitron text-xs tracking-[0.3em] uppercase hover:bg-cyan-500 hover:text-black transition-all duration-300 rounded-sm flex items-center gap-3"
                    >
                        INITIALIZE SCAN
                        <span>→</span>
                    </a>
                </motion.div>
            </div>
        </section>
    );
};

export default AboutSection;
