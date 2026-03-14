import React from 'react';
import { motion } from 'framer-motion';
import { Cpu, Binary, Zap, Network } from 'lucide-react';

const cards = [
    {
        id: 'config',
        title: 'Config Analysis',
        description: 'Deep scan Apache configurations for security breaches.',
        icon: Binary,
        color: 'from-cyan-500 to-blue-500'
    },
    {
        id: 'upload',
        title: 'Upload File',
        description: 'Analyze .htaccess and .conf files for misconfigurations.',
        icon: Cpu,
        color: 'from-purple-500 to-pink-500'
    },
    {
        id: 'url',
        title: 'Scan URL',
        description: 'Test live web endpoints for common vulnerabilities.',
        icon: Zap,
        color: 'from-cyan-400 to-purple-500'
    },
    {
        id: 'network',
        title: 'Network Scan',
        description: 'Scan ports, detect services, and find network vulnerabilities.',
        icon: Network,
        color: 'from-red-500 to-orange-500'
    }
];

const TabCards = ({ onSelect }) => {
    const routesMap = {
        config:  '/scan/apache',
        upload:  '/scan/code',
        url:     '/scan/web',
        network: '/scan/network',
    };

    return (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mt-0 w-full max-w-6xl">
            {cards.map((card, index) => (
                <motion.div
                    key={card.id}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: index * 0.1 + 0.5 }}
                    onClick={() => {
                        onSelect ? onSelect(card.id) : (window.location.href = routesMap[card.id]);
                    }}
                    className="group relative cursor-pointer h-full"
                >
                    <div className="absolute -inset-0.5 bg-gradient-to-r opacity-20 group-hover:opacity-100 transition duration-500 blur-xl rounded-2xl"></div>
                    <div className="relative h-full flex flex-col bg-cyber-panel/80 backdrop-blur-xl border border-white/5 p-8 rounded-2xl hover:border-cyan-500/50 transition-all duration-300 pointer-events-auto shadow-2xl overflow-hidden group">
                        {/* Decorative Gradient Inner */}
                        <div className={`absolute top-0 right-0 w-32 h-32 bg-gradient-to-br ${card.color} opacity-0 group-hover:opacity-10 transition-opacity blur-3xl`}></div>
                        
                        <div className="w-12 h-12 rounded-xl bg-cyan-500/10 flex items-center justify-center mb-6 border border-cyan-500/20 group-hover:scale-110 transition-transform duration-500 shadow-[0_0_15px_rgba(0,245,212,0.1)]">
                            <card.icon className="w-6 h-6 text-cyan-400" />
                        </div>
                        
                        <h3 className="font-orbitron font-bold text-xl text-white mb-3 group-hover:text-cyan-400 transition-colors">
                            {card.title}
                        </h3>
                        <p className="text-gray-400 font-inter text-sm leading-relaxed flex-grow">
                            {card.description}
                        </p>
                        
                        <div className="mt-6 flex items-center gap-2 text-[10px] font-orbitron font-bold text-cyan-500 tracking-[0.2em] uppercase opacity-0 group-hover:opacity-100 transition-opacity translate-y-2 group-hover:translate-y-0 duration-300">
                            INITIALIZE SCAN <span className="text-sm">→</span>
                        </div>
                    </div>
                </motion.div>
            ))}
        </div>
    );
};

export default TabCards;
