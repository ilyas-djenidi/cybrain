import React from 'react';
import { motion } from 'framer-motion';
import { useNavigate } from 'react-router-dom';
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
        title: 'Code Audit',
        description: 'Analyze source files for common security vulnerabilities.',
        icon: Cpu,
        color: 'from-purple-500 to-pink-500'
    },
    {
        id: 'url',
        title: 'Web Scan',
        description: 'Test live web endpoints for OWASP Top 10 vulnerabilities.',
        icon: Zap,
        color: 'from-cyan-400 to-purple-500'
    },
    {
        id: 'network',
        title: 'Network Recon',
        description: 'Scan ports, detect services, and map attack surfaces.',
        icon: Network,
        color: 'from-red-500 to-orange-500'
    }
];

const TabCards = ({ onSelect }) => {
    const navigate = useNavigate();
    
    const routesMap = {
        config:  '/scan/apache',
        upload:  '/scan/code',
        url:     '/scan/web',
        network: '/scan/network',
    };

    const handleClick = (id) => {
        if (onSelect) {
            onSelect(id);
        } else {
            navigate(routesMap[id]);
        }
    };

    return (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 mt-0 w-full max-w-7xl px-4 md:px-0">
            {cards.map((card, index) => (
                <motion.div
                    key={card.id}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: index * 0.1 }}
                    onClick={() => handleClick(card.id)}
                    className="group relative cursor-pointer h-full"
                >
                    <div className="absolute -inset-0.5 bg-gradient-to-r opacity-0 group-hover:opacity-30 transition duration-500 blur-2xl rounded-3xl"></div>
                    <div className="relative h-full flex flex-col bg-white/[0.02] backdrop-blur-3xl border border-white/5 p-8 rounded-3xl hover:border-cyan-500/40 transition-all duration-500 shadow-2xl overflow-hidden group">
                        
                        {/* Decorative Gradient Inner */}
                        <div className={`absolute top-0 right-0 w-32 h-32 bg-gradient-to-br ${card.color} opacity-0 group-hover:opacity-10 transition-opacity blur-3xl`}></div>
                        
                        <div className="w-14 h-14 rounded-2xl bg-cyan-500/10 flex items-center justify-center mb-8 border border-white/10 group-hover:border-cyan-500/40 group-hover:scale-110 transition-all duration-500 shadow-inner">
                            <card.icon className="w-6 h-6 text-cyan-400" />
                        </div>
                        
                        <h3 className="font-orbitron font-bold text-xl text-white mb-4 group-hover:text-cyan-400 transition-colors tracking-wider">
                            {card.title}
                        </h3>
                        <p className="text-gray-500 font-inter text-sm leading-relaxed flex-grow group-hover:text-gray-400 transition-colors">
                            {card.description}
                        </p>
                        
                        <div className="mt-8 flex items-center gap-2 text-[10px] font-orbitron font-bold text-cyan-500 tracking-[0.3em] uppercase opacity-40 group-hover:opacity-100 transition-all translate-y-2 group-hover:translate-y-0 duration-500">
                            INITIALIZE ACTION <span className="text-sm">→</span>
                        </div>
                    </div>
                </motion.div>
            ))}
        </div>
    );
};

export default TabCards;
