import React, { useState, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import axios from 'axios';

const SUGGESTIONS = [
    "What is SQL injection?",
    "How do I fix missing security headers?",
    "Explain the findings from my scan",
    "What is the most critical vulnerability?",
    "How to harden Apache configuration?",
    "What is OWASP Top 10?",
    "How to prevent XSS attacks?",
    "What does CRITICAL severity mean?",
];

const ChatBot = ({
    context = null,
    position = 'fixed'  // 'fixed' or 'inline'
}) => {
    const [open, setOpen]         = useState(false);
    const [messages, setMessages] = useState([{
        role:    'assistant',
        content: (
            '👋 Hello! I\'m **Cybrain AI** — your ' +
            'cybersecurity expert.\n\n' +
            'I can help you:\n' +
            '• Understand vulnerabilities found\n' +
            '• Explain attack techniques\n' +
            '• Recommend security fixes\n' +
            '• Answer any security question'
        ),
    }]);
    const [input, setInput]     = useState('');
    const [loading, setLoading] = useState(false);
    const [apiKey, setApiKey]   = useState(
        localStorage.getItem('openrouter_key') || ''
    );
    const [showKey, setShowKey] = useState(!apiKey);
    const bottomRef = useRef();
    const inputRef  = useRef();

    // Zero automatic scrolling to respect user preference
    useEffect(() => {
        // bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [messages]);

    const sendMessage = async (text) => {
        const msg = (text || input).trim();
        if (!msg || loading) return;
        setInput('');

        const userMsg = { role: 'user', content: msg };
        setMessages(prev => [...prev, userMsg]);
        setLoading(true);

        try {
            const { data } = await axios.post(
                '/api/chat',
                {
                    message: msg,
                    context: context,
                    api_key: apiKey,
                }
            );
            setMessages(prev => [
                ...prev,
                {
                    role:    'assistant',
                    content: data.response
                }
            ]);
        } catch(e) {
            setMessages(prev => [
                ...prev,
                {
                    role:    'assistant',
                    content: (
                        '⚠️ Connection error. ' +
                        'Check your API key or ' +
                        'try again.'
                    ),
                }
            ]);
        } finally {
            setLoading(false);
            inputRef.current?.focus();
        }
    };

    const formatMessage = (content) => {
        return content
            .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
            .replace(/\*(.*?)\*/g, '<em>$1</em>')
            .replace(/`(.*?)`/g, '<code class="bg-black/40 px-1 rounded text-cyan-400">$1</code>')
            .replace(/\n/g, '<br>');
    };

    // UI Renderers
    const renderHeader = () => (
        <div className="p-4 border-b border-cyan-500/10 flex items-center justify-between"
             style={{ background: 'rgba(0,245,212,0.05)' }}>
            <div className="flex items-center gap-3">
                <div className="w-8 h-8 bg-cyan-500/20 rounded-full flex items-center justify-center border border-cyan-500/40">
                    <span className="text-cyan-400 text-sm">✦</span>
                </div>
                <div>
                    <p className="font-orbitron text-cyan-400 text-xs font-bold tracking-wider">CYBRAIN AI</p>
                </div>
            </div>
            <div className="flex gap-2">
                {position === 'fixed' && (
                    <button onClick={() => setOpen(false)} className="text-gray-600 hover:text-gray-400 transition-colors text-lg leading-none">×</button>
                )}
            </div>
        </div>
    );

    const renderApiKey = () => null;

    const renderMessages = () => (
        <div className="flex-1 overflow-y-auto p-4 space-y-3">
            {messages.map((m, i) => (
                <div key={i} className={`flex ${m.role==='user' ? 'justify-end' : 'justify-start'}`}>
                    <div className={`max-w-[85%] rounded-2xl px-4 py-3 text-xs font-inter leading-relaxed ${
                        m.role==='user' ? 'bg-cyan-500/20 text-cyan-100 rounded-br-sm border border-cyan-500/30' : 'bg-white/5 text-gray-300 rounded-bl-sm border border-white/10'
                    }`}>
                        <div dangerouslySetInnerHTML={{ __html: formatMessage(m.content) }} />
                    </div>
                </div>
            ))}
            {loading && (
                <div className="flex justify-start">
                    <div className="bg-white/5 rounded-2xl rounded-bl-sm px-4 py-3 border border-white/10">
                        <div className="flex gap-1">
                            {[0,1,2].map(i => (
                                <div key={i} className="w-1.5 h-1.5 bg-cyan-400 rounded-full animate-bounce" style={{ animationDelay: `${i*0.2}s` }} />
                            ))}
                        </div>
                    </div>
                </div>
            )}
            <div ref={bottomRef} />
        </div>
    );

    const renderSuggestions = () => messages.length <= 1 && (
        <div className="px-4 pb-2 flex flex-wrap gap-1.5">
            {SUGGESTIONS.slice(0,4).map((s, i) => (
                <button key={i} onClick={() => sendMessage(s)} className="text-[10px] text-gray-500 border border-gray-800 rounded-full px-2 py-1 hover:border-cyan-500/40 hover:text-cyan-400 transition-colors font-inter">
                    {s}
                </button>
            ))}
        </div>
    );

    const renderInput = () => (
        <div className="p-4 border-t border-gray-800/50">
            <div className="flex gap-2">
                <input
                    ref={inputRef}
                    value={input}
                    onChange={e => setInput(e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && !e.shiftKey && sendMessage()}
                    placeholder="Ask about security..."
                    className="flex-1 bg-black/40 border border-gray-700 rounded-xl px-3 py-2.5 text-gray-300 text-xs font-inter focus:outline-none focus:border-cyan-500/50 transition-all"
                />
                <motion.button
                    onClick={() => sendMessage()}
                    disabled={!input.trim() || loading}
                    whileHover={{scale:1.05}}
                    whileTap={{scale:0.95}}
                    className="w-10 h-10 border border-cyan-500/50 text-cyan-400 rounded-xl hover:bg-cyan-500 hover:text-black transition-all disabled:opacity-30 flex items-center justify-center text-sm"
                >
                    ▶
                </motion.button>
            </div>
        </div>
    );

    // Fixed floating button
    if (position === 'fixed') {
        return (
            <>
                <AnimatePresence>
                    {open && (
                        <motion.div
                            initial={{ opacity:0, scale:0.9, y:20 }}
                            animate={{ opacity:1, scale:1, y:0 }}
                            exit={{ opacity:0, scale:0.9, y:20 }}
                            className="fixed bottom-24 right-6 z-[200] w-96 h-[560px] flex flex-col rounded-2xl overflow-hidden border border-cyan-500/20 shadow-2xl shadow-cyan-500/10"
                            style={{ background: 'rgba(5,5,15,0.97)', backdropFilter: 'blur(24px)' }}
                        >
                            {renderHeader()}
                            {renderApiKey()}
                            {renderMessages()}
                            {renderSuggestions()}
                            {renderInput()}
                        </motion.div>
                    )}
                </AnimatePresence>
                <motion.button
                    onClick={() => setOpen(!open)}
                    whileHover={{ scale: 1.1 }}
                    whileTap={{ scale: 0.9 }}
                    className="fixed bottom-6 right-6 z-[200] w-14 h-14 rounded-full border border-cyan-500/50 bg-black/80 backdrop-blur-xl flex items-center justify-center shadow-lg shadow-cyan-500/20 hover:bg-cyan-500/20 transition-all"
                    style={{ boxShadow: open ? '0 0 30px rgba(0,245,212,0.3)' : '0 0 15px rgba(0,245,212,0.1)' }}
                >
                    <span className="text-cyan-400 text-xl">{open ? '×' : '✦'}</span>
                </motion.button>
            </>
        );
    }

    // Inline dashboard version
    if (position === 'inline') {
        return (
            <div className="w-full max-w-4xl mx-auto h-[600px] flex flex-col rounded-3xl overflow-hidden border border-cyan-500/20 shadow-2xl bg-black/40 backdrop-blur-3xl">
                {renderHeader()}
                {renderApiKey()}
                {renderMessages()}
                {renderSuggestions()}
                {renderInput()}
            </div>
        );
    }

    return null;
};

export default ChatBot;
