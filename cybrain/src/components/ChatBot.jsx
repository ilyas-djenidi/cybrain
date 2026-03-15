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
            'personal cybersecurity expert.\n\n' +
            'I can help you:\n' +
            '• Understand vulnerabilities found\n' +
            '• Explain attack techniques\n' +
            '• Recommend security fixes\n' +
            '• Answer any security question'
        ),
    }]);
    const [input, setInput]     = useState('');
    const [loading, setLoading] = useState(false);
    
    const bottomRef = useRef();
    const inputRef  = useRef();

    useEffect(() => {
        if (open) {
            bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
        }
    }, [messages, open]);

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
                    context: context
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
            console.error('[CHAT ERROR]', e);
            let errMsg = '⚠️ Connection error. The security engine is currently overloaded. Please try again in a moment.';
            
            // If we got a response from backend, it might contain the quota message
            if (
                e.response?.status === 429 ||
                (e.response?.data?.response || '')
                    .includes('quota')
            ) {
                errMsg = (
                    '⚠️ **Rate limit reached** ' +
                    '(15 requests/minute free tier).\n\n' +
                    'Please wait **60 seconds** and try again.\n\n' +
                    '💡 Tip: Scan results are complete without AI. ' +
                    'AI analysis is optional — it only explains ' +
                    'findings, it does not do the scanning.'
                );
            } else if (e.response?.data?.response) {
                errMsg = e.response.data.response;
            }

            setMessages(prev => [
                ...prev,
                {
                    role:    'assistant',
                    content: errMsg,
                }
            ]);
        } finally {
            setLoading(false);
            inputRef.current?.focus();
        }
    };

    const formatMessage = (content) => {
        if (typeof content !== 'string') return '';
        return content
            .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
            .replace(/\*(.*?)\*/g, '<em>$1</em>')
            .replace(/`(.*?)`/g, '<code class="bg-black/40 px-1 rounded text-cyan-400 font-mono">$1</code>')
            .replace(/\n/g, '<br>');
    };

    const renderHeader = () => (
        <div className="p-4 border-b border-cyan-500/10 flex items-center justify-between"
             style={{ background: 'rgba(0,245,212,0.05)' }}>
            <div className="flex items-center gap-3">
                <div className="w-8 h-8 bg-cyan-500/20 rounded-full flex items-center justify-center border border-cyan-500/40">
                    <span className="text-cyan-400 text-sm">✦</span>
                </div>
                <div>
                    <p className="font-orbitron text-cyan-400 text-[10px] font-bold tracking-wider">CYBRAIN AI</p>
                    <p className="text-[9px] text-gray-500 font-inter">Gemini 2.0 Flash • AI Security Expert</p>
                </div>
            </div>
            <div className="flex gap-2">
                {position === 'fixed' && (
                    <button onClick={() => setOpen(false)} className="text-gray-500 hover:text-white transition-colors text-xl leading-none">×</button>
                )}
            </div>
        </div>
    );

    const renderMessages = () => (
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
            {messages.map((m, i) => (
                <div key={i} className={`flex ${m.role==='user' ? 'justify-end' : 'justify-start'}`}>
                    <div className={`max-w-[90%] rounded-2xl px-4 py-3 text-xs font-inter leading-relaxed ${
                        m.role==='user' 
                            ? 'bg-cyan-500/10 text-cyan-100 rounded-br-sm border border-cyan-500/20' 
                            : 'bg-white/5 text-gray-300 rounded-bl-sm border border-white/5'
                    }`}>
                        <div dangerouslySetInnerHTML={{ __html: formatMessage(m.content) }} />
                    </div>
                </div>
            ))}
            {loading && (
                <div className="flex justify-start">
                    <div className="bg-white/5 rounded-2xl rounded-bl-sm px-4 py-3 border border-white/5">
                        <div className="flex gap-1.5">
                            {[0,1,2].map(i => (
                                <div key={i} className="w-1.5 h-1.5 bg-cyan-400/60 rounded-full animate-bounce" style={{ animationDelay: `${i*0.2}s` }} />
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
                <button 
                    key={i} 
                    onClick={() => sendMessage(s)} 
                    className="text-[10px] text-gray-500 border border-gray-800 rounded-full px-3 py-1.5 hover:border-cyan-500/40 hover:text-cyan-400 transition-all font-inter bg-white/[0.02]"
                >
                    {s}
                </button>
            ))}
        </div>
    );

    const renderInput = () => (
        <div className="p-4 border-t border-white/5">
            <div className="flex gap-2">
                <input
                    ref={inputRef}
                    value={input}
                    onChange={e => setInput(e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && !e.shiftKey && sendMessage()}
                    placeholder="Ask about security..."
                    className="flex-1 bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-gray-300 text-xs font-inter focus:outline-none focus:border-cyan-500/40 transition-all"
                />
                <motion.button
                    onClick={() => sendMessage()}
                    disabled={!input.trim() || loading}
                    whileHover={{scale:1.05}}
                    whileTap={{scale:0.95}}
                    className="w-12 h-12 bg-cyan-500/10 border border-cyan-500/40 text-cyan-400 rounded-xl hover:bg-cyan-500 hover:text-black transition-all disabled:opacity-30 flex items-center justify-center text-sm"
                >
                    <span className="transform rotate-[-45deg] ml-1">➤</span>
                </motion.button>
            </div>
            <p className="text-[9px] text-center text-gray-600 mt-2 font-inter tracking-wider">
                AI can make mistakes. Verify critical results.
            </p>
        </div>
    );

    // Fixed floating button
    if (position === 'fixed') {
        return (
            <>
                <AnimatePresence>
                    {open && (
                        <motion.div
                            initial={{ opacity:0, scale:0.95, y:20 }}
                            animate={{ opacity:1, scale:1, y:0 }}
                            exit={{ opacity:0, scale:0.95, y:20 }}
                            className="fixed bottom-24 right-6 z-[200] w-[350px] md:w-[400px] h-[550px] flex flex-col rounded-3xl overflow-hidden border border-white/10 shadow-2xl"
                            style={{ background: 'rgba(10,10,15,0.95)', backdropFilter: 'blur(30px)' }}
                        >
                            {renderHeader()}
                            {renderMessages()}
                            {renderSuggestions()}
                            {renderInput()}
                        </motion.div>
                    )}
                </AnimatePresence>
                <motion.button
                    onClick={() => setOpen(!open)}
                    whileHover={{ scale: 1.05 }}
                    whileTap={{ scale: 0.95 }}
                    className="fixed bottom-6 right-6 z-[200] w-16 h-16 rounded-full border border-cyan-500/40 bg-black/60 backdrop-blur-2xl flex items-center justify-center shadow-2xl transition-all"
                    style={{ 
                        boxShadow: open 
                            ? '0 0 30px rgba(0,245,212,0.3), inset 0 0 10px rgba(0,245,212,0.2)' 
                            : '0 0 20px rgba(0,245,212,0.1)' 
                    }}
                >
                    <div className="relative">
                        <span className={`text-cyan-400 text-2xl transition-all duration-300 ${open ? 'rotate-90 scale-0 opacity-0' : 'rotate-0 scale-100 opacity-100'}`}>
                            ✦
                        </span>
                        <span className={`absolute inset-0 text-white text-3xl transition-all duration-300 ${open ? 'rotate-0 scale-100 opacity-100' : 'rotate-90 scale-0 opacity-0'}`}>
                            ×
                        </span>
                    </div>
                </motion.button>
            </>
        );
    }

    // Inline dashboard version
    if (position === 'inline') {
        return (
            <div className="w-full min-h-[600px] flex flex-col rounded-3xl overflow-hidden border border-white/10 bg-black/40 backdrop-blur-3xl">
                {renderHeader()}
                {renderMessages()}
                {renderSuggestions()}
                {renderInput()}
            </div>
        );
    }

    return null;
};

export default ChatBot;
