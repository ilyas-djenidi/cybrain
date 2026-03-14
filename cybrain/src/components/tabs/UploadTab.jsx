import React, { useCallback } from 'react';
import { Upload } from 'lucide-react';

const UploadTab = ({ onUpload, loading }) => {
    const handleFileChange = (e) => {
        const file = e.target.files[0];
        if (file) onUpload(file);
    };

    const handleDrop = (e) => {
        e.preventDefault();
        const file = e.dataTransfer.files[0];
        if (file) onUpload(file);
    };

    return (
        <div className="space-y-6">
            <div 
                onDragOver={(e) => e.preventDefault()}
                onDrop={handleDrop}
                className="group relative border-2 border-dashed border-cyan-500/20 rounded-2xl p-16 text-center hover:border-cyan-500/50 hover:bg-cyan-500/5 transition-all cursor-pointer"
                onClick={() => document.getElementById('file-upload').click()}
            >
                <input 
                    type="file" 
                    id="file-upload" 
                    className="hidden" 
                    onChange={handleFileChange}
                    accept=".conf,.htaccess,.txt"
                />
                
                <div className="mb-6 flex justify-center">
                    <div className="w-16 h-16 bg-white/5 rounded-full flex items-center justify-center text-cyan-400 group-hover:scale-110 transition-transform duration-300">
                        <Upload size={32} />
                    </div>
                </div>
                
                <h3 className="font-orbitron font-bold text-lg text-white tracking-widest mb-2">DEPLOY CONFIG FILES</h3>
                <p className="text-gray-500 text-sm font-light max-w-xs mx-auto">
                    Drag and drop your Apache configuration files or <span className="text-cyan-400 font-medium">browse locally</span>
                </p>

                <div className="mt-8 flex justify-center gap-2">
                    <span className="px-3 py-1 bg-white/5 rounded text-[10px] text-gray-500 font-bold border border-white/10 uppercase">.conf</span>
                    <span className="px-3 py-1 bg-white/5 rounded text-[10px] text-gray-500 font-bold border border-white/10 uppercase">.htaccess</span>
                </div>
            </div>
            
            {loading && (
                <div className="text-center text-xs text-gray-500 animate-pulse uppercase tracking-widest font-orbitron">
                    Uploading stream to core engine...
                </div>
            )}
        </div>
    );
};

export default UploadTab;
