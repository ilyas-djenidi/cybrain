import React from 'react';

const SeverityBadge = ({ severity }) => {
    const getStyles = () => {
        switch (severity?.toUpperCase()) {
            case 'CRITICAL':
                return 'bg-red-500/20 text-red-400 border-red-500/40 shadow-[0_0_10px_rgba(239,68,68,0.2)]';
            case 'HIGH':
                return 'bg-orange-500/20 text-orange-400 border-orange-500/40 shadow-[0_0_10px_rgba(249,115,22,0.2)]';
            case 'MEDIUM':
                return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40 shadow-[0_0_10px_rgba(234,179,8,0.2)]';
            case 'LOW':
                return 'bg-green-500/20 text-green-400 border-green-500/40 shadow-[0_0_10px_rgba(34,197,94,0.2)]';
            default:
                return 'bg-blue-500/20 text-blue-400 border-blue-500/40';
        }
    };

    return (
        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border tracking-wider uppercase ${getStyles()}`}>
            {severity}
        </span>
    );
};

export default SeverityBadge;
