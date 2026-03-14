import React from 'react';
import { SEVERITY_STYLES, sortBySeverity }
    from '../utils/logicProtection';
import SeverityBadge from './SeverityBadge';

const ResultsPanel = ({ findings, total }) => {
    const sorted = sortBySeverity(findings);

    // Count by severity
    const counts = sorted.reduce((acc, f) => {
        acc[f.severity] = (acc[f.severity] || 0) + 1;
        return acc;
    }, {});

    const risk = ['CRITICAL','HIGH','MEDIUM','LOW']
        .find(s => counts[s]) || 'INFO';

    return (
        <div className="mt-10 space-y-4">

            {/* Summary bar */}
            <div className="flex flex-wrap items-center justify-between
                            gap-4 p-5 scanner-glass rounded-2xl mb-6">
                <div className="flex items-center gap-3">
                    <span className="font-orbitron text-xs text-gray-500
                                     tracking-widest uppercase">
                        Overall Risk:
                    </span>
                    <SeverityBadge severity={risk} />
                    <span className="font-orbitron text-xs text-gray-500">
                        {total} finding{total !== 1 ? 's' : ''}
                    </span>
                </div>

                <div className="flex items-center gap-4 text-xs
                                font-orbitron tracking-wider">
                    {['CRITICAL','HIGH','MEDIUM','LOW'].map(s => (
                        counts[s] ? (
                            <span key={s}
                                style={{ color: SEVERITY_STYLES[s].text }}>
                                {s}: {counts[s]}
                            </span>
                        ) : null
                    ))}
                </div>

                <a
                    href="/download_report"
                    className="font-orbitron text-[10px] tracking-[0.2em]
                               uppercase px-4 py-2 border border-cyan-500/40
                               text-cyan-400 hover:bg-cyan-500 hover:text-black
                               transition-all duration-300 rounded-sm"
                >
                    Export Report →
                </a>
            </div>

            {/* Finding cards */}
            {sorted.map((f, i) => {
                const style = SEVERITY_STYLES[f.severity]
                           || SEVERITY_STYLES.LOW;
                return (
                    <div
                        key={i}
                        className="rounded-xl p-5 fade-in-up"
                        style={{
                            background:   style.bg,
                            borderLeft:   `3px solid ${style.border}`,
                            animationDelay: `${i * 0.05}s`
                        }}
                    >
                        <div className="flex items-center gap-3 mb-3 flex-wrap">
                            <SeverityBadge severity={f.severity} />
                            <span className="font-orbitron text-xs
                                             font-bold text-white/90
                                             tracking-wider">
                                {f.code || f.title}
                            </span>
                            {f.file && (
                                <span className="ml-auto text-[11px]
                                                 text-gray-600 truncate
                                                 max-w-[200px]">
                                    {f.file}
                                </span>
                            )}
                        </div>
                        <div
                            className="text-gray-400 text-sm leading-relaxed
                                       font-inter whitespace-pre-wrap"
                            dangerouslySetInnerHTML={{
                                __html: f.message
                            }}
                        />
                    </div>
                );
            })}
        </div>
    );
};

export default ResultsPanel;
