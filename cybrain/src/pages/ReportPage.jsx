import React, { useState } from 'react';
import { motion } from 'framer-motion';

const REPORTS = [
    {
        label: 'Markdown Report',
        desc:  'Full vulnerability report with findings, severity, and recommendations',
        icon:  '📋',
        color: 'cyan',
        endpoint: '/download_report',
        filename: 'vulnerability_report.md',
    },
    {
        label: 'CSV Export',
        desc:  'Spreadsheet-ready CSV with all findings for data analysis',
        icon:  '📊',
        color: 'green',
        endpoint: '/download_report_csv',
        filename: 'findings_summary.csv',
    },
    {
        label: 'JSON Export',
        desc:  'Raw JSON data export for integration with other security tools',
        icon:  '🔗',
        color: 'purple',
        endpoint: '/download_report_json',
        filename: 'findings.json',
    },
];

const colorMap = {
    cyan:   { border: 'border-cyan-500/40',   bg: 'bg-cyan-500/5',   text: 'text-cyan-400',   hover: 'hover:bg-cyan-500 hover:text-black hover:border-cyan-500' },
    green:  { border: 'border-green-500/40',  bg: 'bg-green-500/5',  text: 'text-green-400',  hover: 'hover:bg-green-500 hover:text-black hover:border-green-500' },
    purple: { border: 'border-purple-500/40', bg: 'bg-purple-500/5', text: 'text-purple-400', hover: 'hover:bg-purple-500 hover:text-black hover:border-purple-500' },
};

const ReportPage = () => {
    const [downloading, setDownloading] = useState({});

    const handleDownload = async (report) => {
        setDownloading(p => ({ ...p, [report.label]: true }));
        try {
            const res = await fetch(report.endpoint);
            if (!res.ok) {
                const err = await res.json().catch(() => ({}));
                alert(err.error || 'No report found. Run a scan first.');
                return;
            }
            const blob = await res.blob();
            const url  = URL.createObjectURL(blob);
            const a    = document.createElement('a');
            a.href     = url;
            a.download = report.filename;
            a.click();
            URL.revokeObjectURL(url);
        } catch (e) {
            alert('Backend offline or no scan run yet.');
        } finally {
            setDownloading(p => ({ ...p, [report.label]: false }));
        }
    };

    return (
        <div className="min-h-screen bg-black content-section pt-24 pb-16 px-6 md:px-12">
            <div className="max-w-4xl mx-auto">
                {/* Header */}
                <motion.div initial={{ opacity:0, y:20 }} animate={{ opacity:1, y:0 }} className="mb-12 text-center">
                    <a href="/" className="text-cyan-500/60 text-xs font-orbitron tracking-widest uppercase hover:text-cyan-400 mb-4 inline-block transition-colors">
                        ← Back to Home
                    </a>
                    <h1 className="font-orbitron font-black text-4xl text-white tracking-wider mb-2 mt-4">
                        SCAN <span className="text-cyan-400">REPORTS</span>
                    </h1>
                    <p className="text-gray-500 font-inter text-sm">
                        Download your security assessment reports in multiple formats.
                    </p>
                    <div className="h-px w-24 bg-gradient-to-r from-transparent via-cyan-400 to-transparent mx-auto mt-6" />
                </motion.div>

                {/* Report Download Cards */}
                <div className="grid gap-6">
                    {REPORTS.map((report, i) => {
                        const c = colorMap[report.color];
                        return (
                            <motion.div
                                key={report.label}
                                initial={{ opacity: 0, y: 20 }}
                                animate={{ opacity: 1, y: 0 }}
                                transition={{ delay: i * 0.1 }}
                                className={`scanner-glass rounded-2xl p-6 border ${c.border} ${c.bg} flex items-center justify-between gap-6`}
                            >
                                <div className="flex items-center gap-5">
                                    <div className={`text-3xl w-12 h-12 flex items-center justify-center rounded-xl border ${c.border} bg-black/40`}>
                                        {report.icon}
                                    </div>
                                    <div>
                                        <h3 className={`font-orbitron font-bold text-sm tracking-wider mb-1 ${c.text}`}>
                                            {report.label}
                                        </h3>
                                        <p className="text-gray-500 font-inter text-xs leading-relaxed max-w-md">
                                            {report.desc}
                                        </p>
                                    </div>
                                </div>
                                <button
                                    onClick={() => handleDownload(report)}
                                    disabled={downloading[report.label]}
                                    className={`flex-shrink-0 px-6 py-3 border rounded-xl font-orbitron text-[10px] tracking-widest uppercase transition-all duration-300 disabled:opacity-40 ${c.border} ${c.text} ${c.hover}`}
                                >
                                    {downloading[report.label] ? '⟳ Downloading...' : '↓ Download'}
                                </button>
                            </motion.div>
                        );
                    })}
                </div>

                {/* Quick nav to scanners */}
                <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: 0.4 }}
                    className="mt-12 pt-8 border-t border-white/5 text-center"
                >
                    <p className="text-gray-600 font-inter text-xs mb-4">No reports yet? Run a scan first.</p>
                    <div className="flex flex-wrap justify-center gap-4">
                        {[
                            { href: '/scan/web',     label: 'Web Scanner' },
                            { href: '/scan/apache',  label: 'Apache Audit' },
                            { href: '/scan/code',    label: 'Code Analyzer' },
                            { href: '/scan/network', label: 'Network Recon' },
                        ].map(link => (
                            <a
                                key={link.href}
                                href={link.href}
                                className="px-5 py-2 border border-white/10 text-gray-500 font-orbitron text-[10px] tracking-widest uppercase rounded-xl hover:border-cyan-500/50 hover:text-cyan-400 transition-all"
                            >
                                {link.label}
                            </a>
                        ))}
                    </div>
                </motion.div>
            </div>
        </div>
    );
};

export default ReportPage;
