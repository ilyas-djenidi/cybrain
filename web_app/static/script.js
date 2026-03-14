document.addEventListener('DOMContentLoaded', () => {
    const tabs = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');
    const analyzeBtn = document.getElementById('analyze-btn');
    const configInput = document.getElementById('config-input');
    const fileInput = document.getElementById('file-input');
    const dropZone = document.getElementById('drop-zone');
    const resultsSection = document.getElementById('results-section');
    const resultsList = document.getElementById('results-list');
    const scanStats = document.getElementById('scan-stats');

    console.log('--- CYBRAIN INTELLIGENCE INITIALIZED ---');

    // Enhanced Tab Switching
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            tabs.forEach(t => t.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));
            tab.classList.add('active');
            const target = document.getElementById(`${tab.dataset.tab}-tab`);
            if (target) target.classList.add('active');
        });
    });

    // File Upload handling
    if (dropZone) {
        dropZone.addEventListener('click', () => fileInput.click());
        dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropZone.classList.add('dragover');
        });
        dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropZone.classList.remove('dragover');
            if (e.dataTransfer.files.length) handleUpload(e.dataTransfer.files[0]);
        });
    }

    if (fileInput) {
        fileInput.addEventListener('change', (e) => {
            if (e.target.files.length) handleUpload(e.target.files[0]);
        });
    }

    // Analyze Button
    if (analyzeBtn) {
        analyzeBtn.addEventListener('click', () => {
            const content = configInput.value;
            if (!content.trim()) return;
            analyzeData(JSON.stringify({ content: content }), 'application/json');
        });
    }

    // Unified Scan URL Function
    window.scanUrl = async function() {
        const urlInput = document.getElementById('urlInput');
        let url = urlInput.value.trim();
        
        if (!url) {
            alert('Identify a target URL first.');
            return;
        }
        
        if (!url.startsWith('http')) url = 'http://' + url;
        url = url.split('#')[0];
        
        // UI Feedback: Scanning
        resultsList.innerHTML = `
            <div class="scanning-modal" style="grid-column: 1/-1; text-align:center; padding: 60px;">
                <div class="scanning-loader" style="font-size: 3rem; margin-bottom: 20px;">🛡️</div>
                <h3 style="font-family: 'Orbitron', sans-serif; color: var(--accent-cyan);">DECODING TARGET: ${url}</h3>
                <p style="color: var(--text-secondary); margin-top: 10px;">Establishing secure bridge and running 20+ vulnerability tests...</p>
            </div>
        `;
        resultsSection.classList.remove('hidden');
        resultsSection.scrollIntoView({ behavior: 'smooth' });
        
        try {
            const response = await fetch('/scan_url', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: url }),
            });
            
            const data = await response.json();
            if (data.error) throw new Error(data.error);
            
            displayResults(data.results || [], url);
            
        } catch (error) {
            resultsList.innerHTML = `
                <div class="result-card high" style="grid-column: 1/-1;">
                    <div class="result-header"><span class="result-type">ERROR</span></div>
                    <div class="result-message">
                        Intelligence link failed: ${error.message}
                    </div>
                </div>
            `;
        }
    }

    function handleUpload(file) {
        const formData = new FormData();
        formData.append('file', file);
        analyzeData(formData);
    }

    async function analyzeData(body, contentType) {
        resultsList.innerHTML = '<div style="grid-column: 1/-1; text-align:center;">Analyzing Data Stream...</div>';
        resultsSection.classList.remove('hidden');

        try {
            const options = { method: 'POST', body: body };
            if (contentType) options.headers = { 'Content-Type': contentType };

            const response = await fetch('/analyze', options);
            const data = await response.json();
            displayResults(data.results);
        } catch (error) {
            resultsList.innerHTML = '<div class="result-card high">Analysis Error. Check logs.</div>';
        }
    }

    function displayResults(results, targetUrl = '') {
        resultsList.innerHTML = '';
        
        // Update Stats
        if (scanStats) {
            const criticals = results.filter(r => r.severity === 'CRITICAL').length;
            const highs = results.filter(r => r.severity === 'HIGH').length;
            scanStats.innerHTML = `
                <span style="color: #ff0000; margin-right: 15px;">CRITICAL: ${criticals}</span>
                <span style="color: var(--error-red);">HIGH: ${highs}</span>
                <span style="color: var(--text-secondary); margin-left: 15px;">TOTAL: ${results.length}</span>
            `;
        }

        if (!results || results.length === 0) {
            resultsList.innerHTML = '<div class="no-issues" style="grid-column: 1/-1;">CLEAN SCAN: No vulnerabilities detected.</div>';
            return;
        }

        results.forEach(issue => {
            const card = document.createElement('div');
            card.className = `result-card ${issue.severity.toLowerCase()}`;

            const isUrl = (issue.file && (issue.file.startsWith('http') || issue.file.includes('.'))) || targetUrl;
            const targetDisplay = isUrl ? (issue.file || targetUrl) : (issue.file ? issue.file.split(/[\\/]/).pop() : 'RAW INPUT');
            const targetLabel = isUrl ? 'TARGET' : 'SOURCE';
            
            const lineHtml = (issue.line && issue.line !== '-') ? `<span class="result-line">L:${issue.line}</span>` : '';
            const evidenceHtml = issue.evidence ? `<div class="result-evidence"><code>${issue.evidence}</code></div>` : '';
            const fixHtml = issue.fix ? `<div class="result-recommendation"><strong>FIX:</strong> ${issue.fix}</div>` : '';

            card.innerHTML = `
                <div class="result-header">
                    <span class="result-type">${issue.severity}</span>
                    ${lineHtml}
                </div>
                <div style="font-weight: 700; color: var(--accent-cyan); margin-bottom: 10px; font-family: 'Orbitron', sans-serif; font-size: 0.8rem;">${issue.code}</div>
                <div class="result-message">${issue.message}</div>
                ${evidenceHtml}
                ${fixHtml}
                <div style="font-size: 0.7rem; color: var(--text-secondary); margin-top: 15px; border-top: 1px solid var(--glass-border); padding-top: 10px;">
                    ${targetLabel}: ${targetDisplay} | CWE: ${issue.cwe || 'N/A'}
                </div>
            `;
            resultsList.appendChild(card);
        });
    }
});
