"""
CYBRAIN — Flask Backend
PFE Master 2 — Information Security
"""

import os
import sys
import traceback
import tempfile

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from dotenv import load_dotenv

# Load .env FIRST before any other imports
load_dotenv()

# Add web_app directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

app = Flask(__name__)
CORS(app, origins="*")

# ── TEST ROUTE ────────────────────────────────────────────────
@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "status": "ok",
        "gemini": bool(os.environ.get("GEMINI_API_KEY")),
        "message": "Cybrain backend running"
    })

# ── APACHE CONFIG ANALYSIS ────────────────────────────────────
@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        from detect_apache_misconf import ApacheMisconfigDetector
        detector = ApacheMisconfigDetector()
        content     = None
        source_name = "Input Text"

        if 'file' in request.files:
            f = request.files['file']
            if f and f.filename:
                content     = f.read().decode('utf-8', errors='ignore')
                source_name = f.filename
        
        if content is None and request.is_json:
            data = request.get_json(force=True) or {}
            content = data.get('content') or data.get('config', '')
        
        if content is None:
            return jsonify({'error': 'No content provided'}), 400

        detector.scan_content(content.strip(), source_name)
        raw = detector.get_results()

        # Normalize severity
        SEV_MAP = {
            'error':   'CRITICAL', 'Error':   'CRITICAL',
            'high':    'HIGH',     'High':    'HIGH',
            'warning': 'MEDIUM',   'Warning': 'MEDIUM',
            'medium':  'MEDIUM',   'Medium':  'MEDIUM',
            'low':     'LOW',      'Low':     'LOW',
            'info':    'INFO',     'Info':    'INFO',
        }
        results = []
        for m in raw:
            sev = SEV_MAP.get(
                str(m.get('severity', 'Info')),
                str(m.get('severity', 'Info')).upper()
            )
            results.append({
                "severity": sev,
                "line":     str(m.get('line', '-')),
                "message":  m.get('message', ''),
                "code":     m.get('code', ''),
                "file":     str(m.get('file', source_name)),
            })

        # Overall risk
        sevs = [r['severity'] for r in results]
        risk = next(
            (s for s in ['CRITICAL','HIGH','MEDIUM','LOW']
             if s in sevs), 'INFO'
        )

        return jsonify({
            'findings': results,
            'results':  results,  # backwards compat
            'total':    len(results),
            'risk':     risk,
        })

    except Exception as e:
        print(f"[ANALYZE ERROR]\n{traceback.format_exc()}")
        return jsonify({
            'error':    str(e),
            'findings': [],
            'total':    0
        }), 500


# ── WEB VULNERABILITY SCAN ────────────────────────────────────
@app.route('/scan_url', methods=['POST'])
def scan_url():
    try:
        data = request.get_json(force=True)
        if not data:
            return jsonify({"error": "No JSON received"}), 400

        url = data.get('url', '').strip()
        if not url:
            return jsonify({"error": "No URL provided"}), 400

        # Clean URL
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        url = url.split('#')[0].rstrip('/')

        print(f"[SCAN_URL] Scanning: {url}")

        from url_scanner import UrlScanner
        scanner = UrlScanner(url)
        results = scanner.scan()

        # Ensure results is always a list
        if not isinstance(results, list):
            results = []

        risk = scanner._calc_overall_risk()

        return jsonify({
            "findings": results,
            "results":  results,  # backwards compat
            "total":    len(results),
            "url":      url,
            "risk":     risk,
        })

    except Exception as e:
        print(f"[SCAN_URL ERROR]\n{traceback.format_exc()}")
        url_safe = ''
        try:
            url_safe = request.get_json(force=True).get('url','')
        except Exception:
            pass
        return jsonify({
            "findings": [{
                "severity": "HIGH",
                "line":     "-",
                "message":  (
                    f"Scanner error: {str(e)}<br><br>"
                    "<strong>Recommendation:</strong><br>"
                    "Check Flask console for details."
                ),
                "code": "Scanner Error",
                "file": url_safe,
            }],
            "total": 1,
            "risk":  "HIGH",
        }), 200


# ── NETWORK SCAN ──────────────────────────────────────────────
@app.route('/scan_network', methods=['POST'])
def scan_network():
    try:
        data = request.get_json(force=True) or {}
        target = data.get('target', '').strip()
        if not target:
            return jsonify({"error": "No target"}), 400

        # Clean target
        for prefix in ['https://', 'http://']:
            if target.startswith(prefix):
                target = target[len(prefix):]
        target = target.split('/')[0].split(':')[0]

        print(f"[SCAN_NETWORK] Target: {target}")

        from network_scanner import NetworkScanner
        scanner = NetworkScanner(target)
        results = scanner.scan()

        return jsonify({
            "findings":   results,
            "total":      len(results),
            "target":     target,
            "risk":       scanner._calc_overall_risk(),
            "recon": {
                "ip": scanner.recon_data.get(
                    "dns", {}
                ).get("ip"),
                "os": scanner.recon_data.get(
                    "os", {}
                ).get("os"),
                "open_ports": scanner.recon_data.get(
                    "ports", {}
                ).get("total_open", 0),
            }
        })

    except Exception as e:
        print(f"[SCAN_NETWORK ERROR]\n{traceback.format_exc()}")
        target_info = "Unknown"
        try:
            # Re-read target if data not defined
            target_info = request.get_json(force=True).get('target', 'Unknown')
        except:
            pass
            
        return jsonify({
            "findings": [{
                "severity": "HIGH",
                "line":     "-",
                "message":  f"Network scan error: {str(e)}",
                "code":     "Scanner Error",
                "file":     target_info,
            }],
            "total": 1,
        }), 200


# ── CODE ANALYSIS ─────────────────────────────────────────────
@app.route('/analyze_code', methods=['POST'])
def analyze_code():
    try:
        from code_analyzer import CodeAnalyzer
        analyzer = CodeAnalyzer()
        content  = None
        filename = 'code.txt'

        if 'file' in request.files:
            f        = request.files['file']
            filename = f.filename or 'code.txt'
            content  = f.read().decode('utf-8', errors='ignore')
        elif request.is_json:
            data     = request.get_json(force=True) or {}
            content  = data.get('code', '')
            filename = data.get('filename', 'code.txt')

        if not content or not content.strip():
            return jsonify({"error": "Empty file"}), 400

        result = analyzer.analyze(content, filename)

        return jsonify({
            "findings":    result.get("ui_findings", []),
            "total":       len(result.get("ui_findings", [])),
            "language":    result.get("language", "Unknown"),
            "lines":       result.get("lines_of_code", 0),
            "ai_analysis": result.get("ai_analysis"),
            "can_fix":     result.get("fix_supported", False),
            "filename":    filename,
        })

    except Exception as e:
        print(f"[ANALYZE_CODE ERROR]\n{traceback.format_exc()}")
        return jsonify({
            "error":    str(e),
            "findings": [],
            "total":    0,
        }), 500


# ── FIX CODE ──────────────────────────────────────────────────
@app.route('/fix_code', methods=['POST'])
def fix_code():
    try:
        from ai_agent import CybrainAgent
        data     = request.get_json(force=True) or {}
        content  = data.get('code', '')
        filename = data.get('filename', 'code.txt')

        if not content.strip():
            return jsonify({"error": "No code provided"}), 400

        agent  = CybrainAgent()
        result = agent.fix_code(content, filename)

        return jsonify({
            "fixed_code":  result.get("fixed_code"),
            "explanation": result.get("explanation"),
            "filename":    filename,
            "can_download":bool(result.get("fixed_code")),
        })

    except Exception as e:
        print(f"[FIX_CODE ERROR]\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500


# ── FIX APACHE CONFIG ─────────────────────────────────────────
@app.route('/fix_config', methods=['POST'])
def fix_config():
    try:
        from ai_agent import CybrainAgent
        data     = request.get_json(force=True) or {}
        config   = data.get('config', '')
        findings = data.get('findings', [])

        if not config.strip():
            return jsonify({"error": "No config provided"}), 400

        agent  = CybrainAgent()
        result = agent.fix_apache_config(config, findings)

        return jsonify({
            "fixed_config": result.get("fixed_config"),
            "explanation":  result.get("explanation"),
            "can_download": bool(result.get("fixed_config")),
        })

    except Exception as e:
        print(f"[FIX_CONFIG ERROR]\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500


# ── AI CHAT ───────────────────────────────────────────────────
@app.route('/api/chat', methods=['POST'])
def chat():
    try:
        from ai_agent import CybrainAgent
        data    = request.get_json(force=True) or {}
        message = data.get('message', '').strip()
        context = data.get('context', {})

        if not message:
            return jsonify({"error": "No message"}), 400

        agent    = CybrainAgent()
        response = agent.chat(message, context)

        return jsonify({
            "response": response,
            "model":    "Gemini 1.5 Flash"
        })

    except Exception as e:
        print(f"[CHAT ERROR]\n{traceback.format_exc()}")
        return jsonify({
            "response": f"AI error: {str(e)}",
            "model":    "error"
        }), 200


# ── AI FINDINGS ANALYSIS ──────────────────────────────────────
@app.route('/api/analyze_findings', methods=['POST'])
def analyze_findings():
    try:
        from ai_agent import CybrainAgent
        data      = request.get_json(force=True) or {}
        findings  = data.get('findings', [])
        target    = data.get('target', '')
        scan_type = data.get('scan_type', 'web')

        agent  = CybrainAgent()
        result = agent.analyze_findings(
            findings, target, scan_type
        )

        return jsonify({"analysis": result})

    except Exception as e:
        print(f"[ANALYZE_FINDINGS ERROR]\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500


# ── DOWNLOAD REPORT ───────────────────────────────────────────
@app.route('/download_report', methods=['GET'])
def download_report():
    try:
        # Try multiple paths
        paths = [
            os.path.join(
                os.path.dirname(
                    os.path.dirname(os.path.abspath(__file__))
                ),
                "report", "vulnerability_report.md"
            ),
            os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "..", "report", "vulnerability_report.md"
            ),
            "report/vulnerability_report.md",
        ]
        for path in paths:
            if os.path.exists(path):
                return send_file(
                    os.path.abspath(path),
                    as_attachment=True,
                    download_name="vulnerability_report.md"
                )

        # If no report exists, create a placeholder
        placeholder = (
            "# Vulnerability Report\n\n"
            "No scan has been run yet.\n"
            "Run a scan first then export.\n"
        )
        tmp = tempfile.NamedTemporaryFile(
            mode='w', suffix='.md',
            delete=False, encoding='utf-8'
        )
        tmp.write(placeholder)
        tmp.close()
        return send_file(
            tmp.name,
            as_attachment=True,
            download_name="vulnerability_report.md"
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── DOWNLOAD FIXED FILE ───────────────────────────────────────
@app.route('/download_fixed/<filename>', methods=['GET'])
def download_fixed(filename):
    try:
        fixed_dir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "fixed_files"
        )
        path = os.path.join(fixed_dir, filename)
        if os.path.exists(path):
            return send_file(
                path,
                as_attachment=True,
                download_name=filename
            )
        return jsonify({"error": "File not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── MAIN ──────────────────────────────────────────────────────
if __name__ == '__main__':
    print("=" * 50)
    print("CYBRAIN Backend Starting...")
    print(f"Gemini API Key: {'SET' if os.environ.get('GEMINI_API_KEY') else 'NOT SET'}")
    print("=" * 50)
    app.run(
        debug=True,
        host='0.0.0.0',
        port=5000,
        use_reloader=True
    )
