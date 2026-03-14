from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS
import sys
import os
import base64
from dotenv import load_dotenv
from ai_agent import CybrainAgent
from code_analyzer import CodeAnalyzer

# Load environment variables
load_dotenv()

# Add parent directory to path to import detector
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detect_apache_misconf import ApacheMisconfigDetector

app = Flask(__name__)
CORS(app)  # Allow all origins — frontend may be hosted on Netlify/Vercel

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    content = None
    source_name = "Input Text"

    if 'file' in request.files:
        file = request.files['file']
        if file.filename != '':
            content = file.read().decode('utf-8', errors='ignore')
            source_name = file.filename
    
    if content is None:
        data = request.get_json()
        if data and 'content' in data:
            content = data['content']

    if not content:
        return jsonify({'error': 'No content provided'}), 400

    detector = ApacheMisconfigDetector()
    detector.scan_content(content, source_name)
    results = detector.get_results()

    return jsonify({'results': results})

@app.route('/scan_url', methods=['POST'])
def scan_url():
    import traceback
    try:
        data = request.get_json(force=True)
        if not data:
            return jsonify({"error": "No JSON data received"}), 400
        
        url = data.get('url', '').strip()
        if not url:
            return jsonify({"error": "No URL provided"}), 400
        
        # Add http:// if missing
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # Strip fragments that break requests
        url = url.split('#')[0].rstrip('/')
        
        print(f"[SCANNER] Starting scan on: {url}")
        
        from url_scanner import UrlScanner
        scanner = UrlScanner(url)
        results = scanner.scan()
        
        # Calculate risk based on worst severity found
        risk = "INFO"
        if len(results) > 0:
            if hasattr(scanner, '_calc_overall_risk'):
                 risk = scanner._calc_overall_risk()
            else:
                sevs = [r.get("severity", "INFO") for r in results]
                for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                    if s in sevs:
                        risk = s
                        break
        
        print(f"[SCANNER] Done. Found {len(results)} issues. Risk: {risk}")
        
        return jsonify({
            "results": results,
            "total": len(results),
            "url": url,
            "risk": risk
        })
        
    except Exception as e:
        print(f"[SCANNER ERROR] {traceback.format_exc()}")
        return jsonify({
            "results": [{
                "severity": "HIGH",
                "line": "-",
                "message": f"Scanner error: {str(e)}\n\n"
                           f"<strong>Recommendation:</strong><br>"
                           f"Check the Flask console for the full error.",
                "code": "Scanner Error",
                "file": data.get('url', 'unknown') if data else 'unknown'
            }],
            "total": 1
        }), 200

@app.route('/download_report')
def download_report():
    try:
        return send_file('../report/vulnerability_report.md', as_attachment=True)
    except Exception as e:
        return jsonify({"error": str(e)}), 404

from network_scanner import NetworkScanner

@app.route('/scan_network', methods=['POST'])
def scan_network():
    try:
        data = request.get_json(force=True)
        if not data:
            return jsonify({"error": "No data"}), 400

        target = data.get('target', '').strip()
        if not target:
            return jsonify({"error": "No target"}), 400

        print(f"[APP] Network scan: {target}")
        scanner = NetworkScanner(target)
        results = scanner.scan()

        return jsonify({
            "findings": results,
            "total":    len(results),
            "target":   target,
            "risk":     scanner._calc_overall_risk(),
            "recon":    {
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
        import traceback
        print(f"[APP ERROR] {traceback.format_exc()}")
        return jsonify({
            "findings": [{
                "severity": "HIGH",
                "line":     "-",
                "message":  f"Network scan error: {str(e)}",
                "code":     "Scanner Error",
                "file":     target if 'target' in locals()
                            else "unknown"
            }],
            "total": 1
        }), 200


# ── AI CHATBOT ──────────────────────────────────────────────
@app.route('/api/chat', methods=['POST'])
def chat():
    try:
        data    = request.get_json(force=True)
        message = data.get('message', '').strip()
        context = data.get('context', {})
        api_key = data.get('api_key', '')

        if not message:
            return jsonify({"error": "No message"}), 400

        agent    = CybrainAgent(api_key or None)
        response = agent.chat(message, context)

        return jsonify({
            "response": response,
            "model":    "llama-3.3-70b (OpenRouter)"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── CODE FILE ANALYSIS ──────────────────────────────────────
@app.route('/analyze_code', methods=['POST'])
def analyze_code():
    try:
        api_key  = request.form.get('api_key', '')
        analyzer = CodeAnalyzer(api_key or None)

        if 'file' in request.files:
            file     = request.files['file']
            filename = file.filename
            content  = file.read().decode(
                'utf-8', errors='ignore'
            )
        elif request.is_json:
            data     = request.get_json(force=True)
            content  = data.get('code', '')
            filename = data.get('filename', 'code.txt')
            api_key  = data.get('api_key', '')
            analyzer = CodeAnalyzer(api_key or None)
        else:
            return jsonify({"error": "No code provided"}),400

        if not content.strip():
            return jsonify({"error": "Empty file"}), 400

        result = analyzer.analyze(content, filename)

        return jsonify({
            "findings":    result["ui_findings"],
            "total":       len(result["ui_findings"]),
            "language":    result["language"],
            "lines":       result["lines_of_code"],
            "ai_analysis": result["ai_analysis"],
            "can_fix":     result["fix_supported"],
            "filename":    filename,
        })
    except Exception as e:
        import traceback
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500


# ── FIX CODE ────────────────────────────────────────────────
@app.route('/fix_code', methods=['POST'])
def fix_code():
    try:
        data     = request.get_json(force=True)
        content  = data.get('code', '')
        filename = data.get('filename', 'code.txt')
        api_key  = data.get('api_key', '')
        issue    = data.get('specific_issue', None)

        analyzer = CodeAnalyzer(api_key or None)
        result   = analyzer.fix_code(
            content, filename
        )

        return jsonify({
            "fixed_code":  result.get("fixed_code"),
            "explanation": result.get("explanation"),
            "filename":    filename,
            "can_download":bool(result.get("fixed_code")),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── FIX APACHE CONFIG ───────────────────────────────────────
@app.route('/fix_config', methods=['POST'])
def fix_config():
    try:
        data     = request.get_json(force=True)
        config   = data.get('config', '')
        findings = data.get('findings', [])
        api_key  = data.get('api_key', '')

        agent  = CybrainAgent(api_key or None)
        result = agent.fix_apache_config(
            config, findings
        )

        return jsonify({
            "fixed_config": result.get("fixed_config"),
            "explanation":  result.get("explanation"),
            "can_download": bool(
                result.get("fixed_config")
            ),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── AI FINDINGS ANALYSIS ────────────────────────────────────
@app.route('/api/analyze_findings', methods=['POST'])
def analyze_findings():
    try:
        data      = request.get_json(force=True)
        findings  = data.get('findings', [])
        target    = data.get('target', '')
        scan_type = data.get('scan_type', 'web')
        api_key   = data.get('api_key', '')

        agent  = CybrainAgent(api_key or None)
        result = agent.analyze_findings(
            findings, target, scan_type
        )

        return jsonify({"analysis": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── DOWNLOAD FIXED FILE ─────────────────────────────────────
@app.route('/download_fixed/<filename>')
def download_fixed(filename):
    fixed_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "fixed_files", filename
    )
    if os.path.exists(fixed_path):
        return send_file(fixed_path, as_attachment=True)
    return jsonify({"error": "File not found"}), 404


if __name__ == '__main__':
    app.run(debug=True, port=5000)

