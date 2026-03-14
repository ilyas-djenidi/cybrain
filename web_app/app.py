from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS
import sys
import os

# Add parent directory to path to import detector
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detect_apache_misconf import ApacheMisconfigDetector

app = Flask(__name__)
CORS(app, origins=['http://localhost:5173'])

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
        
        print(f"[SCANNER] Done. Found {len(results)} issues.")
        
        return jsonify({
            "results": results,
            "total": len(results),
            "url": url
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

if __name__ == '__main__':
    app.run(debug=True, port=5000)
