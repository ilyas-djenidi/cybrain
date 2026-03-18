"""
===============================================================
  CYBRAIN - Flask Backend  (v2.1)
  PFE Master 2 - Information Security
  University of Mohamed Boudiaf, M'sila - Algeria
===============================================================
"""

import os
import sys
import io
import time
import hashlib
import tempfile
import traceback
import builtins
import logging

# ── UTF-8 stdout guard ────────────────────────────────────────
try:
    if hasattr(sys.stdout, 'encoding') and sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
except Exception:
    pass

# ── Safe print (no UnicodeEncodeError on Windows/Render) ──────
if not hasattr(builtins, '_orig_print_cybrain'):
    builtins._orig_print_cybrain = builtins.print

def safe_print(*args, **kwargs):
    try:
        builtins._orig_print_cybrain(*args, **kwargs)
    except (UnicodeEncodeError, BlockingIOError):
        try:
            ascii_args = [str(a).encode('ascii', 'replace').decode('ascii') for a in args]
            builtins._orig_print_cybrain(*ascii_args, **kwargs)
        except Exception:
            pass
    except Exception:
        pass

builtins.print = safe_print

# ── Logging ───────────────────────────────────────────────────
logging.basicConfig(
    filename='debug.log', level=logging.DEBUG,
    encoding='utf-8',
    format='%(asctime)s %(levelname)s: %(message)s'
)
logging.info("Backend started")

from flask import Flask, request, jsonify, send_file, Response
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ── App init ──────────────────────────────────────────────────
app = Flask(__name__)

# Simple wildcard CORS — flask-cors handles preflight automatically
CORS(app, origins="*", supports_credentials=False,
     methods=["GET", "POST", "OPTIONS"],
     allow_headers=["Content-Type", "Authorization"])

# ── Force CORS on EVERY response (including Gunicorn 502) ─────
@app.after_request
def _add_cors(response):
    response.headers["Access-Control-Allow-Origin"]  = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response

# ── Global exception handler — CORS headers even on crash ─────
@app.errorhandler(Exception)
def _handle_exception(e):
    logging.error(f"Unhandled: {e}\n{traceback.format_exc()}")
    status = getattr(e, 'code', 500)
    resp = jsonify({"error": str(e), "type": e.__class__.__name__})
    resp.status_code = status
    resp.headers["Access-Control-Allow-Origin"]  = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return resp

# ── Explicit OPTIONS preflight for all routes ─────────────────
@app.route("/scan_url",             methods=["OPTIONS"])
@app.route("/scan_network",         methods=["OPTIONS"])
@app.route("/analyze",              methods=["OPTIONS"])
@app.route("/analyze_code",         methods=["OPTIONS"])
@app.route("/fix_code",             methods=["OPTIONS"])
@app.route("/fix_config",           methods=["OPTIONS"])
@app.route("/api/chat",             methods=["OPTIONS"])
@app.route("/api/analyze_findings", methods=["OPTIONS"])
@app.route("/download_report",      methods=["OPTIONS"])
@app.route("/download_report_csv",  methods=["OPTIONS"])
@app.route("/download_report_json", methods=["OPTIONS"])
def _preflight():
    resp = Response("", status=204)
    resp.headers["Access-Control-Allow-Origin"]  = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    resp.headers["Access-Control-Max-Age"]       = "86400"
    return resp

# ── AI response cache (TTL=5min, max 200 entries) ─────────────
_ai_cache:     dict = {}
_ai_cache_ttl: dict = {}
CACHE_TTL = 300
CACHE_MAX = 200

def _get_cache(key: str):
    if key in _ai_cache:
        if time.time() - _ai_cache_ttl[key] < CACHE_TTL:
            return _ai_cache[key]
        del _ai_cache[key], _ai_cache_ttl[key]
    return None

def _set_cache(key: str, value: str):
    if len(_ai_cache) >= CACHE_MAX:
        oldest = min(_ai_cache_ttl, key=lambda k: _ai_cache_ttl[k])
        del _ai_cache[oldest], _ai_cache_ttl[oldest]
    _ai_cache[key]     = value
    _ai_cache_ttl[key] = time.time()

# ── Path traversal guard ──────────────────────────────────────
def _safe_path(directory: str, filename: str):
    safe = os.path.realpath(os.path.join(directory, filename))
    base = os.path.realpath(directory)
    return safe if safe.startswith(base + os.sep) or safe == base else None

def _report_dir() -> str:
    d = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "report")
    os.makedirs(d, exist_ok=True)
    return d

def _fixed_dir() -> str:
    d = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixed_files")
    os.makedirs(d, exist_ok=True)
    return d

# =============================================================
#  HEALTH & ROOT
# =============================================================
@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "message": "Cybrain Intelligence API v2.1 is LIVE",
        "docs": "https://github.com/ilyas-djenidi/cybrain",
        "status": "ready"
    })

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status":  "ok",
        "version": "2.1",
        "gemini":  bool(os.environ.get("GEMINI_API_KEY")),
        "message": "Cybrain backend running",
    })

# =============================================================
#  APACHE CONFIG ANALYSIS
# =============================================================
@app.route("/analyze", methods=["POST"])
def analyze():
    try:
        from detect_apache_misconf import ApacheMisconfigDetector
        detector    = ApacheMisconfigDetector()
        content     = None
        source_name = "Input Text"

        if "file" in request.files:
            f = request.files["file"]
            if f and f.filename:
                content     = f.read().decode("utf-8", errors="ignore")
                source_name = f.filename

        if content is None and request.is_json:
            data    = request.get_json(force=True) or {}
            content = data.get("content") or data.get("config", "")

        if not content or not content.strip():
            return jsonify({"error": "No content provided"}), 400
        if len(content) > 1_000_000:
            return jsonify({"error": "Config too large (max 1MB)"}), 400

        detector.scan_content(content.strip(), source_name)
        raw = detector.get_results()

        SEV_MAP = {
            "error":"CRITICAL","Error":"CRITICAL",
            "high":"HIGH","High":"HIGH",
            "warning":"MEDIUM","Warning":"MEDIUM",
            "medium":"MEDIUM","Medium":"MEDIUM",
            "low":"LOW","Low":"LOW",
            "info":"INFO","Info":"INFO",
        }
        results = [{
            "severity": SEV_MAP.get(str(m.get("severity","Info")), str(m.get("severity","Info")).upper()),
            "line":     str(m.get("line", "-")),
            "message":  m.get("message", ""),
            "code":     m.get("code", ""),
            "file":     str(m.get("file", source_name)),
        } for m in raw]

        sevs = [r["severity"] for r in results]
        risk = next((s for s in ("CRITICAL","HIGH","MEDIUM","LOW") if s in sevs), "INFO")

        return jsonify({"findings": results, "results": results, "total": len(results), "risk": risk})

    except Exception as e:
        print(f"[ANALYZE ERROR]\n{traceback.format_exc()}")
        return jsonify({"error": str(e), "findings": [], "total": 0}), 500

# =============================================================
#  WEB VULNERABILITY SCAN
# =============================================================
@app.route("/scan_url", methods=["POST"])
def scan_url():
    url_safe = ""
    try:
        data = request.get_json(force=True)
        if not data:
            return jsonify({"error": "No JSON received"}), 400

        url = data.get("url", "").strip()
        if not url:
            return jsonify({"error": "No URL provided"}), 400

        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        url      = url.split("#")[0].rstrip("/")
        url_safe = url

        print(f"\n[SCAN_URL] Starting: {url}")
        from url_scanner import UrlScanner
        scanner = UrlScanner(url)
        results = scanner.scan()

        if not isinstance(results, list):
            results = []

        risk = scanner._calc_overall_risk()
        print(f"[SCAN_URL] Done: {len(results)} findings, risk={risk}")

        return jsonify({"findings": results, "results": results, "total": len(results), "url": url, "risk": risk})

    except Exception as e:
        print(f"[SCAN_URL ERROR]\n{traceback.format_exc()}")
        return jsonify({
            "findings": [{
                "severity": "HIGH", "line": "-",
                "message": (
                    f"Scanner error: {str(e)}<br><br>"
                    "<strong>Common causes:</strong><br>"
                    "• Target blocked the scan<br>"
                    "• Network timeout<br>"
                    "• Target returned unexpected response<br><br>"
                    "<strong>Try:</strong><br>"
                    "• http://testphp.vulnweb.com<br>"
                    "• https://demo.testfire.net"
                ),
                "code": "Scan Interrupted",
                "file": url_safe,
            }],
            "total": 1, "risk": "HIGH", "url": url_safe,
        }), 200

# =============================================================
#  NETWORK SCAN
# =============================================================
@app.route("/scan_network", methods=["POST"])
def scan_network():
    target_info = "Unknown"
    try:
        data   = request.get_json(force=True) or {}
        target = str(data.get("target", "")).strip()
        if not target:
            return jsonify({"error": "No target provided"}), 400

        for prefix in ("https://", "http://", "ftp://"):
            if target.startswith(prefix):
                target = target[len(prefix):]
        target      = target.split("/")[0].split(":")[0]
        target_info = target

        print(f"[SCAN_NETWORK] Target: {target}")
        from network_scanner import NetworkScanner
        scanner = NetworkScanner(target)
        results = scanner.scan()

        return jsonify({
            "findings": results, "total": len(results), "target": target,
            "risk": scanner._calc_overall_risk(),
            "recon": {
                "ip":         scanner.recon_data.get("dns",   {}).get("ip"),
                "os":         scanner.recon_data.get("os",    {}).get("os"),
                "open_ports": scanner.recon_data.get("ports", {}).get("total_open", 0),
            },
        })

    except Exception as e:
        safe_e = str(e).encode('ascii', 'replace').decode('ascii')
        return jsonify({
            "findings": [{
                "severity": "HIGH", "line": "-",
                "message": (
                    f"Network scan error: {safe_e}<br><br>"
                    "<strong>Possible causes:</strong><br>"
                    "• Target is unreachable<br>"
                    "• Network blocking scans<br>"
                    "• Invalid IP/Hostname"
                ),
                "code": "Scanner Error", "file": target_info,
            }],
            "total": 1, "target": target_info, "risk": "HIGH",
        }), 200

# =============================================================
#  CODE ANALYSIS
# =============================================================
@app.route("/analyze_code", methods=["POST"])
def analyze_code():
    try:
        from code_analyzer import CodeAnalyzer
        analyzer = CodeAnalyzer()
        content  = None
        filename = "code.txt"

        if "file" in request.files:
            f        = request.files["file"]
            filename = f.filename or "code.txt"
            content  = f.read().decode("utf-8", errors="ignore")
        elif request.is_json:
            data     = request.get_json(force=True) or {}
            content  = str(data.get("code", ""))
            filename = str(data.get("filename", "code.txt"))

        if not content or not content.strip():
            return jsonify({"error": "Empty file or code"}), 400
        if len(content) > 500_000:
            return jsonify({"error": "File too large (max 500KB)"}), 400

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
        return jsonify({"error": str(e), "findings": [], "total": 0}), 500

# =============================================================
#  FIX CODE
# =============================================================
@app.route("/fix_code", methods=["POST"])
def fix_code():
    try:
        from ai_agent import CybrainAgent
        data     = request.get_json(force=True) or {}
        content  = data.get("code", "")
        filename = data.get("filename", "code.txt")

        if not content.strip():
            return jsonify({"error": "No code provided"}), 400

        agent      = CybrainAgent()
        result     = agent.fix_code(content, filename)
        fixed_code = result.get("fixed_code")

        if fixed_code:
            try:
                with open(os.path.join(_fixed_dir(), f"fixed_{filename}"), "w", encoding="utf-8") as fh:
                    fh.write(fixed_code)
            except Exception:
                pass

        return jsonify({
            "fixed_code":  fixed_code,
            "explanation": result.get("explanation"),
            "filename":    filename,
            "can_download": bool(fixed_code),
        })

    except Exception as e:
        print(f"[FIX_CODE ERROR]\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

# =============================================================
#  FIX APACHE CONFIG
# =============================================================
@app.route("/fix_config", methods=["POST"])
def fix_config():
    try:
        from ai_agent import CybrainAgent
        data     = request.get_json(force=True) or {}
        config   = data.get("config", "")
        findings = data.get("findings", [])

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

# =============================================================
#  AI CHAT
# =============================================================
@app.route("/api/chat", methods=["POST"])
def chat():
    try:
        from ai_agent import CybrainAgent
        data    = request.get_json(force=True) or {}
        message = data.get("message", "").strip()
        context = data.get("context", {})

        if not message:
            return jsonify({"error": "No message provided"}), 400
        if len(message) > 5000:
            return jsonify({"error": "Message too long (max 5000 chars)"}), 400

        cache_key = hashlib.md5((message + str(context)).encode()).hexdigest()
        cached    = _get_cache(cache_key)
        if cached:
            return jsonify({"response": cached, "model": "Cybrain Engine (cached)"})

        agent    = CybrainAgent()
        response = agent.chat(message, context)
        if response and not response.startswith("[!]"):
            _set_cache(cache_key, response)

        ai_mode = "Gemini 2.0 Flash" if agent.ai_active else "Cybrain Offline Engine"
        return jsonify({"response": response, "model": ai_mode})

    except Exception as e:
        print(f"[CHAT ERROR]\n{traceback.format_exc()}")
        return jsonify({"response": f"AI error: {str(e)}", "model": "error"}), 200

# =============================================================
#  AI FINDINGS ANALYSIS
# =============================================================
@app.route("/api/analyze_findings", methods=["POST"])
def analyze_findings():
    try:
        from ai_agent import CybrainAgent
        data      = request.get_json(force=True) or {}
        findings  = data.get("findings", [])
        target    = str(data.get("target", ""))
        scan_type = str(data.get("scan_type", "web"))

        if not findings:
            return jsonify({"analysis": "No findings to analyse."}), 200

        cache_key = hashlib.md5((str(findings) + target + scan_type).encode()).hexdigest()
        cached    = _get_cache(cache_key)
        if cached:
            return jsonify({"analysis": cached})

        agent  = CybrainAgent()
        result = agent.analyze_findings(findings, target, scan_type)
        if result:
            _set_cache(cache_key, result)

        return jsonify({"analysis": result})

    except Exception as e:
        print(f"[ANALYZE_FINDINGS ERROR]\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

# =============================================================
#  DOWNLOAD REPORTS
# =============================================================
def _send_report_file(filename: str, download_name: str):
    report_dir = _report_dir()
    for path in [
        os.path.join(report_dir, filename),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "report", filename),
    ]:
        abs_path = os.path.abspath(path)
        if os.path.exists(abs_path):
            return send_file(abs_path, as_attachment=True, download_name=download_name)
    return None

@app.route("/download_report", methods=["GET"])
def download_report():
    try:
        resp = _send_report_file("vulnerability_report.md", "vulnerability_report.md")
        if resp:
            return resp
        return jsonify({"error": "No report available. Please run a scan first."}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/download_report_csv", methods=["GET"])
def download_report_csv():
    try:
        resp = _send_report_file("findings_summary.csv", "findings_summary.csv")
        if resp:
            return resp
        return jsonify({"error": "No CSV report found. Run a scan first."}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/download_report_json", methods=["GET"])
def download_report_json():
    try:
        resp = _send_report_file("findings.json", "findings.json")
        if resp:
            return resp
        return jsonify({"error": "No JSON report found. Run a scan first."}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# =============================================================
#  DOWNLOAD FIXED FILE  (path-traversal protected)
# =============================================================
@app.route("/download_fixed/<path:filename>", methods=["GET"])
def download_fixed(filename: str):
    try:
        fixed_dir = _fixed_dir()
        safe      = _safe_path(fixed_dir, filename)
        if safe is None:
            print(f"[SECURITY] Path traversal blocked: {filename!r}")
            return jsonify({"error": "Invalid filename"}), 400
        if not os.path.exists(safe):
            return jsonify({"error": "File not found"}), 404
        return send_file(safe, as_attachment=True, download_name=os.path.basename(safe))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# =============================================================
#  MAIN
# =============================================================
if __name__ == "__main__":
    bar = "=" * 52
    print(f"\n{bar}")
    print("  CYBRAIN Backend v2.1 - Starting")
    print(f"  Gemini : {'SET [OK]' if os.environ.get('GEMINI_API_KEY') else 'NOT SET (offline mode)'}")
    print(f"{bar}")
    for mod, label in [
        ("url_scanner","URL Scanner"), ("network_scanner","Network Scanner"),
        ("owasp_checks","OWASP Checker"), ("code_analyzer","Code Analyzer"),
        ("ai_agent","AI Agent"), ("report_generator","Report Generator"),
        ("detect_apache_misconf","Apache Detector"),
    ]:
        try:
            __import__(mod)
            print(f"  [+] {label}")
        except ImportError as e:
            print(f"  [-] {label} - {e}")
    print(f"{bar}\n")

    app.run(
        debug=os.environ.get("DEBUG", "False") == "True",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        use_reloader=False,
        threaded=True,
    )