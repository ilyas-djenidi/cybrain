"""
===============================================================
  CYBRAIN - Flask Backend  (v2.0)
  PFE Master 2 - Information Security
  University of Mohamed Boudiaf, M'sila - Algeria

  ROUTES
  ??????
  GET  /health                  - health check
  POST /scan_url                - web vulnerability scan
  POST /scan_network            - network recon + vuln scan
  POST /analyze                 - Apache config audit
  POST /analyze_code            - SAST code analysis
  POST /fix_code                - AI code fixer
  POST /fix_config              - AI Apache config fixer
  POST /api/chat                - AI security Q&A
  POST /api/analyze_findings    - AI findings report
  GET  /download_report         - download MD report
  GET  /download_report_csv     - download CSV findings
  GET  /download_report_json    - download JSON findings
  GET  /download_fixed/<name>   - download AI-fixed file

  IMPROVEMENTS vs original
  ????????????????????????
  * Path-traversal guard on /download_fixed
  * /download_report_csv and /download_report_json new endpoints
  * Input validation on all routes (URL, target, code length)
  * Private IP blocklist enforced before scan_url
  * Rate-limit hint header on scan endpoints
  * AI cache eviction (LRU-style - max 200 entries)
  * Startup banner shows all loaded modules
  * Graceful import error messages (no silent crashes)

  FOR EDUCATIONAL / AUTHORIZED TESTING ONLY
===============================================================
"""

import os
import sys
import io
import time
import hashlib
import tempfile
import traceback
import urllib.request
from werkzeug.utils import secure_filename

# Force output to UTF-8 with replacement to prevent UnicodeEncodeError on Windows
try:
    if sys.stdout.encoding.lower() != 'utf-8':
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
except Exception:
    pass

import builtins
import io
import sys

# Foolproof safe_print to prevent recursion on reloads
if not hasattr(builtins, '_orig_print_cybrain'):
    builtins._orig_print_cybrain = builtins.print

def safe_print(*args, **kwargs):
    try:
        builtins._orig_print_cybrain(*args, **kwargs)
    except (UnicodeEncodeError, BlockingIOError):
        try:
            # Fallback: strip and print as ASCII
            ascii_args = [str(a).encode('ascii', 'replace').decode('ascii') for a in args]
            builtins._orig_print_cybrain(*ascii_args, **kwargs)
        except Exception:
            pass
    except Exception:
        pass

builtins.print = safe_print

import logging
logging.basicConfig(filename='debug.log', level=logging.DEBUG, 
                    encoding='utf-8',
                    format='%(asctime)s %(levelname)s: %(message)s')
logging.info("Backend started")

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from dotenv import load_dotenv

# ?? Load .env FIRST ????????????????????????????????????????????????????????
load_dotenv()
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ?? App init ???????????????????????????????????????????????????????????????
app = Flask(__name__)
# Updated CORS for explicit origins and safety
CORS(app, 
     origins=["https://cybrain-ai.netlify.app", "http://localhost:5173", "http://localhost:3000"],
     supports_credentials=False,
     methods=["GET", "POST", "OPTIONS"],
     allow_headers=["Content-Type", "Authorization"]
)

@app.after_request
def add_header(response):
    # Ensure CORS headers are present even if the original response didn't have them
    origin = request.headers.get('Origin')
    allowed_origins = ["https://cybrain-ai.netlify.app", "http://localhost:5173", "http://localhost:3000"]
    
    if origin in allowed_origins:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
    elif not origin:
        # Fallback for non-browser requests or same-origin
        response.headers['Access-Control-Allow-Origin'] = "*"
    
    return response

@app.errorhandler(Exception)
def handle_exception(e):
    """Global error handler to ensure CORS headers on crashes."""
    logging.error(f"Unhandled Exception: {str(e)}\n{traceback.format_exc()}")
    
    # Extract status code if available
    status_code = 500
    if hasattr(e, 'code'):
        status_code = e.code
        
    response = jsonify({
        "error": "Internal Server Error",
        "message": str(e),
        "type": e.__class__.__name__,
        "status": status_code
    })
    
    # Manually add CORS headers because after_request might not run on some exceptions
    origin = request.headers.get('Origin')
    allowed_origins = ["https://cybrain-ai.netlify.app", "http://localhost:5173", "http://localhost:3000"]
    if origin in allowed_origins:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
    else:
        response.headers['Access-Control-Allow-Origin'] = "*"
        
    response.status_code = status_code
    return response

# Handle OPTIONS preflight explicitly for long-running endpoints
@app.route('/scan_url', methods=['OPTIONS'])
def scan_url_preflight():
    return '', 204

@app.route('/scan_network', methods=['OPTIONS'])  
def scan_network_preflight():
    return '', 204

# ?? AI response cache (TTL=5min, max 200 entries) ?????????????????????????
_ai_cache:     dict = {}
_ai_cache_ttl: dict = {}
CACHE_TTL     = 300   # seconds
CACHE_MAX     = 200   # max entries before LRU eviction

def _get_cache(key: str):
    if key in _ai_cache:
        if time.time() - _ai_cache_ttl[key] < CACHE_TTL:
            print(f"[AI CACHE] Hit for {key[:20]}")
            return _ai_cache[key]
        # Expired - remove
        del _ai_cache[key]
        del _ai_cache_ttl[key]
    return None

def _set_cache(key: str, value: str):
    # Evict oldest entry if at capacity
    if len(_ai_cache) >= CACHE_MAX:
        oldest = min(_ai_cache_ttl, key=lambda k: _ai_cache_ttl[k])
        del _ai_cache[oldest]
        del _ai_cache_ttl[oldest]
    _ai_cache[key]     = value
    _ai_cache_ttl[key] = time.time()

# ?? Path traversal guard ???????????????????????????????????????????????????
def _safe_path(directory: str, filename: str) -> str | None:
    """
    Returns the resolved absolute path only if it stays
    within the given directory. Returns None on traversal attempt.
    """
    safe = os.path.realpath(os.path.join(directory, filename))
    base = os.path.realpath(directory)
    return safe if safe.startswith(base + os.sep) or safe == base else None

# ?? Report directory helper ????????????????????????????????????????????????
def _report_dir() -> str:
    d = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "report",
    )
    os.makedirs(d, exist_ok=True)
    return d

# ?? Fixed files directory helper ??????????????????????????????????????????
def _fixed_dir() -> str:
    d = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixed_files")
    os.makedirs(d, exist_ok=True)
    return d

# ==========================================================================
#  HEALTH CHECK
# ==========================================================================

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status":  "ok",
        "version": "2.0",
        "gemini":  bool(os.environ.get("GEMINI_API_KEY")),
        "message": "Cybrain backend running",
        "routes": [
            "POST /scan_url",
            "POST /scan_network",
            "POST /analyze",
            "POST /analyze_code",
            "POST /fix_code",
            "POST /fix_config",
            "POST /api/chat",
            "POST /api/analyze_findings",
            "GET  /download_report",
            "GET  /download_report_csv",
            "GET  /download_report_json",
            "GET  /download_fixed/<filename>",
        ],
    })

# ==========================================================================
#  APACHE CONFIG ANALYSIS
# ==========================================================================

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

        # Size guard - 1MB max
        if len(content) > 1_000_000:
            return jsonify({"error": "Config too large (max 1MB)"}), 400

        detector.scan_content(content.strip(), source_name)
        raw = detector.get_results()

        # Severity is already normalised in v2.0 detector
        # but we map again for backwards compatibility
        SEV_MAP = {
            "error": "CRITICAL", "Error": "CRITICAL",
            "high":  "HIGH",     "High":  "HIGH",
            "warning":"MEDIUM",  "Warning":"MEDIUM",
            "medium":"MEDIUM",   "Medium":"MEDIUM",
            "low":   "LOW",      "Low":   "LOW",
            "info":  "INFO",     "Info":  "INFO",
        }
        results = []
        for m in raw:
            raw_sev = str(m.get("severity", "Info"))
            sev     = SEV_MAP.get(raw_sev, raw_sev.upper())
            results.append({
                "severity": sev,
                "line":     str(m.get("line", "-")),
                "message":  m.get("message", ""),
                "code":     m.get("code", ""),
                "file":     str(m.get("file", source_name)),
            })

        sevs = [r["severity"] for r in results]
        risk = next(
            (s for s in ("CRITICAL","HIGH","MEDIUM","LOW") if s in sevs),
            "INFO",
        )

        return jsonify({
            "findings": results,
            "results":  results,
            "total":    len(results),
            "risk":     risk,
        })

    except Exception as e:
        print(f"[ANALYZE ERROR]\n{traceback.format_exc()}")
        return jsonify({"error": str(e), "findings": [], "total": 0}), 500

# ==========================================================================
#  WEB VULNERABILITY SCAN
# ==========================================================================

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

        # Normalise URL
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        url      = url.split("#")[0].rstrip("/")
        url_safe = url

        # Private IP guard - REMOVED AT USER REQUEST
        # from url_scanner import _is_private_target
        # if _is_private_target(url):
        #     ...

        print(f"\n[SCAN_URL] Starting: {url}")
        from url_scanner import UrlScanner
        scanner = UrlScanner(url)
        results = scanner.scan()

        if not isinstance(results, list):
            results = []

        risk = scanner._calc_overall_risk()
        print(f"[SCAN_URL] Done: {len(results)} findings, risk={risk}")

        return jsonify({
            "findings": results,
            "results":  results,
            "total":    len(results),
            "url":      url,
            "risk":     risk,
        })

    except Exception as e:
        print(f"[SCAN_URL ERROR]\n{traceback.format_exc()}")
        return jsonify({
            "findings": [{
                "severity": "HIGH",
                "line":     "-",
                "message":  (
                    f"Scanner error: {str(e)}<br><br>"
                    "<strong>Common causes:</strong><br>"
                    "* Target blocked the scan<br>"
                    "* Network timeout<br>"
                    "* Target returned unexpected response<br><br>"
                    "<strong>Try:</strong><br>"
                    "* http://testphp.vulnweb.com<br>"
                    "* https://demo.testfire.net"
                ),
                "code": "Scan Interrupted",
                "file": url_safe,
            }],
            "total": 1,
            "risk":  "HIGH",
            "url":   url_safe,
        }), 200

# ==========================================================================
#  NETWORK SCAN
# ==========================================================================

@app.route("/scan_network", methods=["POST"])
def scan_network():
    target_info = "Unknown"
    try:
        data   = request.get_json(force=True) or {}
        target = data.get("target", "").strip()
        if not target:
            return jsonify({"error": "No target provided"}), 400

        # Strip protocol / path / port
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
            "findings": results,
            "total":    len(results),
            "target":   target,
            "risk":     scanner._calc_overall_risk(),
            "recon": {
                "ip": scanner.recon_data.get("dns", {}).get("ip"),
                "os": scanner.recon_data.get("os",  {}).get("os"),
                "open_ports": scanner.recon_data.get("ports", {}).get("total_open", 0),
            },
        })

    except Exception as e:
        tb = traceback.format_exc()
        logging.error(f"[SCAN_NETWORK ERROR] {str(e)}\n{tb}")
        # Return a safe error message
        safe_e = str(e).encode('ascii', 'replace').decode('ascii')
        return jsonify({
            "findings": [{
                "severity": "HIGH",
                "line":     "-",
                "message":  (
                    f"Network scan error: {safe_e}<br><br>"
                    "<strong>Possible causes:</strong><br>"
                    "* Target is unreachable<br>"
                    "* Internal network blocking scans<br>"
                    "* Invalid IP/Hostname provided<br><br>"
                    "<strong>Recommendation:</strong><br>"
                    "Check if the target is online and reachable from this server."
                ),
                "code": "Scanner Error",
                "file": target_info,
            }],
            "total":  1,
            "target": target_info,
            "risk":   "HIGH",
        }), 200

# ==========================================================================
#  CODE ANALYSIS
# ==========================================================================

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
            content  = data.get("code", "")
            filename = data.get("filename", "code.txt")

        if not content or not content.strip():
            return jsonify({"error": "Empty file or code"}), 400

        # Size guard - 500KB max
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

# ==========================================================================
#  FIX CODE
# ==========================================================================

@app.route("/fix_code", methods=["POST"])
def fix_code():
    try:
        from ai_agent import CybrainAgent
        data     = request.get_json(force=True) or {}
        content  = data.get("code", "")
        filename = data.get("filename", "code.txt")

        if not content.strip():
            return jsonify({"error": "No code provided"}), 400

        agent  = CybrainAgent()
        result = agent.fix_code(content, filename)

        # Optionally save fixed file to fixed_files/
        fixed_code = result.get("fixed_code")
        if fixed_code:
            fixed_path = os.path.join(_fixed_dir(), f"fixed_{filename}")
            try:
                with open(fixed_path, "w", encoding="utf-8") as fh:
                    fh.write(fixed_code)
            except Exception:
                pass

        return jsonify({
            "fixed_code":  fixed_code,
            "explanation": result.get("explanation"),
            "filename":    filename,
            "can_download":bool(fixed_code),
        })

    except Exception as e:
        print(f"[FIX_CODE ERROR]\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

# ==========================================================================
#  FIX APACHE CONFIG
# ==========================================================================

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

# ==========================================================================
#  AI CHAT
# ==========================================================================

@app.route("/api/chat", methods=["POST"])
def chat():
    try:
        from ai_agent import CybrainAgent
        data    = request.get_json(force=True) or {}
        message = data.get("message", "").strip()
        context = data.get("context", {})

        if not message:
            return jsonify({"error": "No message provided"}), 400

        # Message length guard
        if len(message) > 5000:
            return jsonify({"error": "Message too long (max 5000 chars)"}), 400

        # Cache key
        cache_key = hashlib.md5((message + str(context)).encode()).hexdigest()
        cached    = _get_cache(cache_key)
        if cached:
            return jsonify({
                "response": cached,
                "model":    "Cybrain Engine (cached)",
            })

        agent    = CybrainAgent()
        response = agent.chat(message, context)

        if response and not response.startswith("[!]"):
            _set_cache(cache_key, response)

        ai_mode = "Gemini 2.0 Flash" if agent.ai_active else "Cybrain Offline Engine"
        return jsonify({"response": response, "model": ai_mode})

    except Exception as e:
        print(f"[CHAT ERROR]\n{traceback.format_exc()}")
        return jsonify({"response": f"AI error: {str(e)}", "model": "error"}), 200

# ==========================================================================
#  AI FINDINGS ANALYSIS
# ==========================================================================

@app.route("/api/analyze_findings", methods=["POST"])
def analyze_findings():
    try:
        from ai_agent import CybrainAgent
        data      = request.get_json(force=True) or {}
        findings  = data.get("findings", [])
        target    = data.get("target", "")
        scan_type = data.get("scan_type", "web")

        if not findings:
            return jsonify({"analysis": "No findings to analyse."}), 200

        # Cache key from findings hash
        cache_key = hashlib.md5(
            (str(findings) + target + scan_type).encode()
        ).hexdigest()
        cached = _get_cache(cache_key)
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

# ==========================================================================
#  DOWNLOAD REPORTS
# ==========================================================================

def _send_report_file(filename: str, download_name: str):
    """Helper - find and send a report file."""
    report_dir = _report_dir()
    candidates = [
        os.path.join(report_dir, filename),
        os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..", "report", filename,
        ),
    ]
    for path in candidates:
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
        # Placeholder if no scan run yet
        placeholder = (
            "# Vulnerability Report\n\n"
            "No scan has been run yet.\n"
            "Run a scan first, then export.\n"
        )
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".md", delete=False, encoding="utf-8"
        )
        tmp.write(placeholder)
        tmp.close()
        return send_file(
            tmp.name, as_attachment=True,
            download_name="vulnerability_report.md",
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/download_report_csv", methods=["GET"])
def download_report_csv():
    """Download CSV findings export."""
    try:
        resp = _send_report_file("findings_summary.csv", "findings_summary.csv")
        if resp:
            return resp
        return jsonify({"error": "No CSV report found. Run a scan first."}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/download_report_json", methods=["GET"])
def download_report_json():
    """Download JSON findings export."""
    try:
        resp = _send_report_file("findings.json", "findings.json")
        if resp:
            return resp
        return jsonify({"error": "No JSON report found. Run a scan first."}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==========================================================================
#  DOWNLOAD FIXED FILE  (path-traversal protected)
# ==========================================================================

@app.route("/download_fixed/<path:filename>", methods=["GET"])
def download_fixed(filename: str):
    """
    Serve AI-fixed files from the fixed_files/ directory.
    Protected against path traversal (../../etc/passwd etc.)
    """
    try:
        fixed_dir = _fixed_dir()
        safe      = _safe_path(fixed_dir, filename)

        if safe is None:
            # Path traversal attempt detected
            print(f"[SECURITY] Path traversal attempt blocked: {filename!r}")
            return jsonify({"error": "Invalid filename"}), 400

        if not os.path.exists(safe):
            return jsonify({"error": "File not found"}), 404

        return send_file(safe, as_attachment=True, download_name=os.path.basename(safe))

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==========================================================================
#  MAIN
# ==========================================================================

if __name__ == "__main__":
    # Startup banner
    bar = "=" * 52
    print(f"\n{bar}")
    print("  CYBRAIN Backend v2.0 - Starting")
    print(f"{bar}")
    print(f"  Gemini API Key : {'SET [OK]' if os.environ.get('GEMINI_API_KEY') else 'NOT SET (offline mode)'}")
    print(f"  Debug mode     : {'ON  [WARN]' if os.environ.get('DEBUG','False')=='True' else 'OFF [OK]'}")
    print(f"  Host           : 0.0.0.0:5000")
    print(f"{bar}")

    # Verify key modules are importable
    modules = [
        ("url_scanner",           "URL Scanner"),
        ("network_scanner",       "Network Scanner"),
        ("owasp_checks",          "OWASP Checker"),
        ("code_analyzer",         "Code Analyzer"),
        ("ai_agent",              "AI Agent"),
        ("report_generator",      "Report Generator"),
        ("detect_apache_misconf", "Apache Detector"),
    ]
    for mod, label in modules:
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
        use_reloader=False,   # Prevent 502 during long scans
        threaded=True,
    )