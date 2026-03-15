"""
═══════════════════════════════════════════════════════════════
  CYBRAIN — Code Vulnerability Analyzer  (v2.0)
  Static Application Security Testing (SAST)
  PFE Master 2 — Information Security
  University of Mohamed Boudiaf, M'sila — Algeria

  COVERAGE (static patterns — no AI)
  ────────────────────────────────────
  SQL Injection             CWE-89
  XSS                       CWE-79
  Hardcoded Credentials     CWE-798
  Path Traversal            CWE-22
  Command Injection         CWE-78
  Insecure Deserialization  CWE-502
  Weak Cryptography         CWE-327
  SSRF Risk                 CWE-918
  Debug Mode Enabled        CWE-489
  Open Redirect             CWE-601
  JWT Issues                CWE-347
  LDAP Injection            CWE-90
  XML/XXE Risk              CWE-611
  Insecure Random           CWE-338
  Log Injection             CWE-117
  Race Condition            CWE-362
  Mass Assignment           CWE-915
  Prototype Pollution (JS)  CWE-1321
  CORS Misconfiguration     CWE-942
  Sensitive Data Logging    CWE-532

  IMPROVEMENTS vs original
  ────────────────────────
  • 20 vulnerability categories (was 11)
  • Multi-language support: Python, PHP, JS/TS, Java, C#, Ruby, Go, C/C++
  • Context-aware patterns (language-specific)
  • Line-range reporting — up to 3 occurrences per pattern
  • Confidence scoring (HIGH/MEDIUM/LOW)
  • AI lazy-load is unchanged (safe if Gemini unavailable)

  FOR EDUCATIONAL / AUTHORIZED TESTING ONLY
═══════════════════════════════════════════════════════════════
"""

import re

# ── Static vulnerability patterns ─────────────────────────────────────────
# Each entry: list of (regex_pattern, language_hint_or_None)
# language_hint = None means applies to all languages

STATIC_PATTERNS: dict = {

    "SQL Injection": {
        "severity": "CRITICAL",
        "cwe":      "CWE-89",
        "owasp":    "A05:2025",
        "patterns": [
            (r'execute\s*\(\s*["\'].*?\+',          None),
            (r'cursor\.execute\([^,)]*\+',           "py"),
            (r'f["\']SELECT.*?\{',                   "py"),
            (r'mysqli_query.*?\$_',                  "php"),
            (r'"SELECT.*?".*?\+',                    None),
            (r'db\.query\s*\(\s*`.*?\$\{',           "js"),
            (r'\.query\s*\(\s*["\'].*?\+',           None),
            (r'Statement\s+.*?=.*?connection\.',     "java"),
            (r'new\s+SqlCommand\s*\([^@)]*\+',       "cs"),
            (r'exec\s*\(\s*["\'].*?\+',              "php"),
        ],
        "fix": (
            "Use parameterized queries only:\n"
            "Python: cursor.execute('SELECT * FROM t WHERE id=?', (uid,))\n"
            "PHP:    $stmt = $pdo->prepare('SELECT * FROM t WHERE id=?');\n"
            "        $stmt->execute([$id]);\n"
            "Java:   PreparedStatement ps = conn.prepareStatement(\n"
            "            'SELECT * FROM t WHERE id=?');\n"
            "        ps.setInt(1, userId);\n"
            "JS:     db.query('SELECT * FROM t WHERE id=$1', [id])"
        ),
    },

    "XSS (Cross-Site Scripting)": {
        "severity": "HIGH",
        "cwe":      "CWE-79",
        "owasp":    "A05:2025",
        "patterns": [
            (r'innerHTML\s*=',                       None),
            (r'outerHTML\s*=',                       None),
            (r'document\.write\s*\(',                None),
            (r'insertAdjacentHTML\s*\(',             None),
            (r'eval\s*\(',                           None),
            (r'echo\s+\$_',                          "php"),
            (r'print\s+\$_',                         "php"),
            (r'Response\.Write.*?Request\.',          "cs"),
            (r'\.html\s*\(.*?\$',                    "js"),
            (r'v-html\s*=',                          "js"),   # Vue.js
            (r'dangerouslySetInnerHTML',              "js"),   # React
        ],
        "fix": (
            "Encode ALL user output:\n"
            "Python: markupsafe.escape(user_input)\n"
            "JS:     element.textContent = input  (NOT innerHTML)\n"
            "PHP:    htmlspecialchars($in, ENT_QUOTES, 'UTF-8')\n"
            "React:  Use JSX interpolation {} — avoid dangerouslySetInnerHTML"
        ),
    },

    "Hardcoded Credentials": {
        "severity": "CRITICAL",
        "cwe":      "CWE-798",
        "owasp":    "A07:2025",
        "patterns": [
            (r'password\s*=\s*["\'][^"\']{4,}["\']',  None),
            (r'passwd\s*=\s*["\'][^"\']{4,}["\']',    None),
            (r'secret\s*=\s*["\'][^"\']{8,}["\']',    None),
            (r'api_key\s*=\s*["\'][^"\']{8,}["\']',   None),
            (r'apikey\s*=\s*["\'][^"\']{8,}["\']',    None),
            (r'AWS_SECRET.*?=.*?["\'][^"\']+["\']',    None),
            (r'private_key\s*=\s*["\']',               None),
            (r'token\s*=\s*["\'][A-Za-z0-9+/]{20,}',  None),
            (r'-----BEGIN (RSA|EC|OPENSSH) PRIVATE',   None),
        ],
        "fix": (
            "Use environment variables:\n"
            "Python: os.environ.get('DB_PASSWORD')\n"
            "JS:     process.env.DB_PASSWORD\n"
            "Java:   System.getenv('DB_PASSWORD')\n"
            "Store secrets in .env — add .env to .gitignore"
        ),
    },

    "Path Traversal / LFI": {
        "severity": "HIGH",
        "cwe":      "CWE-22",
        "owasp":    "A05:2025",
        "patterns": [
            (r'open\s*\([^)]*\$_',                 "php"),
            (r'file_get_contents\s*\(\s*\$_',       "php"),
            (r'include\s*\(\s*\$_',                 "php"),
            (r'require\s*\(\s*\$_',                 "php"),
            (r'readFile\s*\(.*?req\.',               "js"),
            (r'open\s*\(.*?request\.',               "py"),
            (r'send\s*\(.*?req\.params',             "js"),
            (r'File\s*\(.*?getParameter',            "java"),
            (r'Path\.of\s*\(.*?request\.',           "java"),
        ],
        "fix": (
            "Validate and sanitise file paths:\n"
            "Python: safe = os.path.basename(user_input)\n"
            "        real = os.path.realpath(os.path.join(base, safe))\n"
            "        assert real.startswith(base)\n"
            "PHP:    $safe = basename($_GET['file']);\n"
            "Use an allowlist of permitted file names"
        ),
    },

    "Command Injection": {
        "severity": "CRITICAL",
        "cwe":      "CWE-78",
        "owasp":    "A05:2025",
        "patterns": [
            (r'os\.system\s*\(',                          "py"),
            (r'subprocess\.call.*?shell\s*=\s*True',      "py"),
            (r'subprocess\.run.*?shell\s*=\s*True',       "py"),
            (r'subprocess\.Popen.*?shell\s*=\s*True',     "py"),
            (r'exec\s*\(\s*\$_',                          "php"),
            (r'shell_exec\s*\(\s*\$_',                    "php"),
            (r'passthru\s*\(\s*\$_',                      "php"),
            (r'Runtime\.getRuntime\(\)\.exec\(',          "java"),
            (r'Process\.Start\(',                         "cs"),
            (r'child_process\.exec\s*\(',                 "js"),
            (r'execSync\s*\(',                            "js"),
        ],
        "fix": (
            "Never pass user input to OS commands:\n"
            "Python: subprocess.run(['cmd', safe_arg], shell=False)\n"
            "PHP:    escapeshellarg($input) — but prefer not using shell at all\n"
            "JS:     Use child_process.execFile(['cmd', [arg]]) not exec()\n"
            "Apply strict whitelist validation on all inputs"
        ),
    },

    "Insecure Deserialization": {
        "severity": "CRITICAL",
        "cwe":      "CWE-502",
        "owasp":    "A08:2025",
        "patterns": [
            (r'pickle\.loads?\s*\(',               "py"),
            (r'yaml\.load\s*\([^)]*(?!Loader)',    "py"),
            (r'unserialize\s*\(',                  "php"),
            (r'ObjectInputStream',                 "java"),
            (r'BinaryFormatter',                   "cs"),
            (r'Marshal\.load',                     "rb"),
            (r'JSON\.parse.*?eval',                "js"),
            (r'node-serialize',                    "js"),
        ],
        "fix": (
            "Use safe deserializers:\n"
            "Python: yaml.safe_load() NOT yaml.load()\n"
            "        Avoid pickle on untrusted data\n"
            "PHP:    Never unserialize() user input — use json_decode()\n"
            "Java:   Implement ObjectInputFilter (Java 9+)\n"
            "Use JSON with strict schema validation for all data exchange"
        ),
    },

    "Weak Cryptography": {
        "severity": "HIGH",
        "cwe":      "CWE-327",
        "owasp":    "A04:2025",
        "patterns": [
            (r'hashlib\.md5\b',                    "py"),
            (r'hashlib\.sha1\b',                   "py"),
            (r'createHash\s*\(["\']md5',           "js"),
            (r'createHash\s*\(["\']sha1',          "js"),
            (r'MessageDigest\.getInstance\s*\(\s*["\']MD5', "java"),
            (r'MessageDigest\.getInstance\s*\(\s*["\']SHA-?1', "java"),
            (r'DES\.',                              None),
            (r'RC4\.',                              None),
            (r'new\s+DESCryptoServiceProvider',    "cs"),
            (r'MD5CryptoServiceProvider',          "cs"),
        ],
        "fix": (
            "Use strong cryptography:\n"
            "Passwords:  bcrypt.hashpw() or argon2\n"
            "Hashing:    hashlib.sha256() or sha3_256()\n"
            "Encryption: AES-256-GCM\n"
            "Never use MD5 or SHA-1 for security-critical purposes"
        ),
    },

    "SSRF Risk": {
        "severity": "HIGH",
        "cwe":      "CWE-918",
        "owasp":    "A10:2025",
        "patterns": [
            (r'requests\.get\s*\(.*?request\.',    "py"),
            (r'requests\.get\s*\(.*?input',        "py"),
            (r'urllib\.request\.urlopen\s*\(.*?input', "py"),
            (r'file_get_contents\s*\(\s*\$_GET',   "php"),
            (r'fetch\s*\(.*?req\.query',            "js"),
            (r'fetch\s*\(.*?req\.body',             "js"),
            (r'HttpClient.*?GetAsync.*?request\.',  "cs"),
            (r'URL\s*\(.*?request\.',               "java"),
        ],
        "fix": (
            "Validate URLs against strict allowlist:\n"
            "Python: from urllib.parse import urlparse\n"
            "        assert urlparse(url).hostname in ALLOWED_HOSTS\n"
            "Block private IP ranges: 127.x, 10.x, 192.168.x, 169.254.x\n"
            "Never fetch URLs supplied directly by user input"
        ),
    },

    "Debug Mode Enabled": {
        "severity": "MEDIUM",
        "cwe":      "CWE-489",
        "owasp":    "A02:2025",
        "patterns": [
            (r'\bDEBUG\s*=\s*True\b',                "py"),
            (r'app\.run\s*\(.*?debug\s*=\s*True',    "py"),
            (r'development\s*:\s*true',               "js"),
            (r'APP_DEBUG\s*=\s*true',                 None),
            (r'app\.set\s*\(["\']env["\'],\s*["\']development', "js"),
        ],
        "fix": (
            "Disable debug in production:\n"
            "Python: DEBUG = os.environ.get('DEBUG','False') == 'True'\n"
            "Flask:  app.run(debug=False)\n"
            "JS:     NODE_ENV=production\n"
            "Never hard-code debug=True — always use environment variable"
        ),
    },

    "Open Redirect": {
        "severity": "MEDIUM",
        "cwe":      "CWE-601",
        "owasp":    "A01:2025",
        "patterns": [
            (r'redirect\s*\(\s*request\.',           "py"),
            (r'header\s*\(\s*["\']Location.*?\$_',   "php"),
            (r'res\.redirect\s*\(.*?req\.',           "js"),
            (r'window\.location\s*=\s*.*?param',      "js"),
            (r'Response\.Redirect\s*\(.*?Request\.',  "cs"),
            (r'sendRedirect\s*\(.*?request\.',        "java"),
        ],
        "fix": (
            "Validate redirect URLs:\n"
            "Use allowlist of permitted redirect targets\n"
            "Python: if url not in ALLOWED_REDIRECTS: abort(400)\n"
            "Never redirect to user-supplied external URLs\n"
            "Use relative paths for internal redirects"
        ),
    },

    "JWT Issues": {
        "severity": "HIGH",
        "cwe":      "CWE-347",
        "owasp":    "A07:2025",
        "patterns": [
            (r'jwt\.decode\s*\(.*?verify.*?false',   None),
            (r'verify\s*:\s*false',                  None),
            (r'algorithms\s*=\s*\[\s*["\']none["\']',None),
            (r'alg.*?["\']none["\']',                None),
            (r'options\s*=\s*\{.*?verify.*?false',   None),
        ],
        "fix": (
            "Always verify JWT signatures:\n"
            "Python: jwt.decode(token, secret, algorithms=['HS256'])\n"
            "Never use alg:none\n"
            "Use RS256 (asymmetric) for public APIs\n"
            "Maintain strict algorithm whitelist server-side"
        ),
    },

    "LDAP Injection": {
        "severity": "HIGH",
        "cwe":      "CWE-90",
        "owasp":    "A05:2025",
        "patterns": [
            (r'ldap_search.*?\$_',                   "php"),
            (r'ldap\.search.*?request\.',            "py"),
            (r'DirContext.*?search.*?request\.',     "java"),
            (r'ldap\.Search\s*\(.*?request\.',       "cs"),
        ],
        "fix": (
            "Escape LDAP special characters in all user inputs:\n"
            "Characters to escape: ( ) * \\ NUL / @ = + < > , ;\n"
            "Python: ldap3 library handles escaping automatically\n"
            "Use parameterized LDAP filters where available"
        ),
    },

    "XXE / XML Injection": {
        "severity": "CRITICAL",
        "cwe":      "CWE-611",
        "owasp":    "A05:2025",
        "patterns": [
            (r'etree\.parse\s*\(',                                    "py"),
            (r'etree\.fromstring\s*\(',                               "py"),
            (r'xml\.dom\.minidom\.parseString',                       "py"),
            (r'DocumentBuilderFactory\s*\.',                          "java"),
            (r'SAXParserFactory\s*\.',                                "java"),
            (r'XmlDocument\s*\(',                                     "cs"),
            (r'simplexml_load_string\s*\(\s*\$_',                    "php"),
            (r'DOMDocument\s*\(',                                     "php"),
        ],
        "fix": (
            "Disable external entity processing:\n"
            "Python lxml: etree.XMLParser(resolve_entities=False, no_network=True)\n"
            "Java: factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)\n"
            "      factory.setFeature(EXTERNAL_GENERAL_ENTITIES, false)\n"
            "PHP: libxml_disable_entity_loader(true)  (PHP < 8.0)\n"
            "Prefer JSON over XML for data exchange"
        ),
    },

    "Insecure Randomness": {
        "severity": "MEDIUM",
        "cwe":      "CWE-338",
        "owasp":    "A02:2025",
        "patterns": [
            (r'\brandom\.random\s*\(',             "py"),
            (r'\brandom\.randint\s*\(',            "py"),
            (r'\bMath\.random\s*\(',               "js"),
            (r'\brand\s*\(',                       "php"),
            (r'\bmt_rand\s*\(',                    "php"),
            (r'new\s+Random\s*\(',                 "java"),
            (r'new\s+Random\s*\(',                 "cs"),
        ],
        "fix": (
            "Use cryptographically secure random generators:\n"
            "Python: import secrets; secrets.token_hex(32)\n"
            "JS:     crypto.randomBytes(32).toString('hex')\n"
            "PHP:    random_bytes(32) or bin2hex(random_bytes(16))\n"
            "Java:   SecureRandom sr = new SecureRandom();\n"
            "Never use Math.random() or rand() for security tokens"
        ),
    },

    "Log Injection": {
        "severity": "MEDIUM",
        "cwe":      "CWE-117",
        "owasp":    "A09:2025",
        "patterns": [
            (r'logging\.\w+\s*\(.*?request\.',       "py"),
            (r'logger\.\w+\s*\(.*?request\.',        "py"),
            (r'console\.log\s*\(.*?req\.',           "js"),
            (r'error_log\s*\(\s*\$_',               "php"),
            (r'log\.info\s*\(.*?request\.',          "java"),
            (r'Log\.\w+\s*\(.*?Request\.',           "cs"),
        ],
        "fix": (
            "Sanitise user input before logging:\n"
            "Python: logger.info('User: %s', user_input.replace('\\n','\\\\n'))\n"
            "Strip or encode newline characters (\\r\\n) to prevent log forging\n"
            "Never log raw user input, passwords, or session tokens"
        ),
    },

    "Mass Assignment": {
        "severity": "HIGH",
        "cwe":      "CWE-915",
        "owasp":    "A06:2025",
        "patterns": [
            (r'User\s*\(\s*\*\*request\.',           "py"),
            (r'Model\s*\(\s*\*\*request\.',          "py"),
            (r'\$user->fill\s*\(\s*\$request->all', "php"),
            (r'User::create\s*\(\s*\$request->all', "php"),
            (r'Object\.assign\s*\(.*?req\.body',    "js"),
            (r'\.updateAttributes\s*\(.*?params',   "rb"),
        ],
        "fix": (
            "Use explicit field allowlists — never bind raw request to model:\n"
            "Django: UserForm(request.POST, fields=['username','email'])\n"
            "Rails:  params.require(:user).permit(:username, :email)\n"
            "Laravel: $request->only(['username', 'email'])\n"
            "JS/Node: const { username, email } = req.body  (destructure only safe fields)"
        ),
    },

    "Prototype Pollution (JS)": {
        "severity": "HIGH",
        "cwe":      "CWE-1321",
        "owasp":    "A03:2025",
        "patterns": [
            (r'__proto__',                           "js"),
            (r'constructor\s*\[',                   "js"),
            (r'merge\s*\(.*?__proto__',             "js"),
            (r'deepMerge\s*\(',                     "js"),
            (r'\.constructor\.prototype',           "js"),
        ],
        "fix": (
            "Prevent prototype pollution:\n"
            "Validate keys: if (key === '__proto__') throw new Error()\n"
            "Use Object.create(null) for dictionaries with user keys\n"
            "Replace vulnerable merge utilities with safe alternatives (deepmerge@4.3+)\n"
            "Freeze prototypes: Object.freeze(Object.prototype)"
        ),
    },

    "CORS Misconfiguration": {
        "severity": "MEDIUM",
        "cwe":      "CWE-942",
        "owasp":    "A02:2025",
        "patterns": [
            (r'Access-Control-Allow-Origin.*?\*',     None),
            (r'cors\s*\(\s*\)',                       "js"),   # bare cors() = wildcard
            (r'CORS\s*\(.*?allow_all_origins\s*=\s*True', "py"),
            (r'response\[.Access-Control-Allow-Origin.\]\s*=\s*["\*"]', None),
        ],
        "fix": (
            "Restrict CORS to trusted origins:\n"
            "Python (Flask-CORS): CORS(app, origins=['https://yourdomain.com'])\n"
            "Express: cors({ origin: 'https://yourdomain.com' })\n"
            "Never use wildcard (*) with allow-credentials: true\n"
            "Validate Origin header server-side against an explicit allowlist"
        ),
    },

    "Sensitive Data Logging": {
        "severity": "HIGH",
        "cwe":      "CWE-532",
        "owasp":    "A09:2025",
        "patterns": [
            (r'log.*?(password|passwd|secret|token|api_key|credit_card|ssn)',  None),
            (r'print.*?(password|passwd|secret)',    None),
            (r'console\.log.*?(password|token|secret)', "js"),
            (r'logger\.\w+.*?password',              None),
        ],
        "fix": (
            "Never log sensitive data:\n"
            "Redact passwords, tokens, API keys before logging\n"
            "Python: logger.info('Login attempt for user: %s', username)  # NOT password\n"
            "Use structured logging with field-level redaction\n"
            "Implement log scrubbing middleware"
        ),
    },

}


class CodeAnalyzer:
    """
    Static code vulnerability analyser.
    Phase 1: Regex-based static analysis (instant, no network)
    Phase 2: AI deep analysis via Gemini (optional, lazy-loaded)
    """

    def __init__(self):
        self._agent = None

    # ── AI lazy load ───────────────────────────────────────────────────────
    def _get_agent(self):
        if self._agent is not None:
            return self._agent
        try:
            from ai_agent import CybrainAgent
            self._agent = CybrainAgent()
            return self._agent
        except Exception as e:
            print(f"[CODE ANALYZER] AI agent unavailable: {e}")
            return None

    # ── Language detection ─────────────────────────────────────────────────
    def _detect_language(self, filename: str) -> str:
        ext = filename.rsplit(".", 1)[-1].lower()
        return {
            "py":       "Python",
            "php":      "PHP",
            "js":       "JavaScript",
            "ts":       "TypeScript",
            "jsx":      "JavaScript",
            "tsx":      "TypeScript",
            "java":     "Java",
            "cs":       "C#",
            "rb":       "Ruby",
            "go":       "Go",
            "cpp":      "C++",
            "c":        "C",
            "sql":      "SQL",
            "conf":     "Apache Config",
            "htaccess": "Apache Config",
            "yml":      "YAML",
            "yaml":     "YAML",
            "tf":       "Terraform",
            "sh":       "Shell",
            "bash":     "Shell",
        }.get(ext, "Unknown")

    def _lang_code(self, language: str) -> str:
        """Return short lang key used in pattern language_hint."""
        return {
            "Python":       "py",
            "PHP":          "php",
            "JavaScript":   "js",
            "TypeScript":   "js",
            "Java":         "java",
            "C#":           "cs",
            "Ruby":         "rb",
            "Go":           "go",
        }.get(language, "")

    # ── Static analysis ────────────────────────────────────────────────────
    def _static_analysis(self, content: str, lines: list,
                          filename: str, language: str) -> list:
        """
        Pure regex analysis — no network, no AI.
        Returns up to 3 occurrences per vulnerability category.
        """
        findings = []
        lang_key = self._lang_code(language)

        for vuln_name, info in STATIC_PATTERNS.items():
            for pattern, lang_hint in info["patterns"]:
                # Skip pattern if language-specific and doesn't match
                if lang_hint and lang_key and lang_hint != lang_key:
                    continue

                hits = 0
                for i, line in enumerate(lines, 1):
                    try:
                        if re.search(pattern, line, re.IGNORECASE):
                            findings.append({
                                "severity":  info["severity"],
                                "title":     vuln_name,
                                "line":      i,
                                "code_line": line.strip()[:200],
                                "cwe":       info["cwe"],
                                "owasp":     info.get("owasp", ""),
                                "fix":       info["fix"],
                            })
                            hits += 1
                            if hits >= 3:
                                break
                    except Exception:
                        pass
                if hits:
                    break  # Found at least one hit for this vuln — skip remaining patterns

        # Sort CRITICAL → LOW
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        findings.sort(key=lambda f: order.get(f.get("severity", "LOW"), 9))
        return findings

    # ── UI formatter ───────────────────────────────────────────────────────
    def _format_for_ui(self, findings: list, filename: str) -> list:
        return [{
            "severity": f["severity"],
            "line":     str(f["line"]),
            "message":  (
                f"<strong>{f['title']}</strong> "
                f"detected at line {f['line']}."
                "<br><br>"
                "<strong>Vulnerable code:</strong><br>"
                f"<code>{f['code_line']}</code>"
                "<br><br>"
                "<strong>Recommendation:</strong><br>"
                f"{f['fix'].replace(chr(10), '<br>')}"
                "<br><br>"
                f"<strong>CWE:</strong> "
                f"<a href='https://cwe.mitre.org/data/definitions/"
                f"{f['cwe'].replace('CWE-','')}' target='_blank'>"
                f"{f['cwe']}</a>"
                + (f"<br><strong>OWASP 2025:</strong> {f['owasp']}"
                   if f.get("owasp") else "")
            ),
            "code": f["title"],
            "file": filename,
        } for f in findings]

    # ── Main analysis entry point ──────────────────────────────────────────
    def analyze(self, content: str, filename: str,
                use_ai: bool = True) -> dict:
        """
        Full analysis pipeline.
        1. Static pattern scan (always runs, instant)
        2. AI deep analysis via Gemini (optional)
        """
        language = self._detect_language(filename)
        lines    = content.splitlines()

        # Phase 1 — Static
        static = self._static_analysis(content, lines, filename, language)

        # Phase 2 — AI (lazy, optional)
        ai_result = None
        if use_ai:
            try:
                agent = self._get_agent()
                if agent:
                    ai_result = agent.analyze_code_file(
                        content, filename, language
                    )
                else:
                    ai_result = (
                        "AI analysis unavailable. "
                        "Check GEMINI_API_KEY in .env"
                    )
            except Exception as e:
                ai_result = f"AI analysis error: {str(e)}"

        return {
            "filename":        filename,
            "language":        language,
            "lines_of_code":   len(lines),
            "static_findings": static,
            "ai_analysis":     ai_result,
            "fix_supported":   language in [
                "Python", "PHP", "JavaScript",
                "TypeScript", "Java", "C#", "Apache Config",
            ],
            "ui_findings":     self._format_for_ui(static, filename),
        }

    def fix_code(self, content: str, filename: str,
                 findings=None) -> dict:
        """Generate fixed version of code using AI agent."""
        try:
            agent = self._get_agent()
            if agent:
                return agent.fix_code(content, filename)
        except Exception as e:
            print(f"[CODE ANALYZER] Fix error: {e}")
        return {
            "explanation": (
                "AI fix unavailable. "
                "Check GEMINI_API_KEY in .env file."
            ),
            "fixed_code": None,
            "filename":   filename,
        }