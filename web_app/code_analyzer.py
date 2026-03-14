"""
CYBRAIN — Code File Vulnerability Analyzer
Supports: Python, PHP, JavaScript, Java, SQL, C#, Go
Static analysis + AI deep analysis
"""

import re
import os
from ai_agent import CybrainAgent


# Static analysis patterns (no AI needed)
STATIC_PATTERNS = {
    "SQL Injection": {
        "severity": "CRITICAL",
        "cwe": "CWE-89",
        "patterns": [
            r'execute\s*\(\s*["\'].*?\+',
            r'query\s*\(\s*["\'].*?%s',
            r'SELECT.*?\+\s*\$',
            r'\"SELECT.*?\".*?\+',
            r'cursor\.execute\([^,)]*\+',
            r'f["\']SELECT.*?\{',
            r'mysqli_query.*?\$_',
            r'mysql_query.*?\$_',
        ],
        "fix": "Use parameterized queries",
    },
    "XSS": {
        "severity": "HIGH",
        "cwe": "CWE-79",
        "patterns": [
            r'innerHTML\s*=',
            r'document\.write\s*\(',
            r'eval\s*\(',
            r'\.html\s*\(.*?\$',
            r'echo\s+\$_',
            r'print\s+\$_',
            r'Response\.Write.*?Request\.',
        ],
        "fix": "Encode output / use textContent",
    },
    "Hardcoded Credentials": {
        "severity": "CRITICAL",
        "cwe": "CWE-798",
        "patterns": [
            r'password\s*=\s*["\'][^"\']{4,}["\']',
            r'passwd\s*=\s*["\'][^"\']{4,}["\']',
            r'secret\s*=\s*["\'][^"\']{8,}["\']',
            r'api_key\s*=\s*["\'][^"\']{8,}["\']',
            r'token\s*=\s*["\'][^"\']{8,}["\']',
            r'AWS_SECRET.*?=.*?["\'][^"\']+["\']',
            r'private_key\s*=',
        ],
        "fix": "Use environment variables",
    },
    "Path Traversal": {
        "severity": "HIGH",
        "cwe": "CWE-22",
        "patterns": [
            r'open\s*\([^)]*\$_',
            r'file_get_contents\s*\(\s*\$_',
            r'include\s*\(\s*\$_',
            r'require\s*\(\s*\$_',
            r'readFile\s*\(.*?req\.',
            r'open\s*\(.*?request\.',
        ],
        "fix": "Validate and sanitize file paths",
    },
    "Command Injection": {
        "severity": "CRITICAL",
        "cwe": "CWE-78",
        "patterns": [
            r'os\.system\s*\(',
            r'subprocess\.call.*?shell=True',
            r'exec\s*\(\s*\$_',
            r'shell_exec\s*\(\s*\$_',
            r'popen\s*\(.*?\$_',
            r'Runtime\.exec\s*\(',
        ],
        "fix": "Use safe APIs, avoid shell=True",
    },
    "Insecure Deserialization": {
        "severity": "CRITICAL",
        "cwe": "CWE-502",
        "patterns": [
            r'pickle\.loads?\s*\(',
            r'yaml\.load\s*\([^)]*Loader',
            r'unserialize\s*\(',
            r'ObjectInputStream',
            r'BinaryFormatter',
        ],
        "fix": "Use safe deserializers with type checking",
    },
    "Weak Cryptography": {
        "severity": "HIGH",
        "cwe": "CWE-327",
        "patterns": [
            r'md5\s*\(',
            r'sha1\s*\(',
            r'DES\.',
            r'RC4\.',
            r'hashlib\.md5',
            r'hashlib\.sha1',
            r'createHash\s*\(["\']md5',
            r'createHash\s*\(["\']sha1',
        ],
        "fix": "Use SHA-256/bcrypt/argon2",
    },
    "SSRF Risk": {
        "severity": "HIGH",
        "cwe": "CWE-918",
        "patterns": [
            r'requests\.get\s*\(.*?request\.',
            r'urllib\.request\.urlopen\s*\(.*?input',
            r'file_get_contents\s*\(\s*\$_GET',
            r'curl_setopt.*?CURLOPT_URL.*?\$_',
            r'fetch\s*\(.*?req\.query',
        ],
        "fix": "Validate URLs against allowlist",
    },
    "Missing Auth Check": {
        "severity": "HIGH",
        "cwe": "CWE-306",
        "patterns": [
            r'@app\.route.*?\ndef\s+\w+\s*\([^)]*\)\s*:\s*\n\s*(?!.*login_required)',
            r'router\.\w+\s*\([^)]+\)\s*\{(?!.*auth)',
        ],
        "fix": "Add authentication middleware",
    },
    "Debug Mode": {
        "severity": "MEDIUM",
        "cwe": "CWE-489",
        "patterns": [
            r'DEBUG\s*=\s*True',
            r'app\.run\s*\(.*?debug\s*=\s*True',
            r'development\s*:\s*true',
            r'verbose\s*=\s*True',
        ],
        "fix": "Set DEBUG=False in production",
    },
}


class CodeAnalyzer:

    def __init__(self, api_key=None):
        self.agent = CybrainAgent(api_key)

    def analyze(self, content, filename,
                use_ai=True):
        """
        Full code analysis:
        1. Static pattern matching (instant)
        2. AI deep analysis (if API key available)
        """
        language = self._detect_language(filename)
        lines    = content.splitlines()

        # Static analysis
        static_findings = self._static_analysis(
            content, lines, filename
        )

        result = {
            "filename":       filename,
            "language":       language,
            "lines_of_code":  len(lines),
            "static_findings":static_findings,
            "ai_analysis":    None,
            "can_fix":        True,
            "fix_supported":  language in [
                "Python", "PHP", "JavaScript",
                "TypeScript", "Java", "Apache Config", "Unknown"
            ],
        }

        # AI analysis
        if use_ai:
            result["ai_analysis"] = (
                self.agent.analyze_code_file(
                    content, filename, language
                )
            )

        # Format for UI
        result["ui_findings"] = self._format_for_ui(
            static_findings, filename
        )

        return result

    def _detect_language(self, filename):
        ext = filename.split(".")[-1].lower()
        return {
            "py":    "Python",
            "php":   "PHP",
            "js":    "JavaScript",
            "ts":    "TypeScript",
            "jsx":   "JavaScript (React)",
            "tsx":   "TypeScript (React)",
            "java":  "Java",
            "cs":    "C#",
            "rb":    "Ruby",
            "go":    "Go",
            "cpp":   "C++",
            "c":     "C",
            "sql":   "SQL",
            "conf":  "Apache Config",
            "htaccess": "Apache Config",
        }.get(ext, "Unknown")

    def _static_analysis(self, content, lines,
                          filename):
        findings = []
        for vuln_name, info in STATIC_PATTERNS.items():
            for pattern in info["patterns"]:
                for i, line in enumerate(lines, 1):
                    if re.search(
                        pattern, line,
                        re.IGNORECASE
                    ):
                        findings.append({
                            "severity": info["severity"],
                            "title":    vuln_name,
                            "line":     i,
                            "code_line":line.strip(),
                            "cwe":      info["cwe"],
                            "fix":      info["fix"],
                            "pattern":  pattern,
                        })
                        break  # One per pattern

        # Sort by severity
        order = {
            "CRITICAL":0,"HIGH":1,
            "MEDIUM":2,"LOW":3
        }
        findings.sort(
            key=lambda f: order.get(
                f["severity"], 9
            )
        )
        return findings

    def _format_for_ui(self, findings, filename):
        ui_results = []
        for f in findings:
            ui_results.append({
                "severity": f["severity"],
                "line":     str(f["line"]),
                "message":  (
                    f"{f['title']} detected at line "
                    f"{f['line']}.\n\n"
                    f"<strong>Vulnerable code:</strong>"
                    f"<br><code>{f['code_line'][:200]}</code>"
                    f"\n\n<strong>Recommendation:</strong>"
                    f"<br>{f['fix']}"
                    f"\n\n<strong>CWE:</strong> {f['cwe']}"
                ),
                "code":     f["title"],
                "file":     filename,
            })
        return ui_results

    def fix_code(self, content, filename,
                 findings=None):
        """Generate fixed version of the code."""
        return self.agent.fix_code(
            code_content=content,
            filename=filename,
        )
