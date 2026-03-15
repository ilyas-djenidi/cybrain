"""
CYBRAIN — Code File Vulnerability Analyzer
Static analysis + AI deep analysis
"""

import re
from ai_agent import CybrainAgent

STATIC_PATTERNS = {
    "SQL Injection": {
        "severity": "CRITICAL",
        "cwe": "CWE-89",
        "patterns": [
            r'execute\s*\(\s*["\'].*?\+',
            r'cursor\.execute\([^,)]*\+',
            r'f["\']SELECT.*?\{',
            r'mysqli_query.*?\$_',
            r'"SELECT.*?".*?\+',
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
            r'echo\s+\$_',
        ],
        "fix": "Encode output before rendering",
    },
    "Hardcoded Credentials": {
        "severity": "CRITICAL",
        "cwe": "CWE-798",
        "patterns": [
            r'password\s*=\s*["\'][^"\']{4,}["\']',
            r'secret\s*=\s*["\'][^"\']{8,}["\']',
            r'api_key\s*=\s*["\'][^"\']{8,}["\']',
        ],
        "fix": "Use environment variables",
    },
    "Path Traversal": {
        "severity": "HIGH",
        "cwe": "CWE-22",
        "patterns": [
            r'open\s*\([^)]*\$_',
            r'file_get_contents\s*\(\s*\$_',
            r'readFile\s*\(.*?req\.',
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
        ],
        "fix": "Never pass user input to shell commands",
    },
    "Weak Cryptography": {
        "severity": "HIGH",
        "cwe": "CWE-327",
        "patterns": [
            r'hashlib\.md5',
            r'hashlib\.sha1',
            r'createHash\s*\(["\']md5',
        ],
        "fix": "Use SHA-256 or bcrypt",
    },
    "Debug Mode": {
        "severity": "MEDIUM",
        "cwe": "CWE-489",
        "patterns": [
            r'DEBUG\s*=\s*True',
            r'app\.run\s*\(.*?debug\s*=\s*True',
        ],
        "fix": "Set DEBUG=False in production",
    },
}


class CodeAnalyzer:

    def __init__(self):
        self.agent = CybrainAgent()

    def analyze(self, content, filename, use_ai=True):
        language = self._detect_language(filename)
        lines    = content.splitlines()
        static   = self._static_analysis(
            content, lines, filename
        )
        ai_result = None
        if use_ai:
            try:
                ai_result = self.agent.analyze_code_file(
                    content, filename, language
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
                "TypeScript", "Java", "Apache Config"
            ],
            "ui_findings": self._format_for_ui(
                static, filename
            ),
        }

    def _detect_language(self, filename):
        ext = filename.split(".")[-1].lower()
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
        }.get(ext, "Unknown")

    def _static_analysis(self, content, lines, filename):
        findings = []
        for vuln_name, info in STATIC_PATTERNS.items():
            for pattern in info["patterns"]:
                for i, line in enumerate(lines, 1):
                    if re.search(
                        pattern, line, re.IGNORECASE
                    ):
                        findings.append({
                            "severity": info["severity"],
                            "title":    vuln_name,
                            "line":     i,
                            "code_line":line.strip()[:200],
                            "cwe":      info["cwe"],
                            "fix":      info["fix"],
                        })
                        break

        order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}
        findings.sort(
            key=lambda f: order.get(f["severity"], 9)
        )
        return findings

    def _format_for_ui(self, findings, filename):
        return [{
            "severity": f["severity"],
            "line":     str(f["line"]),
            "message":  (
                f"{f['title']} at line {f['line']}.\n\n"
                f"<strong>Vulnerable code:</strong>"
                f"<br><code>{f['code_line']}</code>"
                f"\n\n<strong>Recommendation:</strong>"
                f"<br>{f['fix']}"
                f"\n\n<strong>CWE:</strong> {f['cwe']}"
            ),
            "code": f["title"],
            "file": filename,
        } for f in findings]
