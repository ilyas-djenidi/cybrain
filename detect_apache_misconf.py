import re
import os
import sys

class ApacheMisconfigDetector:
    def __init__(self):
        self.misconfigurations = []
        self.files_scanned = 0

    def scan_content(self, content, source_name="Input Text"):
        """Scans a string of Apache configuration content."""
        self.files_scanned += 1
        lines = content.splitlines()
        self._check_ca8_proxypass_in_directory(source_name, content, lines)
        self._check_deprecated_directives(source_name, content, lines)
        self._check_syntax_errors(source_name, content, lines)
        self._check_module_dependencies(source_name, content, lines)
        self._check_security_hardening(source_name, content, lines)

    def scan_file(self, file_path):
        """Scans a single Apache configuration file for misconfigurations."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            self.scan_content(content, file_path)
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")

    def _check_ca8_proxypass_in_directory(self, file_path, content, lines):
        """
        Detects CA8: ProxyPass cannot occur within <Directory> section.
        """
        directory_block_regex = re.compile(r'<Directory\s+[^>]+>(.*?)</Directory>', re.DOTALL | re.IGNORECASE)
        proxypass_regex = re.compile(r'^\s*ProxyPass\s+', re.MULTILINE | re.IGNORECASE)

        for match in directory_block_regex.finditer(content):
            block_content = match.group(1)
            if proxypass_regex.search(block_content):
                # Find line number (approximate)
                start_index = match.start()
                line_num = content[:start_index].count('\n') + 1
                self.misconfigurations.append({
                    'file': file_path,
                    'line': line_num,
                    'code': 'CA8',
                    'severity': 'Error',
                    'message': 'ProxyPass directive cannot occur within <Directory> section.'
                })

    def _check_deprecated_directives(self, file_path, content, lines):
        """
        Detects deprecated directives in Apache 2.4 (Order, Allow, Deny).
        """
        deprecated_keywords = ['Order', 'Allow', 'Deny']
        
        for i, line in enumerate(lines):
            stripped_line = line.strip()
            if stripped_line.startswith('#'):
                continue
            
            for keyword in deprecated_keywords:
                # Basic check: starts with keyword followed by space
                if re.match(fr'^{keyword}\s+', stripped_line, re.IGNORECASE):
                    self.misconfigurations.append({
                        'file': file_path,
                        'line': i + 1,
                        'code': 'DEPRECATED',
                        'severity': 'Warning',
                        'message': f"Directive '{keyword}' is deprecated in Apache 2.4. Use 'Require' instead or ensure mod_access_compat is loaded."
                    })

    def _check_syntax_errors(self, file_path, content, lines):
        """
        Checks for basic syntax errors like unclosed tags.
        """
        open_tags = []
        tag_regex = re.compile(r'^\s*<(/?)(\w+)([^>]*)>', re.IGNORECASE)

        for i, line in enumerate(lines):
            if line.strip().startswith('#'):
                continue

            match = tag_regex.match(line)
            if match:
                is_close = match.group(1) == '/'
                tag_name = match.group(2)
                
                if not is_close:
                    if not line.strip().endswith('/>'): # Self-closing check (rare in Apache but possible in XML-like)
                         open_tags.append((tag_name, i + 1))
                else:
                    if not open_tags:
                        self.misconfigurations.append({
                            'file': file_path,
                            'line': i + 1,
                            'code': 'SYNTAX',
                            'severity': 'Error',
                            'message': f"Unexpected closing tag </{tag_name}>."
                        })
                    else:
                        last_open_tag, last_line = open_tags.pop()
                        if last_open_tag.lower() != tag_name.lower():
                            self.misconfigurations.append({
                                'file': file_path,
                                'line': i + 1,
                                'code': 'SYNTAX',
                                'severity': 'Error',
                                'message': f"Mismatched closing tag </{tag_name}>. Expected </{last_open_tag}> (opened line {last_line})."
                            })

        if open_tags:
            for tag_name, line_num in open_tags:
                 self.misconfigurations.append({
                    'file': file_path,
                    'line': line_num,
                    'code': 'SYNTAX',
                    'severity': 'Error',
                    'message': f"Unclosed tag <{tag_name}>."
                })

    def _check_security_hardening(self, file_path, content, lines):
        """
        Unified check for various hardening rules.
        """
        # Rule 1: Default credentials/AuthUserFile
        if re.search(r'^\s*AuthUserFile\s+.*htpasswd', content, re.MULTILINE | re.IGNORECASE):
            self._report(file_path, content, 'AuthUserFile', 'HARDENING', 'Warning', 
                         "AuthUserFile detected. Ensure it doesn't use default credentials or paths.")

        # Rule 2: Directory listing enabled
        if re.search(r'^\s*Options\s+.*Indexes', content, re.MULTILINE | re.IGNORECASE) and \
           not re.search(r'^\s*Options\s+.*-Indexes', content, re.MULTILINE | re.IGNORECASE):
            self._report(file_path, content, 'Options.*Indexes', 'HARDENING', 'High', 
                         "Directory listing (Indexes) is enabled. This can expose sensitive files.")

        # Rule 3: Server signature exposed
        if re.search(r'^\s*ServerSignature\s+On', content, re.MULTILINE | re.IGNORECASE) or \
           re.search(r'^\s*ServerTokens\s+(?!(Prod|Minimal))', content, re.MULTILINE | re.IGNORECASE):
            self._report(file_path, content, 'ServerSignature|ServerTokens', 'INFO_DISCLOSURE', 'Medium', 
                         "Server signature or detailed version tokens are enabled.")

        # Rule 4: SSL/TLS weak protocols
        weak_ssl = re.search(r'^\s*SSLProtocol\s+.*(SSLv2|SSLv3|TLSv1\.|TLSv1$)', content, re.MULTILINE | re.IGNORECASE)
        if weak_ssl:
            self._report(file_path, content, 'SSLProtocol', 'SSL_WEAK', 'High', 
                         "Weak SSL/TLS protocols (SSLv2, SSLv3, TLSv1.0, TLSv1.1) are enabled.")

        # Rule 5: Weak SSL cipher suites
        weak_ciphers = re.search(r'^\s*SSLCipherSuite\s+.*(NULL|EXPORT|RC4|MD5|DES)', content, re.MULTILINE | re.IGNORECASE)
        if weak_ciphers:
            self._report(file_path, content, 'SSLCipherSuite', 'SSL_WEAK', 'High', 
                         "Weak SSL ciphers (NULL, EXPORT, RC4, MD5, DES) are enabled.")

        # Rule 6: TRACE method enabled
        if re.search(r'^\s*TraceEnable\s+On', content, re.MULTILINE | re.IGNORECASE) or \
           ( 'TraceEnable' not in content and 'httpd.conf' in file_path.lower()):
            self._report(file_path, content, 'TraceEnable', 'HARDENING', 'Medium', 
                         "TRACE method is enabled or not explicitly disabled. Vulnerable to Cross-Site Tracing (XST).")

        # Rule 7: Missing security headers (Basic check in config)
        required_headers = ['Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options', 'Strict-Transport-Security']
        for header in required_headers:
            if f"Header always set {header}" not in content and f"Header set {header}" not in content:
                if 'httpd.conf' in file_path.lower() or '.htaccess' in file_path.lower():
                    self.misconfigurations.append({
                        'file': file_path,
                        'line': '-',
                        'code': 'MISSING_HEADER',
                        'severity': 'Medium',
                        'message': f"Security header '{header}' is not configured in the Apache config."
                    })

        # Rule 8: Unlimited request size
        if re.search(r'^\s*LimitRequestBody\s+0', content, re.MULTILINE | re.IGNORECASE):
            self._report(file_path, content, 'LimitRequestBody', 'DOS_RISK', 'Medium', 
                         "LimitRequestBody is set to 0 (unlimited). Risk of Denial of Service.")

        # Rule 9: Timeout not configured or too large
        timeout_match = re.search(r'^\s*Timeout\s+(\d+)', content, re.MULTILINE | re.IGNORECASE)
        if timeout_match:
            if int(timeout_match.group(1)) > 300:
                self._report(file_path, content, 'Timeout', 'DOS_RISK', 'Low', 
                             "Timeout is set to a value greater than 300 seconds.")
        elif 'httpd.conf' in file_path.lower():
            self.misconfigurations.append({
                'file': file_path,
                'line': '-',
                'code': 'DOS_RISK',
                'severity': 'Low',
                'message': "Timeout directive is not explicitly configured. Default might be too high."
            })

        # Rule 10: FollowSymLinks without SymLinksIfOwnerMatch
        if re.search(r'^\s*Options\s+.*FollowSymLinks', content, re.MULTILINE | re.IGNORECASE) and \
           not re.search(r'^\s*Options\s+.*SymLinksIfOwnerMatch', content, re.MULTILINE | re.IGNORECASE):
            self._report(file_path, content, 'Options.*FollowSymLinks', 'HARDENING', 'High', 
                         "FollowSymLinks is enabled without SymLinksIfOwnerMatch. Possible security risk.")

    def _report(self, file_path, content, pattern, code, severity, message):
        """Helper to find line numbers for regex matches and report."""
        regex = re.compile(fr'^\s*{pattern}', re.MULTILINE | re.IGNORECASE)
        for match in regex.finditer(content):
            line_num = content[:match.start()].count('\n') + 1
            self.misconfigurations.append({
                'file': file_path,
                'line': line_num,
                'code': code,
                'severity': severity,
                'message': message
            })

    def _check_module_dependencies(self, file_path, content, lines):
         """Checks for directives that require specific modules."""
         # Example: SSL directives require mod_ssl
         if 'SSLEngine On' in content and 'LoadModule ssl_module' not in content:
             if 'httpd.conf' in file_path.lower():
                 self.misconfigurations.append({
                     'file': file_path,
                     'line': '-',
                     'code': 'MODULE_MISSING',
                     'severity': 'Error',
                     'message': "SSLEngine is On but mod_ssl does not appear to be loaded."
                 })
    
    def scan_directory(self, directory_path):
        """Recursively scans a directory for Apache config files."""
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                if file.endswith('.conf') or file == '.htaccess' or file.startswith('httpd'):
                     self.scan_file(os.path.join(root, file))

    def get_results(self):
        return self.misconfigurations

    def generate_report(self):
        print(f"Scanned {self.files_scanned} files.")
        if not self.misconfigurations:
            print("No misconfigurations found.")
            return

        print("\n=== Misconfiguration Report ===\n")
        # Sort by file and line
        sorted_issues = sorted(self.misconfigurations, key=lambda x: (x['file'], x['line']))
        
        current_file = None
        for issue in sorted_issues:
            if issue['file'] != current_file:
                current_file = issue['file']
                print(f"File: {current_file}")
            
            print(f"  [Line {issue['line']}] [{issue['severity']}] {issue['code']}: {issue['message']}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python detect_apache_misconf.py <file_or_directory>")
        sys.exit(1)

    target_path = sys.argv[1]
    
    detector = ApacheMisconfigDetector()
    
    if os.path.isfile(target_path):
        detector.scan_file(target_path)
    elif os.path.isdir(target_path):
        detector.scan_directory(target_path)
    else:
        print(f"Error: {target_path} is not a valid file or directory.")
        sys.exit(1)

    detector.generate_report()
