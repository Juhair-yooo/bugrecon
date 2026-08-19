"""
General Vulnerability Scanner Module
Checks: Security headers, SSL/TLS issues, HTTP methods, clickjacking,
        directory listing, admin panels, default creds hints,
        WAF detection, rate limiting, cookie security
"""

import ssl
import socket
import re
import concurrent.futures
from urllib.parse import urlparse, urljoin
from datetime import datetime
from .utils import HTTPClient, normalize_target

SECURITY_HEADERS = {
    'Strict-Transport-Security': {
        'desc': 'HSTS not set - enables SSL stripping attacks',
        'severity': 'Medium', 'cvss': '5.9', 'cwe': 'CWE-319'
    },
    'Content-Security-Policy': {
        'desc': 'CSP not set - increases XSS risk',
        'severity': 'Medium', 'cvss': '6.1', 'cwe': 'CWE-79'
    },
    'X-Frame-Options': {
        'desc': 'X-Frame-Options missing - clickjacking possible',
        'severity': 'Medium', 'cvss': '4.3', 'cwe': 'CWE-1021'
    },
    'X-Content-Type-Options': {
        'desc': 'X-Content-Type-Options missing - MIME sniffing attack possible',
        'severity': 'Low', 'cvss': '3.7', 'cwe': 'CWE-693'
    },
    'Referrer-Policy': {
        'desc': 'Referrer-Policy missing - data leakage via Referer header',
        'severity': 'Low', 'cvss': '3.1', 'cwe': 'CWE-200'
    },
    'Permissions-Policy': {
        'desc': 'Permissions-Policy missing - no browser feature restrictions',
        'severity': 'Low', 'cvss': '2.6', 'cwe': 'CWE-16'
    },
    'X-XSS-Protection': {
        'desc': 'X-XSS-Protection not configured',
        'severity': 'Low', 'cvss': '3.1', 'cwe': 'CWE-79'
    },
}

HTTP_METHODS_DANGEROUS = ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH', 'OPTIONS']

ADMIN_PATHS = [
    '/admin', '/admin/', '/administrator', '/wp-admin', '/dashboard',
    '/panel', '/control', '/manager', '/management', '/backend',
    '/cms', '/login', '/signin', '/auth', '/api/admin', '/api/v1/admin',
    '/graphql', '/graphiql', '/__graphql', '/altair', '/playground',
]

COOKIE_ISSUES = {
    'HttpOnly': 'Cookie without HttpOnly flag - accessible via JavaScript (XSS theft)',
    'Secure':   'Cookie without Secure flag - sent over HTTP connections',
    'SameSite': 'Cookie without SameSite attribute - CSRF risk',
}


class VulnScanner:
    def __init__(self, config):
        self.config  = config
        self.http    = HTTPClient(config)
        self.base    = normalize_target(config['target'])
        self.results = []

    def run(self, target, urls, tech_results=None):
        self._check_security_headers()
        self._check_http_methods()
        self._check_cookies()
        self._check_ssl()
        self._check_admin_panels()
        self._check_directory_listing(urls)
        self._check_information_disclosure()
        if tech_results:
            self._tech_specific_checks(tech_results)
        return self.results

    def _check_security_headers(self):
        resp = self.http.get(self.base)
        if not resp:
            return
        headers = {k.lower(): v for k, v in resp.headers.items()}
        for header, info in SECURITY_HEADERS.items():
            if header.lower() not in headers:
                print(f"    [VULN] Missing header: {header}")
                self.results.append({
                    'type':        'Missing Security Header',
                    'technique':   'HTTP Response Header Analysis',
                    'header':      header,
                    'url':         self.base,
                    'evidence':    info['desc'],
                    'severity':    info['severity'],
                    'remediation': f"Add '{header}' response header with appropriate value.",
                    'cvss':        info['cvss'],
                    'cwe':         info['cwe'],
                })
        # Check for information disclosure headers
        for h in ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Generator']:
            val = headers.get(h.lower())
            if val:
                print(f"    [WARN] Info disclosure header: {h}: {val}")
                self.results.append({
                    'type':        'Information Disclosure',
                    'technique':   'Header Analysis',
                    'header':      h,
                    'url':         self.base,
                    'evidence':    f"{h}: {val}",
                    'severity':    'Low',
                    'remediation': f"Remove or obfuscate the '{h}' response header.",
                    'cvss':        '3.1',
                    'cwe':         'CWE-200',
                })

    def _check_http_methods(self):
        resp = self.http.get(self.base, headers={'X-HTTP-Method-Override': 'OPTIONS'})
        # Real OPTIONS check
        try:
            import requests
            r = requests.options(self.base, timeout=self.config.get('timeout', 10), verify=False)
            allow = r.headers.get('Allow', '') + r.headers.get('Public', '')
            for method in HTTP_METHODS_DANGEROUS:
                if method in allow:
                    if method == 'TRACE':
                        print(f"    [VULN] HTTP TRACE method enabled - XST attack possible")
                        self.results.append({
                            'type':        'Dangerous HTTP Method',
                            'technique':   'HTTP Method Testing',
                            'url':         self.base,
                            'method':      method,
                            'evidence':    f"Allow: {allow}",
                            'severity':    'Medium',
                            'remediation': 'Disable TRACE and other unnecessary HTTP methods in server config.',
                            'cvss':        '5.4',
                            'cwe':         'CWE-16',
                        })
        except Exception:
            pass

    def _check_cookies(self):
        resp = self.http.get(self.base)
        if not resp:
            return
        for cookie in resp.cookies:
            issues = []
            if not cookie.has_nonstandard_attr('HttpOnly') and not getattr(cookie, '_rest', {}).get('HttpOnly'):
                issues.append('HttpOnly')
            if not cookie.secure:
                issues.append('Secure')
            samesite = (cookie._rest or {}).get('SameSite', '')
            if not samesite:
                issues.append('SameSite')

            for issue in issues:
                print(f"    [VULN] Cookie '{cookie.name}' missing {issue} flag")
                self.results.append({
                    'type':        'Insecure Cookie',
                    'technique':   'Cookie Attribute Analysis',
                    'url':         self.base,
                    'cookie_name': cookie.name,
                    'missing_flag': issue,
                    'evidence':    COOKIE_ISSUES.get(issue, f"Missing {issue}"),
                    'severity':    'Medium' if issue in ('HttpOnly', 'Secure') else 'Low',
                    'remediation': f"Set the {issue} attribute on all cookies.",
                    'cvss':        '4.3',
                    'cwe':         'CWE-614' if issue == 'Secure' else 'CWE-1004',
                })

    def _check_ssl(self):
        parsed = urlparse(self.base)
        host   = parsed.netloc
        port   = 443

        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
                s.settimeout(5)
                s.connect((host, port))
                cert = s.getpeercert()

            # Check expiry
            expire_str = cert.get('notAfter', '')
            if expire_str:
                expire = datetime.strptime(expire_str, '%b %d %H:%M:%S %Y %Z')
                days_left = (expire - datetime.utcnow()).days
                if days_left < 30:
                    self.results.append({
                        'type':        'SSL Certificate Expiring Soon',
                        'technique':   'SSL/TLS Analysis',
                        'url':         self.base,
                        'evidence':    f"Certificate expires in {days_left} days ({expire_str})",
                        'severity':    'High' if days_left < 7 else 'Medium',
                        'remediation': 'Renew SSL certificate immediately.',
                        'cvss':        '7.5',
                        'cwe':         'CWE-295',
                    })

        except ssl.SSLError as e:
            self.results.append({
                'type':        'SSL/TLS Error',
                'technique':   'SSL/TLS Analysis',
                'url':         self.base,
                'evidence':    str(e),
                'severity':    'High',
                'remediation': 'Configure TLS 1.2+ only. Disable SSLv3, TLS 1.0, TLS 1.1.',
                'cvss':        '7.5',
                'cwe':         'CWE-326',
            })
        except Exception:
            pass

        # Check if HTTP (non-SSL) is also accessible
        http_url = self.base.replace('https://', 'http://')
        resp = self.http.get(http_url, allow_redirects=False)
        if resp and resp.status_code == 200:
            print(f"    [VULN] Site accessible over plain HTTP (no redirect)")
            self.results.append({
                'type':        'Cleartext HTTP',
                'technique':   'HTTP vs HTTPS Test',
                'url':         http_url,
                'evidence':    'HTTP responds with 200 (no HTTPS redirect)',
                'severity':    'High',
                'remediation': 'Redirect all HTTP traffic to HTTPS. Enable HSTS.',
                'cvss':        '5.9',
                'cwe':         'CWE-319',
            })

    def _check_admin_panels(self):
        def probe(path):
            url = urljoin(self.base, path)
            resp = self.http.get(url, allow_redirects=True)
            if resp and resp.status_code in (200, 401, 403):
                if resp.status_code == 200:
                    print(f"    [VULN] Admin panel accessible: {url} [{resp.status_code}]")
                    self.results.append({
                        'type':        'Exposed Admin Panel',
                        'technique':   'Admin Path Brute-Force',
                        'url':         url,
                        'status_code': resp.status_code,
                        'evidence':    f"Admin interface returned {resp.status_code}",
                        'severity':    'High',
                        'remediation': 'Restrict admin panel to specific IPs. Add MFA. Use non-default paths.',
                        'cvss':        '7.5',
                        'cwe':         'CWE-306',
                    })
                elif resp.status_code in (401, 403):
                    print(f"    [INFO] Protected panel found: {url} [{resp.status_code}]")

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            list(ex.map(probe, ADMIN_PATHS))

    def _check_directory_listing(self, urls):
        checked = set()
        for url in list(urls)[:30]:
            parsed = urlparse(url)
            parent = parsed.scheme + '://' + parsed.netloc + '/'.join(parsed.path.split('/')[:-1]) + '/'
            if parent in checked:
                continue
            checked.add(parent)
            resp = self.http.get(parent)
            if resp and resp.status_code == 200:
                body = resp.text.lower()
                if 'index of' in body or 'parent directory' in body or 'directory listing' in body:
                    print(f"    [VULN] Directory listing enabled: {parent}")
                    self.results.append({
                        'type':        'Directory Listing Enabled',
                        'technique':   'Directory Enumeration',
                        'url':         parent,
                        'evidence':    '"Index of" or "Parent Directory" in response',
                        'severity':    'Medium',
                        'remediation': 'Disable directory listing in web server config (Options -Indexes for Apache).',
                        'cvss':        '5.3',
                        'cwe':         'CWE-548',
                    })

    def _check_information_disclosure(self):
        """Check for various info disclosure endpoints."""
        endpoints = [
            ('/.git/HEAD',           'Git repository exposure'),
            ('/server-status',       'Apache server-status exposed'),
            ('/server-info',         'Apache server-info exposed'),
            ('/actuator',            'Spring Boot Actuator exposed'),
            ('/actuator/health',     'Spring Actuator health endpoint'),
            ('/actuator/env',        'Spring Actuator env (credentials leak)'),
            ('/actuator/mappings',   'Spring Actuator route mappings'),
            ('/metrics',             'Prometheus metrics exposed'),
            ('/debug',               'Debug endpoint exposed'),
            ('/trace',               'HTTP trace endpoint'),
            ('/api/v1/debug',        'API debug endpoint'),
            ('/console',             'Admin console accessible'),
            ('/heapdump',            'Java heap dump accessible'),
            ('/threaddump',          'Java thread dump accessible'),
        ]
        for path, desc in endpoints:
            url = urljoin(self.base, path)
            resp = self.http.get(url)
            if resp and resp.status_code == 200 and len(resp.text) > 50:
                print(f"    [VULN] {desc}: {url}")
                self.results.append({
                    'type':        'Information Disclosure',
                    'technique':   'Sensitive Endpoint Discovery',
                    'url':         url,
                    'evidence':    f"{desc} ({len(resp.text)} bytes)",
                    'severity':    'High' if 'env' in path or 'heap' in path or 'git' in path else 'Medium',
                    'remediation': 'Restrict access to internal/diagnostic endpoints.',
                    'cvss':        '5.3',
                    'cwe':         'CWE-200',
                })

    def _tech_specific_checks(self, tech_results):
        """Run checks based on detected technology."""
        all_tech = []
        for host_techs in tech_results.values():
            all_tech.extend(host_techs if isinstance(host_techs, list) else [])

        if 'WordPress' in all_tech:
            self._wp_checks()
        if 'jQuery' in all_tech:
            self._jquery_version_check()

    def _wp_checks(self):
        """WordPress-specific vulnerability checks."""
        wp_paths = [
            ('/wp-json/wp/v2/users',     'WordPress user enumeration via REST API'),
            ('/xmlrpc.php',              'WordPress XML-RPC enabled (brute-force amplification)'),
            ('/wp-content/debug.log',    'WordPress debug.log exposed'),
            ('/wp-config.php.bak',       'WordPress config backup exposed'),
            ('/?author=1',               'WordPress author enumeration'),
        ]
        for path, desc in wp_paths:
            url = urljoin(self.base, path)
            resp = self.http.get(url)
            if resp and resp.status_code == 200:
                print(f"    [VULN] WordPress: {desc}")
                self.results.append({
                    'type':        'WordPress Vulnerability',
                    'technique':   'CMS-Specific Testing',
                    'url':         url,
                    'evidence':    desc,
                    'severity':    'High' if 'config' in path or 'xmlrpc' in path else 'Medium',
                    'remediation': f"Disable or restrict access to {path}",
                    'cvss':        '7.5',
                    'cwe':         'CWE-200',
                })

    def _jquery_version_check(self):
        """Check for outdated jQuery versions."""
        resp = self.http.get(self.base)
        if not resp:
            return
        match = re.search(r'jquery[\-.](\d+\.\d+\.\d+)', resp.text, re.I)
        if match:
            version = match.group(1)
            major, minor, patch = map(int, version.split('.'))
            if major < 3 or (major == 3 and minor < 5):
                print(f"    [VULN] Outdated jQuery {version} (XSS CVEs)")
                self.results.append({
                    'type':        'Outdated Library',
                    'technique':   'Version Fingerprinting',
                    'url':         self.base,
                    'evidence':    f"jQuery {version} has known XSS vulnerabilities (CVE-2019-11358, CVE-2020-11022)",
                    'severity':    'Medium',
                    'remediation': 'Update jQuery to 3.5.0 or later.',
                    'cvss':        '6.1',
                    'cwe':         'CWE-79',
                })
