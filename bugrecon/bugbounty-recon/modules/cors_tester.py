"""
CORS Misconfiguration Testing Module
Checks: wildcard origins, null origin, trusted subdomain bypass,
        pre-domain bypass, arbitrary origin reflection, credentials with wildcard
"""

import concurrent.futures
from urllib.parse import urlparse
from .utils import HTTPClient, normalize_target

class CORSTester:
    def __init__(self, config):
        self.http    = HTTPClient(config)
        self.threads = config.get('threads', 20)
        self.results = []

    def run(self, target, urls):
        base = normalize_target(target)
        parsed = urlparse(base)
        domain = parsed.netloc

        test_origins = [
            "https://evil.com",
            "null",
            f"https://evil.{domain}",
            f"https://{domain}.evil.com",
            f"https://not{domain}",
            f"http://{domain}",
            "https://localhost",
            f"https://{domain}%60.evil.com",
            f"https://{domain}_.evil.com",
        ]

        endpoints = list(set(urls))[:50]
        if not endpoints:
            endpoints = [base]

        print(f"    [~] Testing CORS on {len(endpoints)} endpoints...")

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = [
                ex.submit(self._test, url, origin)
                for url in endpoints
                for origin in test_origins
            ]
            for f in concurrent.futures.as_completed(futures):
                res = f.result()
                if res:
                    self.results.append(res)
        return self.results

    def _test(self, url, origin):
        headers = {'Origin': origin}
        resp = self.http.get(url, headers=headers)
        if not resp:
            return None

        acao = resp.headers.get('Access-Control-Allow-Origin', '')
        acac = resp.headers.get('Access-Control-Allow-Credentials', '').lower()

        # Wildcard with credentials
        if acao == '*' and acac == 'true':
            print(f"    [VULN] CORS wildcard+credentials @ {url}")
            return self._finding(url, origin, acao, acac, 'Wildcard origin with credentials', 'Critical')

        # Reflects attacker origin
        if acao == origin and origin != 'null':
            if acac == 'true':
                print(f"    [VULN] CORS reflected origin+credentials @ {url}")
                return self._finding(url, origin, acao, acac, 'Origin reflected with credentials=true', 'Critical')
            else:
                print(f"    [VULN] CORS reflected origin @ {url}")
                return self._finding(url, origin, acao, acac, 'Origin reflected without validation', 'High')

        # Null origin accepted
        if acao == 'null' and origin == 'null':
            print(f"    [VULN] CORS null origin @ {url}")
            return self._finding(url, origin, acao, acac, 'Null origin accepted', 'Medium')

        return None

    def _finding(self, url, origin, acao, acac, evidence, severity):
        return {
            'type':        'CORS Misconfiguration',
            'technique':   'Cross-Origin Resource Sharing',
            'url':         url,
            'origin_used': origin,
            'acao_header': acao,
            'acac_header': acac,
            'evidence':    evidence,
            'severity':    severity,
            'remediation': 'Whitelist specific trusted origins. Never use wildcard with credentials. Validate Origin header server-side.',
            'cvss':        '8.1' if severity == 'Critical' else '5.4',
            'cwe':         'CWE-346',
        }
