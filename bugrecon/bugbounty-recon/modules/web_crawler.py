"""
Web Crawler Module
Discovers: URLs, forms, input parameters, JS files, API endpoints, comments
"""

import re
import concurrent.futures
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from .utils import HTTPClient, normalize_target


# Regex patterns for discovering interesting content
RE_JS_URLS       = re.compile(r'(?:fetch|axios|get|post|put|delete|request)\s*\(\s*[\'"`]([^\'"` ]+)[\'"`]', re.I)
RE_API_PATHS     = re.compile(r'[\'"`](/(?:api|v\d|rest|graphql)[^\'"`\s]{0,100})[\'"`]', re.I)
RE_COMMENTS      = re.compile(r'<!--(.*?)-->', re.DOTALL)
RE_EMAILS        = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
RE_PHONE         = re.compile(r'\+?[\d\s\-().]{10,}')
RE_JWT           = re.compile(r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+')
RE_INTERNAL_IP   = re.compile(r'\b(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d+\.\d+\b')


class WebCrawler:
    def __init__(self, config):
        self.config    = config
        self.base_url  = normalize_target(config['target'])
        self.base_host = urlparse(self.base_url).netloc
        self.depth     = config.get('depth', 3)
        self.threads   = config.get('threads', 20)
        self.http      = HTTPClient(config)

        self.visited   = set()
        self.urls      = set()
        self.forms     = []
        self.params    = set()
        self.js_files  = set()
        self.endpoints = set()
        self.emails    = set()
        self.comments  = []
        self.jwts      = set()
        self.int_ips   = set()

    def run(self, target=None):
        start = self.base_url
        print(f"    [~] Crawling {start} (depth={self.depth})")
        self._crawl(start, depth=0)

        # Also crawl discovered JS files for more endpoints
        self._analyze_js_files()

        return {
            'urls':      list(self.urls),
            'forms':     self.forms,
            'params':    list(self.params),
            'js_files':  list(self.js_files),
            'endpoints': list(self.endpoints),
            'emails':    list(self.emails),
            'comments':  self.comments[:20],  # cap
            'jwts':      list(self.jwts),
            'internal_ips': list(self.int_ips),
        }

    def _crawl(self, url, depth):
        if depth > self.depth or url in self.visited:
            return
        self.visited.add(url)

        resp = self.http.get(url)
        if not resp:
            return

        self.urls.add(url)
        content_type = resp.headers.get('Content-Type', '')

        if 'html' in content_type:
            self._parse_html(url, resp.text)
        elif 'javascript' in content_type or url.endswith('.js'):
            self._parse_js(url, resp.text)

    def _parse_html(self, base, html):
        try:
            soup = BeautifulSoup(html, 'html.parser')
        except Exception:
            return

        # Collect all links
        new_links = set()
        for tag in soup.find_all(['a', 'link', 'script', 'img', 'form', 'iframe', 'frame']):
            for attr in ['href', 'src', 'action']:
                val = tag.get(attr)
                if val:
                    abs_url = urljoin(base, val)
                    parsed  = urlparse(abs_url)
                    if parsed.netloc == self.base_host and parsed.scheme in ('http','https'):
                        new_links.add(abs_url)
                        # Track JS files
                        if abs_url.endswith('.js'):
                            self.js_files.add(abs_url)

        # Extract forms
        for form in soup.find_all('form'):
            form_data = {
                'action': urljoin(base, form.get('action', '')),
                'method': form.get('method', 'GET').upper(),
                'inputs': []
            }
            for inp in form.find_all(['input', 'textarea', 'select']):
                name = inp.get('name')
                if name:
                    form_data['inputs'].append({
                        'name':  name,
                        'type':  inp.get('type', 'text'),
                        'value': inp.get('value', '')
                    })
                    self.params.add(name)
            if form_data['inputs']:
                self.forms.append(form_data)

        # Extract query params from URLs
        for link in new_links:
            qs = parse_qs(urlparse(link).query)
            for key in qs:
                self.params.add(key)

        # Extract comments
        for c in RE_COMMENTS.findall(html):
            stripped = c.strip()
            if len(stripped) > 5:
                self.comments.append({'source': base, 'content': stripped[:200]})

        # Find emails
        for e in RE_EMAILS.findall(html):
            self.emails.add(e)

        # Find JWTs
        for j in RE_JWT.findall(html):
            self.jwts.add(j)

        # Find internal IPs
        for ip in RE_INTERNAL_IP.findall(html):
            self.int_ips.add(ip)

        # Extract API paths from inline scripts
        for script in soup.find_all('script'):
            if script.string:
                for path in RE_API_PATHS.findall(script.string):
                    self.endpoints.add(urljoin(base, path))

        # Crawl discovered links
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(self._crawl, link, 1): link for link in new_links - self.visited}
            for f in concurrent.futures.as_completed(futures):
                pass  # errors handled in _crawl

    def _parse_js(self, base, js_text):
        """Extract API endpoints and params from JS files."""
        for path in RE_API_PATHS.findall(js_text):
            self.endpoints.add(urljoin(base, path))
        for url in RE_JS_URLS.findall(js_text):
            if url.startswith('/'):
                self.endpoints.add(urljoin(base, url))
        for j in RE_JWT.findall(js_text):
            self.jwts.add(j)
        for ip in RE_INTERNAL_IP.findall(js_text):
            self.int_ips.add(ip)

    def _analyze_js_files(self):
        """Deep-crawl all discovered JS files."""
        def fetch_js(url):
            if url in self.visited:
                return
            self.visited.add(url)
            resp = self.http.get(url)
            if resp:
                self._parse_js(url, resp.text)

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            list(ex.map(fetch_js, list(self.js_files)))
