"""
Technology Detection Module
Detects: Web servers, frameworks, CMS, databases, CDNs, WAFs,
         JavaScript libraries, analytics, cloud providers
"""

import re
import concurrent.futures
from .utils import HTTPClient, normalize_target

FINGERPRINTS = {
    'header': {
        'Apache':       {'Server': r'Apache'},
        'Nginx':        {'Server': r'nginx'},
        'IIS':          {'Server': r'Microsoft-IIS'},
        'Cloudflare':   {'Server': r'cloudflare', 'CF-RAY': r'.+'},
        'AWS':          {'Server': r'AmazonS3|awselb'},
        'Akamai':       {'X-Check-Cacheable': r'.+', 'X-Akamai-Session-Info': r'.+'},
        'Varnish':      {'Via': r'varnish', 'X-Varnish': r'.+'},
        'PHP':          {'X-Powered-By': r'PHP'},
        'ASP.NET':      {'X-Powered-By': r'ASP\.NET', 'X-AspNet-Version': r'.+'},
        'Express':      {'X-Powered-By': r'Express'},
        'Django':       {'X-Frame-Options': r'.+', 'Set-Cookie': r'csrftoken'},
        'Laravel':      {'Set-Cookie': r'laravel_session'},
        'Drupal':       {'X-Generator': r'Drupal'},
        'WordPress':    {'Link': r'wp-json'},
        'WAF-Sucuri':   {'X-Sucuri-ID': r'.+'},
        'WAF-ModSec':   {'Server': r'mod_security'},
    },
    'body': {
        'WordPress':    r'wp-content|wp-includes|wordpress',
        'Joomla':       r'Joomla!|joomla',
        'Drupal':       r'Drupal|drupal\.org',
        'Magento':      r'Magento|mage',
        'Shopify':      r'Shopify|shopify\.com',
        'Wix':          r'wix\.com|wixsite',
        'React':        r'__react|react-root|data-reactroot',
        'Angular':      r'ng-version|angular\.js',
        'Vue':          r'data-v-|__vue__',
        'Next.js':      r'__NEXT_DATA__|_next/',
        'Nuxt.js':      r'__NUXT__|_nuxt/',
        'jQuery':       r'jquery[\-.][\d.]+',
        'Bootstrap':    r'bootstrap\.min\.(js|css)',
        'Laravel':      r'laravel|csrf-token.*laravel',
        'Django':       r'csrfmiddlewaretoken',
        'Rails':        r'authenticity_token|rails',
        'Flask':        r'Werkzeug|flask',
        'Spring':       r'spring|springframework',
        'Google Analytics': r'google-analytics\.com|gtag|UA-\d+',
        'Google Tag Manager': r'googletagmanager\.com|GTM-',
        'Cloudflare':   r'cloudflareinsights\.com|__cfduid',
        'AWS S3':       r'amazonaws\.com',
        'Stripe':       r'stripe\.com/v\d',
        'PayPal':       r'paypal\.com/sdk',
        'Recaptcha':    r'google\.com/recaptcha',
        'Intercom':     r'intercom\.io',
        'Zendesk':      r'zendesk\.com',
        'HubSpot':      r'hubspot\.com|hs-analytics',
    },
    'cookie': {
        'PHP':          r'PHPSESSID',
        'ASP.NET':      r'ASP\.NET_SessionId',
        'WordPress':    r'wordpress_|wp-settings',
        'Joomla':       r'joomla_user_state',
        'Django':       r'csrftoken|sessionid',
        'Laravel':      r'laravel_session|XSRF-TOKEN',
        'Rails':        r'_session_id|authenticity_token',
        'Java':         r'JSESSIONID',
        'ColdFusion':   r'CFID|CFTOKEN',
    }
}

VULN_TECH_MAP = {
    'WordPress':  'Check for outdated plugins/themes, xmlrpc.php, user enumeration (/wp-json/wp/v2/users)',
    'Joomla':     'Check /administrator, outdated extensions, SQL injection in components',
    'Drupal':     'Check Drupalgeddon (SA-CORE-2018-002), outdated modules',
    'Magento':    'Check /downloader, Magento Shoplift (SUPEE-5994), admin path',
    'jQuery':     'Check for outdated version with known CVEs',
    'Apache':     'Check for directory traversal, mod_status exposure',
    'Nginx':      'Check for misconfigured location blocks, path traversal',
    'IIS':        'Check for WebDAV, TRACE method enabled, .NET deserialization',
    'PHP':        'Check for exposed phpinfo(), outdated PHP version',
    'ASP.NET':    'Check for ViewState without encryption, .NET deserialization',
}


class TechDetector:
    def __init__(self, config):
        self.http    = HTTPClient(config)
        self.threads = config.get('threads', 20)

    def run(self, target, subdomains=None):
        base = normalize_target(target)
        hosts = [base]
        if subdomains:
            hosts += [normalize_target(s) for s in (subdomains or [])[:20]]

        print(f"    [~] Fingerprinting {len(hosts)} hosts...")
        results = {}

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(self._detect, host): host for host in hosts}
            for f in concurrent.futures.as_completed(futures):
                host = futures[f]
                try:
                    results[host] = f.result()
                except Exception:
                    results[host] = []

        # Print summary
        for host, techs in results.items():
            if techs:
                print(f"    [+] {host}: {', '.join(techs)}")
                for t in techs:
                    if t in VULN_TECH_MAP:
                        print(f"        ⚠ {t}: {VULN_TECH_MAP[t]}")

        return results

    def _detect(self, url):
        resp = self.http.get(url)
        if not resp:
            return []

        detected = set()
        headers  = {k.lower(): v for k, v in resp.headers.items()}
        body     = resp.text.lower()
        cookies  = '; '.join([f"{c.name}={c.value}" for c in resp.cookies])

        # Header fingerprints
        for tech, patterns in FINGERPRINTS['header'].items():
            for header, pattern in patterns.items():
                header_val = headers.get(header.lower(), '')
                if header_val and re.search(pattern, header_val, re.I):
                    detected.add(tech)

        # Body fingerprints
        for tech, pattern in FINGERPRINTS['body'].items():
            if re.search(pattern, body, re.I):
                detected.add(tech)

        # Cookie fingerprints
        for tech, pattern in FINGERPRINTS['cookie'].items():
            if re.search(pattern, cookies, re.I):
                detected.add(tech)

        return list(detected)
