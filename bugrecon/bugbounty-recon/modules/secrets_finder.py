"""
Secrets & Sensitive Data Discovery Module
Finds: API keys, tokens, credentials, private keys, config leaks,
       debug endpoints, backup files, .git exposure, .env files
"""

import re
import concurrent.futures
from urllib.parse import urljoin
from .utils import HTTPClient, normalize_target

# ─── Regex patterns for secrets ───────────────────────────────────────────────
SECRET_PATTERNS = {
    'AWS Access Key':         r'AKIA[0-9A-Z]{16}',
    'AWS Secret Key':         r'(?i)aws.{0,20}[\'"][0-9a-zA-Z/+]{40}[\'"]',
    'AWS Session Token':      r'(?i)aws.{0,20}session.{0,20}[\'"][0-9a-zA-Z/+]{200,}[\'"]',
    'Google API Key':         r'AIza[0-9A-Za-z\-_]{33,40}',
    'Google OAuth':           r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
    'Stripe Secret Key':      r'sk_live_[0-9a-zA-Z]{24}',
    'Stripe Public Key':      r'pk_live_[0-9a-zA-Z]{24}',
    'Twilio Account SID':     r'AC[a-zA-Z0-9]{32}',
    'Twilio Auth Token':      r'(?i)twilio.{0,20}[\'"][a-f0-9]{32}[\'"]',
    'SendGrid API Key':       r'SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}',
    'Slack Token':            r'xox[baprs]-[0-9a-zA-Z]{10,48}',
    'Slack Webhook':          r'https://hooks\.slack\.com/services/T[a-zA-Z0-9]+/B[a-zA-Z0-9]+/[a-zA-Z0-9]+',
    'GitHub Token':           r'ghp_[a-zA-Z0-9]{36}',
    'GitHub OAuth':           r'gho_[a-zA-Z0-9]{36}',
    'GitHub App Token':       r'(ghu|ghs)_[a-zA-Z0-9]{36}',
    'GitLab Token':           r'glpat-[a-zA-Z0-9\-_]{20}',
    'Heroku API Key':         r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
    'JWT Token':              r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+',
    'Private Key':            r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
    'Basic Auth in URL':      r'https?://[a-zA-Z0-9]+:[a-zA-Z0-9]+@',
    'Generic API Key':        r'(?i)(api[_\-]?key|apikey)\s*[=:\s]+[a-zA-Z0-9\-_\.]{16,}',
    'Generic Secret':         r'(?i)(secret|password|passwd|pwd)\s*[=:\s_\-]+[a-zA-Z0-9!@#\$%\^&\*\-_\.]{6,}',
    'Generic Token':          r'(?i)(token|auth[_\-]token|access[_\-]token|bearer)\s*[=:\s]+[a-zA-Z0-9\-_\.]{16,}',
    'Database URL':           r'(?i)(mysql|postgresql|mongodb|redis|sqlite):\/\/[^\s\'"]+',
    'SMTP Credentials':       r'(?i)smtp\.(host|user|pass|password)\s*[=:]\s*[\'"][^\'"]+[\'"]',
    'Azure Key':              r'(?i)azure.{0,30}[\'"][0-9a-zA-Z/+=]{20,}[\'"]',
    'Facebook Token':         r'EAACEdEose0cBA[0-9A-Za-z]+',
    'Mailgun API Key':        r'key-[0-9a-zA-Z]{32}',
    'Square Access Token':    r'sq0atp-[0-9A-Za-z\-_]{22}',
    'PayPal Client ID':       r'(?i)paypal.{0,20}client.{0,10}[\'"][A-Za-z0-9]{80}[\'"]',
    'Shopify Token':          r'shpat_[a-fA-F0-9]{32}',
    'Twitch Client Secret':   r'(?i)twitch.{0,20}[\'"][a-z0-9]{30}[\'"]',
    'Discord Token':          r'(?i)discord.{0,20}[\'"][MN][a-zA-Z0-9]{23}\.[a-zA-Z0-9\-_]{6}\.[a-zA-Z0-9\-_]{27}[\'"]',
    'NPM Token':              r'npm_[a-zA-Z0-9]{36}',
}

# Sensitive file paths to probe
SENSITIVE_PATHS = [
    # Config & env
    '/.env', '/.env.local', '/.env.backup', '/.env.prod', '/.env.dev',
    '/config.php', '/config.json', '/config.yaml', '/config.yml',
    '/settings.py', '/settings.json', '/app.config', '/web.config',
    '/database.yml', '/database.json', '/db.php',
    # Git exposure
    '/.git/HEAD', '/.git/config', '/.git/COMMIT_EDITMSG',
    '/.gitignore', '/.gitconfig',
    # Backup files
    '/backup.zip', '/backup.tar.gz', '/backup.sql', '/db.sql', '/dump.sql',
    '/site.zip', '/www.zip', '/html.tar.gz', '/src.zip',
    # Debug & admin
    '/phpinfo.php', '/info.php', '/test.php', '/debug.php',
    '/admin', '/admin.php', '/administrator', '/wp-admin',
    '/phpmyadmin', '/adminer.php', '/adminer',
    # Logs
    '/error.log', '/access.log', '/debug.log', '/app.log', '/laravel.log',
    '/logs/error.log', '/log/access.log',
    # Common sensitive
    '/robots.txt', '/sitemap.xml', '/crossdomain.xml', '/clientaccesspolicy.xml',
    '/humans.txt', '/security.txt', '/.well-known/security.txt',
    '/swagger.json', '/swagger.yaml', '/openapi.json', '/openapi.yaml',
    '/api-docs', '/api/swagger', '/v1/swagger',
    '/server-status', '/server-info',
    # Package files that reveal tech stack
    '/package.json', '/composer.json', '/requirements.txt', '/Gemfile',
    '/yarn.lock', '/package-lock.json',
    # Cloud
    '/aws.json', '/.aws/credentials', '/gcp-credentials.json',
]


class SecretsFinder:
    def __init__(self, config):
        self.http    = HTTPClient(config)
        self.base    = normalize_target(config['target'])
        self.threads = config.get('threads', 30)
        self.results = []
        self.compiled = {name: re.compile(pat) for name, pat in SECRET_PATTERNS.items()}

    def run(self, target, urls):
        print(f"    [~] Scanning for secrets in {len(urls)} URLs...")

        # Probe sensitive files
        print(f"    [~] Probing {len(SENSITIVE_PATHS)} sensitive file paths...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = [ex.submit(self._probe_path, path) for path in SENSITIVE_PATHS]
            for f in concurrent.futures.as_completed(futures):
                res = f.result()
                if res:
                    self.results.append(res)

        # Scan crawled URLs for secrets in response body
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = [ex.submit(self._scan_url, url) for url in list(urls)[:100]]
            for f in concurrent.futures.as_completed(futures):
                res = f.result()
                if res:
                    self.results.extend(res)

        return self.results

    def _probe_path(self, path):
        url = urljoin(self.base, path)
        resp = self.http.get(url)
        if not resp or resp.status_code not in (200, 403):
            return None
        
        # 200 is interesting; 403 on .git is also interesting
        if resp.status_code == 200 and len(resp.text) > 0:
            print(f"    [VULN] Sensitive file accessible: {url} [{resp.status_code}]")
            severity = 'Critical' if any(x in path for x in ['.env', 'backup', '.git', 'sql', 'credentials']) else 'Medium'
            result = {
                'type':        'Sensitive File Exposure',
                'technique':   'Path Probing',
                'url':         url,
                'status_code': resp.status_code,
                'file_size':   len(resp.text),
                'severity':    severity,
                'evidence':    f"File accessible ({len(resp.text)} bytes)",
                'remediation': 'Block access to sensitive files. Move secrets out of web root. Add to .htaccess or nginx deny rules.',
                'cvss':        '9.1' if severity == 'Critical' else '5.3',
                'cwe':         'CWE-538',
            }
            # Also scan content for secrets
            secrets_in_body = self._find_secrets_in_text(resp.text, url)
            if secrets_in_body:
                result['secrets_found'] = secrets_in_body
            return result
        
        if resp.status_code == 403 and '.git' in path:
            print(f"    [WARN] .git directory exists (403) @ {url}")
        return None

    def _scan_url(self, url):
        resp = self.http.get(url)
        if not resp:
            return []
        return self._find_secrets_in_text(resp.text, url)

    def _find_secrets_in_text(self, text, source_url):
        found = []
        for name, pattern in self.compiled.items():
            matches = pattern.findall(text)
            for match in matches[:3]:  # Cap at 3 per pattern
                # Redact long secrets for display
                display = match[:30] + '...' if len(match) > 30 else match
                print(f"    [VULN] {name} found in {source_url}")
                found.append({
                    'type':        'Secret/Credential Exposure',
                    'technique':   'Pattern Matching',
                    'secret_type': name,
                    'url':         source_url,
                    'match':       display,
                    'severity':    'Critical',
                    'evidence':    f"{name} pattern matched",
                    'remediation': 'Rotate compromised credentials immediately. Store secrets in environment variables or secret managers (Vault, AWS Secrets Manager).',
                    'cvss':        '9.8',
                    'cwe':         'CWE-312',
                })
        return found
