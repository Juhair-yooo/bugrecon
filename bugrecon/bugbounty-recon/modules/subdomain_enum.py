"""
Subdomain Enumeration Module
Techniques: DNS brute-force, crt.sh, HackerTarget API, AlienVault OTX,
            ThreatCrowd, SecurityTrails (if key), CommonCrawl, VirusTotal (if key)
"""

import dns.resolver
import requests
import json
import concurrent.futures
import os
from .utils import HTTPClient, extract_domain, normalize_target


BUILTIN_WORDLIST = [
    "www","mail","ftp","admin","api","dev","staging","test","beta","app",
    "portal","cdn","static","assets","img","images","media","files","blog",
    "shop","store","secure","vpn","remote","mx","smtp","pop","imap","webmail",
    "support","help","docs","wiki","forum","community","internal","intranet",
    "corp","office","cloud","aws","azure","gcp","prod","production","qa","uat",
    "mobile","m","wap","old","legacy","v1","v2","v3","api1","api2","api3",
    "auth","login","sso","oauth","signup","register","dashboard","panel",
    "cpanel","whm","phpmyadmin","jenkins","ci","cd","gitlab","github","bitbucket",
    "jira","confluence","slack","teams","zoom","meet","calendar","mail2",
    "smtp2","relay","gateway","proxy","fw","firewall","vpn2","dns","ns1","ns2",
    "backup","bak","archive","log","logs","monitor","monitoring","grafana","kibana",
    "elasticsearch","redis","mysql","db","database","postgres","mongo","cassandra",
    "kafka","rabbit","rabbitmq","zookeeper","etcd","consul","vault","puppet",
    "chef","ansible","terraform","k8s","kubernetes","docker","registry","nexus",
    "sonar","sonarqube","artifactory","splunk","datadog","newrelic","sentry",
    "status","health","ping","metrics","telemetry","analytics","tracking",
    "payment","pay","billing","invoice","checkout","cart","order","orders",
    "user","users","account","accounts","profile","settings","config",
    "upload","uploads","download","downloads","export","import","report","reports"
]


class SubdomainEnumerator:
    def __init__(self, config):
        self.config  = config
        self.domain  = extract_domain(config['target'])
        self.http    = HTTPClient(config)
        self.threads = config.get('threads', 50)
        self.found   = set()

    def run(self):
        print(f"    [~] Enumerating subdomains for: {self.domain}")
        
        # Run all sources in parallel categories
        self._from_crtsh()
        self._from_hackertarget()
        self._from_alienvault()
        self._from_threatcrowd()
        self._from_commoncrawl()
        self._dns_bruteforce()
        self._validate_subdomains()

        results = sorted(self.found)
        for sub in results:
            print(f"    [+] {sub}")
        return results

    def _add(self, sub):
        sub = sub.strip().lower().rstrip('.')
        if sub.endswith(f".{self.domain}") or sub == self.domain:
            self.found.add(sub)

    # ─── Passive Sources ──────────────────────────────────────────────────────

    def _from_crtsh(self):
        """Certificate Transparency logs via crt.sh"""
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            resp = self.http.get(url, timeout=15)
            if resp and resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    names = entry.get('name_value', '').split('\n')
                    for name in names:
                        name = name.replace('*.', '').strip()
                        self._add(name)
            print(f"    [*] crt.sh: {len(self.found)} subdomains so far")
        except Exception as e:
            print(f"    [!] crt.sh error: {e}")

    def _from_hackertarget(self):
        """HackerTarget API (free tier)"""
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            resp = self.http.get(url, timeout=10)
            if resp and resp.status_code == 200 and 'error' not in resp.text.lower():
                for line in resp.text.splitlines():
                    parts = line.split(',')
                    if parts:
                        self._add(parts[0])
        except Exception:
            pass

    def _from_alienvault(self):
        """AlienVault OTX"""
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
            resp = self.http.get(url, timeout=10)
            if resp and resp.status_code == 200:
                data = resp.json()
                for entry in data.get('passive_dns', []):
                    hostname = entry.get('hostname', '')
                    self._add(hostname)
        except Exception:
            pass

    def _from_threatcrowd(self):
        """ThreatCrowd API"""
        try:
            url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}"
            resp = self.http.get(url, timeout=10)
            if resp and resp.status_code == 200:
                data = resp.json()
                for sub in data.get('subdomains', []):
                    self._add(sub)
        except Exception:
            pass

    def _from_commoncrawl(self):
        """CommonCrawl index"""
        try:
            url = f"http://index.commoncrawl.org/CC-MAIN-2024-10-index?url=*.{self.domain}&output=json&limit=100"
            resp = self.http.get(url, timeout=15)
            if resp and resp.status_code == 200:
                for line in resp.text.splitlines():
                    try:
                        data = json.loads(line)
                        url_val = data.get('url', '')
                        from urllib.parse import urlparse
                        parsed = urlparse(url_val)
                        if parsed.netloc:
                            self._add(parsed.netloc)
                    except Exception:
                        pass
        except Exception:
            pass

    # ─── Active DNS Brute-Force ───────────────────────────────────────────────

    def _dns_bruteforce(self):
        """DNS brute-force using built-in wordlist."""
        wordlist = BUILTIN_WORDLIST

        # Load custom wordlist if provided
        if self.config.get('wordlist') and os.path.isfile(self.config['wordlist']):
            with open(self.config['wordlist']) as f:
                wordlist = [line.strip() for line in f if line.strip()]

        print(f"    [~] DNS brute-force with {len(wordlist)} words...")

        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2

        def check(word):
            fqdn = f"{word}.{self.domain}"
            try:
                resolver.resolve(fqdn, 'A')
                self._add(fqdn)
                return fqdn
            except Exception:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            list(ex.map(check, wordlist))

    def _validate_subdomains(self):
        """Re-validate all found subdomains with DNS."""
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2

        validated = set()
        for sub in list(self.found):
            try:
                resolver.resolve(sub, 'A')
                validated.add(sub)
            except Exception:
                pass
        self.found = validated
