"""
Utility helpers: Colors, Logger, Banner, HTTP helpers.
"""

import os
import sys
import time
import logging
import requests
import urllib3
from datetime import datetime
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Colors:
    def __init__(self, disabled=False):
        self.disabled = disabled

    def _c(self, code, text):
        if self.disabled:
            return text
        return f"\033[{code}m{text}\033[0m"

    def red(self, t):     return self._c("91", t)
    def green(self, t):   return self._c("92", t)
    def yellow(self, t):  return self._c("93", t)
    def blue(self, t):    return self._c("94", t)
    def magenta(self, t): return self._c("95", t)
    def cyan(self, t):    return self._c("96", t)
    def bold(self, t):    return self._c("1",  t)
    def dim(self, t):     return self._c("2",  t)
    def white(self, t):   return self._c("97", t)


class Logger:
    def __init__(self, verbose=False, silent=False, log_file=None, colors=True):
        self.verbose = verbose
        self.silent  = silent
        self.c       = Colors(disabled=not colors)
        self._setup_file_logger(log_file)

    def _setup_file_logger(self, log_file):
        self._flog = None
        if log_file:
            logging.basicConfig(
                filename=log_file,
                level=logging.DEBUG,
                format='%(asctime)s [%(levelname)s] %(message)s'
            )
            self._flog = logging.getLogger('recon')

    def _log(self, msg):
        if self._flog:
            self._flog.info(msg)

    def info(self, msg):
        if not self.silent:
            print(f"  {self.c.cyan('[*]')} {msg}")
        self._log(f"[INFO] {msg}")

    def success(self, msg):
        print(f"  {self.c.green('[+]')} {msg}")
        self._log(f"[SUCCESS] {msg}")

    def warn(self, msg):
        if not self.silent:
            print(f"  {self.c.yellow('[!]')} {msg}")
        self._log(f"[WARN] {msg}")

    def error(self, msg):
        print(f"  {self.c.red('[✗]')} {msg}", file=sys.stderr)
        self._log(f"[ERROR] {msg}")

    def critical(self, msg):
        print(f"  {self.c.red(self.c.bold('[VULN]'))} {msg}")
        self._log(f"[VULN] {msg}")

    def result(self, msg):
        print(f"  {self.c.green('[✓]')} {msg}")
        self._log(f"[RESULT] {msg}")

    def debug(self, msg):
        if self.verbose:
            print(f"  {self.c.dim('[~]')} {msg}")
        self._log(f"[DEBUG] {msg}")

    def section(self, title):
        if not self.silent:
            bar = "─" * 60
            print(f"\n  {self.c.bold(self.c.blue(f'┌── {title}'))}")
            print(f"  {self.c.blue('└' + bar)}")

    def banner(self, msg):
        print(f"  {self.c.magenta('◈')} {self.c.bold(msg)}")


class Banner:
    @staticmethod
    def print():
        art = """
\033[91m  ██████╗ ██╗   ██╗ ██████╗ ██████╗  ██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗
  ██╔══██╗██║   ██║██╔════╝ ██╔══██╗██╔═══██╗██║   ██║████╗  ██║╚══██╔══╝╚██╗ ██╔╝
  ██████╔╝██║   ██║██║  ███╗██████╔╝██║   ██║██║   ██║██╔██╗ ██║   ██║    ╚████╔╝ 
  ██╔══██╗██║   ██║██║   ██║██╔══██╗██║   ██║██║   ██║██║╚██╗██║   ██║     ╚██╔╝  
  ██████╔╝╚██████╔╝╚██████╔╝██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║   ██║      ██║   
  ╚═════╝  ╚═════╝  ╚═════╝ ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝      ╚═╝\033[0m
\033[93m         ╔═══════════════════════════════════════════════════════╗
         ║   Bug Bounty Reconnaissance & Vulnerability Framework  ║
         ║          For authorized testing only • v2.0.0          ║
         ╚═══════════════════════════════════════════════════════╝\033[0m
"""
        print(art)


class HTTPClient:
    """Shared HTTP client with retry, proxy, and rate-limit support."""

    def __init__(self, config):
        self.session   = requests.Session()
        self.timeout   = config.get('timeout', 10)
        self.proxies   = config.get('proxies')
        self.headers   = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
            **config.get('headers', {})
        }
        self.rate_limit = config.get('rate_limit', 0)
        self._last_req  = 0

    def get(self, url, **kwargs):
        return self._request('GET', url, **kwargs)

    def post(self, url, **kwargs):
        return self._request('POST', url, **kwargs)

    def _request(self, method, url, **kwargs):
        if self.rate_limit > 0:
            elapsed = time.time() - self._last_req
            gap = 1.0 / self.rate_limit
            if elapsed < gap:
                time.sleep(gap - elapsed)
        try:
            resp = self.session.request(
                method, url,
                headers=self.headers,
                proxies=self.proxies,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
                **kwargs
            )
            self._last_req = time.time()
            return resp
        except Exception:
            return None


def normalize_target(target):
    """Ensure target has a scheme."""
    if not target.startswith(('http://', 'https://')):
        return f"https://{target}"
    return target


def extract_domain(target):
    """Extract bare domain from URL or domain string."""
    if target.startswith(('http://', 'https://')):
        return urlparse(target).netloc
    return target.split('/')[0]
