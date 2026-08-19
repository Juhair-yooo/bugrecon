"""
Port Scanner Module
Fast TCP connect scan with service banner grabbing
"""

import socket
import concurrent.futures
from .utils import extract_domain

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
    443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900,
    6379, 8080, 8443, 8888, 9200, 9300, 27017, 27018,
    6379, 11211, 5000, 5001, 4000, 4443, 8000, 8001,
    8008, 8081, 8082, 8088, 8090, 8181, 8280, 8443,
    9000, 9001, 9090, 9999, 10000, 49152
]

SERVICE_MAP = {
    21:    'FTP',
    22:    'SSH',
    23:    'Telnet',
    25:    'SMTP',
    53:    'DNS',
    80:    'HTTP',
    110:   'POP3',
    143:   'IMAP',
    443:   'HTTPS',
    445:   'SMB',
    3306:  'MySQL',
    3389:  'RDP',
    5432:  'PostgreSQL',
    5900:  'VNC',
    6379:  'Redis',
    8080:  'HTTP-Alt',
    8443:  'HTTPS-Alt',
    9200:  'Elasticsearch',
    27017: 'MongoDB',
    11211: 'Memcached',
}

DANGEROUS_PORTS = {
    21:    'FTP often allows anonymous login or has known CVEs',
    23:    'Telnet transmits credentials in cleartext',
    3389:  'RDP exposed - check for BlueKeep (CVE-2019-0708)',
    5900:  'VNC may have weak/no authentication',
    6379:  'Redis without AUTH is exploitable for RCE',
    9200:  'Elasticsearch often unauthenticated - full DB access',
    27017: 'MongoDB often unauthenticated - full DB access',
    11211: 'Memcached DDoS amplification vector',
    445:   'SMB - check EternalBlue (MS17-010)',
}


class PortScanner:
    def __init__(self, config):
        self.threads = min(config.get('threads', 50), 200)
        self.timeout = min(config.get('timeout', 2), 3)

    def run(self, target, subdomains=None):
        hosts = [extract_domain(target)]
        if subdomains:
            hosts += [extract_domain(s) for s in (subdomains or [])[:10]]

        all_results = {}
        for host in hosts:
            print(f"    [~] Scanning {len(TOP_PORTS)} ports on {host}...")
            results = self._scan_host(host)
            all_results[host] = results
            for port, info in results.items():
                danger = f" ⚠ {DANGEROUS_PORTS[port]}" if port in DANGEROUS_PORTS else ""
                print(f"    [+] {host}:{port} {info['service']} OPEN{danger}")
        return all_results

    def _scan_host(self, host):
        open_ports = {}

        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((host, port))
                if result == 0:
                    banner = self._grab_banner(sock, port)
                    sock.close()
                    return port, {
                        'service': SERVICE_MAP.get(port, 'Unknown'),
                        'banner':  banner,
                        'warning': DANGEROUS_PORTS.get(port),
                    }
                sock.close()
            except Exception:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = [ex.submit(check_port, port) for port in TOP_PORTS]
            for f in concurrent.futures.as_completed(futures):
                res = f.result()
                if res:
                    port, info = res
                    open_ports[port] = info

        return open_ports

    def _grab_banner(self, sock, port):
        try:
            if port in (80, 8080, 8000, 8888):
                sock.send(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
            else:
                sock.send(b"\r\n")
            banner = sock.recv(256).decode('utf-8', errors='ignore').strip()
            return banner[:100] if banner else ''
        except Exception:
            return ''
