#!/usr/bin/env python3
"""
██████╗ ██╗   ██╗ ██████╗ ██████╗  ██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗
██╔══██╗██║   ██║██╔════╝ ██╔══██╗██╔═══██╗██║   ██║████╗  ██║╚══██╔══╝╚██╗ ██╔╝
██████╔╝██║   ██║██║  ███╗██████╔╝██║   ██║██║   ██║██╔██╗ ██║   ██║    ╚████╔╝ 
██╔══██╗██║   ██║██║   ██║██╔══██╗██║   ██║██║   ██║██║╚██╗██║   ██║     ╚██╔╝  
██████╔╝╚██████╔╝╚██████╔╝██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║   ██║      ██║   
╚═════╝  ╚═════╝  ╚═════╝ ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝      ╚═╝  
                        Bug Bounty Reconnaissance Framework
                        Author: Jarir | Version: 2.0.0
"""

import argparse
import sys
import os
import json
import time
from datetime import datetime
from pathlib import Path

# Add modules directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'modules'))

from modules.subdomain_enum import SubdomainEnumerator
from modules.port_scanner import PortScanner
from modules.web_crawler import WebCrawler
from modules.vuln_scanner import VulnScanner
from modules.tech_detector import TechDetector
from modules.sqli_tester import SQLiTester
from modules.xss_tester import XSSTester
from modules.ssrf_tester import SSRFTester
from modules.open_redirect import OpenRedirectTester
from modules.secrets_finder import SecretsFinder
from modules.cors_tester import CORSTester
from modules.report_gen import ReportGenerator
from modules.utils import Colors, Logger, Banner

def parse_args():
    parser = argparse.ArgumentParser(
        description='BugBounty Recon Framework - Full Automated Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 recon.py -t example.com
  python3 recon.py -t example.com --full
  python3 recon.py -t example.com --modules sqli,xss,cors
  python3 recon.py -t example.com --output json
  python3 recon.py -t https://app.example.com --no-subdomain
        """
    )
    parser.add_argument('-t', '--target',    required=True,  help='Target domain (e.g. example.com)')
    parser.add_argument('--full',            action='store_true', help='Run ALL modules (max depth)')
    parser.add_argument('--modules',         help='Comma-separated modules: sqli,xss,ssrf,cors,redirect,secrets,ports,tech,crawl,subdomains')
    parser.add_argument('--no-subdomain',    action='store_true', help='Skip subdomain enumeration')
    parser.add_argument('--output',          choices=['txt','json','html','all'], default='all', help='Report format')
    parser.add_argument('--threads',         type=int, default=50, help='Thread count (default: 50)')
    parser.add_argument('--timeout',         type=int, default=10, help='Request timeout seconds (default: 10)')
    parser.add_argument('--wordlist',        help='Custom wordlist path for fuzzing')
    parser.add_argument('--depth',           type=int, default=3, help='Crawl depth (default: 3)')
    parser.add_argument('--proxy',           help='Proxy URL (e.g. http://127.0.0.1:8080 for Burp)')
    parser.add_argument('--cookies',         help='Session cookies (e.g. "session=abc123")')
    parser.add_argument('--headers',         help='Custom headers JSON (e.g. \'{"Authorization":"Bearer token"}\')')
    parser.add_argument('--rate-limit',      type=int, default=0, help='Requests per second limit (0=unlimited)')
    parser.add_argument('--no-color',        action='store_true', help='Disable colored output')
    parser.add_argument('--verbose', '-v',   action='store_true', help='Verbose output')
    parser.add_argument('--silent',          action='store_true', help='Only show critical findings')
    return parser.parse_args()


def resolve_modules(args):
    """Determine which modules to run."""
    all_modules = ['subdomains','ports','tech','crawl','sqli','xss','ssrf','cors','redirect','secrets']
    
    if args.full:
        return all_modules
    
    if args.modules:
        requested = [m.strip().lower() for m in args.modules.split(',')]
        return [m for m in requested if m in all_modules]
    
    # Default: run everything except brute-force intensive ones
    return ['subdomains','tech','crawl','sqli','xss','cors','redirect','secrets']


def run_scan(args, logger):
    c = Colors(disabled=args.no_color)
    start_time = datetime.now()
    
    # Parse custom headers
    custom_headers = {}
    if args.headers:
        try:
            custom_headers = json.loads(args.headers)
        except json.JSONDecodeError:
            logger.error("Invalid JSON for --headers. Skipping.")
    
    # Parse cookies
    if args.cookies:
        custom_headers['Cookie'] = args.cookies

    # Proxy config
    proxies = None
    if args.proxy:
        proxies = {'http': args.proxy, 'https': args.proxy}
        logger.info(f"Using proxy: {args.proxy}")

    config = {
        'target':      args.target,
        'threads':     args.threads,
        'timeout':     args.timeout,
        'depth':       args.depth,
        'proxies':     proxies,
        'headers':     custom_headers,
        'wordlist':    args.wordlist,
        'verbose':     args.verbose,
        'rate_limit':  args.rate_limit,
    }

    modules_to_run = resolve_modules(args)
    if args.no_subdomain and 'subdomains' in modules_to_run:
        modules_to_run.remove('subdomains')

    logger.banner(f"Target: {args.target}")
    logger.banner(f"Modules: {', '.join(modules_to_run)}")
    logger.banner(f"Threads: {args.threads} | Timeout: {args.timeout}s | Depth: {args.depth}")
    print()

    all_findings = {}
    discovered_urls = set()
    discovered_subdomains = []

    # ─── SUBDOMAIN ENUMERATION ────────────────────────────────────────────────
    if 'subdomains' in modules_to_run:
        logger.section("SUBDOMAIN ENUMERATION")
        enumerator = SubdomainEnumerator(config)
        discovered_subdomains = enumerator.run()
        all_findings['subdomains'] = discovered_subdomains
        logger.result(f"Found {len(discovered_subdomains)} subdomains")

    # ─── PORT SCANNING ────────────────────────────────────────────────────────
    if 'ports' in modules_to_run:
        logger.section("PORT SCANNING")
        scanner = PortScanner(config)
        port_results = scanner.run(args.target, discovered_subdomains)
        all_findings['ports'] = port_results
        open_count = sum(len(v) for v in port_results.values())
        logger.result(f"Found {open_count} open ports across all hosts")

    # ─── TECH DETECTION ───────────────────────────────────────────────────────
    if 'tech' in modules_to_run:
        logger.section("TECHNOLOGY FINGERPRINTING")
        detector = TechDetector(config)
        tech_results = detector.run(args.target, discovered_subdomains)
        all_findings['technologies'] = tech_results
        detected = [k for k, v in tech_results.items() if v]
        logger.result(f"Detected technologies on {len(detected)} hosts")

    # ─── WEB CRAWLING ─────────────────────────────────────────────────────────
    if 'crawl' in modules_to_run:
        logger.section(f"WEB CRAWLING (depth={args.depth})")
        crawler = WebCrawler(config)
        crawl_results = crawler.run(args.target)
        discovered_urls = crawl_results['urls']
        all_findings['crawl'] = crawl_results
        logger.result(f"Discovered {len(discovered_urls)} URLs | {len(crawl_results.get('forms', []))} forms | {len(crawl_results.get('params', []))} parameters")

    # ─── VULNERABILITY MODULES ────────────────────────────────────────────────
    vuln_findings = {}

    if 'sqli' in modules_to_run:
        logger.section("SQL INJECTION TESTING")
        tester = SQLiTester(config)
        sqli_results = tester.run(args.target, discovered_urls)
        vuln_findings['sqli'] = sqli_results
        _log_vuln_count(logger, sqli_results, "SQLi")

    if 'xss' in modules_to_run:
        logger.section("XSS TESTING")
        tester = XSSTester(config)
        xss_results = tester.run(args.target, discovered_urls)
        vuln_findings['xss'] = xss_results
        _log_vuln_count(logger, xss_results, "XSS")

    if 'ssrf' in modules_to_run:
        logger.section("SSRF TESTING")
        tester = SSRFTester(config)
        ssrf_results = tester.run(args.target, discovered_urls)
        vuln_findings['ssrf'] = ssrf_results
        _log_vuln_count(logger, ssrf_results, "SSRF")

    if 'cors' in modules_to_run:
        logger.section("CORS MISCONFIGURATION TESTING")
        tester = CORSTester(config)
        cors_results = tester.run(args.target, discovered_urls)
        vuln_findings['cors'] = cors_results
        _log_vuln_count(logger, cors_results, "CORS")

    if 'redirect' in modules_to_run:
        logger.section("OPEN REDIRECT TESTING")
        tester = OpenRedirectTester(config)
        redirect_results = tester.run(args.target, discovered_urls)
        vuln_findings['redirect'] = redirect_results
        _log_vuln_count(logger, redirect_results, "Open Redirect")

    if 'secrets' in modules_to_run:
        logger.section("SECRETS & SENSITIVE DATA DISCOVERY")
        finder = SecretsFinder(config)
        secrets_results = finder.run(args.target, discovered_urls)
        vuln_findings['secrets'] = secrets_results
        _log_vuln_count(logger, secrets_results, "Secrets")

    all_findings['vulnerabilities'] = vuln_findings

    # ─── GENERAL VULN SCAN ────────────────────────────────────────────────────
    logger.section("GENERAL VULNERABILITY ANALYSIS")
    general_scanner = VulnScanner(config)
    general_results = general_scanner.run(args.target, discovered_urls, all_findings.get('technologies', {}))
    vuln_findings['general'] = general_results
    _log_vuln_count(logger, general_results, "General")

    # ─── REPORT GENERATION ────────────────────────────────────────────────────
    logger.section("GENERATING REPORT")
    elapsed = (datetime.now() - start_time).total_seconds()
    
    report_gen = ReportGenerator(config)
    report_paths = report_gen.generate(
        target=args.target,
        findings=all_findings,
        output_format=args.output,
        scan_time=elapsed,
        modules_run=modules_to_run
    )

    print()
    logger.success("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    logger.success(f"  Scan completed in {elapsed:.1f}s")
    logger.success(f"  Reports saved to: {', '.join(report_paths)}")
    
    # Print summary
    total_vulns = sum(
        len(v) for v in vuln_findings.values() if isinstance(v, list)
    )
    logger.success(f"  Total vulnerabilities found: {total_vulns}")
    logger.success("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print()

    return all_findings


def _log_vuln_count(logger, results, label):
    count = len(results) if isinstance(results, list) else 0
    if count > 0:
        logger.critical(f"  [{label}] {count} potential vulnerabilities found!")
    else:
        logger.info(f"  [{label}] No vulnerabilities detected")


def main():
    Banner.print()
    args = parse_args()
    
    # Setup logger
    log_file = os.path.join('logs', f"{args.target.replace('/', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    os.makedirs('logs', exist_ok=True)
    logger = Logger(verbose=args.verbose, silent=args.silent, log_file=log_file, colors=not args.no_color)
    
    try:
        findings = run_scan(args, logger)
    except KeyboardInterrupt:
        print("\n")
        logger.warn("Scan interrupted by user. Partial results may be saved.")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
