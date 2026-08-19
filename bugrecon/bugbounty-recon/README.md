# 🔍 BugRecon — Bug Bounty Recon Framework

> Full-automated vulnerability reconnaissance tool built for Kali Linux.  
> Point it at a target, get a line-by-line vulnerability report with names, techniques, and remediation.

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-red)
![License](https://img.shields.io/badge/License-MIT-green)
![Usage](https://img.shields.io/badge/For-Authorized%20Testing%20Only-critical)

---

## ⚡ What It Does

You give it a domain. It gives you:

- **Every vulnerability found**, line by line — type, technique used, URL, parameter, payload, CVSS score, CWE ID
- **Subdomain enumeration** from crt.sh, HackerTarget, AlienVault OTX, CommonCrawl + DNS brute-force
- **Port scanning** with banner grabbing and dangerous-port warnings
- **Technology fingerprinting** — web server, framework, CMS, CDN, WAF, JS libs
- **Web crawling** — URLs, forms, parameters, JS files, API endpoints, JWT tokens, internal IPs
- **SQL Injection** — Error-based, Boolean-blind, Time-based blind
- **XSS** — Reflected, DOM hints, WAF bypass payloads
- **SSRF** — AWS/GCP/Azure metadata, localhost, file:// scheme, URL bypass encodings
- **CORS Misconfiguration** — wildcard, null origin, credential leaks, origin reflection
- **Open Redirect** — all common redirect parameter names, bypass encodings
- **Secrets Discovery** — 30+ patterns: AWS keys, GitHub tokens, Stripe, Slack, JWTs, private keys, `.env` files
- **Security Headers** — HSTS, CSP, X-Frame-Options, and 4 more
- **SSL/TLS** — expiry, cleartext HTTP access
- **Admin Panel Discovery** — 20+ common paths
- **Directory Listing** detection
- **Information Disclosure** — Spring Actuator, phpinfo, .git exposure, server-status
- **WordPress-specific** checks — REST API user enum, xmlrpc.php, debug.log
- **Cookie Security** — HttpOnly, Secure, SameSite flag analysis

**Report formats:** `.txt` (plain), `.json` (machine-readable), `.html` (dark-themed interactive table)

---

## 📦 Installation

```bash
# Clone
git clone https://github.com/yourusername/bugrecon.git
cd bugrecon

# Install dependencies
pip install -r requirements.txt

# Make executable
chmod +x recon.py
```

---

## 🚀 Usage

```bash
# Basic scan (default modules)
python3 recon.py -t example.com

# Full scan — all modules enabled
python3 recon.py -t example.com --full

# Specific modules only
python3 recon.py -t example.com --modules sqli,xss,cors,secrets

# Skip subdomain enum (faster, single target)
python3 recon.py -t example.com --no-subdomain

# Route through Burp Suite
python3 recon.py -t example.com --proxy http://127.0.0.1:8080

# Authenticated scan with session cookie
python3 recon.py -t app.example.com --cookies "session=abc123; auth=xyz"

# Custom auth header (JWT / Bearer)
python3 recon.py -t api.example.com --headers '{"Authorization":"Bearer eyJ..."}'

# Control threads, timeout, crawl depth
python3 recon.py -t example.com --threads 100 --timeout 5 --depth 5

# Rate-limited (10 req/sec) — stealthier
python3 recon.py -t example.com --rate-limit 10

# JSON output only
python3 recon.py -t example.com --output json

# Verbose + custom wordlist for DNS brute-force
python3 recon.py -t example.com --wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -v
```

---

## 📁 Output

```
reports/
├── example.com_20240819_143022.txt     ← Plain text report
├── example.com_20240819_143022.json    ← Machine-readable
└── example.com_20240819_143022.html    ← Interactive HTML

logs/
└── example.com_20240819_143022.log     ← Full scan log
```

### Sample HTML Report
Dark-themed table with severity badges, sortable columns, CVSS scores, CWE IDs, and remediation advice per finding.

---

## 🧩 Module Reference

| Module | Flag | What it does |
|--------|------|-------------|
| `subdomains` | default | crt.sh + APIs + DNS brute-force |
| `ports` | `--full` | TCP connect scan top 50 ports |
| `tech` | default | Header/body/cookie fingerprinting |
| `crawl` | default | Spider URLs, forms, params, JS files |
| `sqli` | default | Error, boolean-blind, time-blind SQLi |
| `xss` | default | Reflected XSS + WAF bypass payloads |
| `ssrf` | `--full` | Cloud metadata, localhost, file:// |
| `cors` | default | Origin reflection, null origin, wildcard |
| `redirect` | default | Open redirect via 20+ param names |
| `secrets` | default | 30+ regex patterns + 40+ sensitive paths |

---

## 📋 Vulnerability Report Fields

Every finding includes:

| Field | Description |
|-------|-------------|
| `type` | Vulnerability class name |
| `technique` | Exactly how it was detected |
| `url` | Affected endpoint |
| `parameter` | Vulnerable parameter (if applicable) |
| `payload` | Exact payload that triggered it |
| `evidence` | What confirmed the vulnerability |
| `severity` | Critical / High / Medium / Low |
| `cvss` | CVSS 3.1 base score |
| `cwe` | CWE identifier |
| `remediation` | How to fix it |

---

## ⚙ Config Tips

**Best with SecLists:**
```bash
sudo apt install seclists
python3 recon.py -t example.com \
  --wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
```

**With Burp Suite for manual review:**
```bash
python3 recon.py -t example.com --proxy http://127.0.0.1:8080 --full
# All requests flow through Burp — review in HTTP history
```

**Stealth mode:**
```bash
python3 recon.py -t example.com --rate-limit 5 --threads 10 --timeout 15
```

---

## ⚠️ Legal Disclaimer

This tool is for **authorized penetration testing and bug bounty programs only**.  
Only run this against targets you have **explicit written permission** to test.  
Unauthorized use is illegal under computer fraud laws worldwide.  
The author assumes no liability for misuse.

---

## 📄 License

MIT License — see `LICENSE` for details.
