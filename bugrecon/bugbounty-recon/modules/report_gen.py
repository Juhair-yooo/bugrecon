"""
Report Generator Module
Outputs: Plain text, JSON, and full HTML report with vulnerability table
"""

import os
import json
from datetime import datetime
from .utils import normalize_target

SEVERITY_ORDER = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}
SEVERITY_COLORS = {
    'Critical': '#dc2626',
    'High':     '#ea580c',
    'Medium':   '#d97706',
    'Low':      '#16a34a',
    'Info':     '#2563eb',
}


class ReportGenerator:
    def __init__(self, config):
        self.config = config
        os.makedirs('reports', exist_ok=True)

    def generate(self, target, findings, output_format='all', scan_time=0, modules_run=None):
        ts       = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_t   = target.replace('/', '_').replace(':', '_')
        base     = os.path.join('reports', f"{safe_t}_{ts}")
        paths    = []

        all_vulns = self._collect_vulns(findings)
        meta = {
            'target':       target,
            'scan_time':    f"{scan_time:.1f}s",
            'scan_date':    datetime.now().isoformat(),
            'modules_run':  modules_run or [],
            'total_vulns':  len(all_vulns),
            'critical':     sum(1 for v in all_vulns if v.get('severity') == 'Critical'),
            'high':         sum(1 for v in all_vulns if v.get('severity') == 'High'),
            'medium':       sum(1 for v in all_vulns if v.get('severity') == 'Medium'),
            'low':          sum(1 for v in all_vulns if v.get('severity') == 'Low'),
        }

        if output_format in ('txt', 'all'):
            p = self._write_txt(base, meta, findings, all_vulns)
            paths.append(p)

        if output_format in ('json', 'all'):
            p = self._write_json(base, meta, findings, all_vulns)
            paths.append(p)

        if output_format in ('html', 'all'):
            p = self._write_html(base, meta, findings, all_vulns)
            paths.append(p)

        return paths

    def _collect_vulns(self, findings):
        vulns = []
        vuln_data = findings.get('vulnerabilities', {})
        for category, items in vuln_data.items():
            if isinstance(items, list):
                for item in items:
                    item['category'] = category
                    vulns.append(item)
        return sorted(vulns, key=lambda v: SEVERITY_ORDER.get(v.get('severity', 'Info'), 99))

    # ─── Text Report ──────────────────────────────────────────────────────────

    def _write_txt(self, base, meta, findings, vulns):
        path = base + '.txt'
        with open(path, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write(" BUGRECON - BUG BOUNTY RECON REPORT\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Target:       {meta['target']}\n")
            f.write(f"Scan Date:    {meta['scan_date']}\n")
            f.write(f"Scan Time:    {meta['scan_time']}\n")
            f.write(f"Modules Run:  {', '.join(meta['modules_run'])}\n\n")
            f.write(f"VULNERABILITY SUMMARY\n")
            f.write("-" * 40 + "\n")
            f.write(f"  Total:    {meta['total_vulns']}\n")
            f.write(f"  Critical: {meta['critical']}\n")
            f.write(f"  High:     {meta['high']}\n")
            f.write(f"  Medium:   {meta['medium']}\n")
            f.write(f"  Low:      {meta['low']}\n\n")

            # Subdomains
            subs = findings.get('subdomains', [])
            if subs:
                f.write(f"SUBDOMAINS FOUND ({len(subs)})\n")
                f.write("-" * 40 + "\n")
                for s in subs:
                    f.write(f"  {s}\n")
                f.write("\n")

            # Technologies
            tech = findings.get('technologies', {})
            if tech:
                f.write("TECHNOLOGIES DETECTED\n")
                f.write("-" * 40 + "\n")
                for host, techs in tech.items():
                    if techs:
                        f.write(f"  {host}: {', '.join(techs)}\n")
                f.write("\n")

            # Vulnerabilities
            f.write(f"VULNERABILITIES ({len(vulns)})\n")
            f.write("=" * 80 + "\n\n")
            for i, v in enumerate(vulns, 1):
                f.write(f"[{i}] {v.get('type', 'Unknown')} [{v.get('severity', 'Info')}]\n")
                f.write(f"    Detection Method: {v.get('technique', 'N/A')}\n")
                f.write(f"    URL:              {v.get('url', 'N/A')}\n")
                if v.get('parameter'):
                    f.write(f"    Parameter:        {v['parameter']}\n")
                if v.get('payload'):
                    f.write(f"    Payload:          {v['payload'][:80]}\n")
                f.write(f"    Evidence:         {v.get('evidence', 'N/A')}\n")
                f.write(f"    CVSS Score:       {v.get('cvss', 'N/A')}\n")
                f.write(f"    CWE:              {v.get('cwe', 'N/A')}\n")
                f.write(f"    Remediation:      {v.get('remediation', 'N/A')}\n")
                f.write("\n")

        print(f"    [+] TXT report: {path}")
        return path

    # ─── JSON Report ──────────────────────────────────────────────────────────

    def _write_json(self, base, meta, findings, vulns):
        path = base + '.json'
        output = {
            'meta':            meta,
            'subdomains':      findings.get('subdomains', []),
            'technologies':    findings.get('technologies', {}),
            'open_ports':      findings.get('ports', {}),
            'crawl_summary':   {
                'url_count':      len(findings.get('crawl', {}).get('urls', [])),
                'form_count':     len(findings.get('crawl', {}).get('forms', [])),
                'param_count':    len(findings.get('crawl', {}).get('params', [])),
                'js_files':       len(findings.get('crawl', {}).get('js_files', [])),
                'emails_found':   findings.get('crawl', {}).get('emails', []),
                'jwts_found':     list(findings.get('crawl', {}).get('jwts', [])),
                'internal_ips':   list(findings.get('crawl', {}).get('internal_ips', [])),
            },
            'vulnerabilities': vulns,
        }
        with open(path, 'w') as f:
            json.dump(output, f, indent=2, default=str)
        print(f"    [+] JSON report: {path}")
        return path

    # ─── HTML Report ──────────────────────────────────────────────────────────

    def _write_html(self, base, meta, findings, vulns):
        path = base + '.html'
        subs = findings.get('subdomains', [])
        tech = findings.get('technologies', {})
        ports = findings.get('ports', {})
        crawl = findings.get('crawl', {})

        vuln_rows = ''
        for v in vulns:
            sev   = v.get('severity', 'Info')
            color = SEVERITY_COLORS.get(sev, '#6b7280')
            vuln_rows += f"""
            <tr>
                <td><span class="badge" style="background:{color}">{sev}</span></td>
                <td><strong>{v.get('type','')}</strong></td>
                <td class="mono">{v.get('technique','')}</td>
                <td class="mono url-cell">{v.get('url','')}</td>
                <td class="mono">{v.get('parameter','') or '—'}</td>
                <td class="mono payload-cell">{(v.get('payload','') or '')[:60]}</td>
                <td>{v.get('evidence','')}</td>
                <td>{v.get('cvss','')}</td>
                <td>{v.get('cwe','')}</td>
                <td class="remediation">{v.get('remediation','')}</td>
            </tr>"""

        sub_list = '\n'.join(f'<li>{s}</li>' for s in subs) or '<li>None found</li>'
        tech_rows = ''
        for host, techs in tech.items():
            if techs:
                tech_rows += f'<tr><td class="mono">{host}</td><td>{", ".join(techs)}</td></tr>'

        port_rows = ''
        for host, open_ports in ports.items():
            for port, info in open_ports.items():
                warn = f'<span class="warn">⚠ {info["warning"]}</span>' if info.get('warning') else ''
                port_rows += f'<tr><td class="mono">{host}</td><td>{port}</td><td>{info["service"]}</td><td>{warn}</td></tr>'

        email_list = '\n'.join(f'<li>{e}</li>' for e in crawl.get('emails', [])) or '<li>None</li>'
        jwt_list   = '\n'.join(f'<li class="mono">{j[:60]}...</li>' for j in list(crawl.get('jwts', []))[:5]) or '<li>None</li>'
        ip_list    = '\n'.join(f'<li>{ip}</li>' for ip in crawl.get('internal_ips', [])) or '<li>None</li>'

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BugRecon Report – {meta['target']}</title>
<style>
  :root {{
    --bg: #0d1117; --bg2: #161b22; --bg3: #21262d;
    --border: #30363d; --text: #e6edf3; --muted: #8b949e;
    --critical: #dc2626; --high: #ea580c; --medium: #d97706;
    --low: #16a34a; --accent: #58a6ff;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; font-size: 14px; }}
  header {{ background: var(--bg2); border-bottom: 1px solid var(--border); padding: 24px 40px; }}
  header h1 {{ font-size: 22px; font-weight: 700; color: var(--accent); }}
  header p {{ color: var(--muted); margin-top: 4px; font-size: 13px; }}
  .container {{ max-width: 1600px; margin: 0 auto; padding: 32px 40px; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 16px; margin-bottom: 40px; }}
  .card {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 20px; }}
  .card .num {{ font-size: 36px; font-weight: 700; }}
  .card .label {{ color: var(--muted); font-size: 12px; margin-top: 4px; text-transform: uppercase; letter-spacing: .5px; }}
  .card.critical .num {{ color: var(--critical); }}
  .card.high .num {{ color: var(--high); }}
  .card.medium .num {{ color: var(--medium); }}
  .card.low .num {{ color: var(--low); }}
  .section {{ margin-bottom: 40px; }}
  .section h2 {{ font-size: 16px; font-weight: 600; color: var(--accent); margin-bottom: 16px; padding-bottom: 8px; border-bottom: 1px solid var(--border); }}
  table {{ width: 100%; border-collapse: collapse; background: var(--bg2); border-radius: 8px; overflow: hidden; }}
  th {{ background: var(--bg3); color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .5px; padding: 10px 14px; text-align: left; }}
  td {{ padding: 10px 14px; border-top: 1px solid var(--border); vertical-align: top; }}
  tr:hover td {{ background: rgba(255,255,255,0.02); }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; color: #fff; white-space: nowrap; }}
  .mono {{ font-family: 'SFMono-Regular', Consolas, monospace; font-size: 12px; color: #79c0ff; }}
  .url-cell {{ max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
  .payload-cell {{ max-width: 160px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: #ff7b72; }}
  .remediation {{ max-width: 200px; font-size: 12px; color: var(--muted); }}
  .warn {{ color: var(--high); font-size: 12px; }}
  ul {{ list-style: none; padding: 0; }}
  ul li {{ padding: 6px 0; border-bottom: 1px solid var(--border); font-family: monospace; font-size: 13px; color: #79c0ff; }}
  ul li:last-child {{ border: none; }}
  .grid2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }}
  .grid3 {{ display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 24px; }}
  footer {{ text-align: center; color: var(--muted); font-size: 12px; padding: 32px; border-top: 1px solid var(--border); }}
</style>
</head>
<body>
<header>
  <h1>🔍 BugRecon — Vulnerability Report</h1>
  <p>Target: <strong>{meta['target']}</strong> &nbsp;|&nbsp; Scan Date: {meta['scan_date']} &nbsp;|&nbsp; Duration: {meta['scan_time']} &nbsp;|&nbsp; Modules: {', '.join(meta['modules_run'])}</p>
</header>
<div class="container">

  <div class="summary-grid">
    <div class="card"><div class="num">{meta['total_vulns']}</div><div class="label">Total Findings</div></div>
    <div class="card critical"><div class="num">{meta['critical']}</div><div class="label">Critical</div></div>
    <div class="card high"><div class="num">{meta['high']}</div><div class="label">High</div></div>
    <div class="card medium"><div class="num">{meta['medium']}</div><div class="label">Medium</div></div>
    <div class="card low"><div class="num">{meta['low']}</div><div class="label">Low</div></div>
  </div>

  <div class="section">
    <h2>⚠ Vulnerabilities ({len(vulns)})</h2>
    <table>
      <thead><tr>
        <th>Severity</th><th>Type</th><th>Detection Method</th><th>URL</th>
        <th>Parameter</th><th>Payload</th><th>Evidence</th>
        <th>CVSS</th><th>CWE</th><th>Remediation</th>
      </tr></thead>
      <tbody>{vuln_rows}</tbody>
    </table>
  </div>

  <div class="grid2">
    <div class="section">
      <h2>🌐 Subdomains ({len(subs)})</h2>
      <div class="card"><ul>{sub_list}</ul></div>
    </div>
    <div class="section">
      <h2>🔬 Technologies</h2>
      <table><thead><tr><th>Host</th><th>Stack</th></tr></thead>
      <tbody>{tech_rows or '<tr><td colspan=2>None detected</td></tr>'}</tbody></table>
    </div>
  </div>

  <div class="section">
    <h2>🔌 Open Ports</h2>
    <table><thead><tr><th>Host</th><th>Port</th><th>Service</th><th>Warning</th></tr></thead>
    <tbody>{port_rows or '<tr><td colspan=4>None found</td></tr>'}</tbody></table>
  </div>

  <div class="grid3">
    <div class="section">
      <h2>📧 Emails Found</h2>
      <div class="card"><ul>{email_list}</ul></div>
    </div>
    <div class="section">
      <h2>🔑 JWT Tokens</h2>
      <div class="card"><ul>{jwt_list}</ul></div>
    </div>
    <div class="section">
      <h2>🏠 Internal IPs Leaked</h2>
      <div class="card"><ul>{ip_list}</ul></div>
    </div>
  </div>

</div>
<footer>Generated by BugRecon v2.0.0 | For authorized security testing only</footer>
</body>
</html>"""

        with open(path, 'w') as f:
            f.write(html)
        print(f"    [+] HTML report: {path}")
        return path
