#!/usr/bin/env python3
"""
Phase 3 — AI Security Report Generator.

Reads scan results and asks Claude to write a narrative security report.

Environment variables required:
  ANTHROPIC_API_KEY
  REPORTS_DIR   (default: reports/)

Output:
  reports/security-report.md
"""

import os
import sys
import json
import requests
from pathlib import Path
from datetime import date

ANTHROPIC_API_KEY = os.environ.get('ANTHROPIC_API_KEY', '')
REPORTS_DIR       = Path(os.environ.get('REPORTS_DIR', 'reports'))
MODEL             = 'claude-sonnet-4-6'


def read_json(path):
    try:
        with open(path) as f: return json.load(f)
    except Exception: return None


def ask_claude(prompt):
    print(f'[report] Calling model: {MODEL}')
    r = requests.post(
        'https://api.anthropic.com/v1/messages',
        headers={'x-api-key': ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json'},
        json={'model': MODEL, 'max_tokens': 4096, 'messages': [{'role': 'user', 'content': prompt}]},
        timeout=120,
    )
    if r.status_code != 200:
        raise Exception(f'{r.status_code}: {r.text[:400]}')
    return r.json()['content'][0]['text']


def build_prompt(triage_summary, zap_data, npm_data, checkov_data):
    today = date.today().isoformat()
    sections = []
    if triage_summary:
        v = triage_summary.get('verdicts', {})
        fl = triage_summary.get('findings', [])
        lines = ['## AI Triage Results', f"- Total: {triage_summary.get('total', 0)}",
                 f"- True positives: {v.get('true_positive', 0)}",
                 f"- False positives: {v.get('false_positive', 0)}",
                 f"- Needs review: {v.get('needs_review', 0)}", '']
        for f in fl[:20]:
            lines.append(f"- [{f.get('severity','?')}] {f.get('title','Unknown')} ({f.get('file_path','N/A')})")
        sections.append('\n'.join(lines))
    if zap_data:
        site = zap_data.get('site', [])
        alerts = site[0].get('alerts', []) if isinstance(site, list) and site else []
        lines = [f'## DAST Findings (ZAP) - {len(alerts)} alerts']
        for a in alerts[:10]: lines.append(f"- [{a.get('riskdesc','?')}] {a.get('alert','Unknown')}")
        sections.append('\n'.join(lines))
    if npm_data:
        meta = npm_data.get('metadata', {}).get('vulnerabilities', {})
        sections.append(f"## npm audit\n- Critical: {meta.get('critical',0)} High: {meta.get('high',0)} Moderate: {meta.get('moderate',0)} Low: {meta.get('low',0)}")
    if checkov_data:
        s = checkov_data.get('summary', {})
        sections.append(f"## Checkov IaC Scan\n- Passed: {s.get('passed',0)} Failed: {s.get('failed',0)} Skipped: {s.get('skipped',0)}")
    data_block = '\n\n'.join(sections) if sections else 'No scan data available.'
    return f"""You are a senior security consultant writing a formal security assessment report.
Date: {today}
Project: mcp-sec-demo DevSecOps Pipeline

Scan data:
{data_block}

Write a professional Markdown security report with:
1. Executive Summary (non-technical, for management)
2. Methodology
3. Key Findings (by severity)
4. Risk Assessment
5. Recommendations (prioritised)
6. Conclusion

Include a findings summary table. Be concise and actionable."""


def main():
    if not ANTHROPIC_API_KEY:
        print('[report] ANTHROPIC_API_KEY not set — skipping'); sys.exit(0)
    REPORTS_DIR.mkdir(exist_ok=True)
    triage  = read_json(REPORTS_DIR / 'triage-summary.json')
    zap     = read_json(REPORTS_DIR / 'zap-report.json')
    npm     = read_json(REPORTS_DIR / 'npm-audit.json')
    checkov = read_json(REPORTS_DIR / 'results_json.json')
    if not any([triage, zap, npm, checkov]):
        print('[report] No scan data found — skipping'); sys.exit(0)
    print('[report] Generating report with Claude...')
    try:
        report = ask_claude(build_prompt(triage, zap, npm, checkov))
    except Exception as e:
        print(f'[report] Failed: {e}'); sys.exit(1)
    out = REPORTS_DIR / 'security-report.md'
    out.write_text(report)
    print(f'[report] Written to {out} ({len(report)} chars)')
    print('[report] Done.')


if __name__ == '__main__':
    main()
