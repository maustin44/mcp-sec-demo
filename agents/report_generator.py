#!/usr/bin/env python3
"""
Phase 3 — AI Security Report Generator.

Reads the triage summary from context_triage_agent.py and asks Claude
to write a narrative security report suitable for presenting to the client.

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
MODEL             = 'claude-sonnet-4-20250514'


def read_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def ask_claude(prompt):
    r = requests.post(
        'https://api.anthropic.com/v1/messages',
        headers={
            'x-api-key': ANTHROPIC_API_KEY,
            'anthropic-version': '2023-06-01',
            'content-type': 'application/json',
        },
        json={
            'model': MODEL,
            'max_tokens': 4096,
            'messages': [{'role': 'user', 'content': prompt}],
        },
        timeout=120,
    )
    r.raise_for_status()
    return r.json()['content'][0]['text']


def build_prompt(triage_summary, zap_data, npm_data, checkov_data):
    today = date.today().isoformat()

    findings_text = ''
    if triage_summary:
        verdicts = triage_summary.get('verdicts', {})
        findings_list = triage_summary.get('findings', [])
        findings_text = f"""
## AI Triage Results
- Total findings triaged: {triage_summary.get('total', 0)}
- True positives: {verdicts.get('true_positive', 0)}
- False positives: {verdicts.get('false_positive', 0)}
- Needs review: {verdicts.get('needs_review', 0)}

Findings:
"""
        for f in findings_list[:20]:
            findings_text += f"- [{f.get('severity', '?')}] {f.get('title', 'Unknown')} ({f.get('file_path', 'N/A')})\n"

    zap_text = ''
    if zap_data:
        alerts = zap_data.get('site', [{}])[0].get('alerts', []) if isinstance(zap_data.get('site'), list) else []
        zap_text = f'\n## DAST Findings (OWASP ZAP)\n- Alerts found: {len(alerts)}\n'
        for a in alerts[:10]:
            zap_text += f"- [{a.get('riskdesc', '?')}] {a.get('alert', 'Unknown')}\n"

    npm_text = ''
    if npm_data:
        vulns = npm_data.get('vulnerabilities', {})
        meta  = npm_data.get('metadata', {}).get('vulnerabilities', {})
        npm_text = f"""\n## Dependency Vulnerabilities (npm audit)\n- Critical: {meta.get('critical', 0)}\n- High: {meta.get('high', 0)}\n- Moderate: {meta.get('moderate', 0)}\n- Low: {meta.get('low', 0)}\n"""

    checkov_text = ''
    if checkov_data:
        summary = checkov_data.get('summary', {})
        checkov_text = f"""\n## IaC Misconfiguration Scan (Checkov)\n- Passed: {summary.get('passed', 0)}\n- Failed: {summary.get('failed', 0)}\n- Skipped: {summary.get('skipped', 0)}\n"""

    return f"""You are a senior security consultant writing a formal security assessment report.

Date: {today}
Project: mcp-sec-demo DevSecOps Pipeline
Client: Security stakeholder

You have the following scan data from an automated security pipeline:
{findings_text}
{zap_text}
{npm_text}
{checkov_text}

Write a professional security report in Markdown format with these sections:
1. Executive Summary (2-3 paragraphs, non-technical, suitable for management)
2. Methodology (brief description of tools and approach used)
3. Key Findings (organised by severity, with AI triage context)
4. Risk Assessment (overall risk rating with justification)
5. Recommendations (prioritised action items)
6. Conclusion

Tone: Professional, clear, and actionable. Avoid excessive jargon.
Format: Valid Markdown with headers, bullet points, and a summary table."""


def main():
    if not ANTHROPIC_API_KEY:
        print('[report] ANTHROPIC_API_KEY not set — skipping')
        sys.exit(0)

    REPORTS_DIR.mkdir(exist_ok=True)

    print('[report] Reading scan results...')
    triage_summary = read_json(REPORTS_DIR / 'triage-summary.json')
    zap_data       = read_json(REPORTS_DIR / 'zap-report.json')
    npm_data       = read_json(REPORTS_DIR / 'npm-audit.json')
    checkov_data   = read_json(REPORTS_DIR / 'results_json.json')

    if not any([triage_summary, zap_data, npm_data, checkov_data]):
        print('[report] No scan data found in reports/ — nothing to report')
        sys.exit(0)

    print('[report] Asking Claude to generate security report...')
    prompt = build_prompt(triage_summary, zap_data, npm_data, checkov_data)
    report = ask_claude(prompt)

    report_path = REPORTS_DIR / 'security-report.md'
    with open(report_path, 'w') as f:
        f.write(report)

    print(f'[report] Report written to {report_path}')
    print(f'[report] Report length: {len(report)} characters')
    print('[report] Done.')


if __name__ == '__main__':
    main()
