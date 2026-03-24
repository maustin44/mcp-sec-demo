#!/usr/bin/env python3
"""
Phase 3 — AI Context Triage Agent.

Pulls open findings from DefectDojo, sends each one with its surrounding
code context to Claude via the Anthropic API, and writes a triage verdict
back to DefectDojo as a note.

Environment variables required:
  ANTHROPIC_API_KEY
  DEFECTDOJO_URL
  DEFECTDOJO_API_KEY
  DEFECTDOJO_ENGAGEMENT_ID   (optional)
  GITHUB_TOKEN               (optional)
  GITHUB_REPOSITORY          (optional)
"""

import os
import sys
import json
import requests
from pathlib import Path

ANTHROPIC_API_KEY  = os.environ.get('ANTHROPIC_API_KEY', '')
DEFECTDOJO_URL     = os.environ.get('DEFECTDOJO_URL', '').rstrip('/')
DEFECTDOJO_API_KEY = os.environ.get('DEFECTDOJO_API_KEY', '')
ENGAGEMENT_ID      = os.environ.get('DEFECTDOJO_ENGAGEMENT_ID', '')
GITHUB_TOKEN       = os.environ.get('GITHUB_TOKEN', '')
GITHUB_REPO        = os.environ.get('GITHUB_REPOSITORY', '')
MODEL              = 'claude-sonnet-4-6'
MAX_FINDINGS       = int(os.environ.get('MAX_FINDINGS', '20'))


def dd_headers():
    return {'Authorization': f'Token {DEFECTDOJO_API_KEY}', 'Accept': 'application/json', 'Content-Type': 'application/json'}


def get_open_findings():
    params = {'active': True, 'false_p': False, 'limit': MAX_FINDINGS, 'ordering': '-severity'}
    if ENGAGEMENT_ID:
        params['test__engagement'] = ENGAGEMENT_ID
    r = requests.get(f'{DEFECTDOJO_URL}/api/v2/findings/', headers=dd_headers(), params=params, timeout=30)
    r.raise_for_status()
    return r.json().get('results', [])


def get_code_context(file_path, line_number, context_lines=15):
    if not GITHUB_TOKEN or not GITHUB_REPO or not file_path:
        return None
    try:
        r = requests.get(
            f'https://api.github.com/repos/{GITHUB_REPO}/contents/{file_path}',
            headers={'Authorization': f'token {GITHUB_TOKEN}', 'Accept': 'application/vnd.github.v3.raw'},
            timeout=15,
        )
        if r.status_code != 200:
            return None
        lines = r.text.splitlines()
        start = max(0, (line_number or 1) - context_lines - 1)
        end   = min(len(lines), (line_number or 1) + context_lines)
        return '\n'.join(f'{i+1+start}: {l}' for i, l in enumerate(lines[start:end]))
    except Exception:
        return None


def ask_claude(finding, code_context):
    context_block = ''
    if code_context:
        context_block = f'\n\nCode context ({finding.get("file_path")}, line {finding.get("line")}):\n```\n{code_context}\n```'

    prompt = f"""You are a senior application security engineer triaging static analysis findings.

Finding:
- Title: {finding.get('title')}
- Severity: {finding.get('severity')}
- File: {finding.get('file_path')}
- Line: {finding.get('line')}
- CWE: {finding.get('cwe')}
- Description: {finding.get('description', '')[:500]}{context_block}

Respond ONLY in this exact JSON format (no markdown, no explanation):
{{"verdict":"true_positive","confidence":"high","reasoning":"explanation","remediation":"fix or null"}}
verdict must be one of: true_positive, false_positive, needs_review"""

    r = requests.post(
        'https://api.anthropic.com/v1/messages',
        headers={'x-api-key': ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json'},
        json={'model': MODEL, 'max_tokens': 1024, 'messages': [{'role': 'user', 'content': prompt}]},
        timeout=60,
    )
    if r.status_code != 200:
        raise Exception(f'{r.status_code}: {r.text[:300]}')
    content = r.json()['content'][0]['text'].strip()
    if content.startswith('```'):
        content = content.split('```')[1]
        if content.startswith('json'): content = content[4:]
    return json.loads(content.strip())


def post_note(finding_id, verdict_data):
    verdict     = verdict_data.get('verdict', 'needs_review')
    confidence  = verdict_data.get('confidence', 'low')
    reasoning   = verdict_data.get('reasoning', '')
    remediation = verdict_data.get('remediation', '')
    icons = {'true_positive': '⚠️', 'false_positive': '✅', 'needs_review': '🔍'}
    note = f"{icons.get(verdict,'🔍')} **AI Triage: {verdict.replace('_',' ').title()}** (confidence: {confidence})\n\n**Reasoning:** {reasoning}"
    if remediation: note += f'\n\n**Remediation:** {remediation}'
    note += '\n\n*Triaged by Claude AI — mcp-sec-demo*'
    r = requests.post(f'{DEFECTDOJO_URL}/api/v2/notes/', headers=dd_headers(), json={'entry': note, 'note_type': None}, timeout=30)
    if r.status_code not in (200, 201):
        print(f'  [warn] Note failed: {r.status_code}')
        return
    note_id = r.json().get('id')
    requests.post(f'{DEFECTDOJO_URL}/api/v2/findings/{finding_id}/notes/', headers=dd_headers(), json={'note': note_id}, timeout=30)
    if verdict == 'false_positive':
        requests.patch(f'{DEFECTDOJO_URL}/api/v2/findings/{finding_id}/', headers=dd_headers(), json={'false_p': True, 'active': False}, timeout=30)


def main():
    if not ANTHROPIC_API_KEY:
        print('[triage] ANTHROPIC_API_KEY not set — skipping'); sys.exit(0)
    if not DEFECTDOJO_URL or not DEFECTDOJO_API_KEY:
        print('[triage] DefectDojo credentials not set — skipping'); sys.exit(0)

    print(f'[triage] Model: {MODEL}')
    findings = get_open_findings()
    print(f'[triage] {len(findings)} findings to triage')

    verdicts = {'true_positive': 0, 'false_positive': 0, 'needs_review': 0, 'error': 0}
    for f in findings:
        print(f'  [{f.get("severity","?")}] #{f["id"]}: {f.get("title","?")[:60]}')
        try:
            vd = ask_claude(f, get_code_context(f.get('file_path'), f.get('line')))
            v  = vd.get('verdict', 'needs_review')
            verdicts[v] = verdicts.get(v, 0) + 1
            print(f'       → {v} ({vd.get("confidence","?")})')
            post_note(f['id'], vd)
        except Exception as e:
            print(f'       → error: {e}'); verdicts['error'] += 1

    print(f'\n[triage] tp={verdicts["true_positive"]} fp={verdicts["false_positive"]} nr={verdicts["needs_review"]} err={verdicts["error"]}')
    Path('reports').mkdir(exist_ok=True)
    with open('reports/triage-summary.json', 'w') as fh:
        json.dump({'total': len(findings), 'verdicts': verdicts,
                   'findings': [{'id': f['id'], 'title': f.get('title'), 'severity': f.get('severity'), 'file_path': f.get('file_path')} for f in findings]}, fh, indent=2)
    print('[triage] Done.')


if __name__ == '__main__':
    main()
