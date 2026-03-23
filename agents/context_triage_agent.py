#!/usr/bin/env python3
"""
Phase 3 — AI Context Triage Agent.

Pulls open findings from DefectDojo, sends each one with its surrounding
code context to Claude via the Anthropic API, and writes a triage verdict
back to DefectDojo as a note.

Verdict values:
  true_positive   — confirmed vulnerability, should be fixed
  false_positive  — not a real issue given the context
  needs_review    — ambiguous, requires human judgment

Environment variables required:
  ANTHROPIC_API_KEY
  DEFECTDOJO_URL
  DEFECTDOJO_API_KEY
  DEFECTDOJO_ENGAGEMENT_ID   (optional — filters to one engagement)
  GITHUB_TOKEN               (optional — for fetching code context)
  GITHUB_REPOSITORY          (optional — owner/repo for code context)
"""

import os
import sys
import json
import requests
from pathlib import Path

ANTHROPIC_API_KEY    = os.environ.get('ANTHROPIC_API_KEY', '')
DEFECTDOJO_URL       = os.environ.get('DEFECTDOJO_URL', '').rstrip('/')
DEFECTDOJO_API_KEY   = os.environ.get('DEFECTDOJO_API_KEY', '')
ENGAGEMENT_ID        = os.environ.get('DEFECTDOJO_ENGAGEMENT_ID', '')
GITHUB_TOKEN         = os.environ.get('GITHUB_TOKEN', '')
GITHUB_REPO          = os.environ.get('GITHUB_REPOSITORY', '')
MODEL                = 'claude-sonnet-4-20250514'
MAX_FINDINGS         = int(os.environ.get('MAX_FINDINGS', '20'))


def dd_headers():
    return {
        'Authorization': f'Token {DEFECTDOJO_API_KEY}',
        'Accept': 'application/json',
        'Content-Type': 'application/json',
    }


def get_open_findings():
    """Fetch active, unreviewed findings from DefectDojo."""
    params = {
        'active': True,
        'false_p': False,
        'limit': MAX_FINDINGS,
        'ordering': '-severity',
    }
    if ENGAGEMENT_ID:
        params['test__engagement'] = ENGAGEMENT_ID

    r = requests.get(
        f'{DEFECTDOJO_URL}/api/v2/findings/',
        headers=dd_headers(),
        params=params,
        timeout=30,
    )
    r.raise_for_status()
    return r.json().get('results', [])


def get_code_context(file_path, line_number, context_lines=15):
    """Fetch code context from GitHub if available."""
    if not GITHUB_TOKEN or not GITHUB_REPO or not file_path:
        return None
    try:
        url = f'https://api.github.com/repos/{GITHUB_REPO}/contents/{file_path}'
        r = requests.get(
            url,
            headers={'Authorization': f'token {GITHUB_TOKEN}', 'Accept': 'application/vnd.github.v3.raw'},
            timeout=15,
        )
        if r.status_code != 200:
            return None
        lines = r.text.splitlines()
        start = max(0, (line_number or 1) - context_lines - 1)
        end   = min(len(lines), (line_number or 1) + context_lines)
        snippet = '\n'.join(f'{i+1+start}: {l}' for i, l in enumerate(lines[start:end]))
        return snippet
    except Exception:
        return None


def ask_claude(finding, code_context):
    """Send finding + code context to Claude and get a triage verdict."""
    severity    = finding.get('severity', 'Unknown')
    title       = finding.get('title', 'Unknown')
    description = finding.get('description', '')
    file_path   = finding.get('file_path', '')
    line        = finding.get('line', '')
    scanner     = finding.get('test', {}).get('test_type', {}).get('name', '') if isinstance(finding.get('test'), dict) else ''
    cwe         = finding.get('cwe', '')

    context_block = ''
    if code_context:
        context_block = f"""

Code context ({file_path}, around line {line}):
```
{code_context}
```"""

    prompt = f"""You are a senior application security engineer performing triage on static analysis findings.

Finding details:
- Title: {title}
- Severity: {severity}
- Scanner: {scanner}
- File: {file_path}
- Line: {line}
- CWE: {cwe}
- Description: {description}{context_block}

Your task:
1. Analyse whether this is a real vulnerability or a false positive given the code context.
2. Provide a verdict: true_positive, false_positive, or needs_review.
3. Write a concise explanation (2-4 sentences) of your reasoning.
4. If true_positive, suggest a specific remediation.

Respond in this exact JSON format:
{{
  "verdict": "true_positive|false_positive|needs_review",
  "confidence": "high|medium|low",
  "reasoning": "your explanation here",
  "remediation": "specific fix suggestion or null if false_positive"
}}"""

    r = requests.post(
        'https://api.anthropic.com/v1/messages',
        headers={
            'x-api-key': ANTHROPIC_API_KEY,
            'anthropic-version': '2023-06-01',
            'content-type': 'application/json',
        },
        json={
            'model': MODEL,
            'max_tokens': 1024,
            'messages': [{'role': 'user', 'content': prompt}],
        },
        timeout=60,
    )
    r.raise_for_status()
    content = r.json()['content'][0]['text'].strip()

    # Strip markdown code fences if present
    if content.startswith('```'):
        content = content.split('```')[1]
        if content.startswith('json'):
            content = content[4:]
    return json.loads(content.strip())


def post_note_to_defectdojo(finding_id, verdict_data):
    """Write the triage verdict back to DefectDojo as a finding note."""
    verdict   = verdict_data.get('verdict', 'needs_review')
    confidence = verdict_data.get('confidence', 'low')
    reasoning  = verdict_data.get('reasoning', '')
    remediation = verdict_data.get('remediation', '')

    icons = {'true_positive': '⚠️', 'false_positive': '✅', 'needs_review': '🔍'}
    icon = icons.get(verdict, '🔍')

    note_text = f"""{icon} **AI Triage Verdict: {verdict.replace('_', ' ').title()}** (confidence: {confidence})

**Reasoning:** {reasoning}"""
    if remediation:
        note_text += f'\n\n**Suggested remediation:** {remediation}'
    note_text += '\n\n*Triaged by Claude AI — mcp-sec-demo Phase 3*'

    r = requests.post(
        f'{DEFECTDOJO_URL}/api/v2/notes/',
        headers=dd_headers(),
        json={
            'entry': note_text,
            'note_type': None,
        },
        timeout=30,
    )
    if r.status_code not in (200, 201):
        print(f'  [warn] Note post failed ({r.status_code}): {r.text[:200]}')
        return None
    note_id = r.json().get('id')

    # Attach note to the finding
    requests.post(
        f'{DEFECTDOJO_URL}/api/v2/findings/{finding_id}/notes/',
        headers=dd_headers(),
        json={'note': note_id},
        timeout=30,
    )

    # Mark as false positive in DefectDojo if verdict is false_positive
    if verdict == 'false_positive':
        requests.patch(
            f'{DEFECTDOJO_URL}/api/v2/findings/{finding_id}/',
            headers=dd_headers(),
            json={'false_p': True, 'active': False},
            timeout=30,
        )

    return note_id


def main():
    if not ANTHROPIC_API_KEY:
        print('[triage] ANTHROPIC_API_KEY not set — skipping')
        sys.exit(0)
    if not DEFECTDOJO_URL or not DEFECTDOJO_API_KEY:
        print('[triage] DefectDojo credentials not set — skipping')
        sys.exit(0)

    print(f'[triage] Fetching up to {MAX_FINDINGS} open findings from DefectDojo...')
    findings = get_open_findings()
    print(f'[triage] Found {len(findings)} findings to triage')

    verdicts = {'true_positive': 0, 'false_positive': 0, 'needs_review': 0, 'error': 0}

    for finding in findings:
        fid   = finding['id']
        title = finding.get('title', 'Unknown')
        sev   = finding.get('severity', '?')
        print(f'  [{sev}] #{fid}: {title[:60]}')

        try:
            code_context = get_code_context(
                finding.get('file_path'),
                finding.get('line'),
            )
            verdict_data = ask_claude(finding, code_context)
            verdict      = verdict_data.get('verdict', 'needs_review')
            verdicts[verdict] = verdicts.get(verdict, 0) + 1
            print(f'       → {verdict} (confidence: {verdict_data.get("confidence", "?")})')
            post_note_to_defectdojo(fid, verdict_data)
        except Exception as e:
            print(f'       → error: {e}')
            verdicts['error'] += 1

    print(f'\n[triage] Summary:')
    print(f'  True positives:  {verdicts["true_positive"]}')
    print(f'  False positives: {verdicts["false_positive"]}')
    print(f'  Needs review:    {verdicts["needs_review"]}')
    print(f'  Errors:          {verdicts["error"]}')
    print('[triage] Done.')

    # Write summary for report generation
    summary = {
        'total': len(findings),
        'verdicts': verdicts,
        'findings': [
            {
                'id': f['id'],
                'title': f.get('title'),
                'severity': f.get('severity'),
                'file_path': f.get('file_path'),
            }
            for f in findings
        ]
    }
    Path('reports').mkdir(exist_ok=True)
    with open('reports/triage-summary.json', 'w') as fh:
        json.dump(summary, fh, indent=2)
    print('[triage] Summary written to reports/triage-summary.json')


if __name__ == '__main__':
    main()
