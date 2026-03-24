#!/usr/bin/env python3
"""
Pushes scan results to DefectDojo via its REST API.

DefectDojo scan type names must match exactly.
See: /api/v2/test_types/ for full list.

Environment variables required:
  DEFECTDOJO_URL
  DEFECTDOJO_API_KEY
  DEFECTDOJO_ENGAGEMENT_ID
  REPORTS_DIR (default: reports/)
"""

import os
import sys
import json
import requests
from pathlib import Path
from datetime import date

DEFECTDOJO_URL  = os.environ.get('DEFECTDOJO_URL', '').rstrip('/')
API_KEY         = os.environ.get('DEFECTDOJO_API_KEY', '')
ENGAGEMENT_ID   = os.environ.get('DEFECTDOJO_ENGAGEMENT_ID', '')
REPORTS_DIR     = Path(os.environ.get('REPORTS_DIR', 'reports'))


def check_config():
    if not DEFECTDOJO_URL:
        print('[defectdojo_push] DEFECTDOJO_URL not set — skipping')
        sys.exit(0)
    if not API_KEY:
        print('[defectdojo_push] DEFECTDOJO_API_KEY not set — skipping')
        sys.exit(0)
    if not ENGAGEMENT_ID:
        print('[defectdojo_push] DEFECTDOJO_ENGAGEMENT_ID not set — skipping')
        sys.exit(0)


def get_headers():
    return {'Authorization': f'Token {API_KEY}', 'Accept': 'application/json'}


def test_connection():
    r = requests.get(f'{DEFECTDOJO_URL}/api/v2/users/', headers=get_headers(), timeout=15)
    if r.status_code == 200:
        print('[defectdojo_push] Connected to DefectDojo successfully')
        return True
    print(f'[defectdojo_push] Auth check failed ({r.status_code}): {r.text[:200]}')
    return False


def get_valid_scan_types():
    """Fetch valid scan type names from DefectDojo."""
    r = requests.get(f'{DEFECTDOJO_URL}/api/v2/test_types/?limit=200', headers=get_headers(), timeout=15)
    if r.status_code == 200:
        types = [t['name'] for t in r.json().get('results', [])]
        return types
    return []


def import_scan(scan_type, file_path, content_type='application/json'):
    if not file_path.exists():
        print(f'[defectdojo_push] {file_path} not found — skipping')
        return

    size = file_path.stat().st_size
    print(f'[defectdojo_push] Importing "{scan_type}" from {file_path} ({size} bytes)')

    with open(file_path, 'rb') as f:
        response = requests.post(
            f'{DEFECTDOJO_URL}/api/v2/import-scan/',
            headers=get_headers(),
            data={
                'engagement':         ENGAGEMENT_ID,
                'scan_type':          scan_type,
                'scan_date':          date.today().isoformat(),
                'active':             True,
                'verified':           False,
                'close_old_findings': True,
                'minimum_severity':   'Info',
            },
            files={'file': (file_path.name, f, content_type)},
            timeout=120,
        )

    if response.status_code in (200, 201):
        data = response.json()
        count = data.get('finding_count', data.get('findings_count', '?'))
        print(f'[defectdojo_push] ✓ Imported {count} findings from "{scan_type}"')
    else:
        print(f'[defectdojo_push] ✗ Failed ({response.status_code}): {response.text[:500]}')


def main():
    check_config()
    print(f'[defectdojo_push] Pushing reports to DefectDojo (engagement {ENGAGEMENT_ID})')

    if not test_connection():
        print('[defectdojo_push] Cannot connect — aborting')
        sys.exit(1)

    # Print available scan types for debugging
    scan_types = get_valid_scan_types()
    print(f'[defectdojo_push] Available scan types: {len(scan_types)}')
    # Show types relevant to our scans
    for t in scan_types:
        if any(k in t.lower() for k in ['zap', 'npm', 'checkov', 'audit']):
            print(f'  - {t}')

    # ZAP — exact DefectDojo name
    import_scan('ZAP Scan', REPORTS_DIR / 'zap-report.json')

    # npm audit — exact DefectDojo name
    import_scan('NPM Audit Scan', REPORTS_DIR / 'npm-audit.json')

    # Checkov — exact DefectDojo name
    import_scan('Checkov Scan', REPORTS_DIR / 'results_json.json')

    print('[defectdojo_push] Done.')


if __name__ == '__main__':
    main()
