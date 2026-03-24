#!/usr/bin/env python3
"""
Pushes scan results to DefectDojo via its REST API.

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

DEFECTDOJO_URL = os.environ.get('DEFECTDOJO_URL', '').rstrip('/')
API_KEY        = os.environ.get('DEFECTDOJO_API_KEY', '')
ENGAGEMENT_ID  = os.environ.get('DEFECTDOJO_ENGAGEMENT_ID', '')
REPORTS_DIR    = Path(os.environ.get('REPORTS_DIR', 'reports'))


def check_config():
    if not DEFECTDOJO_URL: print('[push] DEFECTDOJO_URL not set'); sys.exit(0)
    if not API_KEY: print('[push] DEFECTDOJO_API_KEY not set'); sys.exit(0)
    if not ENGAGEMENT_ID: print('[push] DEFECTDOJO_ENGAGEMENT_ID not set'); sys.exit(0)


def headers():
    return {'Authorization': f'Token {API_KEY}', 'Accept': 'application/json'}


def import_scan(scan_type, file_path):
    if not file_path.exists():
        print(f'[push] {file_path} not found — skipping')
        return
    print(f'[push] Importing "{scan_type}" ({file_path.stat().st_size} bytes)')
    with open(file_path, 'rb') as f:
        resp = requests.post(
            f'{DEFECTDOJO_URL}/api/v2/import-scan/',
            headers={'Authorization': f'Token {API_KEY}'},
            data={
                'engagement': ENGAGEMENT_ID,
                'scan_type': scan_type,
                'scan_date': date.today().isoformat(),
                'active': 'true',
                'verified': 'false',
                'close_old_findings': 'true',
                'minimum_severity': 'Info',
            },
            files={'file': f},
            timeout=120,
        )
    if resp.status_code in (200, 201):
        print(f'[push] ✓ Success: {resp.json().get("finding_count", "?")} findings')
    else:
        print(f'[push] ✗ {resp.status_code}: {resp.text[:500]}')


def main():
    check_config()
    r = requests.get(f'{DEFECTDOJO_URL}/api/v2/users/', headers=headers(), timeout=15)
    if r.status_code != 200:
        print(f'[push] Auth failed: {r.status_code}'); sys.exit(1)
    print('[push] Connected OK')

    # Print current scan type count
    r2 = requests.get(f'{DEFECTDOJO_URL}/api/v2/test_types/?limit=5', headers=headers(), timeout=15)
    total = r2.json().get('count', '?')
    print(f'[push] DefectDojo has {total} scan types installed')

    import_scan('NPM Audit Scan',  REPORTS_DIR / 'npm-audit.json')
    import_scan('ZAP Scan',        REPORTS_DIR / 'zap-report.json')
    import_scan('Checkov Scan',    REPORTS_DIR / 'results_json.json')

    print('[push] Done.')


if __name__ == '__main__':
    main()
