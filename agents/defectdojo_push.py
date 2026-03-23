#!/usr/bin/env python3
"""
Pushes scan results to DefectDojo via its REST API.

Supported scan types:
  - ZAP DAST  (zap-report.json)  -> 'ZAP Scan'
  - npm audit (npm-audit.json)   -> 'NPM Audit Scan'
  - Checkov   (results_json.json) -> 'Checkov Scan'

Environment variables required:
  DEFECTDOJO_URL           e.g. http://your-alb-dns.amazonaws.com
  DEFECTDOJO_API_KEY       DefectDojo API v2 key
  DEFECTDOJO_ENGAGEMENT_ID Engagement ID to import findings into
  REPORTS_DIR              Directory containing report files (default: reports/)
"""

import os
import sys
import json
import requests
from pathlib import Path
from datetime import date

DEFECTDOJO_URL = os.environ.get('DEFECTDOJO_URL', '').rstrip('/')
API_KEY = os.environ.get('DEFECTDOJO_API_KEY', '')
ENGAGEMENT_ID = os.environ.get('DEFECTDOJO_ENGAGEMENT_ID', '')
REPORTS_DIR = Path(os.environ.get('REPORTS_DIR', 'reports'))

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
    return {
        'Authorization': f'Token {API_KEY}',
        'Accept': 'application/json',
    }

def test_connection():
    """Verify DefectDojo is reachable and credentials work."""
    try:
        r = requests.get(
            f'{DEFECTDOJO_URL}/api/v2/users/',
            headers=get_headers(),
            timeout=15
        )
        if r.status_code == 200:
            print(f'[defectdojo_push] Connected to DefectDojo successfully')
            return True
        else:
            print(f'[defectdojo_push] Auth check failed ({r.status_code}): {r.text[:200]}')
            return False
    except Exception as e:
        print(f'[defectdojo_push] Cannot reach DefectDojo: {e}')
        return False

def import_scan(scan_type, file_path):
    if not file_path.exists():
        print(f'[defectdojo_push] {file_path} not found — skipping')
        return

    print(f'[defectdojo_push] Importing {scan_type} from {file_path} ({file_path.stat().st_size} bytes)')

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
                'minimum_severity':   'Low',
            },
            files={'file': (file_path.name, f, 'application/json')},
            timeout=120,
        )

    if response.status_code in (200, 201):
        data = response.json()
        count = data.get('finding_count', data.get('findings_count', '?'))
        print(f'[defectdojo_push] ✓ Imported {count} findings from {scan_type}')
    else:
        print(f'[defectdojo_push] ✗ Failed ({response.status_code}): {response.text[:500]}')

def main():
    check_config()
    print(f'[defectdojo_push] Pushing reports to DefectDojo (engagement {ENGAGEMENT_ID})')

    if not test_connection():
        print('[defectdojo_push] Cannot connect — aborting')
        sys.exit(1)

    import_scan('ZAP Scan',      REPORTS_DIR / 'zap-report.json')
    import_scan('NPM Audit Scan', REPORTS_DIR / 'npm-audit.json')
    import_scan('Checkov Scan',  REPORTS_DIR / 'results_json.json')

    print('[defectdojo_push] Done.')

if __name__ == '__main__':
    main()
