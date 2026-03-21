#!/usr/bin/env python3
"""
Pushes scan results to DefectDojo via its REST API.

Supported scan types:
  - ZAP DAST (zap-report.json)
  - npm audit (npm-audit.json)

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

DEFECTDOJO_URL = os.environ.get('DEFECTDOJO_URL', '')
API_KEY = os.environ.get('DEFECTDOJO_API_KEY', '')
ENGAGEMENT_ID = os.environ.get('DEFECTDOJO_ENGAGEMENT_ID', '')
REPORTS_DIR = Path(os.environ.get('REPORTS_DIR', 'reports'))

def check_config():
    if not DEFECTDOJO_URL:
        print('[defectdojo_push] DEFECTDOJO_URL not set — skipping (Phase 2 not deployed yet)')
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

def import_scan(scan_type, file_path):
    if not file_path.exists():
        print(f'[defectdojo_push] {file_path} not found — skipping')
        return

    print(f'[defectdojo_push] Importing {scan_type} from {file_path}')

    with open(file_path, 'rb') as f:
        response = requests.post(
            f'{DEFECTDOJO_URL}/api/v2/import-scan/',
            headers=get_headers(),
            data={
                'engagement':    ENGAGEMENT_ID,
                'scan_type':     scan_type,
                'scan_date':     date.today().isoformat(),
                'active':        True,
                'verified':      False,
                'close_old_findings': True,
            },
            files={'file': f},
            timeout=60,
        )

    if response.status_code in (200, 201):
        data = response.json()
        print(f'[defectdojo_push] ✓ Imported {data.get("findings_count", "?")} findings')
    else:
        print(f'[defectdojo_push] ✗ Failed ({response.status_code}): {response.text[:200]}')
        sys.exit(1)

def main():
    check_config()
    print(f'[defectdojo_push] Pushing reports to {DEFECTDOJO_URL}')

    import_scan('ZAP Scan', REPORTS_DIR / 'zap-report.json')
    import_scan('NPM Audit Scan', REPORTS_DIR / 'npm-audit.json')

    print('[defectdojo_push] Done.')

if __name__ == '__main__':
    main()
