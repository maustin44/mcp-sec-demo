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


def main():
    check_config()
    print(f'[push] Connecting to DefectDojo...')

    # Test connection
    r = requests.get(f'{DEFECTDOJO_URL}/api/v2/users/', headers=headers(), timeout=15)
    if r.status_code != 200:
        print(f'[push] Auth failed: {r.status_code}'); sys.exit(1)
    print('[push] Connected OK')

    # Print ALL scan types - no filtering
    r2 = requests.get(f'{DEFECTDOJO_URL}/api/v2/test_types/?limit=200', headers=headers(), timeout=15)
    all_types = [t['name'] for t in r2.json().get('results', [])]
    print(f'[push] ALL {len(all_types)} scan types:')
    for t in all_types:
        print(f'  >> {t}')

    # Try NPM audit
    f = REPORTS_DIR / 'npm-audit.json'
    if f.exists():
        print(f'[push] Sending npm-audit.json as NPM Audit Scan...')
        with open(f, 'rb') as fp:
            resp = requests.post(
                f'{DEFECTDOJO_URL}/api/v2/import-scan/',
                headers=headers(),
                data={'engagement': ENGAGEMENT_ID, 'scan_type': 'NPM Audit Scan',
                      'scan_date': date.today().isoformat(), 'active': True,
                      'verified': False, 'minimum_severity': 'Info'},
                files={'file': (f.name, fp, 'application/json')},
                timeout=120,
            )
        print(f'[push] npm-audit result: {resp.status_code} {resp.text[:300]}')

    # Try ZAP
    f = REPORTS_DIR / 'zap-report.json'
    if f.exists():
        print(f'[push] Sending zap-report.json as ZAP Scan...')
        with open(f, 'rb') as fp:
            resp = requests.post(
                f'{DEFECTDOJO_URL}/api/v2/import-scan/',
                headers=headers(),
                data={'engagement': ENGAGEMENT_ID, 'scan_type': 'ZAP Scan',
                      'scan_date': date.today().isoformat(), 'active': True,
                      'verified': False, 'minimum_severity': 'Info'},
                files={'file': (f.name, fp, 'application/json')},
                timeout=120,
            )
        print(f'[push] zap result: {resp.status_code} {resp.text[:300]}')

    # Try Checkov
    f = REPORTS_DIR / 'results_json.json'
    if f.exists():
        print(f'[push] Sending results_json.json as Checkov Scan...')
        with open(f, 'rb') as fp:
            resp = requests.post(
                f'{DEFECTDOJO_URL}/api/v2/import-scan/',
                headers=headers(),
                data={'engagement': ENGAGEMENT_ID, 'scan_type': 'Checkov Scan',
                      'scan_date': date.today().isoformat(), 'active': True,
                      'verified': False, 'minimum_severity': 'Info'},
                files={'file': (f.name, fp, 'application/json')},
                timeout=120,
            )
        print(f'[push] checkov result: {resp.status_code} {resp.text[:300]}')

    print('[push] Done.')


if __name__ == '__main__':
    main()
