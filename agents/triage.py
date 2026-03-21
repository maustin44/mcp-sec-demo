#!/usr/bin/env python3
"""
Phase 3 placeholder — AI triage agent.

This script will:
  1. Pull open findings from DefectDojo
  2. Send each finding + code context to Claude via Anthropic API
  3. Get a triage verdict (true positive / false positive / needs review)
  4. Write verdicts back to DefectDojo as notes
  5. Open GitHub Issues for confirmed true positives

Currently a stub — implementation added in Phase 3.
"""

import sys

def main():
    print("[triage] Phase 3 AI triage agent — not yet implemented.")
    print("[triage] Skipping gracefully. Implement in Phase 3.")
    sys.exit(0)

if __name__ == "__main__":
    main()
