"""
AI Security Triage Agent
Reads Semgrep and OSV scan results, uses Claude to triage findings,
and opens GitHub PRs for confirmed vulnerabilities.
"""

import json
import os
import re
import sys
import requests
import anthropic
from pathlib import Path


# ── Config from environment ────────────────────────────────────────────────
ANTHROPIC_API_KEY = os.environ["ANTHROPIC_API_KEY"]
GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]
GITHUB_REPOSITORY = os.environ["GITHUB_REPOSITORY"]  # e.g. "maustin44/mcp-sec-demo"
GITHUB_SHA = os.environ.get("GITHUB_SHA", "main")
GITHUB_REF = os.environ.get("GITHUB_REF", "refs/heads/main")

GITHUB_API = "https://api.github.com"
HEADERS = {
    "Authorization": f"Bearer {GITHUB_TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)


# ── GitHub helpers ─────────────────────────────────────────────────────────
def get_file_contents(path: str) -> str:
    """Fetch a file's contents from GitHub."""
    url = f"{GITHUB_API}/repos/{GITHUB_REPOSITORY}/contents/{path}"
    resp = requests.get(url, headers=HEADERS, params={"ref": GITHUB_SHA})
    if resp.status_code != 200:
        return ""
    import base64
    content = resp.json().get("content", "")
    return base64.b64decode(content).decode("utf-8", errors="replace")


def get_file_sha(path: str, branch: str) -> str | None:
    """Get the SHA of an existing file on a branch (needed for updates)."""
    url = f"{GITHUB_API}/repos/{GITHUB_REPOSITORY}/contents/{path}"
    resp = requests.get(url, headers=HEADERS, params={"ref": branch})
    if resp.status_code == 200:
        return resp.json().get("sha")
    return None


def create_branch(branch_name: str, base_sha: str) -> bool:
    """Create a new branch from a given SHA."""
    url = f"{GITHUB_API}/repos/{GITHUB_REPOSITORY}/git/refs"
    resp = requests.post(url, headers=HEADERS, json={
        "ref": f"refs/heads/{branch_name}",
        "sha": base_sha,
    })
    return resp.status_code in (200, 201, 422)  # 422 = branch already exists


def push_file(path: str, content: str, message: str, branch: str):
    """Create or update a file on a branch."""
    import base64
    url = f"{GITHUB_API}/repos/{GITHUB_REPOSITORY}/contents/{path}"
    body = {
        "message": message,
        "content": base64.b64encode(content.encode()).decode(),
        "branch": branch,
    }
    sha = get_file_sha(path, branch)
    if sha:
        body["sha"] = sha
    resp = requests.put(url, headers=HEADERS, json=body)
    return resp.status_code in (200, 201)


def open_pull_request(title: str, body: str, head: str, base: str = "main") -> str | None:
    """Open a PR and return its URL."""
    url = f"{GITHUB_API}/repos/{GITHUB_REPOSITORY}/pulls"
    resp = requests.post(url, headers=HEADERS, json={
        "title": title,
        "body": body,
        "head": head,
        "base": base,
    })
    if resp.status_code in (200, 201):
        return resp.json().get("html_url")
    print(f"  PR creation failed: {resp.status_code} {resp.text}")
    return None


def post_issue_comment(issue_number: int, comment: str):
    """Post a comment on a PR or issue."""
    url = f"{GITHUB_API}/repos/{GITHUB_REPOSITORY}/issues/{issue_number}/comments"
    requests.post(url, headers=HEADERS, json={"body": comment})


# ── Load scan results ──────────────────────────────────────────────────────
def load_semgrep_findings() -> list[dict]:
    path = Path("semgrep-results.json")
    if not path.exists():
        print("No semgrep-results.json found, skipping.")
        return []
    data = json.loads(path.read_text())
    return data.get("results", [])


def load_osv_findings() -> list[dict]:
    path = Path("osv-results.json")
    if not path.exists():
        print("No osv-results.json found, skipping.")
        return []
    try:
        data = json.loads(path.read_text())
        vulns = []
        for result in data.get("results", []):
            for pkg in result.get("packages", []):
                for vuln in pkg.get("vulnerabilities", []):
                    vulns.append({
                        "package": pkg.get("package", {}).get("name", "unknown"),
                        "version": pkg.get("package", {}).get("version", "unknown"),
                        "id": vuln.get("id", ""),
                        "summary": vuln.get("summary", ""),
                        "severity": vuln.get("database_specific", {}).get("severity", "UNKNOWN"),
                    })
        return vulns
    except Exception as e:
        print(f"Error parsing OSV results: {e}")
        return []


# ── Claude triage ──────────────────────────────────────────────────────────
def triage_semgrep_finding(finding: dict) -> dict:
    """Ask Claude whether a Semgrep finding is real or a false positive."""
    file_path = finding.get("path", "")
    line = finding.get("start", {}).get("line", 0)
    rule = finding.get("check_id", "")
    message = finding.get("extra", {}).get("message", "")
    flagged_line = finding.get("extra", {}).get("lines", "")
    severity = finding.get("extra", {}).get("severity", "")

    # Fetch full file for context
    file_contents = get_file_contents(file_path)
    
    # Limit context to avoid huge prompts — send 50 lines around the finding
    lines = file_contents.splitlines()
    start = max(0, line - 25)
    end = min(len(lines), line + 25)
    context = "\n".join(f"{i+1}: {l}" for i, l in enumerate(lines[start:end], start=start))

    prompt = f"""You are a senior security engineer triaging SAST findings.

A Semgrep scan flagged the following issue:

Rule: {rule}
Severity: {severity}
File: {file_path}
Line: {line}
Message: {message}
Flagged code: {flagged_line}

Surrounding code context (lines {start+1}-{end}):
```
{context}
```

Your job:
1. Determine if this is a REAL vulnerability or a FALSE POSITIVE
2. If REAL: provide a specific code fix
3. If FALSE POSITIVE: explain exactly why

Respond in this exact JSON format:
{{
  "verdict": "REAL" or "FALSE_POSITIVE",
  "confidence": "HIGH", "MEDIUM", or "LOW",
  "explanation": "brief explanation",
  "fix": "the fixed code snippet (only if REAL, otherwise null)",
  "fix_description": "what was changed and why (only if REAL, otherwise null)"
}}"""

    response = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=1000,
        messages=[{"role": "user", "content": prompt}]
    )
    
    raw = response.content[0].text.strip()
    # Strip markdown code fences if present
    raw = re.sub(r"^```json\s*", "", raw)
    raw = re.sub(r"\s*```$", "", raw)
    
    try:
        result = json.loads(raw)
    except json.JSONDecodeError:
        result = {
            "verdict": "REAL",
            "confidence": "LOW",
            "explanation": "Could not parse Claude response, flagging for manual review.",
            "fix": None,
            "fix_description": None,
        }
    
    result["finding"] = finding
    result["file_path"] = file_path
    result["full_file_contents"] = file_contents
    return result


def triage_osv_finding(finding: dict) -> dict:
    """Ask Claude to summarise an OSV dependency vulnerability."""
    prompt = f"""You are a security engineer reviewing a dependency vulnerability.

Package: {finding['package']} version {finding['version']}
CVE/ID: {finding['id']}
Severity: {finding['severity']}
Summary: {finding['summary']}

Is this worth fixing immediately? Respond in JSON:
{{
  "verdict": "REAL",
  "confidence": "HIGH",
  "explanation": "brief explanation of risk",
  "fix_description": "recommended action e.g. upgrade to version X.Y.Z"
}}"""

    response = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=500,
        messages=[{"role": "user", "content": prompt}]
    )
    raw = response.content[0].text.strip()
    raw = re.sub(r"^```json\s*", "", raw)
    raw = re.sub(r"\s*```$", "", raw)

    try:
        result = json.loads(raw)
    except json.JSONDecodeError:
        result = {
            "verdict": "REAL",
            "confidence": "LOW",
            "explanation": "Could not parse Claude response.",
            "fix_description": "Review manually.",
        }
    result["finding"] = finding
    return result


# ── PR creation ────────────────────────────────────────────────────────────
def create_fix_pr(triage_result: dict, branch_name: str):
    """Push the fix to a new branch and open a PR."""
    finding = triage_result["finding"]
    file_path = triage_result["file_path"]
    fix_code = triage_result.get("fix")

    if not fix_code:
        print(f"  No fix code provided for {file_path}, skipping PR.")
        return

    # Create branch
    create_branch(branch_name, GITHUB_SHA)

    # Push fixed file
    original = triage_result.get("full_file_contents", "")
    flagged_line = finding.get("extra", {}).get("lines", "").strip()
    
    # Simple replacement — swap the flagged line with the fix
    if flagged_line and flagged_line in original:
        fixed_contents = original.replace(flagged_line, fix_code.strip(), 1)
    else:
        # Fallback: append fix as a comment if we can't locate the exact line
        fixed_contents = original + f"\n// TODO: Apply this fix manually:\n// {fix_code}\n"

    push_file(
        path=file_path,
        content=fixed_contents,
        message=f"fix({finding.get('check_id', 'security')}): {triage_result['explanation'][:72]}",
        branch=branch_name,
    )

    # Build PR body
    rule = finding.get("check_id", "unknown")
    line = finding.get("start", {}).get("line", "?")
    severity = finding.get("extra", {}).get("severity", "UNKNOWN")

    pr_body = f"""## 🔐 Automated Security Fix

This PR was opened automatically by the AI Security Agent after a Semgrep scan.

### Finding

| Field | Value |
|-------|-------|
| Rule | `{rule}` |
| Severity | **{severity}** |
| File | `{file_path}` |
| Line | {line} |
| Confidence | {triage_result.get('confidence', '?')} |

### Analysis
{triage_result.get('explanation', '')}

### What Changed
{triage_result.get('fix_description', '')}

---
⚠️ **Human review required before merging.** Do not auto-merge.
"""

    pr_url = open_pull_request(
        title=f"fix: {rule} in {file_path} (line {line})",
        body=pr_body,
        head=branch_name,
    )

    if pr_url:
        print(f"  ✅ PR opened: {pr_url}")
    else:
        print(f"  ❌ Failed to open PR for {file_path}")


# ── Main ───────────────────────────────────────────────────────────────────
def main():
    print("=" * 60)
    print("AI Security Triage Agent")
    print("=" * 60)

    # --- Semgrep ---
    semgrep_findings = load_semgrep_findings()
    print(f"\n📋 Semgrep findings: {len(semgrep_findings)}")

    real_count = 0
    fp_count = 0

    for i, finding in enumerate(semgrep_findings):
        file_path = finding.get("path", "unknown")
        rule = finding.get("check_id", "unknown")
        print(f"\n[{i+1}/{len(semgrep_findings)}] Triaging: {rule} in {file_path}")

        result = triage_semgrep_finding(finding)
        verdict = result.get("verdict", "REAL")
        confidence = result.get("confidence", "LOW")
        explanation = result.get("explanation", "")

        print(f"  Verdict: {verdict} ({confidence} confidence)")
        print(f"  Reason:  {explanation}")

        if verdict == "FALSE_POSITIVE":
            fp_count += 1
            print("  → Skipping (false positive)")
        else:
            real_count += 1
            import time
            timestamp = int(time.time())
            branch_name = f"fix/sast-{rule.split('.')[-1]}-{timestamp}"
            print(f"  → Creating PR on branch: {branch_name}")
            create_fix_pr(result, branch_name)

    # --- OSV ---
    osv_findings = load_osv_findings()
    print(f"\n📦 OSV dependency findings: {len(osv_findings)}")

    for i, finding in enumerate(osv_findings):
        pkg = finding.get("package", "unknown")
        vuln_id = finding.get("id", "unknown")
        print(f"\n[{i+1}/{len(osv_findings)}] Triaging: {vuln_id} in {pkg}")

        result = triage_osv_finding(finding)
        print(f"  Verdict: {result.get('verdict')} ({result.get('confidence')} confidence)")
        print(f"  Action:  {result.get('fix_description', '')}")
        # OSV findings don't auto-fix code — they're reported for manual action

    # --- Summary ---
    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    print(f"  Semgrep findings:   {len(semgrep_findings)}")
    print(f"  Real vulnerabilities: {real_count}")
    print(f"  False positives:    {fp_count}")
    print(f"  OSV findings:       {len(osv_findings)}")
    print("=" * 60)


if __name__ == "__main__":
    main()
