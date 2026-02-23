"""
AI Security Triage Agent
Reads Semgrep and OSV scan results, uses an LLM to triage findings,
and opens GitHub PRs for confirmed vulnerabilities.

Supports two LLM providers:
  - Ollama (default) — runs locally, free, private
  - Anthropic API    — set LLM_PROVIDER=anthropic in .env
"""

import json
import os
import re
import time
import requests
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(dotenv_path=Path(__file__).parent.parent / ".env")


# ── LLM config ─────────────────────────────────────────────────────────────
LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "ollama").lower()
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "mistral")
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")


def ask_llm(prompt: str, retries: int = 3) -> str:
    """Send a prompt to either Ollama or Anthropic with retry logic."""
    for attempt in range(retries):
        try:
            if LLM_PROVIDER == "anthropic":
                import anthropic as anthropic_sdk
                client = anthropic_sdk.Anthropic(api_key=ANTHROPIC_API_KEY)
                response = client.messages.create(
                    model="claude-opus-4-6",
                    max_tokens=1000,
                    messages=[{"role": "user", "content": prompt}]
                )
                return response.content[0].text.strip()
            else:
                resp = requests.post(f"{OLLAMA_URL}/api/generate", json={
                    "model": OLLAMA_MODEL,
                    "prompt": prompt,
                    "stream": False,
                }, timeout=120)
                resp.raise_for_status()
                return resp.json()["response"].strip()
        except Exception as e:
            print(f"  LLM attempt {attempt + 1}/{retries} failed: {e}")
            if attempt < retries - 1:
                time.sleep(2)
    return ""


# ── GitHub config ───────────────────────────────────────────────────────────
GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]
GITHUB_REPOSITORY = os.environ["GITHUB_REPOSITORY"]
GITHUB_REF = os.environ.get("GITHUB_REF", "refs/heads/main")

GITHUB_API = "https://api.github.com"
HEADERS = {
    "Authorization": f"Bearer {GITHUB_TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}


def get_default_branch_sha() -> str:
    """Auto-fetch the latest SHA from the default branch."""
    # Get default branch name first
    repo_url = f"{GITHUB_API}/repos/{GITHUB_REPOSITORY}"
    repo_resp = requests.get(repo_url, headers=HEADERS)
    default_branch = repo_resp.json().get("default_branch", "main")

    # Get its SHA
    branch_url = f"{GITHUB_API}/repos/{GITHUB_REPOSITORY}/branches/{default_branch}"
    branch_resp = requests.get(branch_url, headers=HEADERS)
    sha = branch_resp.json().get("commit", {}).get("sha", "")
    print(f"  Auto-fetched SHA for '{default_branch}': {sha[:7]}...")
    return sha


# Set SHA automatically — no need to set it in .env
GITHUB_SHA = os.environ.get("GITHUB_SHA") or get_default_branch_sha()


# ── GitHub helpers ──────────────────────────────────────────────────────────
def get_file_contents(path: str) -> str:
    """Fetch a file's contents from GitHub."""
    # Normalize Windows-style paths
    path = path.replace("\\", "/")
    url = f"{GITHUB_API}/repos/{GITHUB_REPOSITORY}/contents/{path}"
    resp = requests.get(url, headers=HEADERS, params={"ref": GITHUB_SHA})
    if resp.status_code != 200:
        return ""
    import base64
    content = resp.json().get("content", "")
    return base64.b64decode(content).decode("utf-8", errors="replace")


def get_file_sha(path: str, branch: str) -> str | None:
    """Get the SHA of an existing file on a branch."""
    path = path.replace("\\", "/")
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
    return resp.status_code in (200, 201, 422)


def push_file(path: str, content: str, message: str, branch: str) -> bool:
    """Create or update a file on a branch."""
    import base64
    path = path.replace("\\", "/")
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


# ── Load scan results ───────────────────────────────────────────────────────
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


# ── Triage functions ────────────────────────────────────────────────────────
def parse_llm_json(raw: str) -> dict:
    """Strip markdown fences and parse JSON from LLM response."""
    raw = re.sub(r"^```json\s*", "", raw)
    raw = re.sub(r"^```\s*", "", raw)
    raw = re.sub(r"\s*```$", "", raw)
    match = re.search(r"\{.*\}", raw, re.DOTALL)
    if match:
        raw = match.group(0)
    return json.loads(raw)


def triage_semgrep_finding(finding: dict) -> dict:
    """Ask LLM whether a Semgrep finding is real or a false positive."""
    file_path = finding.get("path", "")
    line = finding.get("start", {}).get("line", 0)
    rule = finding.get("check_id", "")
    message = finding.get("extra", {}).get("message", "")
    flagged_line = finding.get("extra", {}).get("lines", "")
    severity = finding.get("extra", {}).get("severity", "")

    file_contents = get_file_contents(file_path)
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

You MUST respond with ONLY a JSON object, no other text before or after:
{{
  "verdict": "REAL",
  "confidence": "HIGH",
  "explanation": "brief explanation",
  "fix": "the fixed code snippet or null",
  "fix_description": "what was changed and why or null"
}}"""

    result = None
    for attempt in range(3):
        raw = ask_llm(prompt)
        try:
            result = parse_llm_json(raw)
            # Validate required fields
            if "verdict" in result and "confidence" in result:
                break
        except (json.JSONDecodeError, AttributeError):
            print(f"  JSON parse attempt {attempt + 1}/3 failed, retrying...")
            time.sleep(1)

    if not result:
        result = {
            "verdict": "REAL",
            "confidence": "LOW",
            "explanation": "Could not parse LLM response — flagging for manual review.",
            "fix": None,
            "fix_description": None,
        }

    result["finding"] = finding
    result["file_path"] = file_path
    result["full_file_contents"] = file_contents
    return result


def triage_osv_finding(finding: dict) -> dict:
    """Ask LLM to summarise an OSV dependency vulnerability."""
    prompt = f"""You are a security engineer reviewing a dependency vulnerability.

Package: {finding['package']} version {finding['version']}
CVE/ID: {finding['id']}
Severity: {finding['severity']}
Summary: {finding['summary']}

Respond with ONLY a JSON object, no other text:
{{
  "verdict": "REAL",
  "confidence": "HIGH",
  "explanation": "brief explanation of risk",
  "fix_description": "recommended action e.g. upgrade to version X.Y.Z"
}}"""

    raw = ask_llm(prompt)
    try:
        result = parse_llm_json(raw)
    except (json.JSONDecodeError, AttributeError):
        result = {
            "verdict": "REAL",
            "confidence": "LOW",
            "explanation": "Could not parse LLM response.",
            "fix_description": "Review manually.",
        }
    result["finding"] = finding
    return result


# ── PR creation ─────────────────────────────────────────────────────────────
def create_fix_pr(triage_result: dict, branch_name: str):
    """Push the fix to a new branch and open a PR."""
    finding = triage_result["finding"]
    file_path = triage_result["file_path"]
    fix_code = triage_result.get("fix")

    if not fix_code:
        print(f"  No fix code provided for {file_path}, skipping PR.")
        return

    create_branch(branch_name, GITHUB_SHA)

    original = triage_result.get("full_file_contents", "")
    flagged_line = finding.get("extra", {}).get("lines", "").strip()

    if flagged_line and flagged_line in original:
        fixed_contents = original.replace(flagged_line, fix_code.strip(), 1)
    else:
        fixed_contents = original + f"\n// TODO: Apply this fix manually:\n// {fix_code}\n"

    push_file(
        path=file_path,
        content=fixed_contents,
        message=f"fix({finding.get('check_id', 'security')}): {triage_result['explanation'][:72]}",
        branch=branch_name,
    )

    rule = finding.get("check_id", "unknown")
    line = finding.get("start", {}).get("line", "?")
    severity = finding.get("extra", {}).get("severity", "UNKNOWN")

    pr_body = f"""## 🔐 Automated Security Fix

This PR was opened automatically by the AI Security Agent.

**LLM Provider:** {LLM_PROVIDER.upper()}

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


# ── Main ────────────────────────────────────────────────────────────────────
def main():
    print("=" * 60)
    print("AI Security Triage Agent")
    print(f"LLM Provider: {LLM_PROVIDER.upper()} ", end="")
    if LLM_PROVIDER == "ollama":
        print(f"(model: {OLLAMA_MODEL} @ {OLLAMA_URL})")
    else:
        print("(Anthropic API)")
    print("=" * 60)

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

        print(f"  Verdict:    {verdict} ({confidence} confidence)")
        print(f"  Reason:     {explanation}")

        if verdict == "FALSE_POSITIVE":
            fp_count += 1
            print("  → Skipping (false positive)")
        else:
            real_count += 1
            branch_name = f"fix/sast-{rule.split('.')[-1]}-{int(time.time())}"
            print(f"  → Creating PR on branch: {branch_name}")
            create_fix_pr(result, branch_name)

    osv_findings = load_osv_findings()
    print(f"\n📦 OSV dependency findings: {len(osv_findings)}")

    for i, finding in enumerate(osv_findings):
        pkg = finding.get("package", "unknown")
        vuln_id = finding.get("id", "unknown")
        print(f"\n[{i+1}/{len(osv_findings)}] Triaging: {vuln_id} in {pkg}")

        result = triage_osv_finding(finding)
        print(f"  Verdict:  {result.get('verdict')} ({result.get('confidence')} confidence)")
        print(f"  Action:   {result.get('fix_description', '')}")

    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    print(f"  Semgrep findings:      {len(semgrep_findings)}")
    print(f"  Real vulnerabilities:  {real_count}")
    print(f"  False positives:       {fp_count}")
    print(f"  OSV findings:          {len(osv_findings)}")
    print("=" * 60)


if __name__ == "__main__":
    main()
