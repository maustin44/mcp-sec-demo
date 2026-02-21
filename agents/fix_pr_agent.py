"""
fix_pr_agent.py
---------------
Reads confirmed findings and opens draft Pull Requests on GitHub with
concrete code fixes. Never merges — human review required.

Requires:
  GITHUB_TOKEN       — repo write + pull-requests scope
  ANTHROPIC_API_KEY  — for generating code patches
  GITHUB_ORG         — org or user login
  GITHUB_REPO        — repo name
"""

import os
import sys
import json
import base64
import re
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path

GITHUB_TOKEN      = os.environ.get("GITHUB_TOKEN", "")
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
GITHUB_ORG        = os.environ.get("GITHUB_ORG", "")
GITHUB_REPO       = os.environ.get("GITHUB_REPO", "")

REPO_ROOT = Path(__file__).resolve().parents[1]
DOCS_DIR  = REPO_ROOT / "docs"
REPORTS   = REPO_ROOT / "reports"


def gh_request(method: str, path: str, body: dict | None = None):
    url  = f"https://api.github.com{path}"
    data = json.dumps(body).encode() if body else None
    req  = urllib.request.Request(
        url, data=data, method=method,
        headers={
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        print(f"GitHub API error {e.code}: {e.read().decode()}")
        raise


def get_file(owner, repo, path, ref="main"):
    path = path.replace("\\", "/").lstrip("/")
    data = gh_request("GET", f"/repos/{owner}/{repo}/contents/{path}?ref={ref}")
    content = base64.b64decode(data["content"]).decode("utf-8", errors="replace")
    return content, data["sha"]


def get_default_sha(owner, repo, branch="main") -> str:
    data = gh_request("GET", f"/repos/{owner}/{repo}/branches/{branch}")
    return data["commit"]["sha"]


def create_branch(owner, repo, branch_name, from_sha):
    try:
        gh_request("POST", f"/repos/{owner}/{repo}/git/refs", {
            "ref": f"refs/heads/{branch_name}",
            "sha": from_sha,
        })
        print(f"  Created branch: {branch_name}")
    except urllib.error.HTTPError:
        print(f"  Branch already exists: {branch_name} (continuing)")


def commit_file(owner, repo, branch, file_path, new_content, message, sha):
    file_path = file_path.replace("\\", "/").lstrip("/")
    gh_request("PUT", f"/repos/{owner}/{repo}/contents/{file_path}", {
        "message": message,
        "content": base64.b64encode(new_content.encode()).decode(),
        "branch": branch,
        "sha": sha,
    })


def open_draft_pr(owner, repo, title, body, head, base="main") -> str:
    result = gh_request("POST", f"/repos/{owner}/{repo}/pulls", {
        "title": title, "body": body, "head": head, "base": base, "draft": True,
    })
    return result["html_url"]


def claude_generate_patch(finding_title: str, file_content: str, location: str) -> str:
    if not ANTHROPIC_API_KEY:
        return "(Set ANTHROPIC_API_KEY for AI-generated patches.)"

    prompt = f"""You are a security engineer writing a minimal code patch.

Vulnerability: {finding_title}
Location: {location}

Current file content:
```
{file_content[:6000]}
```

Provide ONLY the corrected version of the vulnerable section as a unified diff or
complete replacement snippet (whichever is cleaner). Include a one-sentence
explanation of the change. Do not add unnecessary refactoring."""

    body = json.dumps({
        "model": "claude-haiku-4-5-20251001",
        "max_tokens": 800,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()

    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=body,
        headers={
            "x-api-key": ANTHROPIC_API_KEY,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        result = json.loads(resp.read())
    return result["content"][0]["text"].strip()


def fix_vulnerable_dep(owner, repo, finding, base_sha):
    title = finding["title"]
    match = re.search(r"Vulnerable dep:\s*([\w\-\.]+)", title)
    if not match:
        print(f"  Could not parse package name from: {title}")
        return None

    pkg_name = match.group(1)
    branch   = f"fix/dep-{pkg_name}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
    create_branch(owner, repo, branch, base_sha)

    for manifest_path, is_npm in [("app/package.json", True), ("requirements.txt", False), ("agents/requirements.txt", False)]:
        try:
            content, file_sha = get_file(owner, repo, manifest_path, branch)
        except Exception:
            continue
        if pkg_name not in content:
            continue

        if not is_npm:
            new_content = re.sub(
                rf"({re.escape(pkg_name)}[^\n]*)",
                rf"\1  # SECURITY: update this package — see PR description",
                content, count=1,
            )
            try:
                commit_file(owner, repo, branch, manifest_path, new_content,
                            f"security: flag vulnerable dependency {pkg_name}", file_sha)
            except Exception as exc:
                print(f"  Commit skipped: {exc}")

        pr_body = f"""## 🔒 Vulnerable Dependency: `{pkg_name}`

**Finding:** {title}
**Manifest:** `{manifest_path}`
**Detected by:** osv-scanner

### What to do
1. Check the latest safe version of `{pkg_name}` on [npmjs.com](https://www.npmjs.com/package/{pkg_name}) or [PyPI](https://pypi.org/project/{pkg_name}).
2. Update the version constraint in `{manifest_path}`.
3. Run your test suite, then merge this PR.

---
*Auto-generated by fix_pr_agent.py — human review required before merging.*"""

        url = open_draft_pr(owner, repo,
            title=f"fix(security): update vulnerable dependency `{pkg_name}`",
            body=pr_body, head=branch)
        print(f"  Opened draft PR: {url}")
        return url

    print(f"  Could not find manifest containing {pkg_name}")
    return None


def fix_sast_finding(owner, repo, finding, base_sha):
    file_path = finding.get("file", "")
    if not file_path or file_path == "dependency-manifest":
        return None

    branch = f"fix/sast-{Path(file_path).stem}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
    create_branch(owner, repo, branch, base_sha)

    try:
        content, _ = get_file(owner, repo, file_path, branch)
    except Exception as exc:
        print(f"  Could not fetch {file_path}: {exc}")
        return None

    patch = claude_generate_patch(finding["title"], content, finding["location"])

    pr_body = f"""## 🔒 SAST Finding: {finding['title']}

**Tool:** {finding['tool']}
**Severity:** {finding['severity']}
**Location:** `{finding['location']}`

### AI Analysis
{finding.get('analysis', {}).get('reasoning', 'See recommended fix below.')}

### Recommended Fix
{patch}

---
*Auto-generated by fix_pr_agent.py — human review required before merging.*"""

    url = open_draft_pr(owner, repo,
        title=f"fix(security): {finding['title'][:72]}",
        body=pr_body, head=branch)
    print(f"  Opened draft PR: {url}")
    return url


def fix_secret_finding(owner, repo, finding, base_sha):
    file_path = finding.get("file", "")
    branch    = f"fix/secret-leak-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
    create_branch(owner, repo, branch, base_sha)

    try:
        gitignore_content, gitignore_sha = get_file(owner, repo, ".gitignore", branch)
    except Exception:
        gitignore_content, gitignore_sha = "", None

    entry = Path(file_path).name
    if entry not in gitignore_content:
        new_gitignore = gitignore_content.rstrip("\n") + f"\n# Added by security agent\n{entry}\n"
        try:
            if gitignore_sha:
                commit_file(owner, repo, branch, ".gitignore", new_gitignore,
                            f"security: add {entry} to .gitignore", gitignore_sha)
            else:
                gh_request("PUT", f"/repos/{owner}/{repo}/contents/.gitignore", {
                    "message": f"security: add {entry} to .gitignore",
                    "content": base64.b64encode(new_gitignore.encode()).decode(),
                    "branch": branch,
                })
        except Exception as exc:
            print(f"  .gitignore update skipped: {exc}")

    pr_body = f"""## 🚨 Secret Leak Detected

**Finding:** {finding['title']}
**File:** `{file_path}`
**Detected by:** gitleaks

### Immediate Actions Required
1. **Rotate the credential** — assume it is compromised.
2. **Remove the secret from git history** using `git filter-repo` or BFG Repo Cleaner.
3. This PR adds `{entry}` to `.gitignore` to prevent future commits.

---
*Auto-generated by fix_pr_agent.py — human review required before merging.*"""

    url = open_draft_pr(owner, repo,
        title=f"fix(security): secret leak in {entry} — rotate credentials",
        body=pr_body, head=branch)
    print(f"  Opened draft PR: {url}")
    return url


def main():
    if not GITHUB_TOKEN:
        sys.exit("ERROR: GITHUB_TOKEN not set.")

    owner = GITHUB_ORG  or "unknown"
    repo  = GITHUB_REPO or "unknown"

    osv_data      = json.loads((REPORTS / "osv.json").read_text())      if (REPORTS / "osv.json").exists()      else None
    semgrep_data  = json.loads((REPORTS / "semgrep.json").read_text())  if (REPORTS / "semgrep.json").exists()  else None
    gitleaks_data = json.loads((REPORTS / "gitleaks.json").read_text()) if (REPORTS / "gitleaks.json").exists() else None

    findings = []

    if osv_data:
        for res in osv_data.get("results", []):
            for p in res.get("packages", []):
                pkg = p.get("package", {}).get("name", "unknown")
                for v in p.get("vulnerabilities", []):
                    findings.append({"type": "dep", "tool": "osv-scanner",
                        "title": f"Vulnerable dep: {pkg} ({v.get('id','OSV')})",
                        "severity": "HIGH", "file": "dependency-manifest",
                        "location": "dependency-manifest",
                        "recommendation": "Update to a patched version."})

    if semgrep_data and "results" in semgrep_data:
        for r in semgrep_data["results"]:
            path = (r.get("path") or "").replace("\\", "/")
            if "node_modules/" in path:
                continue
            findings.append({"type": "sast", "tool": "semgrep",
                "title": f"{r.get('check_id','rule')}: {r.get('extra',{}).get('message','')[:100]}",
                "severity": r.get("extra", {}).get("severity", "MEDIUM"),
                "file": path,
                "location": f"{path}:{r.get('start',{}).get('line','?')}",
                "recommendation": "See Semgrep rule for fix guidance.",
                "analysis": {}})

    if gitleaks_data and isinstance(gitleaks_data, list):
        for r in gitleaks_data:
            findings.append({"type": "secret", "tool": "gitleaks",
                "title": f"Secret: {r.get('Description','unknown')}",
                "severity": "CRITICAL",
                "file": r.get("File", "unknown"),
                "location": f"{r.get('File','?')}:{r.get('StartLine','?')}",
                "recommendation": "Rotate credentials immediately."})

    print(f"Total findings to fix: {len(findings)}")
    base_sha = get_default_sha(owner, repo)
    pr_urls  = []

    for i, f in enumerate(findings, 1):
        print(f"\n[{i}/{len(findings)}] {f['title'][:80]}")
        try:
            if f["type"] == "dep":
                url = fix_vulnerable_dep(owner, repo, f, base_sha)
            elif f["type"] == "sast":
                url = fix_sast_finding(owner, repo, f, base_sha)
            elif f["type"] == "secret":
                url = fix_secret_finding(owner, repo, f, base_sha)
            else:
                url = None
            if url:
                pr_urls.append(url)
        except Exception as exc:
            print(f"  ERROR opening PR: {exc}")

    print(f"\n✅ Opened {len(pr_urls)} draft PR(s):")
    for u in pr_urls:
        print(f"  {u}")


if __name__ == "__main__":
    main()
