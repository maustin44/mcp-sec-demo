"""
context_triage_agent.py
-----------------------
Reads raw scanner reports (Semgrep, Gitleaks, OSV) and fetches the
actual code context from GitHub for each finding.  Claude then decides
whether each finding is a TRUE POSITIVE or FALSE POSITIVE, and produces
a filtered, prioritised FIX_LIST.md — removing noise so developers only
see real issues.

Requires:
  GITHUB_TOKEN      — repo read scope
  ANTHROPIC_API_KEY — for contextual analysis
  GITHUB_ORG        — org or user login
  GITHUB_REPO       — repo name being analysed

Outputs:
  docs/FIX_LIST.md   (filtered, with AI reasoning)
"""

import os
import sys
import json
import base64
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path

GITHUB_TOKEN      = os.environ.get("GITHUB_TOKEN", "")
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
GITHUB_ORG        = os.environ.get("GITHUB_ORG", "")
GITHUB_REPO       = os.environ.get("GITHUB_REPO", "")

REPO_ROOT = Path(__file__).resolve().parents[1]
REPORTS   = REPO_ROOT / "reports"
DOCS_DIR  = REPO_ROOT / "docs"
DOCS_DIR.mkdir(exist_ok=True)


# ---------------------------------------------------------------------------
# GitHub helpers
# ---------------------------------------------------------------------------

def gh_get(path: str) -> dict | list:
    url = f"https://api.github.com{path}"
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    req = requests.Request(url, headers=req.headers) ; with requests.Session().request(req)
        return json.loads(resp.read())


def fetch_file_content(owner: str, repo: str, file_path: str) -> str:
    """Return decoded file content from GitHub (max 8 KB)."""
    # Normalise Windows-style paths that Semgrep may emit
    file_path = file_path.replace("\\", "/").lstrip("/")
    try:
        data = gh_get(f"/repos/{owner}/{repo}/contents/{file_path}")
        raw  = base64.b64decode(data["content"]).decode("utf-8", errors="replace")
        return raw[:8000]
    except Exception as exc:
        return f"(Could not fetch file: {exc})"


# ---------------------------------------------------------------------------
# Report loaders (reuse logic from triage_agent.py)
# ---------------------------------------------------------------------------

def load_json(path: Path):
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def severity_score(sev: str) -> int:
    s = (sev or "").lower()
    if "critical" in s: return 100
    if "high"     in s: return 80
    if "medium"   in s: return 50
    if "low"      in s: return 20
    return 10


def collect_raw_findings(semgrep_data, gitleaks_data, osv_data) -> list[dict]:
    findings = []

    # Semgrep
    if semgrep_data and "results" in semgrep_data:
        for r in semgrep_data["results"]:
            path  = (r.get("path") or "").replace("\\", "/")
            line  = r.get("start", {}).get("line")
            msg   = r.get("extra", {}).get("message", "Semgrep finding")
            sev   = r.get("extra", {}).get("severity", "MEDIUM")
            rule  = r.get("check_id", "unknown-rule")
            if "node_modules/" in path or path.endswith(".md"):
                continue
            findings.append({
                "tool": "semgrep",
                "title": f"{rule}: {msg}",
                "severity": sev,
                "file": path,
                "line": line,
                "location": f"{path}:{line}" if path and line else path or "unknown",
                "recommendation": "Review code context and apply secure coding fix.",
            })

    # Gitleaks
    if gitleaks_data and isinstance(gitleaks_data, list):
        for r in gitleaks_data:
            findings.append({
                "tool": "gitleaks",
                "title": f"Secret detected: {r.get('Description', 'Secret')}",
                "severity": "CRITICAL",
                "file": r.get("File", "unknown"),
                "line": r.get("StartLine"),
                "location": f"{r.get('File','?')}:{r.get('StartLine','?')}",
                "recommendation": "Remove secret, rotate credentials, add pre-commit secret scanning.",
            })

    # OSV
    if osv_data:
        for res in osv_data.get("results", []):
            for p in res.get("packages", []):
                pkg = p.get("package", {}).get("name", "unknown")
                for v in p.get("vulnerabilities", []):
                    findings.append({
                        "tool": "osv-scanner",
                        "title": f"Vulnerable dep: {pkg} ({v.get('id','OSV')})",
                        "severity": "HIGH",
                        "file": "dependency-manifest",
                        "line": None,
                        "location": "dependency-manifest",
                        "recommendation": "Update dependency to patched version.",
                    })

    findings.sort(key=lambda f: severity_score(f.get("severity", "")), reverse=True)
    return findings


# ---------------------------------------------------------------------------
# Claude contextual analysis
# ---------------------------------------------------------------------------

def claude_analyse(finding: dict, code_context: str) -> dict:
    """
    Ask Claude whether a finding is a true or false positive given the
    actual source code.  Returns {verdict, confidence, reasoning, fix}.
    """
    if not ANTHROPIC_API_KEY:
        return {
            "verdict": "UNKNOWN",
            "confidence": "low",
            "reasoning": "ANTHROPIC_API_KEY not set — skipping contextual analysis.",
            "fix": finding["recommendation"],
        }

    prompt = f"""You are a senior application security engineer performing triage on SAST/secret scanner findings.

FINDING:
- Tool: {finding['tool']}
- Rule/Title: {finding['title']}
- Severity: {finding['severity']}
- Location: {finding['location']}

CODE CONTEXT:
```
{code_context}
```

Task:
1. Determine if this is a TRUE_POSITIVE (real vulnerability) or FALSE_POSITIVE (scanner noise / safe pattern).
2. Provide your confidence: HIGH, MEDIUM, or LOW.
3. Explain your reasoning in 2-3 sentences referencing specific lines/patterns in the code.
4. If TRUE_POSITIVE, provide a concise recommended fix (1-3 sentences or a short code snippet).

Respond ONLY with valid JSON matching this schema:
{{
  "verdict": "TRUE_POSITIVE" | "FALSE_POSITIVE",
  "confidence": "HIGH" | "MEDIUM" | "LOW",
  "reasoning": "...",
  "fix": "..." 
}}"""

    body = json.dumps({
        "model": "claude-sonnet-4-20250514",
        "max_tokens": 500,
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
    try:
        with urllib.request.urlopen(req) as resp:
            result  = json.loads(resp.read())
        text = result["content"][0]["text"].strip()
        # Strip markdown fences if present
        if text.startswith("```"):
            text = text.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
        return json.loads(text)
    except Exception as exc:
        return {
            "verdict": "UNKNOWN",
            "confidence": "low",
            "reasoning": f"Claude analysis failed: {exc}",
            "fix": finding["recommendation"],
        }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if not GITHUB_TOKEN:
        sys.exit("ERROR: GITHUB_TOKEN not set.")

    owner = GITHUB_ORG  or "unknown"
    repo  = GITHUB_REPO or "unknown"

    semgrep  = load_json(REPORTS / "semgrep.json")
    gitleaks = load_json(REPORTS / "gitleaks.json")
    osv      = load_json(REPORTS / "osv.json")

    raw_findings = collect_raw_findings(semgrep, gitleaks, osv)
    print(f"Raw findings: {len(raw_findings)}")

    true_positives  = []
    false_positives = []

    for i, finding in enumerate(raw_findings, 1):
        print(f"  [{i}/{len(raw_findings)}] Analysing: {finding['title'][:70]}...")

        # Fetch code context from GitHub when we have a real file path
        if finding["file"] and finding["file"] != "dependency-manifest":
            code_context = fetch_file_content(owner, repo, finding["file"])
        else:
            code_context = "(No source file — dependency or secret finding.)"

        analysis = claude_analyse(finding, code_context)
        finding["analysis"] = analysis

        if analysis["verdict"] == "FALSE_POSITIVE":
            false_positives.append(finding)
        else:
            true_positives.append(finding)

    # Write filtered fix list
    md = [
        "# Fix List (Context-Filtered)",
        "",
        f"- Generated: {datetime.utcnow().isoformat()}Z",
        f"- Raw findings: {len(raw_findings)}",
        f"- True positives: {len(true_positives)}",
        f"- False positives suppressed: {len(false_positives)}",
        "",
    ]

    if not true_positives:
        md.append("✅ No confirmed vulnerabilities found after contextual analysis.")
    else:
        md.append("## Confirmed Vulnerabilities (Action Required)")
        md.append("")
        for i, f in enumerate(true_positives, 1):
            a = f["analysis"]
            md += [
                f"### {i}. {f['title']}",
                f"- **Tool:** `{f['tool']}`",
                f"- **Severity:** **{f['severity']}**",
                f"- **Location:** `{f['location']}`",
                f"- **AI Confidence:** {a.get('confidence','?')}",
                f"- **Reasoning:** {a.get('reasoning','')}",
                f"- **Recommended Fix:** {a.get('fix', f['recommendation'])}",
                "",
            ]

    if false_positives:
        md += [
            "---",
            "",
            "## Suppressed False Positives",
            "",
            "The following were flagged by scanners but determined to be safe after code review:",
            "",
        ]
        for f in false_positives:
            a = f["analysis"]
            md.append(f"- `{f['location']}` — {f['tool']}: {a.get('reasoning', 'False positive')}")
        md.append("")

    out = DOCS_DIR / "FIX_LIST.md"
    out.write_text("\n".join(md), encoding="utf-8")
    print(f"\nWrote {out}")
    print(f"True positives: {len(true_positives)} | False positives suppressed: {len(false_positives)}")


if __name__ == "__main__":
    main()
