"""
org_catalog_agent.py
--------------------
Scans every repository in a GitHub org (or user account) via the GitHub API
and writes a single ORG_CATALOG.md summarising what each repo does.

Requires:
  GITHUB_TOKEN  env var with repo read scope
  GITHUB_ORG    env var — org login OR username (e.g. "maustin44")

Outputs:
  docs/ORG_CATALOG.md
"""

import os
import sys
import json
import base64
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GITHUB_ORG   = os.environ.get("GITHUB_ORG", "")
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")

DOCS_DIR = Path(__file__).resolve().parents[1] / "docs"
DOCS_DIR.mkdir(exist_ok=True)


def gh_get(path: str) -> dict | list:
    """Minimal GitHub REST helper — no external dependencies."""
    url = f"https://api.github.com{path}"
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def list_repos(org: str) -> list[dict]:
    """Return all repos for the org/user (handles pagination)."""
    repos = []
    page = 1
    while True:
        # Try org endpoint first; fall back to user endpoint
        try:
            batch = gh_get(f"/orgs/{org}/repos?per_page=100&page={page}")
        except urllib.error.HTTPError:
            batch = gh_get(f"/users/{org}/repos?per_page=100&page={page}")
        if not batch:
            break
        repos.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    return repos


def get_readme(owner: str, repo: str) -> str:
    """Fetch README content (plain text, max 4 KB)."""
    try:
        data = gh_get(f"/repos/{owner}/{repo}/readme")
        raw = base64.b64decode(data["content"]).decode("utf-8", errors="replace")
        return raw[:4000]  # trim so we don't blow context window
    except Exception:
        return ""


def get_languages(owner: str, repo: str) -> str:
    """Return comma-separated top languages."""
    try:
        langs = gh_get(f"/repos/{owner}/{repo}/languages")
        top = sorted(langs.items(), key=lambda x: x[1], reverse=True)[:4]
        return ", ".join(k for k, _ in top) or "unknown"
    except Exception:
        return "unknown"


def claude_summarise(repo_name: str, description: str, languages: str, readme: str) -> str:
    """Ask Claude for a one-paragraph plain-English summary of what this repo does."""
    if not ANTHROPIC_API_KEY:
        # Graceful degradation — just use GitHub description
        return description or "(No description available — set ANTHROPIC_API_KEY for AI summaries.)"

    prompt = (
        f"Repo: {repo_name}\n"
        f"GitHub description: {description or 'none'}\n"
        f"Languages: {languages}\n"
        f"README (truncated):\n{readme}\n\n"
        "Write a single concise paragraph (2-4 sentences) explaining what this repository "
        "does, who would use it, and any notable security or operational considerations. "
        "Be plain-English; avoid marketing language."
    )

    body = json.dumps({
        "model": "claude-sonnet-4-20250514",
        "max_tokens": 300,
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


def main():
    if not GITHUB_TOKEN:
        sys.exit("ERROR: GITHUB_TOKEN environment variable not set.")
    if not GITHUB_ORG:
        sys.exit("ERROR: GITHUB_ORG environment variable not set.")

    print(f"Fetching repos for: {GITHUB_ORG}")
    repos = list_repos(GITHUB_ORG)
    print(f"Found {len(repos)} repositories.")

    lines = [
        "# Org Repository Catalog",
        "",
        f"- Organisation: `{GITHUB_ORG}`",
        f"- Generated: {datetime.utcnow().isoformat()}Z",
        f"- Total repos: {len(repos)}",
        "",
        "---",
        "",
    ]

    for repo in repos:
        name        = repo["name"]
        full_name   = repo["full_name"]
        description = repo.get("description") or ""
        url         = repo["html_url"]
        archived    = repo.get("archived", False)
        pushed_at   = repo.get("pushed_at", "unknown")
        default_branch = repo.get("default_branch", "main")

        print(f"  Processing {name}...", end=" ", flush=True)

        languages = get_languages(GITHUB_ORG, name)
        readme    = get_readme(GITHUB_ORG, name)
        summary   = claude_summarise(name, description, languages, readme)

        print("done")

        archived_tag = " 🗄️ ARCHIVED" if archived else ""
        lines += [
            f"## [{name}]({url}){archived_tag}",
            "",
            f"- **Languages:** {languages}",
            f"- **Last push:** {pushed_at[:10] if pushed_at != 'unknown' else 'unknown'}",
            f"- **Default branch:** `{default_branch}`",
            "",
            summary,
            "",
            "---",
            "",
        ]

    out = DOCS_DIR / "ORG_CATALOG.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"\nWrote {out}")


if __name__ == "__main__":
    main()
