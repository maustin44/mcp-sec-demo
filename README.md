# AI Security Agent

Automated security scanning pipeline using Semgrep, OSV Scanner, and Claude AI for intelligent false-positive triage.

## What it does

On every push to any branch, the agent:

1. **Runs Semgrep** — scans source code for vulnerability patterns (SQL injection, eval(), hardcoded secrets, etc.)
2. **Runs OSV Scanner** — checks dependencies against known CVE database
3. **Runs Gitleaks** — detects secrets accidentally committed to the repo
4. **AI Triage** — sends each finding + surrounding code context to Claude, which determines if it's a real vulnerability or false positive
5. **Opens PRs** — for confirmed real vulnerabilities, automatically creates a branch and opens a PR with the fix. Human reviews and merges.

## Setup

### 1. Add GitHub Secrets

Go to your repo → Settings → Secrets and variables → Actions → New repository secret

| Secret | Description |
|--------|-------------|
| `ANTHROPIC_API_KEY` | Your Anthropic API key from console.anthropic.com |
| `SEMGREP_APP_TOKEN` | Your Semgrep token from semgrep.dev (optional but recommended) |
| `GITLEAKS_LICENSE` | Gitleaks license key (optional for private repos) |

`GITHUB_TOKEN` is provided automatically by GitHub Actions — no setup needed.

### 2. Add the workflow to your repo

Copy the `.github/workflows/security-scan.yml` file into your repository.

Copy the `agent/triage.py` file into your repository.

### 3. Push to trigger

Push any code change and the workflow will trigger automatically. Check the Actions tab in GitHub to see it running.

## File structure

```
.github/
  workflows/
    security-scan.yml    # GitHub Actions workflow
agent/
  triage.py             # AI triage agent (Claude)
```

## How false positive detection works

For each Semgrep finding, the agent fetches the full file from GitHub and sends:
- The flagged line
- 25 lines of context above and below
- The rule that triggered
- The severity level

Claude then reads the actual code and determines whether the pattern is genuinely dangerous in context, or whether mitigations are already in place. For example:
- A flagged `db.query()` call that's already using a sanitized ORM → **false positive**
- A `eval(userInput)` with no validation → **real vulnerability**

## Supported languages

Semgrep supports: Python, JavaScript, TypeScript, Go, Java, Ruby, PHP, C, C++, and more.

OSV Scanner supports: npm, pip, Go modules, Maven, Cargo, and more.
