# SonarCloud Setup

SonarCloud is the hosted version of SonarQube — free for public repositories.

## Step 1 — Create a SonarCloud account

1. Go to https://sonarcloud.io
2. Sign in with your GitHub account
3. Click **+** → **Analyze new project**
4. Select the `mcp-sec-demo` repository
5. Choose **GitHub Actions** as the analysis method

## Step 2 — Get your SONAR_TOKEN

1. In SonarCloud: **My Account → Security → Generate Token**
2. Name it `github-actions`
3. Copy the token

## Step 3 — Add GitHub secret

In your GitHub repo: **Settings → Secrets → Actions → New secret**

| Secret | Value |
|--------|-------|
| `SONAR_TOKEN` | Token from Step 2 |

## Step 4 — Verify sonar-project.properties

The `sonar-project.properties` file in the repo root must match your SonarCloud project key and organization.
Update these values if they differ from what SonarCloud shows:

```properties
sonar.projectKey=maustin44_mcp-sec-demo
sonar.organization=maustin44
```

## What SonarCloud catches

- Security vulnerabilities (injection, XSS, etc.)
- Security hotspots (code requiring manual review)
- Bugs and code smells
- Duplicated code
- Test coverage gaps

Results appear in the SonarCloud dashboard and as PR decorations on pull requests.
