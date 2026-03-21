# Architecture

## Overview

This project implements a DevSecOps pipeline that continuously scans a single-page application for security vulnerabilities, stores findings in DefectDojo, and uses an AI agent (Claude via MCP) to contextualise and triage results.

## Components

| Component | Technology | Purpose |
|-----------|-----------|--------|
| SPA | HTML/JS (static) | Demo application hosted on CloudFront |
| IaC | Terraform | Reproducible AWS infrastructure |
| CI/CD | GitHub Actions | Build, scan, deploy on every push |
| SAST | SonarCloud | Static code analysis on every push |
| DAST | OWASP ZAP | Dynamic attack scan against live app (scheduled) |
| Dep scan | npm audit | Dependency vulnerability scanning |
| Secret scan | Gitleaks | Detects secrets committed to the repo |
| Findings store | DefectDojo | Vulnerability tracking and deduplication |
| AI triage | Claude + MCP | False positive reduction and contextualisation |
| Hosting | AWS S3 + CloudFront | Secure, scalable SPA delivery |

## Pipeline flow

```
Push to main
    │
    ├── SonarCloud SAST
    ├── npm audit
    ├── Gitleaks secret scan
    └── Deploy to S3/CloudFront (gated on above)

Cron (Mon + Thu 08:00 UTC)
    │
    ├── SonarCloud full scan
    ├── OWASP ZAP DAST → hits live CloudFront URL
    ├── npm audit
    └── Push results → DefectDojo
            └── AI triage agent → annotate findings
```

## Scan tool responsibilities

| Tool | Type | When | Finds |
|------|------|------|-------|
| SonarCloud | SAST | Every push + scheduled | Code vulnerabilities, hotspots, bugs |
| OWASP ZAP | DAST | Scheduled only | Runtime issues, XSS, misconfig headers |
| npm audit | SCA | Every push + scheduled | Dependency CVEs |
| Gitleaks | Secret scan | Every push | Hardcoded secrets, tokens |

## Phases

- **Phase 1** (complete): GitHub repo, Terraform AWS infra, CI/CD pipeline, SPA
- **Phase 2** (next): Scheduled scans wired to DefectDojo
- **Phase 3**: AI MCP triage agent
- **Phase 4**: Reporting and documentation

## Reproducibility

All infrastructure is defined in Terraform. A new environment can be stood up by:
1. Running `terraform/bootstrap` once
2. Running `terraform apply` in `terraform/`
3. Adding the required GitHub secrets (see `docs/aws-setup.md` and `docs/sonarcloud-setup.md`)
