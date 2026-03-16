# Architecture

## Overview

This project implements a DevSecOps pipeline that continuously scans a single-page application for security vulnerabilities, stores findings in DefectDojo, and uses an AI agent (Claude via MCP) to contextualise and triage results.

## Components

| Component | Technology | Purpose |
|-----------|-----------|--------|
| SPA | HTML/JS (static) | Demo application hosted on CloudFront |
| IaC | Terraform | Reproducible AWS infrastructure |
| CI/CD | GitHub Actions | Build, test, scan, deploy on every push |
| SAST | Semgrep | Static code analysis |
| Dep scan | npm audit / OSV | Dependency vulnerability scanning |
| Findings store | DefectDojo | Vulnerability tracking and deduplication |
| AI triage | Claude + MCP | False positive reduction and contextualisation |
| Hosting | AWS S3 + CloudFront | Secure, scalable SPA delivery |

## Pipeline flow

```
Push to main
    │
    ├─ Build & test (Node)
    ├─ Semgrep SAST scan
    └─ Deploy to S3/CloudFront

Cron (Mon + Thu)
    │
    ├─ Semgrep full scan
    ├─ npm audit
    ├─ OWASP ZAP (DAST)
    ├─ Push results → DefectDojo
    └─ AI triage agent → annotate findings
```

## Phases

- **Phase 1** (current): GitHub repo, Terraform AWS infra, CI/CD pipeline, SPA skeleton
- **Phase 2**: Scheduled scans, DefectDojo deployment
- **Phase 3**: AI MCP triage agent
- **Phase 4**: Reporting and documentation

## Reproducibility

All infrastructure is defined in Terraform. A new environment can be stood up by:
1. Running `terraform/bootstrap` once
2. Running `terraform apply` in `terraform/`
3. Adding the required GitHub secrets (see `docs/aws-setup.md`)
