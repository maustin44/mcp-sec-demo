# Architecture

## Overview

This project implements a DevSecOps pipeline that continuously scans a single-page application and its supporting infrastructure for security vulnerabilities and misconfigurations, stores findings in DefectDojo, and uses an AI agent (Claude via MCP) to contextualise and triage results — both in CI and locally in VS Code.

## Components

| Component | Technology | Purpose |
|-----------|-----------|--------|
| SPA | HTML/JS (static) | Demo application hosted on CloudFront |
| IaC | Terraform | Reproducible AWS infrastructure |
| CI/CD | GitHub Actions | Build, scan, deploy on every push |
| SAST | SonarCloud | Static code analysis on every push |
| IaC scan | Checkov | Terraform misconfiguration detection |
| DAST | OWASP ZAP | Dynamic attack scan against live app (scheduled) |
| Dep scan | npm audit | Dependency vulnerability scanning |
| Secret scan | Gitleaks | Detects secrets committed to the repo |
| Findings store | DefectDojo | Vulnerability tracking and deduplication |
| AI triage (CI) | Claude + GitHub Actions | Automated false positive reduction |
| AI triage (IDE) | Claude + VS Code MCP | Local interactive triage and report generation |
| Hosting | AWS S3 + CloudFront | Secure, scalable SPA delivery |

## Pipeline flow

```
Push to main
    |
    |-- SonarCloud SAST
    |-- Checkov IaC misconfiguration scan
    |-- npm audit
    |-- Gitleaks secret scan
    +-- Deploy to S3/CloudFront (gated on above)

Cron (Mon + Thu 08:00 UTC)
    |
    |-- SonarCloud full scan
    |-- Checkov IaC scan
    |-- OWASP ZAP DAST --> hits live CloudFront URL
    |-- npm audit
    +-- Push results --> DefectDojo
            +-- AI triage agent --> annotate findings

Local VS Code (on demand)
    |
    Claude extension
        |
        MCP server (agents/mcp_server.py)
            |
            |-- AWS APIs --> list services/containers
            |-- DefectDojo API --> get/update findings
            +-- Generate narrative report
```

## Scan tool responsibilities

| Tool | Type | When | Finds |
|------|------|------|-------|
| SonarCloud | SAST | Every push + scheduled | Code vulnerabilities, hotspots, bugs |
| Checkov | IaC scan | Every push + scheduled | Terraform misconfigurations |
| OWASP ZAP | DAST | Scheduled only | Runtime issues, XSS, misconfig headers |
| npm audit | SCA | Every push + scheduled | Dependency CVEs |
| Gitleaks | Secret scan | Every push | Hardcoded secrets, tokens |

## Phases

- **Phase 1** (complete): GitHub repo, Terraform AWS infra, CI/CD pipeline, SPA
- **Phase 2** (in progress): DefectDojo on ECS, scheduled scans wired to DefectDojo
- **Phase 3** (next): AI MCP triage agent — CI + VS Code IDE
- **Phase 4**: Reporting and documentation

## Reproducibility

All infrastructure is defined in Terraform. A new environment can be stood up by:
1. Running `terraform/bootstrap` once
2. Running `terraform apply` in `terraform/`
3. Adding the required GitHub secrets
4. Following `docs/vscode-mcp-setup.md` for local IDE setup
