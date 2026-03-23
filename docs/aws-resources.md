# Live AWS Resources

> Updated after Phase 2 Terraform apply. Do not edit manually.

## Environment: dev

| Resource | Value |
|----------|-------|
| CloudFront URL | https://dc4u52ktze490.cloudfront.net |
| CloudFront Distribution ID | E1D9LJBVCAP692 |
| S3 Bucket | mcp-sec-demo-spa-dev |
| DefectDojo URL | http://mcp-sec-demo-dev-alb-1744594438.us-east-1.elb.amazonaws.com |
| AWS Region | us-east-1 |
| Terraform State Bucket | mcp-sec-demo-tfstate |
| Terraform Lock Table | mcp-sec-demo-tfstate-lock |

## GitHub Actions Secrets Required

| Secret | Value |
|--------|-------|
| `AWS_ACCESS_KEY_ID` | IAM user access key |
| `AWS_SECRET_ACCESS_KEY` | IAM user secret key |
| `S3_BUCKET_NAME` | `mcp-sec-demo-spa-dev` |
| `CLOUDFRONT_DISTRIBUTION_ID` | `E1D9LJBVCAP692` |
| `SONAR_TOKEN` | From sonarcloud.io |
| `DEFECTDOJO_URL` | `http://mcp-sec-demo-dev-alb-1744594438.us-east-1.elb.amazonaws.com` |
| `DEFECTDOJO_API_KEY` | From DefectDojo admin panel (Step 4 below) |
| `DEFECTDOJO_ENGAGEMENT_ID` | From DefectDojo after creating engagement (Step 3 below) |
| `ANTHROPIC_API_KEY` | From console.anthropic.com (Phase 3) |

## Status

- [x] Phase 1 — Terraform bootstrap
- [x] Phase 1 — SPA infrastructure (S3 + CloudFront)
- [x] Phase 1 — CI/CD pipeline (GitHub Actions)
- [x] Phase 2 — DefectDojo on ECS Fargate + RDS
- [x] Phase 2 — Checkov IaC misconfiguration scanning
- [x] Phase 2 — VS Code MCP local config
- [ ] Phase 2 — Wire scheduled scans to DefectDojo (needs secrets)
- [ ] Phase 3 — AI MCP triage agent (full implementation)
- [ ] Phase 4 — Reporting and documentation
