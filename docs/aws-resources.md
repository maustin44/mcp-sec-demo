# Live AWS Resources

> Auto-generated after Phase 1 Terraform apply. Do not edit manually.

## Environment: dev

| Resource | Value |
|----------|-------|
| CloudFront URL | https://dc4u52ktze490.cloudfront.net |
| CloudFront Distribution ID | E1D9LJBVCAP692 |
| S3 Bucket | mcp-sec-demo-spa-dev |
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
| `ANTHROPIC_API_KEY` | From console.anthropic.com (Phase 3) |
| `SEMGREP_APP_TOKEN` | From semgrep.dev (Phase 2, optional) |

## Status

- [x] Phase 1 — Terraform bootstrap
- [x] Phase 1 — SPA infrastructure (S3 + CloudFront)
- [x] Phase 1 — CI/CD pipeline (GitHub Actions)
- [ ] Phase 2 — Scheduled scans + DefectDojo
- [ ] Phase 3 — AI MCP triage agent
- [ ] Phase 4 — Reporting
