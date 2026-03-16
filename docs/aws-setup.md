# AWS Setup Guide

One-time steps required before the Terraform pipeline can run.

## Prerequisites

- AWS CLI installed and configured (`aws configure`)
- Terraform >= 1.5 installed
- An AWS account with sufficient IAM permissions

## Step 1 — Bootstrap Terraform state backend

This creates the S3 bucket and DynamoDB table used by all subsequent Terraform runs.
Only run this once.

```bash
cd terraform/bootstrap
terraform init
terraform apply
```

## Step 2 — Create a deploy IAM user for GitHub Actions

```bash
# Create user
aws iam create-user --user-name mcp-sec-demo-deploy

# Attach policies (least privilege — expand as needed)
aws iam attach-user-policy \
  --user-name mcp-sec-demo-deploy \
  --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess

aws iam attach-user-policy \
  --user-name mcp-sec-demo-deploy \
  --policy-arn arn:aws:iam::aws:policy/CloudFrontFullAccess

# Create access keys — save these for GitHub secrets
aws iam create-access-key --user-name mcp-sec-demo-deploy
```

## Step 3 — Provision the SPA infrastructure

```bash
cd terraform
terraform init
terraform plan
terraform apply
```

Note the outputs — you'll need `cloudfront_url`, `s3_bucket_name`, and `cloudfront_distribution_id`.

## Step 4 — Add GitHub Actions secrets

In your GitHub repo: Settings → Secrets and variables → Actions

| Secret | Value |
|--------|-------|
| `AWS_ACCESS_KEY_ID` | From Step 2 |
| `AWS_SECRET_ACCESS_KEY` | From Step 2 |
| `S3_BUCKET_NAME` | From Terraform output |
| `CLOUDFRONT_DISTRIBUTION_ID` | From Terraform output |
| `SEMGREP_APP_TOKEN` | From semgrep.dev (optional) |
| `ANTHROPIC_API_KEY` | From console.anthropic.com |

## Architecture

```
GitHub Actions
     │
     ▼
  S3 Bucket (private)
     │
     ▼
CloudFront (HTTPS, OAC)
     │
     ▼
   Browser
```

All traffic is HTTPS-only. S3 is fully private — only CloudFront can read from it via Origin Access Control.
