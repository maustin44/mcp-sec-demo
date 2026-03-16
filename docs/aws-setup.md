# AWS Setup Guide

One-time steps required before the Terraform pipeline can run.

## Prerequisites

### Install Terraform

**Windows (winget):**
```powershell
winget install HashiCorp.Terraform
```

**Windows (Chocolatey):**
```powershell
choco install terraform -y
```

**Windows (manual):**
1. Download from https://developer.hashicorp.com/terraform/install#windows
2. Extract `terraform.exe` to `C:\Windows\System32\`
3. Verify: `terraform -version`

**macOS:**
```bash
brew tap hashicorp/tap && brew install hashicorp/tap/terraform
```

### Install AWS CLI

**Windows:**
```powershell
winget install Amazon.AWSCLI
```

**macOS:**
```bash
brew install awscli
```

### Configure AWS credentials

```bash
aws configure
# Enter: Access Key ID, Secret Access Key, region (us-east-1), output format (json)
```

---

## Step 1 — Bootstrap Terraform state backend

This creates the S3 bucket and DynamoDB table used by all subsequent Terraform runs.
**Only run this once.**

```bash
cd terraform/bootstrap
terraform init
terraform apply
```

## Step 2 — Create a deploy IAM user for GitHub Actions

```bash
# Create user
aws iam create-user --user-name mcp-sec-demo-deploy

# Attach policies
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

Note the outputs — you will need `cloudfront_url`, `s3_bucket_name`, and `cloudfront_distribution_id`.

## Step 4 — Add GitHub Actions secrets

In your GitHub repo: Settings → Secrets and variables → Actions

| Secret | Where to get it |
|--------|----------------|
| `AWS_ACCESS_KEY_ID` | Step 2 output |
| `AWS_SECRET_ACCESS_KEY` | Step 2 output |
| `S3_BUCKET_NAME` | Terraform output |
| `CLOUDFRONT_DISTRIBUTION_ID` | Terraform output |
| `SEMGREP_APP_TOKEN` | semgrep.dev (optional) |
| `ANTHROPIC_API_KEY` | console.anthropic.com |

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
