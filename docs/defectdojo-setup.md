# DefectDojo Setup Guide

DefectDojo is deployed on AWS ECS Fargate with RDS PostgreSQL via Terraform.

## Step 1 — Create a tfvars file

Create `terraform/terraform.tfvars` (never commit this file):

```hcl
aws_region    = "us-east-1"
project       = "mcp-sec-demo"
environment   = "dev"
db_password   = "your-strong-password-here"
dd_secret_key = "your-random-secret-key-min-50-chars"
```

Generate a good secret key:
```bash
python3 -c "import secrets; print(secrets.token_urlsafe(50))"
```

## Step 2 — Apply Terraform

```bash
cd terraform
terraform init
terraform plan
terraform apply
```

Note the `defectdojo_url` output — this is your DefectDojo instance.

> Note: DefectDojo takes 3–5 minutes to start up after ECS deploys it.

## Step 3 — Initial DefectDojo setup

1. Open the `defectdojo_url` in your browser
2. Log in with default credentials: `admin` / `defectdojo`
3. **Immediately change the admin password**
4. Create a Product: `mcp-sec-demo`
5. Create an Engagement: `Scheduled Scans`
6. Note the Engagement ID from the URL (e.g. `/engagement/1/`)

## Step 4 — Get an API key

1. In DefectDojo: top right → **API v2 key**
2. Copy the key

## Step 5 — Add GitHub Actions secrets

| Secret | Value |
|--------|-------|
| `DEFECTDOJO_URL` | Terraform output `defectdojo_url` |
| `DEFECTDOJO_API_KEY` | From Step 4 |
| `DEFECTDOJO_ENGAGEMENT_ID` | From Step 3 |

## Architecture

```
GitHub Actions (scheduled)
        │
        ▼
  ZAP + npm audit results
        │
        ▼
  defectdojo_push.py
        │
        ▼
  ALB (port 80)
        │
        ▼
  ECS Fargate (DefectDojo Django)
        │
        ▼
  RDS PostgreSQL
```
