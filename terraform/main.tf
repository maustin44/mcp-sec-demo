terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    bucket         = "mcp-sec-demo-tfstate"
    key            = "global/s3/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "mcp-sec-demo-tfstate-lock"
    encrypt        = true
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "mcp-sec-demo"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

module "spa_hosting" {
  source      = "./modules/s3-cloudfront"
  project     = var.project
  environment = var.environment
}

module "defectdojo" {
  source        = "./modules/defectdojo"
  project       = var.project
  environment   = var.environment
  aws_region    = var.aws_region
  db_password   = var.db_password
  dd_secret_key = var.dd_secret_key
}
