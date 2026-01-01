# Production Terraform Backend Configuration
# Usage: terraform init -backend-config=backend-prod.hcl -reconfigure

bucket         = "a13e-terraform-state"
key            = "prod/terraform.tfstate"
region         = "eu-west-2"
encrypt        = true
dynamodb_table = "a13e-terraform-lock"
