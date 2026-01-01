# Staging Terraform Backend Configuration
# Usage: terraform init -backend-config=backend-staging.hcl -reconfigure

bucket         = "a13e-terraform-state"
key            = "staging/terraform.tfstate"
region         = "eu-west-2"
encrypt        = true
dynamodb_table = "a13e-terraform-lock"
