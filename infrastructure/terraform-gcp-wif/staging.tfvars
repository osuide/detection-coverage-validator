# A13E GCP WIF Configuration - Staging
#
# Usage:
#   cd infrastructure/terraform-gcp-wif
#   gcloud auth application-default login --project=a13e-workspace-automation
#   terraform init
#   terraform plan -var-file="staging.tfvars"
#   terraform apply -var-file="staging.tfvars"

aws_region                      = "eu-west-2"
aws_account_id                  = "123080274263"
environment                     = "staging"
gcp_project_id                  = "a13e-workspace-automation"
workspace_admin_email           = "austin@a13e.com"
workspace_service_account_email = "workspace-automation@a13e-workspace-automation.iam.gserviceaccount.com"
