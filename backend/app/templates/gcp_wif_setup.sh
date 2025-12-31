#!/bin/bash
# A13E Detection Coverage Validator - GCP Workload Identity Federation Setup
#
# This script configures your GCP project to allow A13E to scan for security
# detections using Workload Identity Federation (WIF).
#
# Prerequisites:
#   - gcloud CLI installed and authenticated
#   - Owner or IAM Admin role on the GCP project
#   - A13E AWS account ID (shown in the A13E app during setup: 123080274263)
#
# Usage:
#   chmod +x gcp_wif_setup.sh
#   ./gcp_wif_setup.sh --project your-project-id --aws-account 123080274263
#
# For help:
#   ./gcp_wif_setup.sh --help

set -euo pipefail

# ============================================================================
# Configuration - modify these or pass as arguments
# ============================================================================

# Your GCP project ID (required)
PROJECT_ID=""

# A13E's AWS account ID (provided by A13E)
A13E_AWS_ACCOUNT_ID=""

# A13E's AWS IAM role name (provided by A13E)
A13E_AWS_ROLE_NAME="A13E-Scanner-Role"

# WIF pool configuration (defaults work for most cases)
POOL_ID="a13e-pool"
PROVIDER_ID="aws"
SERVICE_ACCOUNT_ID="a13e-scanner"
CUSTOM_ROLE_ID="a13e_detection_scanner"

# ============================================================================
# Helper functions
# ============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Colour

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

usage() {
    cat << EOF
A13E GCP Workload Identity Federation Setup

Usage: $0 [OPTIONS]

Required:
  --project PROJECT_ID      Your GCP project ID
  --aws-account ACCOUNT_ID  A13E's AWS account ID (provided by A13E)

Optional:
  --aws-role ROLE_NAME      A13E's AWS IAM role name (default: A13E-Scanner-Role)
  --pool-id POOL_ID         WIF pool ID (default: a13e-pool)
  --provider-id PROVIDER_ID AWS provider ID (default: aws)
  --sa-id SERVICE_ACCOUNT   Service account ID (default: a13e-scanner)
  --help                    Show this help message

Example:
  $0 --project my-gcp-project --aws-account 123080274263

EOF
    exit 0
}

# ============================================================================
# Parse arguments
# ============================================================================

while [[ $# -gt 0 ]]; do
    case $1 in
        --project)
            PROJECT_ID="$2"
            shift 2
            ;;
        --aws-account)
            A13E_AWS_ACCOUNT_ID="$2"
            shift 2
            ;;
        --aws-role)
            A13E_AWS_ROLE_NAME="$2"
            shift 2
            ;;
        --pool-id)
            POOL_ID="$2"
            shift 2
            ;;
        --provider-id)
            PROVIDER_ID="$2"
            shift 2
            ;;
        --sa-id)
            SERVICE_ACCOUNT_ID="$2"
            shift 2
            ;;
        --help)
            usage
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            ;;
    esac
done

# Validate required arguments
if [[ -z "$PROJECT_ID" ]]; then
    log_error "Missing required argument: --project"
    usage
fi

if [[ -z "$A13E_AWS_ACCOUNT_ID" ]]; then
    log_error "Missing required argument: --aws-account"
    usage
fi

# ============================================================================
# Main setup
# ============================================================================

log_info "Setting up A13E WIF for project: $PROJECT_ID"
log_info "Using AWS account: $A13E_AWS_ACCOUNT_ID"

# Set the project
gcloud config set project "$PROJECT_ID"

# ----------------------------------------------------------------------------
# Step 1: Enable required APIs
# ----------------------------------------------------------------------------

log_info "Step 1/7: Enabling required APIs..."

gcloud services enable \
    iam.googleapis.com \
    iamcredentials.googleapis.com \
    sts.googleapis.com \
    cloudresourcemanager.googleapis.com \
    logging.googleapis.com \
    monitoring.googleapis.com \
    securitycenter.googleapis.com \
    eventarc.googleapis.com \
    cloudfunctions.googleapis.com \
    run.googleapis.com \
    --quiet

log_info "APIs enabled successfully"

# ----------------------------------------------------------------------------
# Step 2: Create Workload Identity Pool
# ----------------------------------------------------------------------------

log_info "Step 2/7: Creating Workload Identity Pool..."

# Check if pool already exists
if gcloud iam workload-identity-pools describe "$POOL_ID" \
    --location="global" \
    --project="$PROJECT_ID" &>/dev/null; then
    log_warn "WIF pool '$POOL_ID' already exists, skipping creation"
else
    gcloud iam workload-identity-pools create "$POOL_ID" \
        --location="global" \
        --display-name="A13E Detection Scanner" \
        --description="Workload Identity Pool for A13E Detection Coverage Validator" \
        --project="$PROJECT_ID"
    log_info "WIF pool created"
fi

# ----------------------------------------------------------------------------
# Step 3: Create AWS Provider
# ----------------------------------------------------------------------------

log_info "Step 3/7: Creating AWS OIDC Provider..."

# Check if provider already exists
if gcloud iam workload-identity-pools providers describe "$PROVIDER_ID" \
    --workload-identity-pool="$POOL_ID" \
    --location="global" \
    --project="$PROJECT_ID" &>/dev/null; then
    log_warn "AWS provider '$PROVIDER_ID' already exists, skipping creation"
else
    gcloud iam workload-identity-pools providers create-aws "$PROVIDER_ID" \
        --workload-identity-pool="$POOL_ID" \
        --location="global" \
        --account-id="$A13E_AWS_ACCOUNT_ID" \
        --display-name="AWS Federation" \
        --description="AWS OIDC provider for A13E running on AWS ECS" \
        --attribute-mapping="google.subject=assertion.arn,attribute.aws_account=assertion.account,attribute.aws_role=assertion.arn.extract('/assumed-role/{role}/')" \
        --attribute-condition="attribute.aws_role == '${A13E_AWS_ROLE_NAME}'" \
        --project="$PROJECT_ID"
    log_info "AWS provider created"
fi

# ----------------------------------------------------------------------------
# Step 4: Create Service Account
# ----------------------------------------------------------------------------

log_info "Step 4/7: Creating Service Account..."

SERVICE_ACCOUNT_EMAIL="${SERVICE_ACCOUNT_ID}@${PROJECT_ID}.iam.gserviceaccount.com"

# Check if service account exists
if gcloud iam service-accounts describe "$SERVICE_ACCOUNT_EMAIL" \
    --project="$PROJECT_ID" &>/dev/null; then
    log_warn "Service account '$SERVICE_ACCOUNT_EMAIL' already exists, skipping creation"
else
    gcloud iam service-accounts create "$SERVICE_ACCOUNT_ID" \
        --display-name="A13E Detection Scanner" \
        --description="Service account for A13E Detection Coverage Validator. Read-only access to security configurations." \
        --project="$PROJECT_ID"
    log_info "Service account created"
fi

# ----------------------------------------------------------------------------
# Step 5: Create Custom IAM Role
# ----------------------------------------------------------------------------

log_info "Step 5/7: Creating Custom IAM Role..."

# Define permissions
PERMISSIONS=(
    # Cloud Logging
    "logging.logMetrics.list"
    "logging.logMetrics.get"
    "logging.sinks.list"
    "logging.sinks.get"
    # Cloud Monitoring
    "monitoring.alertPolicies.list"
    "monitoring.alertPolicies.get"
    "monitoring.notificationChannels.list"
    "monitoring.notificationChannels.get"
    # Security Command Center
    "securitycenter.findings.list"
    "securitycenter.findings.get"
    "securitycenter.sources.list"
    "securitycenter.sources.get"
    # Google SecOps / Chronicle SIEM
    "chronicle.rules.list"
    "chronicle.rules.get"
    "chronicle.detections.list"
    "chronicle.detections.get"
    "chronicle.curatedRuleSets.list"
    "chronicle.curatedRuleSets.get"
    "chronicle.alertGroupingRules.list"
    "chronicle.alertGroupingRules.get"
    "chronicle.referenceLists.list"
    "chronicle.referenceLists.get"
    # Eventarc
    "eventarc.triggers.list"
    "eventarc.triggers.get"
    # Cloud Functions
    "cloudfunctions.functions.list"
    "cloudfunctions.functions.get"
    # Cloud Run
    "run.services.list"
    "run.services.get"
    # Resource Manager
    "resourcemanager.projects.get"
)

PERMISSIONS_STRING=$(IFS=,; echo "${PERMISSIONS[*]}")

# Check if role exists
if gcloud iam roles describe "$CUSTOM_ROLE_ID" \
    --project="$PROJECT_ID" &>/dev/null; then
    log_warn "Custom role '$CUSTOM_ROLE_ID' already exists, updating permissions"
    gcloud iam roles update "$CUSTOM_ROLE_ID" \
        --project="$PROJECT_ID" \
        --permissions="$PERMISSIONS_STRING" \
        --quiet
else
    gcloud iam roles create "$CUSTOM_ROLE_ID" \
        --project="$PROJECT_ID" \
        --title="A13E Detection Scanner" \
        --description="Minimum read-only permissions for A13E to scan security detection configurations" \
        --permissions="$PERMISSIONS_STRING" \
        --stage="GA"
    log_info "Custom role created"
fi

# ----------------------------------------------------------------------------
# Step 6: Bind Role to Service Account
# ----------------------------------------------------------------------------

log_info "Step 6/7: Binding custom role to service account..."

gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="serviceAccount:${SERVICE_ACCOUNT_EMAIL}" \
    --role="projects/${PROJECT_ID}/roles/${CUSTOM_ROLE_ID}" \
    --condition=None \
    --quiet

log_info "Role binding created"

# ----------------------------------------------------------------------------
# Step 7: Allow WIF to Impersonate Service Account
# ----------------------------------------------------------------------------

log_info "Step 7/7: Configuring WIF impersonation permissions..."

# Get the full pool name
POOL_NAME="projects/${PROJECT_ID}/locations/global/workloadIdentityPools/${POOL_ID}"

# Workload Identity User role
gcloud iam service-accounts add-iam-policy-binding "$SERVICE_ACCOUNT_EMAIL" \
    --project="$PROJECT_ID" \
    --role="roles/iam.workloadIdentityUser" \
    --member="principalSet://iam.googleapis.com/${POOL_NAME}/attribute.aws_role/${A13E_AWS_ROLE_NAME}" \
    --condition=None \
    --quiet

# Service Account Token Creator role
gcloud iam service-accounts add-iam-policy-binding "$SERVICE_ACCOUNT_EMAIL" \
    --project="$PROJECT_ID" \
    --role="roles/iam.serviceAccountTokenCreator" \
    --member="principalSet://iam.googleapis.com/${POOL_NAME}/attribute.aws_role/${A13E_AWS_ROLE_NAME}" \
    --condition=None \
    --quiet

log_info "WIF impersonation configured"

# ============================================================================
# Output configuration for A13E
# ============================================================================

echo ""
echo "============================================================================"
echo "                    A13E WIF SETUP COMPLETE"
echo "============================================================================"
echo ""
echo "Provide these values to A13E:"
echo ""
echo "  project_id:            $PROJECT_ID"
echo "  pool_id:               $POOL_ID"
echo "  provider_id:           $PROVIDER_ID"
echo "  service_account_email: $SERVICE_ACCOUNT_EMAIL"
echo "  pool_location:         global"
echo ""
echo "============================================================================"
echo ""
log_info "Setup complete! You can now add this GCP project to A13E."
