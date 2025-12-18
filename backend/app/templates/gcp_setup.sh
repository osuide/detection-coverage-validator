#!/bin/bash
# A13E Detection Coverage Validator - GCP Setup Script
#
# This script creates a custom IAM role and service account with the minimum
# permissions required for A13E to scan your security detection configurations.
#
# Prerequisites:
#   - gcloud CLI installed and authenticated
#   - Project Owner or IAM Admin role
#
# Usage:
#   chmod +x gcp_setup.sh
#   ./gcp_setup.sh --project YOUR_PROJECT_ID --external-account A13E_WORKLOAD_IDENTITY
#
# What this role CAN access:
#   - Cloud Logging metrics and sinks (detection rules)
#   - Cloud Monitoring alerting policies
#   - Security Command Center findings
#   - Eventarc triggers
#   - Cloud Functions configurations
#   - Cloud Run service configurations
#
# What this role CANNOT access:
#   - Log data contents
#   - Cloud Storage bucket contents
#   - Database data
#   - Secrets or credentials
#   - Any write operations

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
ROLE_ID="a13e_detection_scanner"
ROLE_TITLE="A13E Detection Scanner"
SA_NAME="a13e-scanner"
SA_DISPLAY_NAME="A13E Detection Scanner"

# Parse arguments
PROJECT_ID=""
A13E_WORKLOAD_IDENTITY=""
USE_SA_KEY=false

print_usage() {
    echo "Usage: $0 --project PROJECT_ID [--workload-identity POOL_ID | --use-sa-key]"
    echo ""
    echo "Options:"
    echo "  --project PROJECT_ID        Your GCP project ID (required)"
    echo "  --workload-identity POOL_ID A13E's workload identity pool ID (recommended)"
    echo "  --use-sa-key                Generate a service account key file (less secure)"
    echo ""
    echo "Example:"
    echo "  $0 --project my-project-123 --workload-identity a13e-prod-pool"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --project)
            PROJECT_ID="$2"
            shift 2
            ;;
        --workload-identity)
            A13E_WORKLOAD_IDENTITY="$2"
            shift 2
            ;;
        --use-sa-key)
            USE_SA_KEY=true
            shift
            ;;
        -h|--help)
            print_usage
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            print_usage
            ;;
    esac
done

if [[ -z "$PROJECT_ID" ]]; then
    echo -e "${RED}Error: --project is required${NC}"
    print_usage
fi

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}A13E Detection Scanner - GCP Setup${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Project: $PROJECT_ID"
echo ""

# Set the project
echo -e "${YELLOW}Setting project...${NC}"
gcloud config set project "$PROJECT_ID"

# Enable required APIs
echo -e "${YELLOW}Enabling required APIs...${NC}"
gcloud services enable \
    logging.googleapis.com \
    monitoring.googleapis.com \
    securitycenter.googleapis.com \
    eventarc.googleapis.com \
    cloudfunctions.googleapis.com \
    run.googleapis.com \
    iam.googleapis.com \
    cloudresourcemanager.googleapis.com

# Create custom role
echo -e "${YELLOW}Creating custom IAM role...${NC}"

# Check if role exists
if gcloud iam roles describe "$ROLE_ID" --project="$PROJECT_ID" &>/dev/null; then
    echo "Role already exists, updating..."
    gcloud iam roles update "$ROLE_ID" \
        --project="$PROJECT_ID" \
        --title="$ROLE_TITLE" \
        --description="Minimum permissions for A13E to scan security detection configurations. Read-only access to logging, monitoring, and security services." \
        --permissions="\
logging.logMetrics.list,\
logging.logMetrics.get,\
logging.sinks.list,\
logging.sinks.get,\
monitoring.alertPolicies.list,\
monitoring.alertPolicies.get,\
monitoring.notificationChannels.list,\
monitoring.notificationChannels.get,\
securitycenter.findings.list,\
securitycenter.findings.get,\
securitycenter.sources.list,\
securitycenter.sources.get,\
eventarc.triggers.list,\
eventarc.triggers.get,\
cloudfunctions.functions.list,\
cloudfunctions.functions.get,\
run.services.list,\
run.services.get,\
resourcemanager.projects.get"
else
    gcloud iam roles create "$ROLE_ID" \
        --project="$PROJECT_ID" \
        --title="$ROLE_TITLE" \
        --description="Minimum permissions for A13E to scan security detection configurations. Read-only access to logging, monitoring, and security services." \
        --permissions="\
logging.logMetrics.list,\
logging.logMetrics.get,\
logging.sinks.list,\
logging.sinks.get,\
monitoring.alertPolicies.list,\
monitoring.alertPolicies.get,\
monitoring.notificationChannels.list,\
monitoring.notificationChannels.get,\
securitycenter.findings.list,\
securitycenter.findings.get,\
securitycenter.sources.list,\
securitycenter.sources.get,\
eventarc.triggers.list,\
eventarc.triggers.get,\
cloudfunctions.functions.list,\
cloudfunctions.functions.get,\
run.services.list,\
run.services.get,\
resourcemanager.projects.get"
fi

echo -e "${GREEN}Custom role created: projects/$PROJECT_ID/roles/$ROLE_ID${NC}"

# Create service account
echo -e "${YELLOW}Creating service account...${NC}"

SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

if gcloud iam service-accounts describe "$SA_EMAIL" &>/dev/null; then
    echo "Service account already exists: $SA_EMAIL"
else
    gcloud iam service-accounts create "$SA_NAME" \
        --display-name="$SA_DISPLAY_NAME" \
        --description="Service account for A13E Detection Coverage Validator. Read-only access to security configurations."
fi

# Bind role to service account
echo -e "${YELLOW}Binding role to service account...${NC}"
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="serviceAccount:$SA_EMAIL" \
    --role="projects/$PROJECT_ID/roles/$ROLE_ID" \
    --condition=None

echo -e "${GREEN}Service account configured: $SA_EMAIL${NC}"

# Configure access method
if [[ -n "$A13E_WORKLOAD_IDENTITY" ]]; then
    echo -e "${YELLOW}Configuring Workload Identity Federation...${NC}"

    # This would need A13E's actual workload identity pool details
    # For now, we show the manual steps
    echo ""
    echo -e "${YELLOW}Manual step required:${NC}"
    echo "Run the following command to allow A13E to impersonate this service account:"
    echo ""
    echo "gcloud iam service-accounts add-iam-policy-binding $SA_EMAIL \\"
    echo "    --project=$PROJECT_ID \\"
    echo "    --role=roles/iam.workloadIdentityUser \\"
    echo "    --member=\"principalSet://iam.googleapis.com/$A13E_WORKLOAD_IDENTITY/attribute.a13e_org/YOUR_A13E_ORG_ID\""
    echo ""

elif [[ "$USE_SA_KEY" == true ]]; then
    echo -e "${YELLOW}Generating service account key...${NC}"
    echo -e "${RED}WARNING: Service account keys are a security risk. Consider using Workload Identity Federation instead.${NC}"

    KEY_FILE="a13e-scanner-key-${PROJECT_ID}.json"
    gcloud iam service-accounts keys create "$KEY_FILE" \
        --iam-account="$SA_EMAIL"

    echo -e "${GREEN}Key file created: $KEY_FILE${NC}"
    echo -e "${RED}IMPORTANT: Keep this file secure. Upload it to A13E and then delete it from your local system.${NC}"
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Setup Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Next steps:"
echo "1. Go to A13E Dashboard > Cloud Accounts"
echo "2. Click 'Add GCP Project'"
echo "3. Enter the following details:"
echo ""
echo "   Project ID: $PROJECT_ID"
echo "   Service Account: $SA_EMAIL"
if [[ "$USE_SA_KEY" == true ]]; then
    echo "   Key File: Upload $KEY_FILE"
fi
echo ""
echo "4. Click 'Validate Connection'"
echo ""
echo -e "${YELLOW}Permissions granted (19 total):${NC}"
echo "  - logging.logMetrics.list/get"
echo "  - logging.sinks.list/get"
echo "  - monitoring.alertPolicies.list/get"
echo "  - monitoring.notificationChannels.list/get"
echo "  - securitycenter.findings.list/get"
echo "  - securitycenter.sources.list/get"
echo "  - eventarc.triggers.list/get"
echo "  - cloudfunctions.functions.list/get"
echo "  - run.services.list/get"
echo "  - resourcemanager.projects.get"
