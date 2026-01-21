#!/bin/bash
# A13E Detection Coverage Validator - Azure Workload Identity Federation Setup
#
# This script configures your Azure subscription to allow A13E to scan for security
# detections using Workload Identity Federation (WIF).
#
# Prerequisites:
#   - Azure CLI installed and authenticated (az login)
#   - Owner or User Access Administrator role on the Azure subscription
#   - Global Administrator or Application Administrator role in Azure AD
#
# Usage:
#   chmod +x azure_wif_setup.sh
#   ./azure_wif_setup.sh --subscription <subscription-id>
#
# For help:
#   ./azure_wif_setup.sh --help

set -euo pipefail

# ============================================================================
# Configuration - modify these or pass as arguments
# ============================================================================

# Your Azure subscription ID (required)
SUBSCRIPTION_ID=""

# A13E's AWS Account ID (fixed - A13E's infrastructure)
A13E_AWS_ACCOUNT_ID="123080274263"

# A13E's AWS Region
A13E_AWS_REGION="eu-west-2"

# App registration configuration (defaults work for most cases)
APP_NAME="A13E-DetectionScanner"

# ============================================================================
# Helper functions
# ============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

usage() {
    cat << EOF
A13E Azure Workload Identity Federation Setup

This script creates the Azure AD application and service principal required
for A13E to scan your Azure subscription for security detection coverage.

Usage: $0 [OPTIONS]

Required:
  --subscription SUBSCRIPTION_ID   Your Azure subscription ID (GUID)

Optional:
  --app-name NAME                  Azure AD app name (default: A13E-DetectionScanner)
  --help                           Show this help message

Example:
  $0 --subscription 12345678-1234-1234-1234-123456789abc

What this script creates:
  1. Azure AD App Registration (A13E-DetectionScanner)
  2. Service Principal for the app
  3. Federated Identity Credential (trusts A13E's AWS infrastructure)
  4. Role assignments (Reader + Security Reader on your subscription)

What A13E CAN access:
  - Microsoft Defender for Cloud security assessments
  - Azure Policy compliance state
  - Security Center recommendations
  - Resource configurations (read-only)

What A13E CANNOT access:
  - Key Vault secrets or certificates
  - Storage account data
  - Database contents
  - Any write operations

EOF
    exit 0
}

# ============================================================================
# Parse arguments
# ============================================================================

while [[ $# -gt 0 ]]; do
    case $1 in
        --subscription)
            SUBSCRIPTION_ID="$2"
            shift 2
            ;;
        --app-name)
            APP_NAME="$2"
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
if [[ -z "$SUBSCRIPTION_ID" ]]; then
    log_error "Missing required argument: --subscription"
    echo ""
    usage
fi

# Validate subscription ID format (GUID)
if ! [[ "$SUBSCRIPTION_ID" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
    log_error "Invalid subscription ID format. Expected GUID (e.g., 12345678-1234-1234-1234-123456789abc)"
    exit 1
fi

# Normalise to lowercase
SUBSCRIPTION_ID=$(echo "$SUBSCRIPTION_ID" | tr '[:upper:]' '[:lower:]')

# ============================================================================
# Pre-flight checks
# ============================================================================

log_info "Performing pre-flight checks..."

# Check Azure CLI is installed
if ! command -v az &> /dev/null; then
    log_error "Azure CLI (az) is not installed. Please install it first:"
    echo "  https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
    exit 1
fi

# Check jq is installed (needed for JSON parsing)
if ! command -v jq &> /dev/null; then
    log_error "jq is not installed. Please install it first:"
    echo "  macOS: brew install jq"
    echo "  Ubuntu/Debian: sudo apt-get install jq"
    echo "  RHEL/CentOS: sudo yum install jq"
    exit 1
fi

# Check Azure CLI is logged in
if ! az account show &> /dev/null; then
    log_error "Not logged in to Azure CLI. Please run: az login"
    exit 1
fi

# Get current tenant ID
TENANT_ID=$(az account show --query tenantId -o tsv)
if [[ -z "$TENANT_ID" ]]; then
    log_error "Failed to get tenant ID. Please ensure you're logged in."
    exit 1
fi

log_info "Using tenant: $TENANT_ID"
log_info "Target subscription: $SUBSCRIPTION_ID"

# Set the subscription
az account set --subscription "$SUBSCRIPTION_ID"

# Verify subscription access
if ! az account show --subscription "$SUBSCRIPTION_ID" &> /dev/null; then
    log_error "Cannot access subscription $SUBSCRIPTION_ID. Please check your permissions."
    exit 1
fi

# ============================================================================
# Main setup
# ============================================================================

echo ""
echo "============================================================================"
echo "           A13E Azure WIF Setup - Starting Configuration"
echo "============================================================================"
echo ""

# ----------------------------------------------------------------------------
# Step 1: Create App Registration
# ----------------------------------------------------------------------------

log_step "Step 1/4: Creating Azure AD App Registration..."

# Check if app already exists
EXISTING_APP=$(az ad app list --display-name "$APP_NAME" --query "[0].appId" -o tsv 2>/dev/null || echo "")

if [[ -n "$EXISTING_APP" ]]; then
    log_warn "App registration '$APP_NAME' already exists (App ID: $EXISTING_APP)"
    APP_ID="$EXISTING_APP"
    APP_OBJECT_ID=$(az ad app show --id "$APP_ID" --query "id" -o tsv)
else
    # Create new app registration
    APP_RESULT=$(az ad app create \
        --display-name "$APP_NAME" \
        --sign-in-audience "AzureADMyOrg" \
        --query "{appId: appId, id: id}" \
        -o json)

    APP_ID=$(echo "$APP_RESULT" | jq -r '.appId')
    APP_OBJECT_ID=$(echo "$APP_RESULT" | jq -r '.id')

    log_info "App registration created (App ID: $APP_ID)"
fi

# Wait for replication
log_info "Waiting for Azure AD replication (15 seconds)..."
sleep 15

# ----------------------------------------------------------------------------
# Step 2: Create Service Principal
# ----------------------------------------------------------------------------

log_step "Step 2/4: Creating Service Principal..."

# Check if service principal already exists
EXISTING_SP=$(az ad sp list --filter "appId eq '$APP_ID'" --query "[0].id" -o tsv 2>/dev/null || echo "")

if [[ -n "$EXISTING_SP" ]]; then
    log_warn "Service principal already exists"
    SP_OBJECT_ID="$EXISTING_SP"
else
    # Create service principal
    SP_RESULT=$(az ad sp create --id "$APP_ID" --query "id" -o tsv)
    SP_OBJECT_ID="$SP_RESULT"
    log_info "Service principal created"
fi

# Wait for replication
log_info "Waiting for Azure AD replication (10 seconds)..."
sleep 10

# ----------------------------------------------------------------------------
# Step 3: Create Federated Identity Credential
# ----------------------------------------------------------------------------

log_step "Step 3/4: Creating Federated Identity Credential..."

# Federated credential configuration for AWS ECS
# Uses sts.amazonaws.com as the OIDC issuer with the A13E AWS account/role as subject
FIC_NAME="A13E-AWS-Federation"

# AWS STS regional endpoint as OIDC issuer
# Subject format: arn:aws:sts::{account}:assumed-role/{role-name}/{session-name}
FIC_ISSUER="https://sts.${A13E_AWS_REGION}.amazonaws.com"
FIC_SUBJECT="arn:aws:sts::${A13E_AWS_ACCOUNT_ID}:assumed-role/A13E-Scanner-Role/*"
FIC_AUDIENCE="sts.amazonaws.com"

# Check if federated credential already exists
EXISTING_FIC=$(az ad app federated-credential list --id "$APP_OBJECT_ID" --query "[?name=='$FIC_NAME'].name" -o tsv 2>/dev/null || echo "")

if [[ -n "$EXISTING_FIC" ]]; then
    log_warn "Federated identity credential '$FIC_NAME' already exists, updating..."
    az ad app federated-credential delete --id "$APP_OBJECT_ID" --federated-credential-id "$FIC_NAME" 2>/dev/null || true
    sleep 5
fi

# Create federated credential using JSON parameters
# Note: Azure AD WIF supports various OIDC providers
cat > /tmp/a13e_fic.json << EOF
{
    "name": "$FIC_NAME",
    "issuer": "$FIC_ISSUER",
    "subject": "$FIC_SUBJECT",
    "audiences": ["$FIC_AUDIENCE"],
    "description": "A13E Detection Coverage Validator - AWS ECS to Azure federation"
}
EOF

log_info "Creating federated credential with:"
log_info "  Issuer:   $FIC_ISSUER"
log_info "  Subject:  $FIC_SUBJECT"
log_info "  Audience: $FIC_AUDIENCE"

az ad app federated-credential create \
    --id "$APP_OBJECT_ID" \
    --parameters /tmp/a13e_fic.json

rm -f /tmp/a13e_fic.json

log_info "Federated identity credential created"

# ----------------------------------------------------------------------------
# Step 4: Assign Roles
# ----------------------------------------------------------------------------

log_step "Step 4/4: Assigning roles on subscription..."

# Reader role (basic resource visibility)
log_info "Assigning Reader role..."
EXISTING_READER=$(az role assignment list \
    --assignee "$SP_OBJECT_ID" \
    --scope "/subscriptions/$SUBSCRIPTION_ID" \
    --role "Reader" \
    --query "[0].id" -o tsv 2>/dev/null || echo "")

if [[ -n "$EXISTING_READER" ]]; then
    log_warn "Reader role assignment already exists"
else
    az role assignment create \
        --assignee-object-id "$SP_OBJECT_ID" \
        --assignee-principal-type "ServicePrincipal" \
        --role "Reader" \
        --scope "/subscriptions/$SUBSCRIPTION_ID" \
        --description "A13E Detection Coverage Validator - Read-only security scanning"

    log_info "Reader role assigned"
fi

# Security Reader role (Defender for Cloud access)
log_info "Assigning Security Reader role..."
EXISTING_SEC_READER=$(az role assignment list \
    --assignee "$SP_OBJECT_ID" \
    --scope "/subscriptions/$SUBSCRIPTION_ID" \
    --role "Security Reader" \
    --query "[0].id" -o tsv 2>/dev/null || echo "")

if [[ -n "$EXISTING_SEC_READER" ]]; then
    log_warn "Security Reader role assignment already exists"
else
    az role assignment create \
        --assignee-object-id "$SP_OBJECT_ID" \
        --assignee-principal-type "ServicePrincipal" \
        --role "Security Reader" \
        --scope "/subscriptions/$SUBSCRIPTION_ID" \
        --description "A13E Detection Coverage Validator - Defender for Cloud access"

    log_info "Security Reader role assigned"
fi

# ============================================================================
# Output configuration for A13E
# ============================================================================

echo ""
echo "============================================================================"
echo "                    A13E AZURE WIF SETUP COMPLETE"
echo "============================================================================"
echo ""
echo "Provide these values to A13E when adding your Azure subscription:"
echo ""
echo "  ┌─────────────────────────────────────────────────────────────────────┐"
echo "  │  Tenant ID:        $TENANT_ID  │"
echo "  │  Client ID:        $APP_ID  │"
echo "  │  Subscription ID:  $SUBSCRIPTION_ID  │"
echo "  └─────────────────────────────────────────────────────────────────────┘"
echo ""
echo "Roles assigned:"
echo "  ✓ Reader (subscription-level resource visibility)"
echo "  ✓ Security Reader (Microsoft Defender for Cloud access)"
echo ""
echo "============================================================================"
echo ""
log_info "Setup complete! You can now add this Azure subscription to A13E."
echo ""
echo "Next steps:"
echo "  1. Go to A13E Dashboard > Cloud Accounts"
echo "  2. Click 'Add Account' and select 'Azure'"
echo "  3. Enter the values shown above:"
echo "     - Subscription ID: $SUBSCRIPTION_ID"
echo "     - Tenant ID: $TENANT_ID"
echo "     - Client ID: $APP_ID"
echo "  4. Click 'Save' to complete the connection"
echo ""
