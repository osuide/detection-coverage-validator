#!/bin/bash
#
# A13E API Examples using curl
#
# Usage:
#   export A13E_API_KEY="dcv_live_xxxxxxxx_xxxxxxxxxxxxxx"
#   ./examples.sh
#
# Or run individual commands:
#   source examples.sh
#   list_accounts

set -e

# Configuration
API_KEY="${A13E_API_KEY:-}"
BASE_URL="${A13E_API_URL:-https://api.a13e.com/api/v1}"

# Check for API key
if [ -z "$API_KEY" ]; then
    echo "Error: A13E_API_KEY environment variable not set"
    exit 1
fi

# Common curl options
CURL_OPTS="-s -H 'Authorization: Bearer ${API_KEY}' -H 'Content-Type: application/json'"

# =============================================================================
# Helper Functions
# =============================================================================

# List all cloud accounts
list_accounts() {
    echo "Listing cloud accounts..."
    curl -s "${BASE_URL}/accounts" \
        -H "Authorization: Bearer ${API_KEY}" | jq
}

# Get a specific account
get_account() {
    local account_id="$1"
    curl -s "${BASE_URL}/accounts/${account_id}" \
        -H "Authorization: Bearer ${API_KEY}" | jq
}

# Trigger a scan
trigger_scan() {
    local account_id="$1"
    local regions="${2:-eu-west-2}"

    echo "Triggering scan for account ${account_id}..."
    curl -s -X POST "${BASE_URL}/accounts/${account_id}/scans" \
        -H "Authorization: Bearer ${API_KEY}" \
        -H "Content-Type: application/json" \
        -d "{\"regions\": [\"${regions}\"]}" | jq
}

# Get scan status
get_scan_status() {
    local scan_id="$1"
    curl -s "${BASE_URL}/scans/${scan_id}" \
        -H "Authorization: Bearer ${API_KEY}" | jq
}

# Wait for scan completion
wait_for_scan() {
    local scan_id="$1"
    local max_attempts="${2:-60}"
    local attempt=0

    echo "Waiting for scan ${scan_id} to complete..."

    while [ $attempt -lt $max_attempts ]; do
        status=$(curl -s "${BASE_URL}/scans/${scan_id}" \
            -H "Authorization: Bearer ${API_KEY}" | jq -r '.status')

        case "$status" in
            completed)
                echo "Scan completed!"
                return 0
                ;;
            failed)
                echo "Scan failed!"
                return 1
                ;;
            *)
                progress=$(curl -s "${BASE_URL}/scans/${scan_id}" \
                    -H "Authorization: Bearer ${API_KEY}" | jq -r '.progress_percent // 0')
                echo "  Progress: ${progress}%"
                sleep 10
                ;;
        esac

        attempt=$((attempt + 1))
    done

    echo "Timeout waiting for scan"
    return 1
}

# Get coverage analysis
get_coverage() {
    local account_id="$1"
    echo "Getting coverage for account ${account_id}..."
    curl -s "${BASE_URL}/accounts/${account_id}/coverage" \
        -H "Authorization: Bearer ${API_KEY}" | jq
}

# Get coverage gaps
get_gaps() {
    local account_id="$1"
    local priority="${2:-}"

    echo "Getting gaps for account ${account_id}..."

    local url="${BASE_URL}/accounts/${account_id}/coverage/gaps"
    if [ -n "$priority" ]; then
        url="${url}?priority=${priority}"
    fi

    curl -s "${url}" \
        -H "Authorization: Bearer ${API_KEY}" | jq
}

# Get detections
get_detections() {
    local account_id="$1"
    echo "Getting detections for account ${account_id}..."
    curl -s "${BASE_URL}/accounts/${account_id}/detections" \
        -H "Authorization: Bearer ${API_KEY}" | jq
}

# =============================================================================
# Example: Full Scan Workflow
# =============================================================================

run_full_example() {
    echo "=== A13E API Example: Full Scan Workflow ==="
    echo ""

    # 1. List accounts
    echo "Step 1: Listing accounts..."
    accounts=$(curl -s "${BASE_URL}/accounts" \
        -H "Authorization: Bearer ${API_KEY}")

    account_id=$(echo "$accounts" | jq -r '.items[0].id')
    account_name=$(echo "$accounts" | jq -r '.items[0].name')

    if [ "$account_id" = "null" ]; then
        echo "No accounts found. Please connect an AWS account first."
        exit 1
    fi

    echo "Using account: ${account_name} (${account_id})"
    echo ""

    # 2. Trigger scan
    echo "Step 2: Triggering scan..."
    scan=$(curl -s -X POST "${BASE_URL}/accounts/${account_id}/scans" \
        -H "Authorization: Bearer ${API_KEY}" \
        -H "Content-Type: application/json" \
        -d '{"regions": ["eu-west-2"]}')

    scan_id=$(echo "$scan" | jq -r '.id')
    echo "Scan started: ${scan_id}"
    echo ""

    # 3. Wait for completion
    echo "Step 3: Waiting for scan..."
    wait_for_scan "$scan_id"
    echo ""

    # 4. Get coverage
    echo "Step 4: Getting coverage..."
    coverage=$(curl -s "${BASE_URL}/accounts/${account_id}/coverage" \
        -H "Authorization: Bearer ${API_KEY}")

    echo "Coverage: $(echo "$coverage" | jq -r '.coverage_percentage')%"
    echo "  Covered: $(echo "$coverage" | jq -r '.covered_count') techniques"
    echo "  Partial: $(echo "$coverage" | jq -r '.partial_count') techniques"
    echo "  Gaps: $(echo "$coverage" | jq -r '.gap_count') techniques"
    echo ""

    # 5. Get critical gaps
    echo "Step 5: Critical coverage gaps..."
    gaps=$(curl -s "${BASE_URL}/accounts/${account_id}/coverage/gaps?priority=critical" \
        -H "Authorization: Bearer ${API_KEY}")

    echo "$gaps" | jq -r '.items[:5][] | "  [\(.technique_id)] \(.technique_name)"'
    echo ""

    echo "=== Done! ==="
}

# =============================================================================
# Quick Commands (copy-paste ready)
# =============================================================================

# Uncomment to run these examples:

# List accounts
# curl -s "${BASE_URL}/accounts" -H "Authorization: Bearer ${API_KEY}" | jq

# Trigger scan (replace ACCOUNT_ID)
# curl -s -X POST "${BASE_URL}/accounts/ACCOUNT_ID/scans" \
#     -H "Authorization: Bearer ${API_KEY}" \
#     -H "Content-Type: application/json" \
#     -d '{"regions": ["eu-west-2"]}' | jq

# Get scan status (replace SCAN_ID)
# curl -s "${BASE_URL}/scans/SCAN_ID" -H "Authorization: Bearer ${API_KEY}" | jq

# Get coverage (replace ACCOUNT_ID)
# curl -s "${BASE_URL}/accounts/ACCOUNT_ID/coverage" -H "Authorization: Bearer ${API_KEY}" | jq

# Get critical gaps (replace ACCOUNT_ID)
# curl -s "${BASE_URL}/accounts/ACCOUNT_ID/coverage/gaps?priority=critical" \
#     -H "Authorization: Bearer ${API_KEY}" | jq

# =============================================================================
# Main
# =============================================================================

# Run full example if script is executed directly
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    run_full_example
fi
