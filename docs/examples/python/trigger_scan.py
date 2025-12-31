#!/usr/bin/env python3
"""
A13E API Example: Trigger a Scan and Wait for Completion

This script demonstrates how to:
1. Authenticate with the A13E API
2. List connected cloud accounts
3. Trigger a detection scan
4. Poll for scan completion
5. Retrieve coverage results

Usage:
    export A13E_API_KEY="dcv_live_xxxxxxxx_xxxxxxxxxxxxxx"
    python trigger_scan.py

Requirements:
    pip install httpx
"""

import os
import sys
import time
from typing import Any

import httpx

# Configuration
API_KEY = os.environ.get("A13E_API_KEY")
BASE_URL = os.environ.get("A13E_API_URL", "https://api.a13e.com/api/v1")
POLL_INTERVAL = 10  # seconds


def get_headers() -> dict[str, str]:
    """Get authentication headers."""
    if not API_KEY:
        print("Error: A13E_API_KEY environment variable not set")
        sys.exit(1)
    return {"Authorization": f"Bearer {API_KEY}"}


def list_accounts() -> list[dict[str, Any]]:
    """List all connected cloud accounts."""
    response = httpx.get(f"{BASE_URL}/accounts", headers=get_headers())
    response.raise_for_status()
    return response.json()["items"]


def trigger_scan(account_id: str, regions: list[str] | None = None) -> dict[str, Any]:
    """Trigger a new scan for an account.

    Args:
        account_id: The cloud account ID to scan
        regions: Optional list of regions to scan (default: all configured regions)

    Returns:
        Scan object with id and status
    """
    payload = {}
    if regions:
        payload["regions"] = regions

    response = httpx.post(
        f"{BASE_URL}/accounts/{account_id}/scans",
        headers=get_headers(),
        json=payload,
    )
    response.raise_for_status()
    return response.json()


def get_scan_status(scan_id: str) -> dict[str, Any]:
    """Get the current status of a scan."""
    response = httpx.get(f"{BASE_URL}/scans/{scan_id}", headers=get_headers())
    response.raise_for_status()
    return response.json()


def wait_for_scan(scan_id: str, timeout: int = 600) -> dict[str, Any]:
    """Wait for a scan to complete.

    Args:
        scan_id: The scan ID to monitor
        timeout: Maximum time to wait in seconds

    Returns:
        Final scan status

    Raises:
        TimeoutError: If scan doesn't complete within timeout
    """
    start_time = time.time()

    while True:
        status = get_scan_status(scan_id)

        if status["status"] == "completed":
            return status
        elif status["status"] == "failed":
            raise RuntimeError(f"Scan failed: {status.get('error_message', 'Unknown error')}")

        elapsed = time.time() - start_time
        if elapsed > timeout:
            raise TimeoutError(f"Scan did not complete within {timeout} seconds")

        progress = status.get("progress_percent", 0)
        print(f"  Scan progress: {progress}%")
        time.sleep(POLL_INTERVAL)


def get_coverage(account_id: str) -> dict[str, Any]:
    """Get coverage analysis for an account."""
    response = httpx.get(
        f"{BASE_URL}/accounts/{account_id}/coverage",
        headers=get_headers(),
    )
    response.raise_for_status()
    return response.json()


def get_gaps(account_id: str, priority: str | None = None) -> list[dict[str, Any]]:
    """Get coverage gaps for an account.

    Args:
        account_id: The cloud account ID
        priority: Optional filter by priority (critical, high, medium, low)

    Returns:
        List of coverage gaps
    """
    params = {}
    if priority:
        params["priority"] = priority

    response = httpx.get(
        f"{BASE_URL}/accounts/{account_id}/coverage/gaps",
        headers=get_headers(),
        params=params,
    )
    response.raise_for_status()
    return response.json()["items"]


def main():
    """Main entry point."""
    print("A13E API Example: Trigger Scan\n")

    # 1. List accounts
    print("Fetching cloud accounts...")
    accounts = list_accounts()

    if not accounts:
        print("No cloud accounts found. Please connect an AWS account first.")
        sys.exit(1)

    account = accounts[0]
    print(f"Using account: {account['name']} ({account['id']})\n")

    # 2. Trigger scan
    print("Triggering scan...")
    scan = trigger_scan(account["id"], regions=["eu-west-2"])
    print(f"Scan started: {scan['id']}\n")

    # 3. Wait for completion
    print("Waiting for scan to complete...")
    try:
        result = wait_for_scan(scan["id"])
        print(f"\nScan complete!")
        print(f"  Detections found: {result.get('detections_found', 0)}")
        print(f"  Duration: {result.get('duration_seconds', 0)}s\n")
    except (RuntimeError, TimeoutError) as e:
        print(f"\nError: {e}")
        sys.exit(1)

    # 4. Get coverage
    print("Fetching coverage analysis...")
    coverage = get_coverage(account["id"])
    print(f"Coverage: {coverage['coverage_percentage']}%")
    print(f"  Covered: {coverage['covered_count']} techniques")
    print(f"  Partial: {coverage['partial_count']} techniques")
    print(f"  Gaps: {coverage['gap_count']} techniques\n")

    # 5. Get critical gaps
    print("Critical coverage gaps:")
    gaps = get_gaps(account["id"], priority="critical")

    if gaps:
        for gap in gaps[:5]:
            print(f"  [{gap['technique_id']}] {gap['technique_name']}")
    else:
        print("  No critical gaps found!")

    print("\nDone!")


if __name__ == "__main__":
    main()
