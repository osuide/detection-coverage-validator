/**
 * A13E API Example: Trigger a Scan and Wait for Completion
 *
 * This script demonstrates how to:
 * 1. Authenticate with the A13E API
 * 2. List connected cloud accounts
 * 3. Trigger a detection scan
 * 4. Poll for scan completion
 * 5. Retrieve coverage results
 *
 * Usage:
 *   export A13E_API_KEY="dcv_live_xxxxxxxx_xxxxxxxxxxxxxx"
 *   node trigger_scan.js
 *
 * Requirements:
 *   Node.js 18+ (for native fetch)
 */

const API_KEY = process.env.A13E_API_KEY;
const BASE_URL = process.env.A13E_API_URL || 'https://api.a13e.com/api/v1';
const POLL_INTERVAL = 10000; // 10 seconds

/**
 * Get authentication headers
 */
function getHeaders() {
  if (!API_KEY) {
    console.error('Error: A13E_API_KEY environment variable not set');
    process.exit(1);
  }
  return {
    'Authorization': `Bearer ${API_KEY}`,
    'Content-Type': 'application/json',
  };
}

/**
 * Make an API request with error handling
 */
async function apiRequest(endpoint, options = {}) {
  const url = `${BASE_URL}${endpoint}`;
  const response = await fetch(url, {
    ...options,
    headers: { ...getHeaders(), ...options.headers },
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(`API error: ${response.status} - ${error.detail || response.statusText}`);
  }

  return response.json();
}

/**
 * List all connected cloud accounts
 */
async function listAccounts() {
  const data = await apiRequest('/accounts');
  return data.items;
}

/**
 * Trigger a new scan for an account
 */
async function triggerScan(accountId, regions = null) {
  const payload = regions ? { regions } : {};

  return apiRequest(`/accounts/${accountId}/scans`, {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

/**
 * Get the current status of a scan
 */
async function getScanStatus(scanId) {
  return apiRequest(`/scans/${scanId}`);
}

/**
 * Wait for a scan to complete
 */
async function waitForScan(scanId, timeout = 600000) {
  const startTime = Date.now();

  while (true) {
    const status = await getScanStatus(scanId);

    if (status.status === 'completed') {
      return status;
    } else if (status.status === 'failed') {
      throw new Error(`Scan failed: ${status.error_message || 'Unknown error'}`);
    }

    const elapsed = Date.now() - startTime;
    if (elapsed > timeout) {
      throw new Error(`Scan did not complete within ${timeout / 1000} seconds`);
    }

    const progress = status.progress_percent || 0;
    console.log(`  Scan progress: ${progress}%`);

    await new Promise(resolve => setTimeout(resolve, POLL_INTERVAL));
  }
}

/**
 * Get coverage analysis for an account
 */
async function getCoverage(accountId) {
  return apiRequest(`/accounts/${accountId}/coverage`);
}

/**
 * Get coverage gaps for an account
 */
async function getGaps(accountId, priority = null) {
  const params = priority ? `?priority=${priority}` : '';
  const data = await apiRequest(`/accounts/${accountId}/coverage/gaps${params}`);
  return data.items;
}

/**
 * Main entry point
 */
async function main() {
  console.log('A13E API Example: Trigger Scan\n');

  try {
    // 1. List accounts
    console.log('Fetching cloud accounts...');
    const accounts = await listAccounts();

    if (accounts.length === 0) {
      console.log('No cloud accounts found. Please connect an AWS account first.');
      process.exit(1);
    }

    const account = accounts[0];
    console.log(`Using account: ${account.name} (${account.id})\n`);

    // 2. Trigger scan
    console.log('Triggering scan...');
    const scan = await triggerScan(account.id, ['eu-west-2']);
    console.log(`Scan started: ${scan.id}\n`);

    // 3. Wait for completion
    console.log('Waiting for scan to complete...');
    const result = await waitForScan(scan.id);
    console.log('\nScan complete!');
    console.log(`  Detections found: ${result.detections_found || 0}`);
    console.log(`  Duration: ${result.duration_seconds || 0}s\n`);

    // 4. Get coverage
    console.log('Fetching coverage analysis...');
    const coverage = await getCoverage(account.id);
    console.log(`Coverage: ${coverage.coverage_percentage}%`);
    console.log(`  Covered: ${coverage.covered_count} techniques`);
    console.log(`  Partial: ${coverage.partial_count} techniques`);
    console.log(`  Gaps: ${coverage.gap_count} techniques\n`);

    // 5. Get critical gaps
    console.log('Critical coverage gaps:');
    const gaps = await getGaps(account.id, 'critical');

    if (gaps.length > 0) {
      gaps.slice(0, 5).forEach(gap => {
        console.log(`  [${gap.technique_id}] ${gap.technique_name}`);
      });
    } else {
      console.log('  No critical gaps found!');
    }

    console.log('\nDone!');
  } catch (error) {
    console.error(`\nError: ${error.message}`);
    process.exit(1);
  }
}

main();
