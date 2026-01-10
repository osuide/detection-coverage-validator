"""
Telemetry Bridge: Prometheus to Google Sheets.

This script runs as a background agent to collect platform performance metrics
from the local FastAPI /metrics endpoint and push them to a Google Sheet.
This enables cost-effective, real-time dashboards using Looker Studio.

Environment Variables:
    TELEMETRY_SHEET_ID: The ID of the Google Sheet to write to.
    TELEMETRY_SHEET_NAME: The tab name (default: 'Metrics').
    METRICS_URL: URL of the metrics endpoint (default: http://localhost:8000/metrics).
"""

import asyncio
import os
import re
from datetime import datetime, timezone
import httpx
import structlog
from app.services.google_workspace_service import get_workspace_service
from app.core.config import get_settings

# Configure logger
logger = structlog.get_logger()
settings = get_settings()

# Configuration
SHEET_ID = settings.telemetry_sheet_id
SHEET_NAME = os.environ.get("TELEMETRY_SHEET_NAME", "Metrics")
METRICS_URL = os.environ.get("METRICS_URL", "http://localhost:8000/metrics")


async def fetch_metrics() -> str:
    """Fetch raw metrics from the application."""
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(METRICS_URL, timeout=5.0)
            response.raise_for_status()
            return response.text
        except Exception as e:
            logger.error("metrics_fetch_failed", error=str(e))
            return ""


def parse_metrics(raw_data: str) -> dict:
    """
    Parse Prometheus text format into key indicators.

    We focus on high-level signals suitable for a business/ops dashboard:
    1. Total Request Count
    2. Error Count (4xx/5xx)
    3. Average Latency
    4. CPU/Memory Usage
    """
    metrics = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_requests": 0,
        "total_errors": 0,
        "avg_latency_ms": 0.0,
        "cpu_seconds": 0.0,
        "memory_bytes": 0,
    }

    # Regex patterns (standard Prometheus format)
    # http_request_duration_seconds_count{...} 10.0
    req_count_pattern = re.compile(
        r'http_requests_total\{.*status="([0-9]+)".*\}\s+([0-9\.]+)'
    )
    # http_request_duration_seconds_sum 0.5
    latency_sum_pattern = re.compile(r"http_request_duration_seconds_sum\s+([0-9\.]+)")
    latency_count_pattern = re.compile(
        r"http_request_duration_seconds_count\s+([0-9\.]+)"
    )
    # process_cpu_seconds_total 1.2
    cpu_pattern = re.compile(r"process_cpu_seconds_total\s+([0-9\.]+)")
    # process_resident_memory_bytes 1024.0
    mem_pattern = re.compile(r"process_resident_memory_bytes\s+([0-9\.]+)")

    total_latency_sum = 0.0
    total_latency_count = 0.0

    for line in raw_data.split("\n"):
        if line.startswith("#"):
            continue

        # Requests & Errors
        match = req_count_pattern.search(line)
        if match:
            status = int(match.group(1))
            count = float(match.group(2))
            metrics["total_requests"] += int(count)
            if status >= 400:
                metrics["total_errors"] += int(count)

        # Latency (Global Sum)
        # Note: Instrumentator usually gives a summary/histogram. We look for the root sum/count.
        if "http_request_duration_seconds_sum" in line and "handler" not in line:
            match = latency_sum_pattern.search(line)
            if match:
                total_latency_sum = float(match.group(1))

        if "http_request_duration_seconds_count" in line and "handler" not in line:
            match = latency_count_pattern.search(line)
            if match:
                total_latency_count = float(match.group(1))

        # Resources
        match = cpu_pattern.search(line)
        if match:
            metrics["cpu_seconds"] = float(match.group(1))

        match = mem_pattern.search(line)
        if match:
            metrics["memory_bytes"] = float(match.group(1))

    # Calculate derived stats
    if total_latency_count > 0:
        metrics["avg_latency_ms"] = (total_latency_sum / total_latency_count) * 1000

    return metrics


async def push_to_sheets(metrics: dict) -> None:
    """Push the parsed metrics to Google Sheets."""
    ws = get_workspace_service()

    # Format row: [Timestamp, Requests, Errors, Latency(ms), CPU(s), RAM(MB)]
    row = [
        metrics["timestamp"],
        metrics["total_requests"],
        metrics["total_errors"],
        round(metrics["avg_latency_ms"], 2),
        round(metrics["cpu_seconds"], 2),
        round(metrics["memory_bytes"] / 1024 / 1024, 2),  # Convert to MB
    ]

    try:
        # Check if we need to add headers (heuristic: check A1)
        # For simplicity in this script, we assume headers exist or we just append.
        # Ideally, we'd check `ws.get_sheet_values(SHEET_ID, "A1")`

        ws.append_to_sheet(SHEET_ID, SHEET_NAME, [row])
        logger.info("telemetry_pushed", row=row)
    except Exception as e:
        logger.error("telemetry_push_failed", error=str(e))


async def main() -> None:
    """Main execution loop."""
    # Safety Check: Only run if explicitly configured or in production
    # Prevents staging data from polluting the prod dashboard
    if not SHEET_ID:
        logger.warning("telemetry_skip", reason="TELEMETRY_SHEET_ID not set")
        return

    if settings.environment not in ("production", "prod"):
        logger.info(
            "telemetry_skip", reason="Not in production", env=settings.environment
        )
        return

    logger.info("telemetry_agent_starting", target=METRICS_URL, sheet=SHEET_ID)

    raw = await fetch_metrics()
    if raw:
        data = parse_metrics(raw)
        await push_to_sheets(data)
    else:
        logger.warning("telemetry_no_data")


if __name__ == "__main__":
    # Run once (intended to be called by a scheduler or cron)
    asyncio.run(main())
