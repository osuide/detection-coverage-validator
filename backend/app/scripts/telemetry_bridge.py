"""
Telemetry Bridge: Prometheus to Google Sheets.

This script runs as a background agent to collect platform performance metrics
from the local FastAPI /metrics endpoint and push them to a Google Sheet.
This enables cost-effective, real-time dashboards using Looker Studio.

PRODUCTION ONLY: This script only runs in production environment to avoid
polluting telemetry data with staging metrics.

Environment Variables:
    TELEMETRY_SHEET_ID: The ID of the Google Sheet to write to.
    TELEMETRY_SHEET_NAME: The tab name (default: 'Metrics').
    METRICS_URL: URL of the metrics endpoint (default: http://localhost:8000/metrics).

Metrics Collected:
    - Requests: Total HTTP requests (2xx, 4xx, 5xx breakdown)
    - Error Rate: Percentage of requests resulting in errors
    - Latency: Average, P50, P95, P99 response times
    - CPU: Percentage utilisation (calculated from delta)
    - Memory: Resident memory in MB
    - Uptime: Time since process start
    - Task ID: ECS task identifier for multi-instance aggregation
"""

import asyncio
import os
import re
import socket
import time
from datetime import datetime, timezone
from typing import Optional

import httpx
import structlog

from app.core.config import get_settings
from app.services.google_workspace_service import get_workspace_service


def get_task_id() -> str:
    """Get a unique identifier for this ECS task.

    In ECS, we can use the hostname which is set to the task ID.
    Falls back to a short hostname if not in ECS.

    Returns:
        Short task identifier (last 8 chars of hostname or task ID)
    """
    # ECS sets hostname to the task ID
    hostname = socket.gethostname()
    # Return last 8 characters as a short identifier
    return hostname[-8:] if len(hostname) > 8 else hostname


# Configure logger
logger = structlog.get_logger()
settings = get_settings()

# Configuration
SHEET_ID = settings.telemetry_sheet_id
SHEET_NAME = os.environ.get("TELEMETRY_SHEET_NAME", "Metrics")
METRICS_URL = os.environ.get("METRICS_URL", "http://localhost:8000/metrics")

# Cache for CPU delta calculation
_last_cpu_sample: Optional[dict] = None

# Track actual container start time (when this module loads)
# This is more reliable than Prometheus process_start_time_seconds which can
# report EC2 instance start time instead of container start time in ECS
_container_start_time: float = time.time()


def sanitise_for_sheets(value: str) -> str:
    """
    Protect against Google Sheets formula injection.

    Sheets interprets cells starting with =, +, -, @, or tab as formulas.
    Prefix with single quote to force text interpretation.
    """
    if isinstance(value, str) and value and value[0] in "=+-@\t":
        return f"'{value}"
    return value


def parse_scientific_notation(value: str) -> float:
    """
    Parse numbers that may be in scientific notation.

    Prometheus can output large numbers as scientific notation:
    e.g., 8.30652416e+08 for ~830MB
    """
    try:
        return float(value)
    except (ValueError, TypeError):
        return 0.0


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
    Parse Prometheus text format into comprehensive metrics.

    Extracts:
    1. Request counts by status category (2xx, 4xx, 5xx)
    2. Latency statistics (avg, p50, p95, p99)
    3. CPU utilisation (requires previous sample for delta calculation)
    4. Memory usage
    5. Process uptime
    6. Requests per minute (RPM)
    """
    global _last_cpu_sample

    now = datetime.now(timezone.utc)

    metrics = {
        # Prefix with single quote to force Sheets to treat as text string
        # (prevents auto-conversion to serial date number)
        "timestamp": "'" + now.strftime("%Y-%m-%d %H:%M:%S"),
        "requests_2xx": 0,
        "requests_4xx": 0,
        "requests_5xx": 0,
        "total_requests": 0,
        "error_rate_pct": 0.0,
        "avg_latency_ms": 0.0,
        "p50_latency_ms": 0.0,
        "p95_latency_ms": 0.0,
        "p99_latency_ms": 0.0,
        "cpu_pct": 0.0,
        "memory_mb": 0.0,
        "uptime_hours": 0.0,
        "rpm": 0.0,  # Requests per minute
    }

    # Patterns for Prometheus metrics
    # Status uses "2xx", "4xx", "5xx" format in our instrumentator
    requests_pattern = re.compile(
        r'http_requests_total\{[^}]*status="(\d+xx)"[^}]*\}\s+([\d.eE+\-]+)'
    )

    # Latency histogram (highr = high resolution)
    latency_sum_pattern = re.compile(
        r"http_request_duration_highr_seconds_sum\s+([\d.eE+\-]+)"
    )
    latency_count_pattern = re.compile(
        r"http_request_duration_highr_seconds_count\s+([\d.eE+\-]+)"
    )
    # Histogram buckets for percentile calculation
    latency_bucket_pattern = re.compile(
        r'http_request_duration_highr_seconds_bucket\{le="([\d.]+)"\}\s+([\d.eE+\-]+)'
    )

    # Process metrics
    cpu_pattern = re.compile(r"process_cpu_seconds_total\s+([\d.eE+\-]+)")
    memory_pattern = re.compile(r"process_resident_memory_bytes\s+([\d.eE+\-]+)")

    # Collect histogram buckets for percentile calculation
    histogram_buckets: list[tuple[float, float]] = []
    total_latency_sum = 0.0
    total_latency_count = 0.0
    cpu_seconds = 0.0

    for line in raw_data.split("\n"):
        if line.startswith("#"):
            continue

        # Request counts by status
        match = requests_pattern.search(line)
        if match:
            status = match.group(1)
            count = parse_scientific_notation(match.group(2))
            if status == "2xx":
                metrics["requests_2xx"] += int(count)
            elif status == "4xx":
                metrics["requests_4xx"] += int(count)
            elif status == "5xx":
                metrics["requests_5xx"] += int(count)
            continue

        # Latency sum
        match = latency_sum_pattern.search(line)
        if match:
            total_latency_sum = parse_scientific_notation(match.group(1))
            continue

        # Latency count
        match = latency_count_pattern.search(line)
        if match:
            total_latency_count = parse_scientific_notation(match.group(1))
            continue

        # Histogram buckets
        match = latency_bucket_pattern.search(line)
        if match:
            le = float(match.group(1))
            count = parse_scientific_notation(match.group(2))
            histogram_buckets.append((le, count))
            continue

        # CPU seconds
        match = cpu_pattern.search(line)
        if match:
            cpu_seconds = parse_scientific_notation(match.group(1))
            continue

        # Memory bytes (handles scientific notation like 8.30652416e+08)
        match = memory_pattern.search(line)
        if match:
            memory_bytes = parse_scientific_notation(match.group(1))
            metrics["memory_mb"] = round(memory_bytes / 1024 / 1024, 2)
            continue

    # Calculate total requests
    metrics["total_requests"] = (
        metrics["requests_2xx"] + metrics["requests_4xx"] + metrics["requests_5xx"]
    )

    # Calculate error rate
    if metrics["total_requests"] > 0:
        errors = metrics["requests_4xx"] + metrics["requests_5xx"]
        metrics["error_rate_pct"] = round((errors / metrics["total_requests"]) * 100, 2)

    # Calculate average latency
    if total_latency_count > 0:
        metrics["avg_latency_ms"] = round(
            (total_latency_sum / total_latency_count) * 1000, 2
        )

    # Calculate percentiles from histogram
    if histogram_buckets and total_latency_count > 0:
        # Sort by bucket boundary
        histogram_buckets.sort(key=lambda x: x[0])

        def calculate_percentile(percentile: float) -> float:
            """Calculate percentile from histogram buckets."""
            target_count = total_latency_count * percentile
            for le, count in histogram_buckets:
                if count >= target_count:
                    return le * 1000  # Convert to ms
            # If we exceed all buckets, return the last bucket
            return histogram_buckets[-1][0] * 1000 if histogram_buckets else 0.0

        metrics["p50_latency_ms"] = round(calculate_percentile(0.5), 2)
        metrics["p95_latency_ms"] = round(calculate_percentile(0.95), 2)
        metrics["p99_latency_ms"] = round(calculate_percentile(0.99), 2)

    # Calculate CPU percentage using delta from last sample
    # CPU seconds is cumulative, so we need to calculate the rate of change
    current_time = now.timestamp()
    if _last_cpu_sample is not None:
        time_delta = current_time - _last_cpu_sample["timestamp"]
        cpu_delta = cpu_seconds - _last_cpu_sample["cpu_seconds"]

        if time_delta > 0:
            # CPU percentage = (cpu_seconds_used / elapsed_seconds) * 100
            metrics["cpu_pct"] = round((cpu_delta / time_delta) * 100, 2)
            # Clamp to reasonable range (can exceed 100% with multiple cores)
            metrics["cpu_pct"] = max(0, min(metrics["cpu_pct"], 800))  # 8 cores max

            # Calculate requests per minute
            if _last_cpu_sample.get("total_requests") is not None:
                requests_delta = (
                    metrics["total_requests"] - _last_cpu_sample["total_requests"]
                )
                minutes_delta = time_delta / 60
                if minutes_delta > 0:
                    metrics["rpm"] = round(requests_delta / minutes_delta, 2)

    # Update the last sample for next calculation
    _last_cpu_sample = {
        "timestamp": current_time,
        "cpu_seconds": cpu_seconds,
        "total_requests": metrics["total_requests"],
    }

    # Calculate uptime using our tracked container start time
    # This is more reliable than Prometheus process_start_time_seconds which can
    # report EC2 instance start time instead of container start time in ECS
    uptime_seconds = current_time - _container_start_time
    metrics["uptime_hours"] = round(uptime_seconds / 3600, 2)

    # Debug: Log the container start time to verify it's correct
    logger.debug(
        "uptime_calculation",
        container_start_time=_container_start_time,
        current_time=current_time,
        uptime_seconds=uptime_seconds,
        uptime_hours=metrics["uptime_hours"],
    )

    return metrics


async def push_to_sheets(metrics: dict) -> None:
    """
    Push the parsed metrics to Google Sheets.

    Note: GoogleWorkspaceService methods are synchronous (blocking).
    We use asyncio.to_thread() to run them in a thread pool to avoid
    blocking the event loop (same pattern as boto3 in CLAUDE.md).
    """
    ws = get_workspace_service()

    # Get task identifier for multi-instance aggregation
    task_id = get_task_id()

    # Headers for the sheet (Task ID added for multi-instance aggregation)
    headers = [
        "Timestamp",
        "Task ID",
        "Total Requests",
        "2xx",
        "4xx",
        "5xx",
        "Error Rate (%)",
        "Avg Latency (ms)",
        "P50 (ms)",
        "P95 (ms)",
        "P99 (ms)",
        "CPU (%)",
        "Memory (MB)",
        "Uptime (hrs)",
        "RPM",
    ]

    # Format row with formula injection protection
    row = [
        sanitise_for_sheets(metrics["timestamp"]),
        sanitise_for_sheets(task_id),
        metrics["total_requests"],
        metrics["requests_2xx"],
        metrics["requests_4xx"],
        metrics["requests_5xx"],
        metrics["error_rate_pct"],
        metrics["avg_latency_ms"],
        metrics["p50_latency_ms"],
        metrics["p95_latency_ms"],
        metrics["p99_latency_ms"],
        metrics["cpu_pct"],
        metrics["memory_mb"],
        metrics["uptime_hours"],
        metrics["rpm"],
    ]

    try:
        # Check if header exists in A1
        try:
            current_headers = await asyncio.to_thread(
                ws.get_sheet_values, SHEET_ID, f"{SHEET_NAME}!A1:O1"
            )
            if not current_headers or not current_headers[0]:
                logger.info("telemetry_initialising_headers", sheet=SHEET_NAME)
                await asyncio.to_thread(
                    ws.append_to_sheet, SHEET_ID, SHEET_NAME, [headers]
                )
        except Exception as header_error:
            # If sheet doesn't exist or other error, try to just append
            logger.warning("telemetry_header_check_failed", error=str(header_error))

        await asyncio.to_thread(ws.append_to_sheet, SHEET_ID, SHEET_NAME, [row])
        logger.info(
            "telemetry_pushed",
            total_requests=metrics["total_requests"],
            error_rate=metrics["error_rate_pct"],
            cpu_pct=metrics["cpu_pct"],
            memory_mb=metrics["memory_mb"],
            uptime_hours=metrics["uptime_hours"],
        )
    except Exception as e:
        logger.error("telemetry_push_failed", error=str(e))


async def main() -> None:
    """Main execution loop."""
    # Safety Check: Only run in production
    # This prevents staging data from polluting the production dashboard
    if not SHEET_ID:
        logger.warning("telemetry_skip", reason="TELEMETRY_SHEET_ID not set")
        return

    # Strict production-only check
    if settings.environment not in ("production", "prod"):
        logger.info(
            "telemetry_skip",
            reason="Not production environment",
            env=settings.environment,
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
