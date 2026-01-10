import pytest
from unittest.mock import MagicMock, patch

# Import the modules to be tested
from app.scripts.telemetry_bridge import parse_metrics, push_to_sheets
from app.services.scheduler_service import SchedulerService


@pytest.mark.asyncio
async def test_telemetry_parse_metrics():
    """Test that metrics are parsed correctly from Prometheus format."""
    raw_metrics = """
# HELP http_requests_total Total number of HTTP requests.
# TYPE http_requests_total counter
http_requests_total{method="GET",path="/metrics",status="200"} 50.0
http_requests_total{method="POST",path="/api/v1/scan",status="200"} 10.0
http_requests_total{method="POST",path="/api/v1/auth",status="401"} 5.0
http_requests_total{method="GET",path="/error",status="500"} 2.0
# HELP http_request_duration_seconds_sum Total duration of HTTP requests.
http_request_duration_seconds_sum 12.5
# HELP http_request_duration_seconds_count Total number of HTTP requests.
http_request_duration_seconds_count 67.0
# HELP process_cpu_seconds_total Total user and system CPU time spent in seconds.
process_cpu_seconds_total 123.45
# HELP process_resident_memory_bytes Resident memory size in bytes.
process_resident_memory_bytes 104857600.0
    """

    data = parse_metrics(raw_metrics)

    # 50 + 10 + 5 + 2 = 67 requests
    assert data["total_requests"] == 67
    # 5 (401) + 2 (500) = 7 errors
    assert data["total_errors"] == 7
    # 12.5 / 67 * 1000 = ~186.56 ms
    assert abs(data["avg_latency_ms"] - 186.56) < 0.1
    assert data["cpu_seconds"] == 123.45
    # 104857600 bytes = 100 MB
    assert data["memory_bytes"] == 104857600.0


@pytest.mark.asyncio
@patch("app.scripts.telemetry_bridge.get_workspace_service")
async def test_push_to_sheets(mock_get_ws):
    """Test pushing data to Google Sheets."""
    # Setup mock
    mock_ws = MagicMock()
    mock_get_ws.return_value = mock_ws
    mock_ws.append_to_sheet = MagicMock()
    # Handle header check
    mock_ws.get_sheet_values = MagicMock(
        return_value=[
            [
                "Timestamp",
                "Requests",
                "Errors",
                "Latency (ms)",
                "CPU (s)",
                "Memory (MB)",
            ]
        ]
    )

    # Test data
    metrics = {
        "timestamp": "2023-10-27T10:00:00+00:00",
        "total_requests": 100,
        "total_errors": 5,
        "avg_latency_ms": 50.5,
        "cpu_seconds": 10.2,
        "memory_bytes": 52428800,  # 50 MB
    }

    # Set env var for sheet ID to ensure it runs
    with patch.dict("os.environ", {"TELEMETRY_SHEET_ID": "test_sheet_id"}):
        await push_to_sheets(metrics)

    # Verify call
    mock_ws.append_to_sheet.assert_called_once()
    call_args = mock_ws.append_to_sheet.call_args
    assert call_args[0][0] == "test_sheet_id"  # Sheet ID
    assert call_args[0][1] == "Metrics"  # Sheet Name

    row = call_args[0][2][0]
    assert row[1] == 100  # Requests
    assert row[2] == 5  # Errors
    assert row[5] == 50.0  # Memory in MB


@pytest.mark.asyncio
@patch("app.services.scheduler_service.create_async_engine")
@patch("app.services.scheduler_service.AsyncIOScheduler")
async def test_scheduler_telemetry_job_registration(mock_scheduler_cls, mock_engine):
    """Test that the telemetry job is registered in the scheduler."""

    # Setup mocks
    mock_scheduler_instance = MagicMock()
    mock_scheduler_cls.return_value = mock_scheduler_instance

    # We need to reset the singleton to ensure __init__ runs
    SchedulerService._instance = None
    service = SchedulerService()

    # Test loading telemetry schedule
    await service._load_telemetry_schedule()

    # Verify add_job was called for telemetry
    # We expect call with id="telemetry_push"
    calls = mock_scheduler_instance.add_job.call_args_list
    telemetry_called = False
    for call in calls:
        if call.kwargs.get("id") == "telemetry_push":
            telemetry_called = True
            assert (
                call.kwargs.get("trigger").fields[4].name == "minute"
            )  # 5th field is minute in cron?
            break

    assert telemetry_called, "Telemetry job was not registered with scheduler"
