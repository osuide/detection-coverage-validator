---
name: testing-agent
description: Designs the comprehensive testing strategy to ensure quality, reliability, and correctness across all system components.
---

# Testing Agent - Detection Coverage Validator

## Role
You are the Testing Agent responsible for designing the comprehensive testing strategy for the Detection Coverage Validator. Your job is to ensure quality, reliability, and correctness across all system components.

## Prerequisites
- Review all previous agent outputs (schema, API, architecture, parsers, mappers, analysis, UI)
- Understand cloud provider APIs and mocking strategies
- Review `detection-coverage-validator-model.md` for accuracy requirements

## Your Mission
Design a testing strategy that:
1. Validates correctness of all system components
2. Tests cloud integrations without live accounts
3. Measures mapping accuracy and coverage calculation precision
4. Ensures API reliability and performance
5. Validates UI functionality and accessibility

---

## Chain-of-Thought Reasoning Process

### Step 1: Testing Pyramid Strategy

```
                    ┌───────────────┐
                    │     E2E       │  ← Fewest tests, highest confidence
                    │    Tests      │  ← Full user journeys
                    │    (10%)      │  ← Slowest, most brittle
                    └───────┬───────┘
                            │
                    ┌───────▼───────┐
                    │  Integration  │  ← API contracts, DB operations
                    │    Tests      │  ← Service interactions
                    │    (20%)      │  ← Mock external services
                    └───────┬───────┘
                            │
            ┌───────────────▼───────────────┐
            │          Unit Tests           │  ← Most tests, fastest
            │           (70%)               │  ← Pure functions
            │  Parsers, Mappers, Analyzers  │  ← No external deps
            └───────────────────────────────┘

Strategy Rationale:
- Heavy unit testing for parsing/mapping logic (correctness critical)
- Integration tests for API endpoints and database operations
- E2E tests for critical user journeys only
- Mock cloud providers at integration level
```

---

### Step 2: Unit Testing Design

#### Parser Unit Tests

```python
# tests/unit/parsers/test_eventbridge_parser.py

import pytest
from src.parsers.eventbridge import EventBridgePatternParser
from src.models.detection import RawDetection, DetectionType

class TestEventBridgeParser:
    """Unit tests for EventBridge pattern parser."""

    @pytest.fixture
    def parser(self):
        return EventBridgePatternParser()

    # =========================================================================
    # Basic Parsing Tests
    # =========================================================================

    def test_parse_simple_pattern(self, parser):
        """Test parsing a simple EventBridge pattern."""
        raw = RawDetection(
            external_id="rule-1",
            name="guardduty-findings",
            description="Alert on GuardDuty findings",
            source_service="eventbridge",
            detection_type=DetectionType.EVENT_PATTERN,
            raw_config={
                "event_pattern": '{"source": ["aws.guardduty"]}'
            },
            region="us-east-1",
            status="enabled",
            created_at=None,
            last_modified=None,
            owner=None,
            tags={}
        )

        result = parser.parse(raw)

        assert result.parse_success is True
        assert result.parse_confidence >= 0.8
        assert len(result.monitored_entities) >= 1
        assert any(e.entity_id == "aws.guardduty" for e in result.monitored_entities)

    def test_parse_complex_pattern_with_detail(self, parser):
        """Test parsing EventBridge pattern with detail conditions."""
        raw = RawDetection(
            external_id="rule-2",
            name="iam-changes",
            description="Alert on IAM changes",
            source_service="eventbridge",
            detection_type=DetectionType.EVENT_PATTERN,
            raw_config={
                "event_pattern": """{
                    "source": ["aws.iam"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": ["CreateUser", "DeleteUser", "AttachUserPolicy"]
                    }
                }"""
            },
            region="us-east-1",
            status="enabled",
            created_at=None,
            last_modified=None,
            owner=None,
            tags={}
        )

        result = parser.parse(raw)

        assert result.parse_success is True
        assert len(result.trigger_conditions) >= 1

        # Check that eventName conditions were extracted
        event_names = [
            c.value for c in result.trigger_conditions
            if 'eventName' in c.field.lower()
        ]
        assert "CreateUser" in str(event_names)

    def test_parse_pattern_with_exists_operator(self, parser):
        """Test parsing pattern with 'exists' operator."""
        raw = RawDetection(
            external_id="rule-3",
            name="failed-api-calls",
            description="Alert on failed API calls",
            source_service="eventbridge",
            detection_type=DetectionType.EVENT_PATTERN,
            raw_config={
                "event_pattern": """{
                    "source": ["aws.iam"],
                    "detail": {
                        "errorCode": [{"exists": true}]
                    }
                }"""
            },
            region="us-east-1",
            status="enabled",
            created_at=None,
            last_modified=None,
            owner=None,
            tags={}
        )

        result = parser.parse(raw)

        assert result.parse_success is True
        # Check for EXISTS operator
        exists_conditions = [
            c for c in result.trigger_conditions
            if c.operator.value == "exists"
        ]
        assert len(exists_conditions) >= 1

    # =========================================================================
    # Edge Case Tests
    # =========================================================================

    def test_parse_invalid_json(self, parser):
        """Test handling of invalid JSON pattern."""
        raw = RawDetection(
            external_id="rule-bad",
            name="bad-pattern",
            description=None,
            source_service="eventbridge",
            detection_type=DetectionType.EVENT_PATTERN,
            raw_config={
                "event_pattern": "not valid json {{{{"
            },
            region="us-east-1",
            status="enabled",
            created_at=None,
            last_modified=None,
            owner=None,
            tags={}
        )

        result = parser.parse(raw)

        assert result.parse_success is False
        assert len(result.parse_errors) > 0
        assert result.parse_confidence < 0.5

    def test_parse_empty_pattern(self, parser):
        """Test handling of empty pattern."""
        raw = RawDetection(
            external_id="rule-empty",
            name="empty-pattern",
            description=None,
            source_service="eventbridge",
            detection_type=DetectionType.EVENT_PATTERN,
            raw_config={
                "event_pattern": "{}"
            },
            region="us-east-1",
            status="enabled",
            created_at=None,
            last_modified=None,
            owner=None,
            tags={}
        )

        result = parser.parse(raw)

        # Empty pattern should parse but have no entities
        assert result.parse_success is True
        assert len(result.monitored_entities) == 0

    def test_can_parse_returns_false_for_wrong_service(self, parser):
        """Test that parser rejects non-EventBridge detections."""
        raw = RawDetection(
            external_id="rule-cw",
            name="cloudwatch-alarm",
            description=None,
            source_service="cloudwatch",  # Wrong service
            detection_type=DetectionType.METRIC_ALARM,
            raw_config={},
            region="us-east-1",
            status="enabled",
            created_at=None,
            last_modified=None,
            owner=None,
            tags={}
        )

        assert parser.can_parse(raw) is False

    # =========================================================================
    # Severity Inference Tests
    # =========================================================================

    def test_infer_critical_severity_from_pattern(self, parser):
        """Test severity inference for security-critical patterns."""
        raw = RawDetection(
            external_id="rule-critical",
            name="guardduty-disabled",
            description=None,
            source_service="eventbridge",
            detection_type=DetectionType.EVENT_PATTERN,
            raw_config={
                "event_pattern": """{
                    "source": ["aws.guardduty"],
                    "detail": {
                        "eventName": ["DeleteDetector"]
                    }
                }"""
            },
            region="us-east-1",
            status="enabled",
            created_at=None,
            last_modified=None,
            owner=None,
            tags={}
        )

        result = parser.parse(raw)

        assert result.severity in ["critical", "high"]

    def test_infer_severity_from_name(self, parser):
        """Test severity inference from detection name."""
        raw = RawDetection(
            external_id="rule-named",
            name="CRITICAL-security-alert",
            description=None,
            source_service="eventbridge",
            detection_type=DetectionType.EVENT_PATTERN,
            raw_config={
                "event_pattern": '{"source": ["aws.ec2"]}'
            },
            region="us-east-1",
            status="enabled",
            created_at=None,
            last_modified=None,
            owner=None,
            tags={}
        )

        result = parser.parse(raw)

        assert result.severity == "critical"
```

---

#### Mapper Unit Tests

```python
# tests/unit/mapping/test_pattern_matcher.py

import pytest
from src.mapping.pattern_matcher import PatternMatcher
from src.mapping.indicators import TechniqueIndicator, build_indicator_list
from src.models.detection import ParsedDetection, MonitoredEntity, Condition, Operator

class TestPatternMatcher:
    """Unit tests for pattern-based MITRE mapping."""

    @pytest.fixture
    def matcher(self):
        indicators = build_indicator_list()
        return PatternMatcher(indicators)

    @pytest.fixture
    def sample_parsed_detection(self):
        """Create a sample parsed detection for IAM user creation."""
        return ParsedDetection(
            detection_id="det-1",
            parse_success=True,
            parse_confidence=0.9,
            monitored_entities=[
                MonitoredEntity(
                    entity_type="api_call",
                    entity_id="iam:CreateUser",
                    provider_specific={}
                ),
                MonitoredEntity(
                    entity_type="aws_service",
                    entity_id="aws.iam",
                    provider_specific={}
                )
            ],
            trigger_conditions=[
                Condition(
                    field="detail.eventName",
                    operator=Operator.EQUALS,
                    value="CreateUser"
                )
            ],
            actions=[],
            severity="high",
            parser_version="1.0.0",
            parse_errors=[],
            unparsed_elements=[]
        )

    # =========================================================================
    # Basic Mapping Tests
    # =========================================================================

    def test_map_iam_createuser_to_t1136(self, matcher, sample_parsed_detection):
        """Test that iam:CreateUser maps to T1136 (Create Account)."""
        results = matcher.map(sample_parsed_detection, provider="aws")

        technique_ids = [r.technique_id for r in results]
        assert "T1136" in technique_ids

    def test_mapping_confidence_is_valid(self, matcher, sample_parsed_detection):
        """Test that confidence scores are in valid range."""
        results = matcher.map(sample_parsed_detection, provider="aws")

        for result in results:
            assert 0.0 <= result.confidence <= 1.0

    def test_mapping_includes_rationale(self, matcher, sample_parsed_detection):
        """Test that mappings include rationale."""
        results = matcher.map(sample_parsed_detection, provider="aws")

        for result in results:
            assert result.rationale is not None
            assert len(result.rationale) > 0

    # =========================================================================
    # Multi-Technique Mapping Tests
    # =========================================================================

    def test_detection_can_map_to_multiple_techniques(self, matcher):
        """Test that a detection can map to multiple techniques."""
        # Detection monitoring AssumeRole could be T1078 and T1078.004
        parsed = ParsedDetection(
            detection_id="det-2",
            parse_success=True,
            parse_confidence=0.9,
            monitored_entities=[
                MonitoredEntity(
                    entity_type="api_call",
                    entity_id="sts:AssumeRole",
                    provider_specific={}
                )
            ],
            trigger_conditions=[],
            actions=[],
            severity="high",
            parser_version="1.0.0",
            parse_errors=[],
            unparsed_elements=[]
        )

        results = matcher.map(parsed, provider="aws")

        technique_ids = [r.technique_id for r in results]
        # Should map to both parent and sub-technique
        assert len(set(technique_ids)) >= 1

    def test_multiple_indicators_boost_confidence(self, matcher):
        """Test that multiple matching indicators increase confidence."""
        # Detection with multiple IAM-related indicators
        parsed = ParsedDetection(
            detection_id="det-3",
            parse_success=True,
            parse_confidence=0.9,
            monitored_entities=[
                MonitoredEntity(entity_type="api_call", entity_id="iam:CreateUser", provider_specific={}),
                MonitoredEntity(entity_type="api_call", entity_id="iam:CreateLoginProfile", provider_specific={}),
            ],
            trigger_conditions=[],
            actions=[],
            severity="high",
            parser_version="1.0.0",
            parse_errors=[],
            unparsed_elements=[]
        )

        results = matcher.map(parsed, provider="aws")

        # T1136 mapping should have higher confidence with multiple indicators
        t1136_mappings = [r for r in results if r.technique_id == "T1136"]
        if t1136_mappings:
            assert t1136_mappings[0].confidence >= 0.85

    # =========================================================================
    # Context Matching Tests
    # =========================================================================

    def test_context_matching_for_failed_login(self, matcher):
        """Test that context requirements are checked for mappings."""
        # Failed login (errorCode exists) should map to T1110 (Brute Force)
        parsed = ParsedDetection(
            detection_id="det-4",
            parse_success=True,
            parse_confidence=0.9,
            monitored_entities=[
                MonitoredEntity(entity_type="event_name", entity_id="ConsoleLogin", provider_specific={})
            ],
            trigger_conditions=[
                Condition(field="errorCode", operator=Operator.EXISTS, value=None)
            ],
            actions=[],
            severity="high",
            parser_version="1.0.0",
            parse_errors=[],
            unparsed_elements=[]
        )

        results = matcher.map(parsed, provider="aws")

        technique_ids = [r.technique_id for r in results]
        assert "T1110" in technique_ids or "T1078" in technique_ids

    # =========================================================================
    # Provider Filtering Tests
    # =========================================================================

    def test_aws_indicators_not_matched_for_gcp(self, matcher):
        """Test that AWS-specific indicators don't match for GCP provider."""
        parsed = ParsedDetection(
            detection_id="det-5",
            parse_success=True,
            parse_confidence=0.9,
            monitored_entities=[
                MonitoredEntity(entity_type="api_call", entity_id="iam:CreateUser", provider_specific={})
            ],
            trigger_conditions=[],
            actions=[],
            severity="high",
            parser_version="1.0.0",
            parse_errors=[],
            unparsed_elements=[]
        )

        results = matcher.map(parsed, provider="gcp")

        # AWS-specific indicator shouldn't match for GCP
        # (unless there's a generic indicator)
        assert len(results) == 0 or all(
            r.confidence < 0.5 for r in results
        )

    # =========================================================================
    # Edge Case Tests
    # =========================================================================

    def test_no_mappings_for_unknown_indicators(self, matcher):
        """Test handling of detection with unknown indicators."""
        parsed = ParsedDetection(
            detection_id="det-unknown",
            parse_success=True,
            parse_confidence=0.9,
            monitored_entities=[
                MonitoredEntity(entity_type="api_call", entity_id="custom:UnknownAPI", provider_specific={})
            ],
            trigger_conditions=[],
            actions=[],
            severity="medium",
            parser_version="1.0.0",
            parse_errors=[],
            unparsed_elements=[]
        )

        results = matcher.map(parsed, provider="aws")

        # Should return empty or very low confidence results
        assert len(results) == 0 or all(r.confidence < 0.5 for r in results)

    def test_empty_detection_returns_no_mappings(self, matcher):
        """Test handling of detection with no entities."""
        parsed = ParsedDetection(
            detection_id="det-empty",
            parse_success=True,
            parse_confidence=0.9,
            monitored_entities=[],
            trigger_conditions=[],
            actions=[],
            severity=None,
            parser_version="1.0.0",
            parse_errors=[],
            unparsed_elements=[]
        )

        results = matcher.map(parsed, provider="aws")

        assert len(results) == 0
```

---

#### Coverage Calculator Unit Tests

```python
# tests/unit/analysis/test_coverage.py

import pytest
from src.analysis.coverage import CoverageCalculator
from src.mapping.models import MappingResult

class TestCoverageCalculator:
    """Unit tests for coverage calculation."""

    @pytest.fixture
    def techniques(self):
        """Sample MITRE techniques for testing."""
        from src.models.mitre import MITRETechnique
        return [
            MITRETechnique(
                technique_id="T1078",
                name="Valid Accounts",
                description="...",
                tactics=["TA0001", "TA0003", "TA0004", "TA0005"],
                platforms=["IaaS"],
                data_sources=[],
                detection_guidance="",
                parent_id=None
            ),
            MITRETechnique(
                technique_id="T1110",
                name="Brute Force",
                description="...",
                tactics=["TA0006"],
                platforms=["IaaS"],
                data_sources=[],
                detection_guidance="",
                parent_id=None
            ),
            MITRETechnique(
                technique_id="T1562",
                name="Impair Defenses",
                description="...",
                tactics=["TA0005"],
                platforms=["IaaS"],
                data_sources=[],
                detection_guidance="",
                parent_id=None
            ),
        ]

    @pytest.fixture
    def calculator(self, techniques):
        return CoverageCalculator(techniques, confidence_threshold=0.6)

    # =========================================================================
    # Basic Coverage Tests
    # =========================================================================

    def test_full_coverage_calculation(self, calculator):
        """Test coverage when all techniques are covered."""
        mappings = {
            "det-1": [MappingResult("T1078", 0.9, "pattern", "", [])],
            "det-2": [MappingResult("T1110", 0.85, "pattern", "", [])],
            "det-3": [MappingResult("T1562", 0.8, "pattern", "", [])],
        }

        result = calculator.calculate("account-1", mappings)

        assert result.overall_percentage == 100.0
        assert result.mapped_detections == 3
        assert result.unmapped_detections == 0

    def test_partial_coverage_calculation(self, calculator):
        """Test coverage when some techniques are not covered."""
        mappings = {
            "det-1": [MappingResult("T1078", 0.9, "pattern", "", [])],
            "det-2": [],  # Unmapped detection
        }

        result = calculator.calculate("account-1", mappings)

        # 1 out of 3 techniques covered
        assert result.overall_percentage < 100.0
        assert result.mapped_detections == 1
        assert result.unmapped_detections == 1

    def test_zero_coverage(self, calculator):
        """Test coverage when nothing is covered."""
        mappings = {
            "det-1": [],
            "det-2": [],
        }

        result = calculator.calculate("account-1", mappings)

        assert result.overall_percentage == 0.0
        assert result.mapped_detections == 0

    # =========================================================================
    # Confidence Threshold Tests
    # =========================================================================

    def test_low_confidence_mappings_not_counted(self, calculator):
        """Test that mappings below threshold aren't counted as coverage."""
        mappings = {
            "det-1": [MappingResult("T1078", 0.3, "pattern", "", [])],  # Below threshold
        }

        result = calculator.calculate("account-1", mappings)

        # T1078 shouldn't be counted as covered
        t1078_coverage = next(
            (t for t in result.techniques if t.technique_id == "T1078"),
            None
        )
        assert t1078_coverage.coverage_status == "none"

    def test_partial_coverage_for_medium_confidence(self, calculator):
        """Test that medium confidence gives partial coverage."""
        calculator = CoverageCalculator(
            calculator.techniques.values(),
            confidence_threshold=0.6,
            partial_threshold=0.4
        )

        mappings = {
            "det-1": [MappingResult("T1078", 0.5, "pattern", "", [])],  # Between thresholds
        }

        result = calculator.calculate("account-1", mappings)

        t1078_coverage = next(
            (t for t in result.techniques if t.technique_id == "T1078"),
            None
        )
        assert t1078_coverage.coverage_status == "partial"

    # =========================================================================
    # Multi-Detection Tests
    # =========================================================================

    def test_multiple_detections_per_technique(self, calculator):
        """Test handling of multiple detections for same technique."""
        mappings = {
            "det-1": [MappingResult("T1078", 0.9, "pattern", "", [])],
            "det-2": [MappingResult("T1078", 0.85, "nlp", "", [])],
            "det-3": [MappingResult("T1078", 0.7, "pattern", "", [])],
        }

        result = calculator.calculate("account-1", mappings)

        t1078_coverage = next(
            (t for t in result.techniques if t.technique_id == "T1078"),
            None
        )

        assert t1078_coverage.detection_count == 3
        assert t1078_coverage.max_confidence == 0.9

    # =========================================================================
    # Tactic Coverage Tests
    # =========================================================================

    def test_tactic_coverage_calculation(self, calculator):
        """Test per-tactic coverage calculation."""
        mappings = {
            "det-1": [MappingResult("T1078", 0.9, "pattern", "", [])],  # Multiple tactics
        }

        result = calculator.calculate("account-1", mappings)

        # T1078 covers TA0001, TA0003, TA0004, TA0005
        # Find Defense Evasion (TA0005) which has T1078 and T1562
        defense_evasion = next(
            (t for t in result.tactics if t.tactic_id == "TA0005"),
            None
        )

        assert defense_evasion is not None
        # 1 technique covered (T1078) out of 2 (T1078 + T1562) = 50%
        assert defense_evasion.covered_techniques == 1
```

---

### Step 3: Integration Testing Design

#### API Integration Tests

```python
# tests/integration/api/test_accounts_api.py

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.main import app
from src.database import Base, get_db

# Test database
TEST_DATABASE_URL = "postgresql://test:test@localhost:5432/test_db"

@pytest.fixture(scope="module")
def test_db():
    engine = create_engine(TEST_DATABASE_URL)
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(bind=engine)

    yield TestingSessionLocal()

    Base.metadata.drop_all(bind=engine)

@pytest.fixture
def client(test_db):
    def override_get_db():
        yield test_db

    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app)

@pytest.fixture
def auth_headers():
    return {"Authorization": "Bearer test-api-key"}


class TestAccountsAPI:
    """Integration tests for /accounts endpoints."""

    def test_create_account(self, client, auth_headers):
        """Test creating a new account."""
        response = client.post(
            "/api/v1/accounts",
            headers=auth_headers,
            json={
                "account_identifier": "123456789012",
                "account_name": "test-account",
                "provider": "aws",
                "regions": ["us-east-1"],
                "environment": "dev",
                "criticality": "medium"
            }
        )

        assert response.status_code == 201
        data = response.json()
        assert data["account_identifier"] == "123456789012"
        assert "id" in data

    def test_list_accounts(self, client, auth_headers):
        """Test listing accounts."""
        response = client.get(
            "/api/v1/accounts",
            headers=auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert "data" in data
        assert "pagination" in data

    def test_get_account_not_found(self, client, auth_headers):
        """Test getting non-existent account."""
        response = client.get(
            "/api/v1/accounts/00000000-0000-0000-0000-000000000000",
            headers=auth_headers
        )

        assert response.status_code == 404
        data = response.json()
        assert data["error"]["code"] == "NOT_FOUND"

    def test_create_account_validation_error(self, client, auth_headers):
        """Test account creation with invalid data."""
        response = client.post(
            "/api/v1/accounts",
            headers=auth_headers,
            json={
                "account_identifier": "",  # Invalid: empty
                "account_name": "test",
                "provider": "invalid_provider"  # Invalid: not aws/gcp
            }
        )

        assert response.status_code == 400
        data = response.json()
        assert data["error"]["code"] == "VALIDATION_ERROR"

    def test_unauthorized_without_token(self, client):
        """Test that requests without auth are rejected."""
        response = client.get("/api/v1/accounts")

        assert response.status_code == 401


class TestCoverageAPI:
    """Integration tests for coverage endpoints."""

    @pytest.fixture
    def account_with_coverage(self, client, auth_headers, test_db):
        """Create account with detections and mappings."""
        # Create account
        account_response = client.post(
            "/api/v1/accounts",
            headers=auth_headers,
            json={
                "account_identifier": "111111111111",
                "account_name": "coverage-test",
                "provider": "aws",
                "regions": ["us-east-1"],
                "environment": "dev",
                "criticality": "medium"
            }
        )
        account_id = account_response.json()["id"]

        # Add test detections and mappings directly to DB
        # (or use internal service methods)

        return account_id

    def test_get_coverage(self, client, auth_headers, account_with_coverage):
        """Test getting coverage for an account."""
        response = client.get(
            f"/api/v1/accounts/{account_with_coverage}/coverage",
            headers=auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert "overall_coverage_percentage" in data
        assert "by_tactic" in data

    def test_get_coverage_gaps(self, client, auth_headers, account_with_coverage):
        """Test getting coverage gaps."""
        response = client.get(
            f"/api/v1/accounts/{account_with_coverage}/coverage/gaps",
            headers=auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert "data" in data
        assert "summary" in data
```

---

#### Cloud Provider Mock Tests

```python
# tests/integration/scanners/test_aws_scanner.py

import pytest
from unittest.mock import Mock, patch
from moto import mock_logs, mock_events

from src.scanners.aws.cloudwatch import CloudWatchLogsScanner
from src.scanners.aws.eventbridge import EventBridgeScanner

class TestCloudWatchLogsScanner:
    """Integration tests for CloudWatch Logs scanner using moto."""

    @mock_logs
    def test_scan_metric_filters(self):
        """Test scanning CloudWatch metric filters."""
        import boto3

        # Setup mock CloudWatch Logs
        client = boto3.client('logs', region_name='us-east-1')
        client.create_log_group(logGroupName='/aws/cloudtrail/test')
        client.put_metric_filter(
            logGroupName='/aws/cloudtrail/test',
            filterName='failed-logins',
            filterPattern='{ $.eventName = "ConsoleLogin" && $.errorCode EXISTS }',
            metricTransformations=[{
                'metricName': 'FailedLogins',
                'metricNamespace': 'Security',
                'metricValue': '1'
            }]
        )

        # Run scanner
        scanner = CloudWatchLogsScanner()
        credentials = {
            'access_key_id': 'testing',
            'secret_access_key': 'testing'
        }

        import asyncio
        detections = asyncio.run(
            scanner.scan(credentials, regions=['us-east-1'])
        )

        assert len(detections) >= 1
        assert any(d.name == 'failed-logins' for d in detections)

    @mock_logs
    def test_scan_saved_queries(self):
        """Test scanning CloudWatch Logs Insights saved queries."""
        import boto3

        client = boto3.client('logs', region_name='us-east-1')
        client.put_query_definition(
            name='security-query',
            queryString='filter @message like /error/',
            logGroupNames=['/aws/cloudtrail/test']
        )

        scanner = CloudWatchLogsScanner()
        credentials = {
            'access_key_id': 'testing',
            'secret_access_key': 'testing'
        }

        import asyncio
        detections = asyncio.run(
            scanner.scan(credentials, regions=['us-east-1'])
        )

        assert any(d.name == 'security-query' for d in detections)


class TestEventBridgeScanner:
    """Integration tests for EventBridge scanner using moto."""

    @mock_events
    def test_scan_event_rules(self):
        """Test scanning EventBridge rules."""
        import boto3

        client = boto3.client('events', region_name='us-east-1')
        client.put_rule(
            Name='guardduty-findings',
            EventPattern='{"source": ["aws.guardduty"]}',
            State='ENABLED',
            Description='Alert on GuardDuty findings'
        )
        client.put_targets(
            Rule='guardduty-findings',
            Targets=[{
                'Id': 'sns-target',
                'Arn': 'arn:aws:sns:us-east-1:123456789012:alerts'
            }]
        )

        scanner = EventBridgeScanner()
        credentials = {
            'access_key_id': 'testing',
            'secret_access_key': 'testing'
        }

        import asyncio
        detections = asyncio.run(
            scanner.scan(credentials, regions=['us-east-1'])
        )

        assert len(detections) >= 1
        assert any(d.name == 'guardduty-findings' for d in detections)

    @mock_events
    def test_scan_disabled_rules(self):
        """Test that disabled rules are detected with correct status."""
        import boto3

        client = boto3.client('events', region_name='us-east-1')
        client.put_rule(
            Name='disabled-rule',
            EventPattern='{"source": ["aws.ec2"]}',
            State='DISABLED'
        )

        scanner = EventBridgeScanner()
        credentials = {
            'access_key_id': 'testing',
            'secret_access_key': 'testing'
        }

        import asyncio
        detections = asyncio.run(
            scanner.scan(credentials, regions=['us-east-1'])
        )

        disabled_rule = next(
            (d for d in detections if d.name == 'disabled-rule'),
            None
        )
        assert disabled_rule is not None
        assert disabled_rule.status == 'disabled'
```

---

### Step 4: End-to-End Testing Design

```python
# tests/e2e/test_coverage_workflow.py

import pytest
from playwright.sync_api import Page, expect

class TestCoverageWorkflow:
    """End-to-end tests for coverage analysis workflow."""

    @pytest.fixture
    def setup_test_data(self, api_client):
        """Setup test account with detections."""
        # Create account
        account = api_client.post("/api/v1/accounts", json={...})

        # Trigger scan
        scan = api_client.post(f"/api/v1/accounts/{account['id']}/scans")

        # Wait for scan completion
        api_client.wait_for_scan(scan['scan_id'])

        return account

    def test_view_coverage_dashboard(self, page: Page, setup_test_data):
        """Test viewing coverage dashboard."""
        page.goto("/dashboard")

        # Check coverage score is visible
        expect(page.locator("[data-testid=coverage-score]")).to_be_visible()

        # Check tactic bars are rendered
        expect(page.locator("[data-testid=tactic-bar]")).to_have_count(12)

        # Check critical gaps section
        expect(page.locator("[data-testid=critical-gaps]")).to_be_visible()

    def test_view_gap_details(self, page: Page, setup_test_data):
        """Test viewing and interacting with gap details."""
        page.goto("/gaps")

        # Click on first gap
        page.locator("[data-testid=gap-card]").first.click()

        # Check gap details are shown
        expect(page.locator("[data-testid=gap-detail]")).to_be_visible()
        expect(page.locator("[data-testid=recommendations]")).to_be_visible()

    def test_acknowledge_gap(self, page: Page, setup_test_data):
        """Test acknowledging a gap."""
        page.goto("/gaps")

        # Click acknowledge button
        page.locator("[data-testid=gap-card]").first.locator(
            "[data-testid=acknowledge-btn]"
        ).click()

        # Confirm acknowledgement
        page.locator("[data-testid=confirm-btn]").click()

        # Check gap status changed
        expect(page.locator("[data-testid=gap-status]").first).to_have_text(
            "Acknowledged"
        )

    def test_generate_report(self, page: Page, setup_test_data):
        """Test generating a coverage report."""
        page.goto("/reports")

        # Select report type
        page.locator("[data-testid=report-type]").select_option("coverage")

        # Select accounts
        page.locator("[data-testid=account-checkbox]").first.check()

        # Generate report
        page.locator("[data-testid=generate-btn]").click()

        # Wait for report generation
        expect(page.locator("[data-testid=download-btn]")).to_be_visible(
            timeout=30000
        )

    def test_view_mitre_heatmap(self, page: Page, setup_test_data):
        """Test MITRE heatmap visualization."""
        page.goto("/coverage/heatmap")

        # Check heatmap is rendered
        expect(page.locator("[data-testid=mitre-heatmap]")).to_be_visible()

        # Click on a technique cell
        page.locator("[data-testid=technique-cell-T1078]").click()

        # Check technique detail panel opens
        expect(page.locator("[data-testid=technique-detail]")).to_be_visible()
        expect(page.locator("[data-testid=technique-detail]")).to_contain_text(
            "Valid Accounts"
        )
```

---

### Step 5: Performance Testing

```python
# tests/performance/test_coverage_calculation.py

import pytest
import time
from src.analysis.coverage import CoverageCalculator
from src.mapping.models import MappingResult

class TestCoveragePerformance:
    """Performance tests for coverage calculation."""

    @pytest.fixture
    def large_dataset(self):
        """Generate large dataset for performance testing."""
        # 1000 detections with random mappings
        mappings = {}
        techniques = [f"T{1000 + i}" for i in range(200)]

        import random
        for i in range(1000):
            det_id = f"det-{i}"
            num_mappings = random.randint(0, 5)
            mappings[det_id] = [
                MappingResult(
                    random.choice(techniques),
                    random.uniform(0.5, 1.0),
                    "pattern",
                    "",
                    []
                )
                for _ in range(num_mappings)
            ]

        return mappings

    def test_coverage_calculation_under_1_second(self, large_dataset, techniques):
        """Test that coverage calculation completes within 1 second."""
        calculator = CoverageCalculator(techniques)

        start = time.time()
        result = calculator.calculate("account-1", large_dataset)
        elapsed = time.time() - start

        assert elapsed < 1.0, f"Coverage calculation took {elapsed:.2f}s"

    def test_gap_analysis_under_2_seconds(self, large_dataset, techniques):
        """Test that gap analysis completes within 2 seconds."""
        from src.analysis.gaps import GapAnalyzer

        calculator = CoverageCalculator(techniques)
        coverage = calculator.calculate("account-1", large_dataset)

        analyzer = GapAnalyzer(
            {t.technique_id: t for t in techniques},
            {t.technique_id: 50 for t in techniques}
        )

        start = time.time()
        gaps = analyzer.identify_gaps("account-1", coverage)
        elapsed = time.time() - start

        assert elapsed < 2.0, f"Gap analysis took {elapsed:.2f}s"


# tests/performance/test_api_latency.py

import pytest
import asyncio
import httpx
import statistics

class TestAPIPerformance:
    """Performance tests for API endpoints."""

    @pytest.fixture
    def client(self):
        return httpx.AsyncClient(base_url="http://localhost:8000")

    async def test_coverage_endpoint_latency(self, client, auth_headers, account_id):
        """Test coverage endpoint responds within 500ms."""
        latencies = []

        for _ in range(10):
            start = time.time()
            response = await client.get(
                f"/api/v1/accounts/{account_id}/coverage",
                headers=auth_headers
            )
            latency = (time.time() - start) * 1000
            latencies.append(latency)

            assert response.status_code == 200

        avg_latency = statistics.mean(latencies)
        p95_latency = sorted(latencies)[int(len(latencies) * 0.95)]

        assert avg_latency < 500, f"Average latency: {avg_latency:.0f}ms"
        assert p95_latency < 1000, f"P95 latency: {p95_latency:.0f}ms"

    async def test_gaps_endpoint_latency(self, client, auth_headers, account_id):
        """Test gaps endpoint responds within 500ms."""
        start = time.time()
        response = await client.get(
            f"/api/v1/accounts/{account_id}/coverage/gaps",
            headers=auth_headers
        )
        latency = (time.time() - start) * 1000

        assert response.status_code == 200
        assert latency < 500, f"Latency: {latency:.0f}ms"
```

---

### Step 6: Test Data and Fixtures

```python
# tests/fixtures/sample_detections.py

"""Sample detection configurations for testing."""

SAMPLE_EVENTBRIDGE_DETECTION = {
    "external_id": "arn:aws:events:us-east-1:123456789012:rule/guardduty-alert",
    "name": "guardduty-alert",
    "description": "Alert on GuardDuty findings",
    "source_service": "eventbridge",
    "detection_type": "event_pattern",
    "raw_config": {
        "rule_arn": "arn:aws:events:us-east-1:123456789012:rule/guardduty-alert",
        "rule_name": "guardduty-alert",
        "event_bus_name": "default",
        "event_pattern": """{
            "source": ["aws.guardduty"],
            "detail-type": ["GuardDuty Finding"]
        }""",
        "state": "ENABLED",
        "targets": [{
            "Id": "sns-target",
            "Arn": "arn:aws:sns:us-east-1:123456789012:security-alerts"
        }]
    },
    "region": "us-east-1",
    "status": "enabled",
    "tags": {"Team": "Security"}
}

SAMPLE_CLOUDWATCH_METRIC_FILTER = {
    "external_id": "/aws/cloudtrail/test:failed-logins",
    "name": "failed-logins",
    "description": None,
    "source_service": "cloudwatch_logs",
    "detection_type": "log_query",
    "raw_config": {
        "log_group_name": "/aws/cloudtrail/test",
        "filter_name": "failed-logins",
        "filter_pattern": '{ $.eventName = "ConsoleLogin" && $.errorCode EXISTS }',
        "metric_transformations": [{
            "metricName": "FailedLogins",
            "metricNamespace": "Security",
            "metricValue": "1"
        }]
    },
    "region": "us-east-1",
    "status": "enabled",
    "tags": {}
}

# Expected mapping results for validation
EXPECTED_MAPPINGS = {
    "guardduty-alert": [
        {"technique_id": "T1562", "min_confidence": 0.6},
    ],
    "failed-logins": [
        {"technique_id": "T1078", "min_confidence": 0.7},
        {"technique_id": "T1110", "min_confidence": 0.7},
    ]
}
```

---

### Step 7: CI/CD Pipeline

```yaml
# .github/workflows/test.yml

name: Tests

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install -r requirements-dev.txt

      - name: Run unit tests
        run: |
          pytest tests/unit \
            --cov=src \
            --cov-report=xml \
            --cov-report=html \
            -v

      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          files: ./coverage.xml

  integration-tests:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_USER: test
          POSTGRES_PASSWORD: test
          POSTGRES_DB: test_db
        ports:
          - 5432:5432
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

      redis:
        image: redis:7
        ports:
          - 6379:6379

    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install -r requirements-dev.txt

      - name: Run integration tests
        env:
          DATABASE_URL: postgresql://test:test@localhost:5432/test_db
          REDIS_URL: redis://localhost:6379
        run: |
          pytest tests/integration -v

  e2e-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install -r requirements-dev.txt
          playwright install

      - name: Start application
        run: |
          docker-compose up -d
          sleep 10

      - name: Run E2E tests
        run: |
          pytest tests/e2e -v

      - name: Stop application
        run: docker-compose down

  performance-tests:
    runs-on: ubuntu-latest
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install -r requirements-dev.txt

      - name: Run performance tests
        run: |
          pytest tests/performance -v --benchmark-json=benchmark.json

      - name: Upload benchmark results
        uses: actions/upload-artifact@v3
        with:
          name: benchmark-results
          path: benchmark.json
```

---

## Output Artifacts

### 1. Test Directory Structure
```
tests/
├── unit/
│   ├── parsers/
│   │   ├── test_eventbridge_parser.py
│   │   ├── test_logs_insights_parser.py
│   │   └── test_metric_filter_parser.py
│   ├── mapping/
│   │   ├── test_pattern_matcher.py
│   │   ├── test_nlp_mapper.py
│   │   └── test_confidence.py
│   └── analysis/
│       ├── test_coverage.py
│       ├── test_gaps.py
│       └── test_drift.py
├── integration/
│   ├── api/
│   │   ├── test_accounts_api.py
│   │   ├── test_coverage_api.py
│   │   └── test_detections_api.py
│   └── scanners/
│       ├── test_aws_scanner.py
│       └── test_gcp_scanner.py
├── e2e/
│   ├── test_coverage_workflow.py
│   ├── test_gap_remediation.py
│   └── test_report_generation.py
├── performance/
│   ├── test_coverage_calculation.py
│   └── test_api_latency.py
├── fixtures/
│   ├── sample_detections.py
│   ├── sample_mappings.py
│   └── sample_techniques.py
└── conftest.py
```

### 2. Test Configuration
**File:** `pytest.ini`

### 3. CI/CD Pipeline
**File:** `.github/workflows/test.yml`

### 4. Test Coverage Requirements
- Unit tests: 80% coverage minimum
- Integration tests: All API endpoints
- E2E tests: Critical user journeys

---

## Validation Checklist

- [ ] Unit tests cover all parser edge cases
- [ ] Mapping accuracy tests validate expected results
- [ ] Cloud provider mocks work correctly
- [ ] API integration tests cover all endpoints
- [ ] E2E tests cover critical user journeys
- [ ] Performance benchmarks are established
- [ ] CI/CD pipeline runs all tests
- [ ] Coverage reports are generated

---

**END OF TESTING AGENT**
