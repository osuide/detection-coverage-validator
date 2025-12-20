# Parser Agent - Detection Coverage Validator

## Role
You are the Parser Agent responsible for designing the detection ingestion and parsing system. Your job is to extract structured detection logic from raw cloud-native security configurations across AWS and GCP.

## Prerequisites
- Review `detection-coverage-validator-model.md` - Section 1B (Detection Entities)
- Review completed architecture from Architecture Agent
- Understand cloud service APIs (CloudWatch, GuardDuty, EventBridge, etc.)

## Your Mission
Design a parsing system that:
1. Scans cloud accounts to discover detection configurations
2. Parses diverse detection formats (queries, patterns, rules)
3. Extracts normalized detection logic
4. Handles parsing failures gracefully
5. Supports extensibility for new services/providers

---

## Chain-of-Thought Reasoning Process

### Step 1: Understand Detection Landscape

**AWS Detection Sources:**

| Service | Detection Type | Format | Complexity |
|---------|---------------|--------|------------|
| CloudWatch Logs Insights | Log Query | Custom query language | High |
| CloudWatch Metric Alarms | Metric Alarm | JSON config | Medium |
| CloudWatch Metric Filters | Log Pattern | Filter pattern syntax | Medium |
| EventBridge Rules | Event Pattern | JSON pattern | Medium |
| AWS Config Rules | Config Rule | JSON + Lambda | High |
| GuardDuty | Managed Detection | Opaque (vendor) | Low (no parsing) |
| Security Hub | Aggregator | Findings (not rules) | N/A |
| Lambda (custom) | Custom Function | Code (Python/Node) | Very High |

**GCP Detection Sources:**

| Service | Detection Type | Format | Complexity |
|---------|---------------|--------|------------|
| Cloud Logging | Log Query | Logging query language | High |
| Cloud Logging Metrics | Log-based Metric | Filter + metric | Medium |
| Cloud Monitoring Alerts | Metric Alert | JSON config | Medium |
| Eventarc Triggers | Event Trigger | JSON config | Medium |
| Security Command Center | Managed Detection | Opaque (vendor) | Low |
| Cloud Functions (custom) | Custom Function | Code | Very High |

**Your Analysis:**
```
Parsing Difficulty Spectrum:
1. Easy: Managed detections (GuardDuty, SCC) - just catalog them
2. Medium: JSON configs (EventBridge, Metric Alarms) - structured parsing
3. Hard: Query languages (Logs Insights, Cloud Logging) - need grammar
4. Very Hard: Custom code (Lambda, Cloud Functions) - static analysis

MVP Strategy:
- Start with Medium complexity (JSON configs)
- Add query language parsing for high-value services
- Defer custom code analysis (mark as "unparseable")
- Catalog managed detections (vendor-claimed coverage)
```

---

### Step 2: Parser Architecture Design

#### High-Level Parser Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                       Scanner Orchestrator                       │
│  (Coordinates scanning across services and regions)              │
└─────────────────────────────────┬───────────────────────────────┘
                                  │
          ┌───────────────────────┼───────────────────────┐
          │                       │                       │
          ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  AWS Scanner    │    │  GCP Scanner    │    │ Azure Scanner   │
│  Module         │    │  Module         │    │ (Future)        │
└────────┬────────┘    └────────┬────────┘    └─────────────────┘
         │                      │
         │ Per-Service          │ Per-Service
         ▼ Scanners             ▼ Scanners
┌─────────────────────────────────────────────────────────────────┐
│                    Service-Specific Scanners                     │
│                                                                  │
│  AWS:                          GCP:                              │
│  ├── CloudWatchLogsScannerr    ├── CloudLoggingScanner          │
│  ├── CloudWatchAlarmScanner    ├── CloudMonitoringScanner       │
│  ├── EventBridgeScanner        ├── EventarcScanner              │
│  ├── ConfigRuleScanner         ├── SecurityCenterScanner        │
│  ├── GuardDutyScanner          └── CloudFunctionScanner         │
│  └── LambdaScanner                                               │
└─────────────────────────────────┬───────────────────────────────┘
                                  │
                                  │ Raw Detection Configs
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│                         Parser Registry                          │
│  (Routes configs to appropriate parser based on type)            │
└─────────────────────────────────┬───────────────────────────────┘
                                  │
          ┌───────────────────────┼───────────────────────┐
          │                       │                       │
          ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ Query Language  │    │  JSON Config    │    │ Managed Service │
│ Parser          │    │  Parser         │    │ Cataloger       │
│                 │    │                 │    │                 │
│ - Logs Insights │    │ - EventBridge   │    │ - GuardDuty     │
│ - Cloud Logging │    │ - Metric Alarms │    │ - SCC           │
│ - Config Rules  │    │ - Eventarc      │    │                 │
└────────┬────────┘    └────────┬────────┘    └────────┬────────┘
         │                      │                      │
         └──────────────────────┼──────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                       Normalization Engine                       │
│  (Converts parsed output to unified DetectionLogic schema)       │
└─────────────────────────────────┬───────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Output: Normalized Detection              │
│  {                                                               │
│    "monitored_entities": ["CloudTrail", "IAM"],                  │
│    "trigger_conditions": [...],                                  │
│    "actions": [...],                                             │
│    "severity": "high"                                            │
│  }                                                               │
└─────────────────────────────────────────────────────────────────┘
```

---

### Step 3: Scanner Interface Design

#### Base Scanner Interface

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from enum import Enum

class CloudProvider(Enum):
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"

class DetectionType(Enum):
    LOG_QUERY = "log_query"
    EVENT_PATTERN = "event_pattern"
    METRIC_ALARM = "metric_alarm"
    CONFIG_RULE = "config_rule"
    CUSTOM_FUNCTION = "custom_function"
    MANAGED_DETECTION = "managed_detection"

@dataclass
class RawDetection:
    """Raw detection discovered from cloud provider."""
    external_id: str              # Provider-specific ID
    name: str
    description: Optional[str]
    source_service: str           # e.g., "cloudwatch", "eventbridge"
    detection_type: DetectionType
    raw_config: Dict[str, Any]    # Original configuration
    region: str
    status: str                   # enabled, disabled
    created_at: Optional[str]
    last_modified: Optional[str]
    owner: Optional[str]
    tags: Dict[str, str]

@dataclass
class ScanResult:
    """Result of scanning a cloud account."""
    account_id: str
    provider: CloudProvider
    detections: List[RawDetection]
    errors: List[Dict[str, Any]]
    scan_duration_ms: int
    services_scanned: List[str]
    regions_scanned: List[str]

class BaseScanner(ABC):
    """Abstract base class for cloud service scanners."""

    @property
    @abstractmethod
    def provider(self) -> CloudProvider:
        """Return the cloud provider this scanner targets."""
        pass

    @property
    @abstractmethod
    def service_name(self) -> str:
        """Return the service name (e.g., 'cloudwatch', 'eventbridge')."""
        pass

    @property
    @abstractmethod
    def supported_detection_types(self) -> List[DetectionType]:
        """Return list of detection types this scanner discovers."""
        pass

    @abstractmethod
    async def scan(
        self,
        credentials: Any,
        regions: List[str],
        options: Optional[Dict[str, Any]] = None
    ) -> List[RawDetection]:
        """
        Scan the service for detection configurations.

        Args:
            credentials: Cloud provider credentials
            regions: List of regions to scan
            options: Optional scanner-specific options

        Returns:
            List of discovered raw detections
        """
        pass

    @abstractmethod
    def validate_credentials(self, credentials: Any) -> bool:
        """Validate that credentials have required permissions."""
        pass
```

---

#### AWS CloudWatch Logs Scanner Implementation

```python
import boto3
from botocore.exceptions import ClientError
from typing import List, Dict, Any, Optional
import asyncio
from concurrent.futures import ThreadPoolExecutor

class CloudWatchLogsScanner(BaseScanner):
    """Scanner for CloudWatch Logs detection resources."""

    @property
    def provider(self) -> CloudProvider:
        return CloudProvider.AWS

    @property
    def service_name(self) -> str:
        return "cloudwatch_logs"

    @property
    def supported_detection_types(self) -> List[DetectionType]:
        return [
            DetectionType.LOG_QUERY,      # Logs Insights saved queries
            DetectionType.METRIC_ALARM    # Metric filters + alarms
        ]

    async def scan(
        self,
        credentials: Dict[str, str],
        regions: List[str],
        options: Optional[Dict[str, Any]] = None
    ) -> List[RawDetection]:
        """Scan CloudWatch Logs for detection configurations."""

        detections = []

        # Use thread pool for boto3 calls (not async-native)
        with ThreadPoolExecutor(max_workers=10) as executor:
            loop = asyncio.get_event_loop()

            # Scan each region
            tasks = [
                loop.run_in_executor(
                    executor,
                    self._scan_region,
                    credentials,
                    region
                )
                for region in regions
            ]

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, Exception):
                    # Log error, continue with other regions
                    continue
                detections.extend(result)

        return detections

    def _scan_region(
        self,
        credentials: Dict[str, str],
        region: str
    ) -> List[RawDetection]:
        """Scan a single region for CloudWatch Logs detections."""

        client = boto3.client(
            'logs',
            region_name=region,
            aws_access_key_id=credentials.get('access_key_id'),
            aws_secret_access_key=credentials.get('secret_access_key'),
            aws_session_token=credentials.get('session_token')
        )

        detections = []

        # 1. Scan Metric Filters (detection patterns on logs)
        detections.extend(self._scan_metric_filters(client, region))

        # 2. Scan Saved Queries (Logs Insights queries)
        detections.extend(self._scan_saved_queries(client, region))

        return detections

    def _scan_metric_filters(
        self,
        client: Any,
        region: str
    ) -> List[RawDetection]:
        """Discover CloudWatch Logs Metric Filters."""

        detections = []
        paginator = client.get_paginator('describe_log_groups')

        for log_groups_page in paginator.paginate():
            for log_group in log_groups_page.get('logGroups', []):
                log_group_name = log_group['logGroupName']

                # Get metric filters for this log group
                try:
                    filters_response = client.describe_metric_filters(
                        logGroupName=log_group_name
                    )

                    for mf in filters_response.get('metricFilters', []):
                        detection = RawDetection(
                            external_id=f"{log_group_name}:{mf['filterName']}",
                            name=mf['filterName'],
                            description=None,
                            source_service="cloudwatch_logs",
                            detection_type=DetectionType.LOG_QUERY,
                            raw_config={
                                "log_group_name": log_group_name,
                                "filter_name": mf['filterName'],
                                "filter_pattern": mf['filterPattern'],
                                "metric_transformations": mf.get('metricTransformations', [])
                            },
                            region=region,
                            status="enabled",  # Metric filters don't have status
                            created_at=None,
                            last_modified=None,
                            owner=None,
                            tags={}
                        )
                        detections.append(detection)

                except ClientError as e:
                    # Skip if access denied or log group deleted
                    continue

        return detections

    def _scan_saved_queries(
        self,
        client: Any,
        region: str
    ) -> List[RawDetection]:
        """Discover CloudWatch Logs Insights saved queries."""

        detections = []

        try:
            # List all query definitions
            response = client.describe_query_definitions()

            for query_def in response.get('queryDefinitions', []):
                detection = RawDetection(
                    external_id=query_def['queryDefinitionId'],
                    name=query_def['name'],
                    description=None,
                    source_service="cloudwatch_logs_insights",
                    detection_type=DetectionType.LOG_QUERY,
                    raw_config={
                        "query_definition_id": query_def['queryDefinitionId'],
                        "name": query_def['name'],
                        "query_string": query_def['queryString'],
                        "log_group_names": query_def.get('logGroupNames', [])
                    },
                    region=region,
                    status="enabled",  # Saved queries don't have status
                    created_at=None,
                    last_modified=str(query_def.get('lastModified')),
                    owner=None,
                    tags={}
                )
                detections.append(detection)

        except ClientError as e:
            # Handle permission errors
            pass

        return detections

    def validate_credentials(self, credentials: Dict[str, str]) -> bool:
        """Validate credentials have required permissions."""
        try:
            client = boto3.client(
                'logs',
                aws_access_key_id=credentials.get('access_key_id'),
                aws_secret_access_key=credentials.get('secret_access_key'),
                aws_session_token=credentials.get('session_token')
            )
            # Try a simple API call
            client.describe_log_groups(limit=1)
            return True
        except ClientError:
            return False
```

---

#### AWS EventBridge Scanner Implementation

```python
class EventBridgeScanner(BaseScanner):
    """Scanner for EventBridge detection rules."""

    @property
    def provider(self) -> CloudProvider:
        return CloudProvider.AWS

    @property
    def service_name(self) -> str:
        return "eventbridge"

    @property
    def supported_detection_types(self) -> List[DetectionType]:
        return [DetectionType.EVENT_PATTERN]

    async def scan(
        self,
        credentials: Dict[str, str],
        regions: List[str],
        options: Optional[Dict[str, Any]] = None
    ) -> List[RawDetection]:
        """Scan EventBridge for detection rules."""

        detections = []

        with ThreadPoolExecutor(max_workers=10) as executor:
            loop = asyncio.get_event_loop()
            tasks = [
                loop.run_in_executor(executor, self._scan_region, credentials, region)
                for region in regions
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if not isinstance(result, Exception):
                    detections.extend(result)

        return detections

    def _scan_region(
        self,
        credentials: Dict[str, str],
        region: str
    ) -> List[RawDetection]:
        """Scan a single region for EventBridge rules."""

        client = boto3.client(
            'events',
            region_name=region,
            aws_access_key_id=credentials.get('access_key_id'),
            aws_secret_access_key=credentials.get('secret_access_key'),
            aws_session_token=credentials.get('session_token')
        )

        detections = []

        # List all event buses (including custom)
        try:
            buses_response = client.list_event_buses()
            event_buses = [b['Name'] for b in buses_response.get('EventBuses', [])]
        except ClientError:
            event_buses = ['default']

        for bus_name in event_buses:
            detections.extend(self._scan_bus_rules(client, bus_name, region))

        return detections

    def _scan_bus_rules(
        self,
        client: Any,
        bus_name: str,
        region: str
    ) -> List[RawDetection]:
        """Scan rules for a specific event bus."""

        detections = []
        paginator = client.get_paginator('list_rules')

        for rules_page in paginator.paginate(EventBusName=bus_name):
            for rule in rules_page.get('Rules', []):
                # Get full rule details including event pattern
                try:
                    rule_detail = client.describe_rule(
                        Name=rule['Name'],
                        EventBusName=bus_name
                    )

                    # Get targets for context
                    targets_response = client.list_targets_by_rule(
                        Rule=rule['Name'],
                        EventBusName=bus_name
                    )

                    # Only include rules with event patterns (not scheduled rules)
                    if rule_detail.get('EventPattern'):
                        detection = RawDetection(
                            external_id=rule_detail['Arn'],
                            name=rule_detail['Name'],
                            description=rule_detail.get('Description'),
                            source_service="eventbridge",
                            detection_type=DetectionType.EVENT_PATTERN,
                            raw_config={
                                "rule_arn": rule_detail['Arn'],
                                "rule_name": rule_detail['Name'],
                                "event_bus_name": bus_name,
                                "event_pattern": rule_detail['EventPattern'],
                                "state": rule_detail['State'],
                                "targets": targets_response.get('Targets', [])
                            },
                            region=region,
                            status="enabled" if rule_detail['State'] == 'ENABLED' else "disabled",
                            created_at=None,
                            last_modified=None,
                            owner=None,
                            tags={}
                        )
                        detections.append(detection)

                except ClientError:
                    continue

        return detections

    def validate_credentials(self, credentials: Dict[str, str]) -> bool:
        try:
            client = boto3.client(
                'events',
                aws_access_key_id=credentials.get('access_key_id'),
                aws_secret_access_key=credentials.get('secret_access_key')
            )
            client.list_rules(Limit=1)
            return True
        except ClientError:
            return False
```

---

### Step 4: Parser Interface Design

#### Base Parser Interface

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from enum import Enum

class Operator(Enum):
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    CONTAINS = "contains"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    REGEX = "regex"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    IN = "in"
    NOT_IN = "not_in"
    AND = "and"
    OR = "or"

@dataclass
class Condition:
    """Normalized trigger condition."""
    field: str
    operator: Operator
    value: Any
    negated: bool = False
    children: Optional[List['Condition']] = None  # For AND/OR

@dataclass
class MonitoredEntity:
    """Entity being monitored by detection."""
    entity_type: str      # e.g., "log_group", "api_call", "metric"
    entity_id: str        # e.g., "CloudTrail", "iam:CreateUser"
    provider_specific: Dict[str, Any] = None

@dataclass
class Action:
    """Action taken when detection triggers."""
    action_type: str      # e.g., "sns", "lambda", "email"
    target: str           # e.g., SNS topic ARN
    configuration: Dict[str, Any] = None

@dataclass
class ParsedDetection:
    """Normalized, parsed detection logic."""
    detection_id: str
    parse_success: bool
    parse_confidence: float  # 0.0 to 1.0

    # Normalized fields
    monitored_entities: List[MonitoredEntity]
    trigger_conditions: List[Condition]
    actions: List[Action]
    severity: Optional[str]

    # Metadata
    parser_version: str
    parse_errors: List[str]
    unparsed_elements: List[str]  # Parts that couldn't be parsed

class BaseParser(ABC):
    """Abstract base class for detection parsers."""

    @property
    @abstractmethod
    def parser_name(self) -> str:
        """Return parser identifier."""
        pass

    @property
    @abstractmethod
    def parser_version(self) -> str:
        """Return parser version for tracking."""
        pass

    @property
    @abstractmethod
    def supported_services(self) -> List[str]:
        """Return list of services this parser handles."""
        pass

    @abstractmethod
    def can_parse(self, raw_detection: RawDetection) -> bool:
        """Check if this parser can handle the detection."""
        pass

    @abstractmethod
    def parse(self, raw_detection: RawDetection) -> ParsedDetection:
        """
        Parse raw detection config into normalized format.

        Returns:
            ParsedDetection with normalized logic
        """
        pass
```

---

#### EventBridge Pattern Parser Implementation

```python
import json
from typing import List, Dict, Any

class EventBridgePatternParser(BaseParser):
    """Parser for AWS EventBridge event patterns."""

    @property
    def parser_name(self) -> str:
        return "eventbridge_pattern_parser"

    @property
    def parser_version(self) -> str:
        return "1.0.0"

    @property
    def supported_services(self) -> List[str]:
        return ["eventbridge"]

    def can_parse(self, raw_detection: RawDetection) -> bool:
        return (
            raw_detection.source_service == "eventbridge" and
            raw_detection.detection_type == DetectionType.EVENT_PATTERN
        )

    def parse(self, raw_detection: RawDetection) -> ParsedDetection:
        """Parse EventBridge event pattern."""

        errors = []
        unparsed = []
        conditions = []
        entities = []
        actions = []

        try:
            # Parse event pattern JSON
            event_pattern_str = raw_detection.raw_config.get('event_pattern', '{}')
            if isinstance(event_pattern_str, str):
                event_pattern = json.loads(event_pattern_str)
            else:
                event_pattern = event_pattern_str

            # Extract monitored entities
            entities = self._extract_entities(event_pattern)

            # Extract trigger conditions
            conditions = self._extract_conditions(event_pattern)

            # Extract actions from targets
            actions = self._extract_actions(raw_detection.raw_config.get('targets', []))

            # Determine severity based on pattern
            severity = self._infer_severity(event_pattern, raw_detection.name)

            parse_success = True
            confidence = 0.9  # EventBridge patterns are well-structured

        except json.JSONDecodeError as e:
            errors.append(f"Invalid JSON pattern: {e}")
            parse_success = False
            confidence = 0.0
            severity = None

        except Exception as e:
            errors.append(f"Parse error: {e}")
            parse_success = False
            confidence = 0.5
            severity = None

        return ParsedDetection(
            detection_id=raw_detection.external_id,
            parse_success=parse_success,
            parse_confidence=confidence,
            monitored_entities=entities,
            trigger_conditions=conditions,
            actions=actions,
            severity=severity,
            parser_version=self.parser_version,
            parse_errors=errors,
            unparsed_elements=unparsed
        )

    def _extract_entities(self, pattern: Dict) -> List[MonitoredEntity]:
        """Extract monitored entities from event pattern."""

        entities = []

        # Source field indicates the AWS service
        sources = pattern.get('source', [])
        if isinstance(sources, list):
            for source in sources:
                entities.append(MonitoredEntity(
                    entity_type="aws_service",
                    entity_id=source,
                    provider_specific={"source": source}
                ))

        # Detail-type indicates specific event type
        detail_types = pattern.get('detail-type', [])
        if isinstance(detail_types, list):
            for dt in detail_types:
                entities.append(MonitoredEntity(
                    entity_type="event_type",
                    entity_id=dt,
                    provider_specific={"detail-type": dt}
                ))

        # Extract specific API calls from detail.eventName
        detail = pattern.get('detail', {})
        event_names = detail.get('eventName', [])
        if isinstance(event_names, list):
            for en in event_names:
                entities.append(MonitoredEntity(
                    entity_type="api_call",
                    entity_id=en,
                    provider_specific={"eventName": en}
                ))

        return entities

    def _extract_conditions(
        self,
        pattern: Dict,
        parent_field: str = ""
    ) -> List[Condition]:
        """Recursively extract conditions from event pattern."""

        conditions = []

        for key, value in pattern.items():
            field_path = f"{parent_field}.{key}" if parent_field else key

            if isinstance(value, list):
                # List = OR condition across values
                if len(value) == 1:
                    conditions.append(Condition(
                        field=field_path,
                        operator=Operator.EQUALS,
                        value=value[0]
                    ))
                else:
                    conditions.append(Condition(
                        field=field_path,
                        operator=Operator.IN,
                        value=value
                    ))

            elif isinstance(value, dict):
                # Check for special operators
                if 'exists' in value:
                    conditions.append(Condition(
                        field=field_path,
                        operator=Operator.EXISTS if value['exists'] else Operator.NOT_EXISTS,
                        value=None
                    ))
                elif 'prefix' in value:
                    conditions.append(Condition(
                        field=field_path,
                        operator=Operator.STARTS_WITH,
                        value=value['prefix']
                    ))
                elif 'anything-but' in value:
                    conditions.append(Condition(
                        field=field_path,
                        operator=Operator.NOT_IN,
                        value=value['anything-but']
                    ))
                elif 'numeric' in value:
                    # Numeric comparisons
                    for op, val in zip(value['numeric'][::2], value['numeric'][1::2]):
                        if op == '>':
                            conditions.append(Condition(
                                field=field_path,
                                operator=Operator.GREATER_THAN,
                                value=val
                            ))
                        elif op == '<':
                            conditions.append(Condition(
                                field=field_path,
                                operator=Operator.LESS_THAN,
                                value=val
                            ))
                else:
                    # Nested object - recurse
                    conditions.extend(self._extract_conditions(value, field_path))
            else:
                # Simple value match
                conditions.append(Condition(
                    field=field_path,
                    operator=Operator.EQUALS,
                    value=value
                ))

        return conditions

    def _extract_actions(self, targets: List[Dict]) -> List[Action]:
        """Extract actions from EventBridge targets."""

        actions = []

        for target in targets:
            arn = target.get('Arn', '')

            # Determine action type from ARN
            if ':sns:' in arn:
                action_type = "sns"
            elif ':lambda:' in arn:
                action_type = "lambda"
            elif ':sqs:' in arn:
                action_type = "sqs"
            elif ':states:' in arn:
                action_type = "step_functions"
            else:
                action_type = "unknown"

            actions.append(Action(
                action_type=action_type,
                target=arn,
                configuration={
                    "target_id": target.get('Id'),
                    "input": target.get('Input'),
                    "input_path": target.get('InputPath')
                }
            ))

        return actions

    def _infer_severity(self, pattern: Dict, name: str) -> str:
        """Infer severity from pattern content and rule name."""

        name_lower = name.lower()

        # Check name for severity hints
        if any(s in name_lower for s in ['critical', 'crit', 'emergency']):
            return "critical"
        if any(s in name_lower for s in ['high', 'important', 'alert']):
            return "high"
        if any(s in name_lower for s in ['medium', 'warn', 'warning']):
            return "medium"
        if any(s in name_lower for s in ['low', 'info', 'informational']):
            return "low"

        # Check for security-relevant patterns
        detail = pattern.get('detail', {})
        event_names = detail.get('eventName', [])

        critical_events = [
            'DeleteTrail', 'StopLogging', 'DeleteFlowLogs',
            'DeleteDetector', 'DisableRule', 'PutBucketPolicy'
        ]

        high_events = [
            'CreateUser', 'AttachUserPolicy', 'CreateAccessKey',
            'AssumeRole', 'RunInstances', 'AuthorizeSecurityGroupIngress'
        ]

        if any(e in critical_events for e in event_names):
            return "critical"
        if any(e in high_events for e in event_names):
            return "high"

        return "medium"  # Default
```

---

#### CloudWatch Logs Insights Query Parser

```python
import re
from typing import List, Tuple

class LogsInsightsQueryParser(BaseParser):
    """Parser for CloudWatch Logs Insights query language."""

    @property
    def parser_name(self) -> str:
        return "logs_insights_parser"

    @property
    def parser_version(self) -> str:
        return "1.0.0"

    @property
    def supported_services(self) -> List[str]:
        return ["cloudwatch_logs_insights"]

    def can_parse(self, raw_detection: RawDetection) -> bool:
        return (
            raw_detection.source_service == "cloudwatch_logs_insights" and
            raw_detection.detection_type == DetectionType.LOG_QUERY
        )

    def parse(self, raw_detection: RawDetection) -> ParsedDetection:
        """Parse CloudWatch Logs Insights query."""

        errors = []
        unparsed = []
        conditions = []
        entities = []

        try:
            query_string = raw_detection.raw_config.get('query_string', '')
            log_groups = raw_detection.raw_config.get('log_group_names', [])

            # Extract log groups as monitored entities
            for lg in log_groups:
                entities.append(MonitoredEntity(
                    entity_type="log_group",
                    entity_id=lg,
                    provider_specific={"log_group_name": lg}
                ))

            # Parse query commands
            conditions, fields_parsed, unparsed_parts = self._parse_query(query_string)
            unparsed.extend(unparsed_parts)

            # Add parsed fields as entities
            for field in fields_parsed:
                if field.startswith('@'):
                    continue  # Skip built-in fields
                entities.append(MonitoredEntity(
                    entity_type="log_field",
                    entity_id=field,
                    provider_specific={"field_name": field}
                ))

            parse_success = len(errors) == 0
            # Lower confidence for complex queries
            confidence = max(0.5, 0.9 - (len(unparsed_parts) * 0.1))

            severity = self._infer_severity(query_string, raw_detection.name)

        except Exception as e:
            errors.append(f"Parse error: {e}")
            parse_success = False
            confidence = 0.3
            severity = None

        return ParsedDetection(
            detection_id=raw_detection.external_id,
            parse_success=parse_success,
            parse_confidence=confidence,
            monitored_entities=entities,
            trigger_conditions=conditions,
            actions=[],  # Logs Insights queries don't have built-in actions
            severity=severity,
            parser_version=self.parser_version,
            parse_errors=errors,
            unparsed_elements=unparsed
        )

    def _parse_query(
        self,
        query: str
    ) -> Tuple[List[Condition], List[str], List[str]]:
        """
        Parse Logs Insights query into conditions.

        Returns:
            (conditions, fields_parsed, unparsed_parts)
        """

        conditions = []
        fields = set()
        unparsed = []

        # Normalize whitespace
        query = ' '.join(query.split())

        # Split by pipe to get command chain
        commands = [c.strip() for c in query.split('|')]

        for cmd in commands:
            cmd_lower = cmd.lower()

            # Parse FILTER command
            if cmd_lower.startswith('filter'):
                conds, flds = self._parse_filter(cmd)
                conditions.extend(conds)
                fields.update(flds)

            # Parse FIELDS command (for entity extraction)
            elif cmd_lower.startswith('fields'):
                flds = self._parse_fields(cmd)
                fields.update(flds)

            # Parse STATS command (aggregations)
            elif cmd_lower.startswith('stats'):
                # Stats commands affect what we're monitoring
                flds = self._parse_stats(cmd)
                fields.update(flds)

            # Unknown command
            elif not any(cmd_lower.startswith(known)
                        for known in ['sort', 'limit', 'display', 'parse']):
                unparsed.append(cmd)

        return conditions, list(fields), unparsed

    def _parse_filter(self, filter_cmd: str) -> Tuple[List[Condition], set]:
        """Parse FILTER command into conditions."""

        conditions = []
        fields = set()

        # Remove 'filter' keyword
        filter_expr = re.sub(r'^filter\s+', '', filter_cmd, flags=re.IGNORECASE)

        # Common patterns
        patterns = [
            # field = "value"
            (r'(\w+)\s*=\s*["\']([^"\']+)["\']', Operator.EQUALS),
            # field = value (unquoted)
            (r'(\w+)\s*=\s*(\w+)', Operator.EQUALS),
            # field != "value"
            (r'(\w+)\s*!=\s*["\']([^"\']+)["\']', Operator.NOT_EQUALS),
            # field like /regex/
            (r'(\w+)\s+like\s+/([^/]+)/', Operator.REGEX),
            # field in ["a", "b"]
            (r'(\w+)\s+in\s+\[([^\]]+)\]', Operator.IN),
            # ispresent(field)
            (r'ispresent\((\w+)\)', Operator.EXISTS),
            # isblank(field)
            (r'isblank\((\w+)\)', Operator.NOT_EXISTS),
        ]

        for pattern, operator in patterns:
            matches = re.findall(pattern, filter_expr, re.IGNORECASE)
            for match in matches:
                if len(match) == 2:
                    field, value = match
                elif len(match) == 1:
                    field = match[0]
                    value = None
                else:
                    continue

                fields.add(field)
                conditions.append(Condition(
                    field=field,
                    operator=operator,
                    value=value
                ))

        return conditions, fields

    def _parse_fields(self, fields_cmd: str) -> set:
        """Extract field names from FIELDS command."""

        fields = set()
        # Remove 'fields' keyword
        fields_expr = re.sub(r'^fields\s+', '', fields_cmd, flags=re.IGNORECASE)
        # Split by comma and clean
        for f in fields_expr.split(','):
            f = f.strip()
            # Handle aliases (field as alias)
            if ' as ' in f.lower():
                f = f.split(' as ')[0].strip()
            if f and not f.startswith('@'):
                fields.add(f)

        return fields

    def _parse_stats(self, stats_cmd: str) -> set:
        """Extract field names from STATS command."""

        fields = set()
        # Extract fields from aggregation functions
        # e.g., stats count(*) by eventName, userIdentity.arn

        by_match = re.search(r'\bby\s+(.+)$', stats_cmd, re.IGNORECASE)
        if by_match:
            by_fields = by_match.group(1)
            for f in by_fields.split(','):
                f = f.strip()
                if f and not f.startswith('@'):
                    fields.add(f)

        return fields

    def _infer_severity(self, query: str, name: str) -> str:
        """Infer severity from query content."""

        query_lower = query.lower()
        name_lower = name.lower()

        # Check for security-relevant keywords
        critical_keywords = [
            'deletetrail', 'stoplogging', 'deletedetector',
            'root', 'consolelegin', 'failed'
        ]
        high_keywords = [
            'createuser', 'attachpolicy', 'createaccesskey',
            'assumerole', 'runinstances', 'security'
        ]

        if any(kw in query_lower or kw in name_lower for kw in critical_keywords):
            return "critical"
        if any(kw in query_lower or kw in name_lower for kw in high_keywords):
            return "high"

        return "medium"
```

---

### Step 5: Parser Registry and Orchestration

```python
from typing import Dict, Type, Optional

class ParserRegistry:
    """Registry of available detection parsers."""

    def __init__(self):
        self._parsers: Dict[str, BaseParser] = {}
        self._register_default_parsers()

    def _register_default_parsers(self):
        """Register built-in parsers."""
        self.register(EventBridgePatternParser())
        self.register(LogsInsightsQueryParser())
        self.register(CloudWatchMetricFilterParser())
        self.register(GuardDutyFindingCataloger())
        # Add more parsers as implemented

    def register(self, parser: BaseParser):
        """Register a parser instance."""
        self._parsers[parser.parser_name] = parser

    def get_parser(self, raw_detection: RawDetection) -> Optional[BaseParser]:
        """Find appropriate parser for a detection."""
        for parser in self._parsers.values():
            if parser.can_parse(raw_detection):
                return parser
        return None

    def parse(self, raw_detection: RawDetection) -> ParsedDetection:
        """Parse a detection using appropriate parser."""
        parser = self.get_parser(raw_detection)

        if parser is None:
            # No parser available
            return ParsedDetection(
                detection_id=raw_detection.external_id,
                parse_success=False,
                parse_confidence=0.0,
                monitored_entities=[],
                trigger_conditions=[],
                actions=[],
                severity=None,
                parser_version="none",
                parse_errors=[f"No parser available for {raw_detection.source_service}"],
                unparsed_elements=[str(raw_detection.raw_config)]
            )

        return parser.parse(raw_detection)


class ScanOrchestrator:
    """Orchestrates scanning and parsing across cloud accounts."""

    def __init__(
        self,
        scanner_registry: Dict[str, BaseScanner],
        parser_registry: ParserRegistry
    ):
        self.scanners = scanner_registry
        self.parsers = parser_registry

    async def scan_account(
        self,
        account_id: str,
        provider: CloudProvider,
        credentials: Any,
        regions: List[str],
        services: Optional[List[str]] = None
    ) -> ScanResult:
        """
        Scan a cloud account for detections.

        Args:
            account_id: Account identifier
            provider: Cloud provider enum
            credentials: Provider-specific credentials
            regions: Regions to scan
            services: Optional list of services to scan (all if None)

        Returns:
            ScanResult with all discovered detections
        """

        all_detections = []
        all_errors = []
        services_scanned = []
        start_time = time.time()

        # Get applicable scanners
        applicable_scanners = [
            s for s in self.scanners.values()
            if s.provider == provider and
            (services is None or s.service_name in services)
        ]

        # Run scanners concurrently
        tasks = [
            scanner.scan(credentials, regions)
            for scanner in applicable_scanners
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for scanner, result in zip(applicable_scanners, results):
            services_scanned.append(scanner.service_name)

            if isinstance(result, Exception):
                all_errors.append({
                    "service": scanner.service_name,
                    "error": str(result)
                })
            else:
                all_detections.extend(result)

        scan_duration = int((time.time() - start_time) * 1000)

        return ScanResult(
            account_id=account_id,
            provider=provider,
            detections=all_detections,
            errors=all_errors,
            scan_duration_ms=scan_duration,
            services_scanned=services_scanned,
            regions_scanned=regions
        )

    async def parse_detections(
        self,
        detections: List[RawDetection]
    ) -> List[ParsedDetection]:
        """Parse a list of raw detections."""

        parsed = []
        for detection in detections:
            parsed_detection = self.parsers.parse(detection)
            parsed.append(parsed_detection)

        return parsed
```

---

### Step 6: Normalization Schema

```python
@dataclass
class NormalizedDetection:
    """
    Unified detection representation for MITRE mapping.

    This schema is cloud-agnostic and contains all information
    needed for technique mapping and coverage analysis.
    """

    # Identity
    detection_id: str
    name: str
    description: Optional[str]

    # Source
    provider: CloudProvider
    source_service: str
    detection_type: DetectionType
    region: str

    # Status
    status: str  # enabled, disabled, deprecated

    # Parsed Logic (normalized)
    monitored_entities: List[MonitoredEntity]
    trigger_conditions: List[Condition]
    actions: List[Action]
    severity: Optional[str]

    # Parse Quality
    parse_success: bool
    parse_confidence: float
    unparsed_elements: List[str]

    # Metadata
    raw_config: Dict[str, Any]
    owner: Optional[str]
    tags: Dict[str, str]

    # Timestamps
    created_at: Optional[str]
    last_modified: Optional[str]
    discovered_at: str

    # For change detection
    config_hash: str

def normalize_detection(
    raw: RawDetection,
    parsed: ParsedDetection
) -> NormalizedDetection:
    """Combine raw and parsed detection into normalized form."""

    import hashlib
    import json

    # Create config hash for change detection
    config_str = json.dumps(raw.raw_config, sort_keys=True)
    config_hash = hashlib.sha256(config_str.encode()).hexdigest()[:16]

    return NormalizedDetection(
        detection_id=raw.external_id,
        name=raw.name,
        description=raw.description,
        provider=CloudProvider.AWS,  # From scanner context
        source_service=raw.source_service,
        detection_type=raw.detection_type,
        region=raw.region,
        status=raw.status,
        monitored_entities=parsed.monitored_entities,
        trigger_conditions=parsed.trigger_conditions,
        actions=parsed.actions,
        severity=parsed.severity,
        parse_success=parsed.parse_success,
        parse_confidence=parsed.parse_confidence,
        unparsed_elements=parsed.unparsed_elements,
        raw_config=raw.raw_config,
        owner=raw.owner,
        tags=raw.tags,
        created_at=raw.created_at,
        last_modified=raw.last_modified,
        discovered_at=datetime.utcnow().isoformat(),
        config_hash=config_hash
    )
```

---

## Error Handling Strategy

### Error Categories

| Category | Example | Handling |
|----------|---------|----------|
| Permission Denied | IAM access denied | Log, skip resource, continue |
| Rate Limited | API throttling | Exponential backoff, retry |
| Resource Not Found | Deleted during scan | Log, skip, continue |
| Parse Failure | Invalid query syntax | Mark unparseable, store raw |
| Timeout | Large account | Checkpoint, resume |
| Unknown | Unexpected exception | Log with context, alert |

### Error Recovery

```python
class ErrorRecovery:
    """Error handling and recovery strategies."""

    MAX_RETRIES = 3
    BASE_DELAY_SECONDS = 1

    async def with_retry(
        self,
        func,
        *args,
        retries: int = MAX_RETRIES,
        **kwargs
    ):
        """Execute function with exponential backoff retry."""

        last_error = None

        for attempt in range(retries):
            try:
                return await func(*args, **kwargs)
            except RateLimitError as e:
                delay = self.BASE_DELAY_SECONDS * (2 ** attempt)
                await asyncio.sleep(delay)
                last_error = e
            except PermissionError as e:
                # Don't retry permission errors
                raise
            except Exception as e:
                last_error = e
                if attempt == retries - 1:
                    raise

        raise last_error
```

---

## Output Artifacts

### 1. Scanner Interface Specification
**File:** `src/scanners/base.py`
- Base scanner abstract class
- Common data types (RawDetection, ScanResult)

### 2. Parser Interface Specification
**File:** `src/parsers/base.py`
- Base parser abstract class
- Normalized output types (Condition, MonitoredEntity, ParsedDetection)

### 3. AWS Scanner Implementations
**Files:**
- `src/scanners/aws/cloudwatch.py`
- `src/scanners/aws/eventbridge.py`
- `src/scanners/aws/guardduty.py`
- `src/scanners/aws/config.py`

### 4. Parser Implementations
**Files:**
- `src/parsers/eventbridge.py`
- `src/parsers/logs_insights.py`
- `src/parsers/metric_filter.py`
- `src/parsers/managed_service.py`

### 5. Test Cases
**Files:**
- `tests/scanners/test_cloudwatch.py`
- `tests/parsers/test_eventbridge.py`
- `tests/fixtures/sample_detections.json`

---

## Validation Checklist

- [ ] Scanners cover all MVP detection sources (CloudWatch, EventBridge, GuardDuty)
- [ ] Parsers handle common query patterns
- [ ] Error handling prevents scan failures from blocking
- [ ] Parse confidence accurately reflects extraction quality
- [ ] Normalized output contains all fields needed for mapping
- [ ] Performance: Scan completes within 10 minutes for typical account
- [ ] Tests cover edge cases and malformed inputs

---

## Next Agent

Proceed to: **05-MAPPING-AGENT.md**

Provide the Mapping Agent with:
- Normalized detection schema (ParsedDetection, MonitoredEntity, Condition)
- Sample parsed detections
- Expected volume (1000s of detections to map)

---

**END OF PARSER AGENT**
