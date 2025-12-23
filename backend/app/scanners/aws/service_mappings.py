"""AWS service mappings for service-aware coverage calculation.

This module provides mappings between various AWS identifiers and
normalised service names used throughout the application.
"""

import re
from typing import Optional

# Core 10 AWS services for MVP service-aware coverage
# These are the most common data storage services that customer data resides in
CORE_SERVICES = [
    "S3",
    "EBS",
    "EFS",
    "RDS",
    "DynamoDB",
    "Redshift",
    "ElastiCache",
    "SecretsManager",
    "CloudWatchLogs",
    "ECR",
]

# CloudFormation resource type → normalised service name
AWS_RESOURCE_TO_SERVICE: dict[str, str] = {
    # Object Storage
    "AWS::S3::Bucket": "S3",
    "AWS::S3::AccessPoint": "S3",
    # Block Storage
    "AWS::EC2::Volume": "EBS",
    "AWS::EC2::Snapshot": "EBS",
    # File Storage
    "AWS::EFS::FileSystem": "EFS",
    "AWS::EFS::AccessPoint": "EFS",
    # Relational Databases
    "AWS::RDS::DBInstance": "RDS",
    "AWS::RDS::DBCluster": "RDS",  # Aurora clusters
    "AWS::RDS::DBSnapshot": "RDS",
    # NoSQL
    "AWS::DynamoDB::Table": "DynamoDB",
    "AWS::DynamoDB::GlobalTable": "DynamoDB",
    # Data Warehouse
    "AWS::Redshift::Cluster": "Redshift",
    "AWS::Redshift::ClusterSnapshot": "Redshift",
    # Caching
    "AWS::ElastiCache::CacheCluster": "ElastiCache",
    "AWS::ElastiCache::ReplicationGroup": "ElastiCache",
    # Secrets
    "AWS::SecretsManager::Secret": "SecretsManager",
    # Logging
    "AWS::Logs::LogGroup": "CloudWatchLogs",
    # Container Registry
    "AWS::ECR::Repository": "ECR",
}

# EventBridge event source → normalised service name
AWS_EVENT_SOURCE_TO_SERVICE: dict[str, str] = {
    "s3.amazonaws.com": "S3",
    "ec2.amazonaws.com": "EBS",  # Volume-related events
    "elasticfilesystem.amazonaws.com": "EFS",
    "rds.amazonaws.com": "RDS",
    "dynamodb.amazonaws.com": "DynamoDB",
    "redshift.amazonaws.com": "Redshift",
    "elasticache.amazonaws.com": "ElastiCache",
    "secretsmanager.amazonaws.com": "SecretsManager",
    "logs.amazonaws.com": "CloudWatchLogs",
    "ecr.amazonaws.com": "ECR",
}

# EventBridge source prefix (aws.X) → normalised service name
AWS_SOURCE_PREFIX_TO_SERVICE: dict[str, str] = {
    "aws.s3": "S3",
    "aws.ec2": "EBS",  # Volume-related events
    "aws.efs": "EFS",
    "aws.rds": "RDS",
    "aws.dynamodb": "DynamoDB",
    "aws.redshift": "Redshift",
    "aws.elasticache": "ElastiCache",
    "aws.secretsmanager": "SecretsManager",
    "aws.logs": "CloudWatchLogs",
    "aws.ecr": "ECR",
}

# Log group patterns (regex) → normalised service name
LOG_GROUP_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"/aws/s3/", re.IGNORECASE), "S3"),
    (re.compile(r"/aws/rds/", re.IGNORECASE), "RDS"),
    (re.compile(r"/aws/elasticache/", re.IGNORECASE), "ElastiCache"),
    (re.compile(r"/aws/redshift/", re.IGNORECASE), "Redshift"),
    (re.compile(r"/aws/efs/", re.IGNORECASE), "EFS"),
    (re.compile(r"/aws/ecr/", re.IGNORECASE), "ECR"),
    (re.compile(r"/aws/dynamodb/", re.IGNORECASE), "DynamoDB"),
    # CloudWatch Logs doesn't log to itself, but queries might target it
]


def extract_service_from_resource_type(resource_type: str) -> Optional[str]:
    """Extract normalised service name from CloudFormation resource type.

    Args:
        resource_type: e.g., "AWS::S3::Bucket"

    Returns:
        Normalised service name (e.g., "S3") or None if not in core services
    """
    return AWS_RESOURCE_TO_SERVICE.get(resource_type)


def extract_service_from_event_source(event_source: str) -> Optional[str]:
    """Extract normalised service name from EventBridge event source.

    Args:
        event_source: e.g., "s3.amazonaws.com" or "aws.s3"

    Returns:
        Normalised service name (e.g., "S3") or None if not in core services
    """
    # Try direct match first (e.g., "s3.amazonaws.com")
    service = AWS_EVENT_SOURCE_TO_SERVICE.get(event_source)
    if service:
        return service

    # Try prefix match (e.g., "aws.s3")
    return AWS_SOURCE_PREFIX_TO_SERVICE.get(event_source)


def extract_service_from_log_group(log_group_name: str) -> Optional[str]:
    """Extract normalised service name from CloudWatch log group name.

    Args:
        log_group_name: e.g., "/aws/rds/cluster/mydb/error"

    Returns:
        Normalised service name (e.g., "RDS") or None if not in core services
    """
    for pattern, service in LOG_GROUP_PATTERNS:
        if pattern.search(log_group_name):
            return service
    return None


def extract_services_from_event_pattern(event_pattern: dict) -> list[str]:
    """Extract normalised service names from an EventBridge event pattern.

    Analyses both 'source' and 'detail.eventSource' fields.

    Args:
        event_pattern: EventBridge event pattern dictionary

    Returns:
        List of normalised service names (deduplicated)
    """
    services: set[str] = set()

    # Check 'source' field (e.g., ["aws.s3", "aws.ec2"])
    sources = event_pattern.get("source", [])
    if isinstance(sources, list):
        for source in sources:
            service = extract_service_from_event_source(source)
            if service:
                services.add(service)

    # Check 'detail.eventSource' field (e.g., ["s3.amazonaws.com"])
    detail = event_pattern.get("detail", {})
    if isinstance(detail, dict):
        event_sources = detail.get("eventSource", [])
        if isinstance(event_sources, str):
            event_sources = [event_sources]
        if isinstance(event_sources, list):
            for es in event_sources:
                service = extract_service_from_event_source(es)
                if service:
                    services.add(service)

    return sorted(services)


def extract_services_from_resource_types(resource_types: list[str]) -> list[str]:
    """Extract normalised service names from CloudFormation resource types.

    Args:
        resource_types: List of resource types, e.g., ["AWS::S3::Bucket", "AWS::RDS::DBInstance"]

    Returns:
        List of normalised service names (deduplicated)
    """
    services: set[str] = set()
    for resource_type in resource_types:
        service = extract_service_from_resource_type(resource_type)
        if service:
            services.add(service)
    return sorted(services)


def extract_services_from_log_groups(log_groups: list[str]) -> list[str]:
    """Extract normalised service names from CloudWatch log group names.

    Args:
        log_groups: List of log group names

    Returns:
        List of normalised service names (deduplicated)
    """
    services: set[str] = set()
    for log_group in log_groups:
        service = extract_service_from_log_group(log_group)
        if service:
            services.add(service)
    return sorted(services)
