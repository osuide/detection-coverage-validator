"""Service registry for AWS and GCP service classification.

This module provides the authoritative list of global vs regional services
for proper multi-region scanning. Global services are scanned once from
a designated region, while regional services are scanned per-region.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class ServiceInfo:
    """Information about a cloud service's regional behaviour."""

    name: str
    is_global: bool = False
    endpoint_region: Optional[str] = None  # For global services
    multi_region: bool = True  # For regional services


# =============================================================================
# AWS Services
# =============================================================================

# AWS Global Services - Scan once from designated region
# Source: https://docs.aws.amazon.com/whitepapers/latest/aws-fault-isolation-boundaries/global-services.html
AWS_GLOBAL_SERVICES: dict[str, ServiceInfo] = {
    # Partitional services with control plane in us-east-1
    "iam": ServiceInfo(
        name="IAM",
        is_global=True,
        endpoint_region="us-east-1",
    ),
    "organizations": ServiceInfo(
        name="Organizations",
        is_global=True,
        endpoint_region="us-east-1",
    ),
    "account-management": ServiceInfo(
        name="Account Management",
        is_global=True,
        endpoint_region="us-east-1",
    ),
    "route53-private": ServiceInfo(
        name="Route 53 Private DNS",
        is_global=True,
        endpoint_region="us-east-1",
    ),
    # Global Edge Network services with control plane in us-east-1
    "route53": ServiceInfo(
        name="Route 53 Public DNS",
        is_global=True,
        endpoint_region="us-east-1",
    ),
    "cloudfront": ServiceInfo(
        name="CloudFront",
        is_global=True,
        endpoint_region="us-east-1",
    ),
    "waf-cloudfront": ServiceInfo(
        name="WAF (CloudFront distributions)",
        is_global=True,
        endpoint_region="us-east-1",
    ),
    "acm-cloudfront": ServiceInfo(
        name="ACM for CloudFront",
        is_global=True,
        endpoint_region="us-east-1",
    ),
    "shield-advanced": ServiceInfo(
        name="Shield Advanced",
        is_global=True,
        endpoint_region="us-east-1",
    ),
    # Partitional services with control plane in us-west-2
    "global-accelerator": ServiceInfo(
        name="Global Accelerator",
        is_global=True,
        endpoint_region="us-west-2",
    ),
    "network-manager": ServiceInfo(
        name="Network Manager",
        is_global=True,
        endpoint_region="us-west-2",
    ),
    "route53-arc": ServiceInfo(
        name="Route 53 Application Recovery Controller",
        is_global=True,
        endpoint_region="us-west-2",
    ),
}

# AWS Regional Services - Scan per region
# Source: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_regions.html
# AWS recommends enabling GuardDuty in all supported regions for comprehensive coverage
AWS_REGIONAL_SERVICES: dict[str, ServiceInfo] = {
    "guardduty": ServiceInfo(
        name="GuardDuty",
        is_global=False,
        multi_region=True,
    ),
    "cloudwatch-logs": ServiceInfo(
        name="CloudWatch Logs",
        is_global=False,
        multi_region=True,
    ),
    "cloudwatch-logs-insights": ServiceInfo(
        name="CloudWatch Logs Insights",
        is_global=False,
        multi_region=True,
    ),
    "eventbridge": ServiceInfo(
        name="EventBridge",
        is_global=False,
        multi_region=True,
    ),
    "config": ServiceInfo(
        name="AWS Config",
        is_global=False,
        multi_region=True,
    ),
    "securityhub": ServiceInfo(
        name="Security Hub",
        is_global=False,
        multi_region=True,
    ),
    "lambda": ServiceInfo(
        name="Lambda",
        is_global=False,
        multi_region=True,
    ),
    "waf-regional": ServiceInfo(
        name="WAF (Regional/ALB)",
        is_global=False,
        multi_region=True,
    ),
    "ec2": ServiceInfo(
        name="EC2",
        is_global=False,
        multi_region=True,
    ),
    "s3": ServiceInfo(
        name="S3",
        is_global=False,
        multi_region=True,
    ),
    "rds": ServiceInfo(
        name="RDS",
        is_global=False,
        multi_region=True,
    ),
    "cloudtrail": ServiceInfo(
        name="CloudTrail",
        is_global=False,
        multi_region=True,
    ),
    "inspector": ServiceInfo(
        name="Inspector",
        is_global=False,
        multi_region=True,
    ),
    "macie": ServiceInfo(
        name="Macie",
        is_global=False,
        multi_region=True,
    ),
    "detective": ServiceInfo(
        name="Detective",
        is_global=False,
        multi_region=True,
    ),
}


# =============================================================================
# GCP Services
# =============================================================================

# GCP Global/Organisation-level Services
# Source: https://docs.cloud.google.com/compute/docs/regions-zones/global-regional-zonal-resources
# Source: https://docs.cloud.google.com/logging/docs/region-support
# Note: GCP has a different model than AWS - many services operate at project/org level
# with optional regional data residency for compliance
GCP_GLOBAL_SERVICES: dict[str, ServiceInfo] = {
    # Security Command Center - centralized platform with optional regional endpoints
    # Source: https://docs.cloud.google.com/security-command-center/docs/security-command-center-overview
    "security-command-center": ServiceInfo(
        name="Security Command Center",
        is_global=True,
        endpoint_region="global",  # Can use regional endpoints for data residency
    ),
    # Cloud Logging - default buckets are global, but can create regional buckets
    # Source: https://docs.cloud.google.com/logging/docs/region-support
    "cloud-logging": ServiceInfo(
        name="Cloud Logging",
        is_global=True,
        endpoint_region="global",  # _Required and _Default buckets are global
    ),
    # Organisation-level services
    "org-policy": ServiceInfo(
        name="Organisation Policy",
        is_global=True,
        endpoint_region="global",
    ),
    "iam": ServiceInfo(
        name="IAM",
        is_global=True,
        endpoint_region="global",
    ),
    "resource-manager": ServiceInfo(
        name="Resource Manager",
        is_global=True,
        endpoint_region="global",
    ),
    "access-context-manager": ServiceInfo(
        name="Access Context Manager",
        is_global=True,
        endpoint_region="global",
    ),
    # Chronicle SIEM - typically organisation-scoped
    "chronicle": ServiceInfo(
        name="Chronicle SIEM",
        is_global=True,
        endpoint_region="global",
    ),
}

# GCP Regional Services
# Source: https://docs.cloud.google.com/compute/docs/regions-zones/global-regional-zonal-resources
GCP_REGIONAL_SERVICES: dict[str, ServiceInfo] = {
    "eventarc": ServiceInfo(
        name="Eventarc",
        is_global=False,
        multi_region=True,
    ),
    "cloud-functions": ServiceInfo(
        name="Cloud Functions",
        is_global=False,
        multi_region=True,
    ),
    "cloud-run": ServiceInfo(
        name="Cloud Run",
        is_global=False,
        multi_region=True,
    ),
    "compute": ServiceInfo(
        name="Compute Engine",
        is_global=False,
        multi_region=True,
    ),
    "gke": ServiceInfo(
        name="Google Kubernetes Engine",
        is_global=False,
        multi_region=True,
    ),
    "cloud-sql": ServiceInfo(
        name="Cloud SQL",
        is_global=False,
        multi_region=True,
    ),
    # Regional log buckets (distinct from global default buckets)
    "cloud-logging-regional": ServiceInfo(
        name="Cloud Logging (Regional Buckets)",
        is_global=False,
        multi_region=True,
    ),
}


# =============================================================================
# Standard Region Lists
# =============================================================================

# AWS Regions (as of late 2024)
AWS_REGIONS = [
    # US
    "us-east-1",  # N. Virginia
    "us-east-2",  # Ohio
    "us-west-1",  # N. California
    "us-west-2",  # Oregon
    # Europe
    "eu-west-1",  # Ireland
    "eu-west-2",  # London
    "eu-west-3",  # Paris
    "eu-central-1",  # Frankfurt
    "eu-central-2",  # Zurich
    "eu-north-1",  # Stockholm
    "eu-south-1",  # Milan
    "eu-south-2",  # Spain
    # Asia Pacific
    "ap-northeast-1",  # Tokyo
    "ap-northeast-2",  # Seoul
    "ap-northeast-3",  # Osaka
    "ap-southeast-1",  # Singapore
    "ap-southeast-2",  # Sydney
    "ap-southeast-3",  # Jakarta
    "ap-southeast-4",  # Melbourne
    "ap-south-1",  # Mumbai
    "ap-south-2",  # Hyderabad
    "ap-east-1",  # Hong Kong
    # Americas
    "ca-central-1",  # Canada (Central)
    "ca-west-1",  # Canada (Calgary)
    "sa-east-1",  # Sao Paulo
    # Middle East & Africa
    "me-south-1",  # Bahrain
    "me-central-1",  # UAE
    "af-south-1",  # Cape Town
    "il-central-1",  # Tel Aviv
]

# AWS Regions commonly enabled by default (non-opt-in regions)
AWS_DEFAULT_REGIONS = [
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "eu-central-1",
    "eu-north-1",
    "ap-northeast-1",
    "ap-northeast-2",
    "ap-northeast-3",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-south-1",
    "ca-central-1",
    "sa-east-1",
]

# GCP Regions (as of late 2024)
GCP_REGIONS = [
    # US
    "us-central1",  # Iowa
    "us-east1",  # South Carolina
    "us-east4",  # N. Virginia
    "us-east5",  # Columbus
    "us-south1",  # Dallas
    "us-west1",  # Oregon
    "us-west2",  # Los Angeles
    "us-west3",  # Salt Lake City
    "us-west4",  # Las Vegas
    # Europe
    "europe-west1",  # Belgium
    "europe-west2",  # London
    "europe-west3",  # Frankfurt
    "europe-west4",  # Netherlands
    "europe-west6",  # Zurich
    "europe-west8",  # Milan
    "europe-west9",  # Paris
    "europe-west10",  # Berlin
    "europe-west12",  # Turin
    "europe-north1",  # Finland
    "europe-central2",  # Warsaw
    "europe-southwest1",  # Madrid
    # Asia Pacific
    "asia-east1",  # Taiwan
    "asia-east2",  # Hong Kong
    "asia-northeast1",  # Tokyo
    "asia-northeast2",  # Osaka
    "asia-northeast3",  # Seoul
    "asia-south1",  # Mumbai
    "asia-south2",  # Delhi
    "asia-southeast1",  # Singapore
    "asia-southeast2",  # Jakarta
    # Australia
    "australia-southeast1",  # Sydney
    "australia-southeast2",  # Melbourne
    # Americas
    "northamerica-northeast1",  # Montreal
    "northamerica-northeast2",  # Toronto
    "southamerica-east1",  # Sao Paulo
    "southamerica-west1",  # Santiago
    # Middle East & Africa
    "me-west1",  # Tel Aviv
    "me-central1",  # Doha
    "me-central2",  # Dammam
    "africa-south1",  # Johannesburg
]


# =============================================================================
# Helper Functions
# =============================================================================


def is_global_service(provider: str, service_key: str) -> bool:
    """Check if a service is global (non-regional).

    Args:
        provider: "aws" or "gcp"
        service_key: Service identifier (e.g., "guardduty", "iam")

    Returns:
        True if the service is global, False if regional
    """
    if provider.lower() == "aws":
        return service_key in AWS_GLOBAL_SERVICES
    elif provider.lower() == "gcp":
        return service_key in GCP_GLOBAL_SERVICES
    return False


def get_global_service_region(provider: str, service_key: str) -> Optional[str]:
    """Get the endpoint region for a global service.

    Args:
        provider: "aws" or "gcp"
        service_key: Service identifier

    Returns:
        Region to use for global service API calls, or None if not a global service
    """
    if provider.lower() == "aws":
        service = AWS_GLOBAL_SERVICES.get(service_key)
        if service:
            return service.endpoint_region
    elif provider.lower() == "gcp":
        service = GCP_GLOBAL_SERVICES.get(service_key)
        if service:
            return service.endpoint_region
    return None


def get_all_regions(provider: str) -> list[str]:
    """Get all available regions for a provider.

    Args:
        provider: "aws" or "gcp"

    Returns:
        List of all region codes
    """
    if provider.lower() == "aws":
        return AWS_REGIONS.copy()
    elif provider.lower() == "gcp":
        return GCP_REGIONS.copy()
    return []


def get_default_regions(provider: str) -> list[str]:
    """Get default (commonly enabled) regions for a provider.

    Args:
        provider: "aws" or "gcp"

    Returns:
        List of default region codes
    """
    if provider.lower() == "aws":
        return AWS_DEFAULT_REGIONS.copy()
    elif provider.lower() == "gcp":
        # GCP doesn't have opt-in regions, return first few common ones
        return GCP_REGIONS[:10]
    return []
