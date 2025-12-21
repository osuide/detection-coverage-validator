"""AWS Config Rule to MITRE ATT&CK mappings.

Based on official mappings from the MITRE Center for Threat-Informed Defense
Security Stack Mappings project.

Source: https://center-for-threat-informed-defense.github.io/security-stack-mappings/AWS/
GitHub: https://github.com/center-for-threat-informed-defense/security-stack-mappings

These mappings are based on ATT&CK v9.0+ and cover AWS Config managed rules.
"""

from typing import Optional


# AWS Config managed rule identifier to MITRE technique mappings
# Each rule maps to a list of (technique_id, confidence) tuples
# Confidence is based on MITRE's coverage assessment:
#   Significant = 0.8, Partial = 0.65, Minimal = 0.5

CONFIG_RULE_TECHNIQUES: dict[str, list[tuple[str, float]]] = {
    # === T1020 - Automated Exfiltration (Minimal) ===
    # SSL/TLS rules that protect data in transit
    "ACM_CERTIFICATE_EXPIRATION_CHECK": [
        ("T1020", 0.5),
        ("T1040", 0.65),
        ("T1557", 0.5),
    ],
    "ALB_HTTP_TO_HTTPS_REDIRECTION_CHECK": [
        ("T1020", 0.5),
        ("T1040", 0.65),
        ("T1557", 0.5),
    ],
    "API_GW_SSL_ENABLED": [("T1020", 0.5), ("T1040", 0.65), ("T1557", 0.5)],
    "CLOUDFRONT_CUSTOM_SSL_CERTIFICATE": [
        ("T1020", 0.5),
        ("T1040", 0.65),
        ("T1557", 0.5),
    ],
    "CLOUDFRONT_SNI_ENABLED": [("T1020", 0.5), ("T1040", 0.65), ("T1557", 0.5)],
    "CLOUDFRONT_VIEWER_POLICY_HTTPS": [("T1020", 0.5), ("T1040", 0.65), ("T1557", 0.5)],
    "ELB_ACM_CERTIFICATE_REQUIRED": [("T1020", 0.5), ("T1040", 0.65), ("T1557", 0.5)],
    "ELB_CUSTOM_SECURITY_POLICY_SSL_CHECK": [
        ("T1020", 0.5),
        ("T1040", 0.65),
        ("T1557", 0.5),
    ],
    "ELB_PREDEFINED_SECURITY_POLICY_SSL_CHECK": [
        ("T1020", 0.5),
        ("T1040", 0.65),
        ("T1557", 0.5),
    ],
    "ELB_TLS_HTTPS_LISTENERS_ONLY": [("T1020", 0.5), ("T1040", 0.65), ("T1557", 0.5)],
    "REDSHIFT_REQUIRE_TLS_SSL": [("T1020", 0.5), ("T1040", 0.65), ("T1557", 0.5)],
    "S3_BUCKET_SSL_REQUESTS_ONLY": [("T1020", 0.5), ("T1040", 0.65), ("T1557", 0.5)],
    "ELASTICSEARCH_NODE_TO_NODE_ENCRYPTION_CHECK": [
        ("T1020", 0.5),
        ("T1040", 0.65),
        ("T1557", 0.5),
    ],
    # === T1040 - Network Sniffing (Partial) ===
    # VPC and network isolation rules
    "API_GW_ENDPOINT_TYPE_CHECK": [("T1040", 0.65), ("T1190", 0.65)],
    "ELASTICSEARCH_IN_VPC_ONLY": [("T1040", 0.65), ("T1190", 0.65)],
    "REDSHIFT_ENHANCED_VPC_ROUTING_ENABLED": [("T1040", 0.65)],
    # === T1053 - Scheduled Task/Job (Minimal) ===
    "EKS_ENDPOINT_NO_PUBLIC_ACCESS": [
        ("T1053", 0.5),
        ("T1552", 0.65),
        ("T1609", 0.65),
        ("T1610", 0.65),
        ("T1613", 0.65),
    ],
    # === T1068 - Exploitation for Privilege Escalation (Partial) ===
    "EC2_MANAGEDINSTANCE_APPLICATIONS_BLACKLISTED": [
        ("T1068", 0.65),
        ("T1190", 0.65),
        ("T1203", 0.65),
        ("T1210", 0.65),
        ("T1211", 0.65),
        ("T1212", 0.65),
        ("T1562", 0.5),
    ],
    "EC2_MANAGEDINSTANCE_PLATFORM_CHECK": [
        ("T1068", 0.65),
        ("T1190", 0.65),
        ("T1203", 0.65),
        ("T1211", 0.65),
        ("T1212", 0.65),
    ],
    "ECS_TASK_DEFINITION_USER_FOR_HOST_MODE_CHECK": [("T1068", 0.65), ("T1611", 0.65)],
    # === T1078 - Valid Accounts (Minimal to Significant) ===
    # MFA rules - Significant coverage for brute force
    "IAM_USER_MFA_ENABLED": [
        ("T1078", 0.5),
        ("T1098", 0.5),
        ("T1110", 0.8),
        ("T1136", 0.5),
    ],
    "MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS": [
        ("T1078", 0.5),
        ("T1098", 0.5),
        ("T1110", 0.8),
        ("T1136", 0.5),
        ("T1538", 0.8),
    ],
    "ROOT_ACCOUNT_HARDWARE_MFA_ENABLED": [
        ("T1078", 0.5),
        ("T1098", 0.5),
        ("T1110", 0.8),
        ("T1136", 0.5),
    ],
    "ROOT_ACCOUNT_MFA_ENABLED": [
        ("T1078", 0.5),
        ("T1098", 0.5),
        ("T1110", 0.8),
        ("T1136", 0.5),
    ],
    # IAM policy rules
    "IAM_CUSTOMER_POLICY_BLOCKED_KMS_ACTIONS": [("T1078", 0.5)],
    "IAM_INLINE_POLICY_BLOCKED_KMS_ACTIONS": [("T1078", 0.5)],
    "IAM_NO_INLINE_POLICY_CHECK": [("T1078", 0.5)],
    "IAM_GROUP_HAS_USERS_CHECK": [("T1078", 0.5)],
    "IAM_POLICY_BLACKLISTED_CHECK": [("T1078", 0.5)],
    "IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS": [("T1078", 0.5)],
    "IAM_POLICY_NO_STATEMENTS_WITH_FULL_ACCESS": [("T1078", 0.5)],
    "IAM_ROLE_MANAGED_POLICY_CHECK": [("T1078", 0.5)],
    "IAM_USER_GROUP_MEMBERSHIP_CHECK": [("T1078", 0.5)],
    "IAM_USER_NO_POLICIES_CHECK": [("T1078", 0.5)],
    "EC2_INSTANCE_PROFILE_ATTACHED": [("T1078", 0.5)],
    "IAM_PASSWORD_POLICY": [("T1078", 0.5), ("T1110", 0.8)],
    "IAM_POLICY_IN_USE": [("T1078", 0.5)],
    "IAM_ROOT_ACCESS_KEY_CHECK": [("T1078", 0.5)],
    "IAM_USER_UNUSED_CREDENTIALS_CHECK": [("T1078", 0.5)],
    "ACCESS_KEYS_ROTATED": [("T1078", 0.5)],
    # === T1119 - Automated Collection (Minimal) ===
    "EC2_EBS_ENCRYPTION_BY_DEFAULT": [("T1119", 0.5), ("T1552", 0.65)],
    "ENCRYPTED_VOLUMES": [("T1119", 0.5), ("T1552", 0.65)],
    # === T1190 - Exploit Public-Facing Application (Partial) ===
    "LAMBDA_FUNCTION_PUBLIC_ACCESS_PROHIBITED": [("T1190", 0.65)],
    "EC2_INSTANCE_NO_PUBLIC_IP": [("T1190", 0.65), ("T1210", 0.65)],
    "RDS_AUTOMATIC_MINOR_VERSION_UPGRADE_ENABLED": [("T1190", 0.65)],
    "ELASTIC_BEANSTALK_MANAGED_UPDATES_ENABLED": [("T1190", 0.65)],
    # === T1204 - User Execution (Minimal) ===
    "APPROVED_AMIS_BY_ID": [("T1204", 0.5), ("T1525", 0.5)],
    "APPROVED_AMIS_BY_TAG": [("T1204", 0.5), ("T1525", 0.5)],
    # === T1485/T1486/T1491 - Data Destruction/Encryption/Defacement (Partial to Significant) ===
    # Backup and recovery rules
    "S3_BUCKET_BLACKLISTED_ACTIONS_PROHIBITED": [
        ("T1485", 0.65),
        ("T1486", 0.65),
        ("T1491", 0.8),
    ],
    "S3_BUCKET_DEFAULT_LOCK_ENABLED": [
        ("T1485", 0.65),
        ("T1486", 0.65),
        ("T1491", 0.8),
    ],
    "S3_BUCKET_PUBLIC_WRITE_PROHIBITED": [
        ("T1485", 0.65),
        ("T1486", 0.65),
        ("T1491", 0.8),
    ],
    "AURORA_MYSQL_BACKTRACKING_ENABLED": [
        ("T1485", 0.65),
        ("T1486", 0.65),
        ("T1491", 0.8),
    ],
    "DB_INSTANCE_BACKUP_ENABLED": [("T1485", 0.65), ("T1486", 0.65), ("T1491", 0.8)],
    "RDS_IN_BACKUP_PLAN": [("T1485", 0.65), ("T1486", 0.65), ("T1491", 0.8)],
    "DYNAMODB_IN_BACKUP_PLAN": [("T1485", 0.65), ("T1486", 0.65), ("T1491", 0.8)],
    "DYNAMODB_PITR_ENABLED": [("T1485", 0.65), ("T1486", 0.65), ("T1491", 0.8)],
    "EBS_IN_BACKUP_PLAN": [("T1485", 0.65), ("T1486", 0.65), ("T1491", 0.8)],
    "EFS_IN_BACKUP_PLAN": [("T1485", 0.65), ("T1486", 0.65), ("T1491", 0.8)],
    "ELASTICACHE_REDIS_CLUSTER_AUTOMATIC_BACKUP_CHECK": [
        ("T1485", 0.65),
        ("T1486", 0.65),
        ("T1491", 0.8),
    ],
    "REDSHIFT_BACKUP_ENABLED": [("T1485", 0.65), ("T1486", 0.65), ("T1491", 0.8)],
    "REDSHIFT_CLUSTER_MAINTENANCESETTINGS_CHECK": [
        ("T1485", 0.65),
        ("T1486", 0.65),
        ("T1491", 0.8),
        ("T1496", 0.65),
    ],
    "S3_BUCKET_REPLICATION_ENABLED": [("T1485", 0.65), ("T1486", 0.65), ("T1491", 0.8)],
    "S3_BUCKET_VERSIONING_ENABLED": [("T1485", 0.65), ("T1486", 0.65), ("T1491", 0.8)],
    "CLOUDFRONT_ORIGIN_FAILOVER_ENABLED": [
        ("T1485", 0.65),
        ("T1486", 0.65),
        ("T1491", 0.8),
        ("T1498", 0.5),
        ("T1499", 0.5),
    ],
    "ELB_DELETION_PROTECTION_ENABLED": [("T1485", 0.65)],
    "RDS_CLUSTER_DELETION_PROTECTION_ENABLED": [("T1485", 0.65)],
    "RDS_INSTANCE_DELETION_PROTECTION_ENABLED": [("T1485", 0.65)],
    # === T1496 - Resource Hijacking (Partial) ===
    "CLOUDWATCH_ALARM_ACTION_CHECK": [("T1496", 0.65)],
    "CLOUDWATCH_ALARM_RESOURCE_CHECK": [("T1496", 0.65)],
    "CLOUDWATCH_ALARM_SETTINGS_CHECK": [("T1496", 0.65)],
    "DESIRED_INSTANCE_TENANCY": [("T1496", 0.65)],
    "DESIRED_INSTANCE_TYPE": [("T1496", 0.65)],
    "DYNAMODB_AUTOSCALING_ENABLED": [("T1496", 0.65)],
    "DYNAMODB_THROUGHPUT_LIMIT_CHECK": [("T1496", 0.65)],
    "EC2_INSTANCE_DETAILED_MONITORING_ENABLED": [("T1496", 0.65)],
    "RDS_ENHANCED_MONITORING_ENABLED": [("T1496", 0.65)],
    # === T1498/T1499 - Network/Endpoint Denial of Service (Minimal) ===
    "ELB_CROSS_ZONE_LOAD_BALANCING_ENABLED": [("T1498", 0.5), ("T1499", 0.5)],
    # === T1530 - Data from Cloud Storage Object (Significant) ===
    # S3 access control rules
    "S3_ACCOUNT_LEVEL_PUBLIC_ACCESS_BLOCKS": [("T1530", 0.8), ("T1552", 0.65)],
    "S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED": [("T1530", 0.8), ("T1552", 0.65)],
    "S3_BUCKET_PUBLIC_READ_PROHIBITED": [("T1530", 0.8), ("T1552", 0.65)],
    "S3_BUCKET_POLICY_NOT_MORE_PERMISSIVE": [("T1530", 0.8), ("T1552", 0.65)],
    "CLOUDFRONT_ORIGIN_ACCESS_IDENTITY_ENABLED": [("T1530", 0.8), ("T1552", 0.65)],
    "CLOUDFRONT_DEFAULT_ROOT_OBJECT_CONFIGURED": [("T1530", 0.8), ("T1552", 0.65)],
    "S3_BUCKET_POLICY_GRANTEE_CHECK": [("T1530", 0.8), ("T1552", 0.65)],
    # Database access rules
    "DMS_REPLICATION_NOT_PUBLIC": [("T1530", 0.8)],
    "EMR_MASTER_NO_PUBLIC_IP": [("T1530", 0.8)],
    "RDS_CLUSTER_IAM_AUTHENTICATION_ENABLED": [("T1530", 0.8)],
    "RDS_INSTANCE_IAM_AUTHENTICATION_ENABLED": [("T1530", 0.8)],
    "RDS_INSTANCE_PUBLIC_ACCESS_CHECK": [("T1530", 0.8)],
    "RDS_SNAPSHOTS_PUBLIC_PROHIBITED": [("T1530", 0.8)],
    "REDSHIFT_CLUSTER_PUBLIC_ACCESS_CHECK": [("T1530", 0.8)],
    "SAGEMAKER_NOTEBOOK_NO_DIRECT_INTERNET_ACCESS": [("T1530", 0.8)],
    # Encryption rules for data at rest
    "DAX_ENCRYPTION_ENABLED": [("T1530", 0.8)],
    "DYNAMODB_TABLE_ENCRYPTED_KMS": [("T1530", 0.8)],
    "DYNAMODB_TABLE_ENCRYPTION_ENABLED": [("T1530", 0.8)],
    "EFS_ENCRYPTED_CHECK": [("T1530", 0.8)],
    "ELASTICSEARCH_ENCRYPTED_AT_REST": [("T1530", 0.8)],
    "RDS_SNAPSHOT_ENCRYPTED": [("T1530", 0.8)],
    "RDS_STORAGE_ENCRYPTED": [("T1530", 0.8)],
    "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED": [("T1530", 0.8), ("T1552", 0.65)],
    "S3_DEFAULT_ENCRYPTION_KMS": [("T1530", 0.8), ("T1552", 0.65)],
    "SNS_ENCRYPTED_KMS": [("T1530", 0.8)],
    "REDSHIFT_CLUSTER_CONFIGURATION_CHECK": [("T1530", 0.8), ("T1562", 0.5)],
    "REDSHIFT_CLUSTER_KMS_ENABLED": [("T1530", 0.8)],
    "SAGEMAKER_ENDPOINT_CONFIGURATION_KMS_KEY_CONFIGURED": [("T1530", 0.8)],
    "SAGEMAKER_NOTEBOOK_INSTANCE_KMS_KEY_CONFIGURED": [("T1530", 0.8)],
    # === T1552 - Unsecured Credentials (Partial) ===
    "CODEBUILD_PROJECT_ENVVAR_AWSCRED_CHECK": [("T1552", 0.65)],
    "CODEBUILD_PROJECT_SOURCE_REPO_URL_CHECK": [("T1552", 0.65)],
    "SECRETSMANAGER_ROTATION_ENABLED_CHECK": [("T1552", 0.65)],
    "SECRETSMANAGER_SCHEDULED_ROTATION_SUCCESS_CHECK": [("T1552", 0.65)],
    "SECRETSMANAGER_SECRET_PERIODIC_ROTATION": [("T1552", 0.65)],
    "SECRETSMANAGER_USING_CMK": [("T1552", 0.65)],
    "EC2_IMDSV2_CHECK": [("T1552", 0.65)],
    "EKS_SECRETS_ENCRYPTED": [("T1552", 0.65)],
    # === T1562 - Impair Defenses (Minimal to Partial) ===
    # Security group and firewall rules
    "VPC_DEFAULT_SECURITY_GROUP_CLOSED": [("T1562", 0.65)],
    "VPC_NETWORK_ACL_UNUSED_CHECK": [("T1562", 0.65)],
    "VPC_SG_OPEN_ONLY_TO_AUTHORIZED_PORTS": [("T1562", 0.65)],
    "EC2_SECURITY_GROUP_ATTACHED_TO_ENI": [("T1562", 0.65)],
    "INTERNET_GATEWAY_AUTHORIZED_VPC_ONLY": [("T1562", 0.65)],
    "LAMBDA_INSIDE_VPC": [("T1562", 0.65)],
    "SERVICE_VPC_ENDPOINT_ENABLED": [("T1562", 0.65)],
    "SUBNET_AUTO_ASSIGN_PUBLIC_IP_DISABLED": [("T1562", 0.65)],
    # WAF rules
    "ALB_WAF_ENABLED": [("T1562", 0.65)],
    "API_GW_ASSOCIATED_WITH_WAF": [("T1562", 0.65)],
    "CLOUDFRONT_ASSOCIATED_WITH_WAF": [("T1562", 0.65)],
    "FMS_WEBACL_RESOURCE_POLICY_CHECK": [("T1562", 0.65)],
    "FMS_WEBACL_RULEGROUP_ASSOCIATION_CHECK": [("T1562", 0.65)],
    # Logging rules
    "API_GW_EXECUTION_LOGGING_ENABLED": [("T1562", 0.65)],
    "CLOUDFRONT_ACCESSLOGS_ENABLED": [("T1562", 0.65)],
    "ELASTICSEARCH_LOGS_TO_CLOUDWATCH": [("T1562", 0.65)],
    "ELB_LOGGING_ENABLED": [("T1562", 0.65)],
    "RDS_LOGGING_ENABLED": [("T1562", 0.65)],
    "S3_BUCKET_LOGGING_ENABLED": [("T1562", 0.65)],
    "CLOUDTRAIL_SECURITY_TRAIL_ENABLED": [("T1562", 0.65)],
    "CLOUD_TRAIL_CLOUD_WATCH_LOGS_ENABLED": [("T1562", 0.65)],
    "CLOUDTRAIL_S3_DATAEVENTS_ENABLED": [("T1562", 0.65)],
    "VPC_FLOW_LOGS_ENABLED": [("T1562", 0.65)],
    "WAF_CLASSIC_LOGGING_ENABLED": [("T1562", 0.65)],
    "WAFV2_LOGGING_ENABLED": [("T1562", 0.65)],
    # Other defense rules
    "EC2_MANAGEDINSTANCE_APPLICATIONS_REQUIRED": [("T1562", 0.5)],
    # === Additional Common Rules ===
    # Security group restriction rules (similar to vpc-sg-open-only-to-authorized-ports)
    "RESTRICTED_COMMON_PORTS": [("T1562", 0.65)],
    "RESTRICTED_INCOMING_TRAFFIC": [("T1562", 0.65)],
    "INCOMING_SSH_DISABLED": [("T1562", 0.65)],
    "NACL_NO_UNRESTRICTED_SSH_RDP": [("T1562", 0.65)],
    # CloudTrail rules
    "CLOUDTRAIL_ENABLED": [("T1562", 0.65)],
    "CLOUDTRAIL_ENCRYPTION_ENABLED": [("T1562", 0.65)],
    "MULTI_REGION_CLOUDTRAIL_ENABLED": [("T1562", 0.65)],
    # GuardDuty and Security Hub
    "GUARDDUTY_ENABLED_CENTRALIZED": [("T1562", 0.65)],
    "GUARDDUTY_NON_ARCHIVED_FINDINGS": [("T1562", 0.65)],
    "SECURITYHUB_ENABLED": [("T1562", 0.65)],
    # KMS rules
    "CMK_BACKING_KEY_ROTATION_ENABLED": [("T1486", 0.65)],
    "KMS_CMK_NOT_SCHEDULED_FOR_DELETION": [("T1486", 0.65)],
    # CloudWatch rules
    "CLOUDWATCH_LOG_GROUP_ENCRYPTED": [("T1562", 0.65)],
    "CW_LOGGROUP_RETENTION_PERIOD_CHECK": [("T1562", 0.65)],
    # EBS rules
    "EBS_SNAPSHOT_PUBLIC_RESTORABLE_CHECK": [("T1530", 0.8)],
}


def get_techniques_for_config_rule(
    source_identifier: str,
    rule_name: Optional[str] = None,
) -> list[tuple[str, float]]:
    """Get MITRE technique mappings for an AWS Config rule.

    Args:
        source_identifier: The AWS Config rule source identifier (e.g., 'INCOMING_SSH_DISABLED')
        rule_name: Optional rule name for additional matching

    Returns:
        List of (technique_id, confidence) tuples
    """
    techniques = []

    # Normalise identifiers to uppercase
    source_upper = source_identifier.upper() if source_identifier else ""
    name_upper = rule_name.upper() if rule_name else ""

    # Try exact match on source_identifier first
    if source_upper in CONFIG_RULE_TECHNIQUES:
        techniques.extend(CONFIG_RULE_TECHNIQUES[source_upper])

    # Also try normalised versions (with underscores)
    normalised = source_upper.replace("-", "_")
    if normalised != source_upper and normalised in CONFIG_RULE_TECHNIQUES:
        for tech in CONFIG_RULE_TECHNIQUES[normalised]:
            if tech not in techniques:
                techniques.append(tech)

    # If no match and we have a rule name, try partial matching on known patterns
    if not techniques and name_upper:
        for rule_id, techs in CONFIG_RULE_TECHNIQUES.items():
            # Check if the rule ID pattern appears in the name
            if rule_id.replace("_", "-") in name_upper.replace("_", "-"):
                for tech in techs:
                    if tech not in techniques:
                        techniques.append(tech)

    return techniques


def get_all_mapped_rules() -> list[str]:
    """Get list of all Config rules that have MITRE mappings."""
    return list(CONFIG_RULE_TECHNIQUES.keys())
