"""AWS Config Rules scanner for compliance-based detections."""

from typing import Any, Optional
from botocore.exceptions import ClientError

from app.models.detection import DetectionType
from app.scanners.base import BaseScanner, RawDetection


class ConfigRulesScanner(BaseScanner):
    """Scanner for AWS Config Rules.

    AWS Config Rules provide continuous compliance monitoring and can
    detect security misconfigurations. This scanner discovers:
    - Managed AWS Config Rules
    - Custom Config Rules (Lambda-based)
    - Conformance pack rules
    """

    @property
    def detection_type(self) -> DetectionType:
        return DetectionType.CONFIG_RULE

    async def scan(
        self,
        regions: list[str],
        options: Optional[dict[str, Any]] = None,
    ) -> list[RawDetection]:
        """Scan all regions for AWS Config Rules."""
        all_detections = []

        for region in regions:
            try:
                region_detections = await self.scan_region(region, options)
                all_detections.extend(region_detections)
            except ClientError as e:
                self.logger.warning("config_scan_error", region=region, error=str(e))

        return all_detections

    async def scan_region(
        self,
        region: str,
        options: Optional[dict[str, Any]] = None,
    ) -> list[RawDetection]:
        """Scan a single region for Config Rules."""
        detections = []
        client = self.session.client("config", region_name=region)

        try:
            # List all Config Rules
            paginator = client.get_paginator("describe_config_rules")

            for page in paginator.paginate():
                for rule in page.get("ConfigRules", []):
                    detection = self._parse_config_rule(rule, region)
                    if detection:
                        detections.append(detection)

        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDeniedException":
                self.logger.warning("config_access_denied", region=region)
            elif (
                e.response["Error"]["Code"]
                == "NoAvailableConfigurationRecorderException"
            ):
                # Config not enabled in this region
                self.logger.info("config_not_enabled", region=region)
            else:
                raise

        return detections

    def _parse_config_rule(
        self,
        rule: dict,
        region: str,
    ) -> Optional[RawDetection]:
        """Parse a Config Rule into a RawDetection."""
        rule_name = rule.get("ConfigRuleName", "")
        rule_arn = rule.get("ConfigRuleArn", "")
        rule_state = rule.get("ConfigRuleState", "ACTIVE")

        # Determine if managed or custom
        source = rule.get("Source", {})
        source_identifier = source.get("SourceIdentifier", "")
        owner = source.get("Owner", "")
        is_managed = owner == "AWS"

        # Get rule scope (what resources it monitors)
        scope = rule.get("Scope", {})
        compliance_resource_types = scope.get("ComplianceResourceTypes", [])

        # Get input parameters
        input_parameters = rule.get("InputParameters", "{}")

        # Build description
        description = rule.get("Description", "")
        if not description and is_managed:
            description = self._get_managed_rule_description(source_identifier)

        return RawDetection(
            name=rule_name,
            detection_type=DetectionType.CONFIG_RULE,
            source_arn=rule_arn,
            region=region,
            raw_config={
                "rule_name": rule_name,
                "rule_arn": rule_arn,
                "rule_id": rule.get("ConfigRuleId"),
                "rule_state": rule_state,
                "owner": owner,
                "source_identifier": source_identifier,
                "source_details": source.get("SourceDetails", []),
                "scope": scope,
                "compliance_resource_types": compliance_resource_types,
                "input_parameters": input_parameters,
                "maximum_execution_frequency": rule.get("MaximumExecutionFrequency"),
                "evaluation_modes": rule.get("EvaluationModes", []),
            },
            description=description,
            is_managed=is_managed,
        )

    def _get_managed_rule_description(self, source_identifier: str) -> str:
        """Get description for AWS managed Config Rules."""
        managed_rules = {
            # Security-focused Config Rules
            "ACCESS_KEYS_ROTATED": "Checks whether access keys are rotated within the number of days specified",
            "ACCOUNT_PART_OF_ORGANIZATIONS": "Checks whether the AWS account is part of AWS Organizations",
            "ACM_CERTIFICATE_EXPIRATION_CHECK": "Checks if ACM certificates in your account are marked for expiration",
            "ALB_HTTP_DROP_INVALID_HEADER_ENABLED": "Checks if Application Load Balancer is configured to drop invalid HTTP headers",
            "ALB_HTTP_TO_HTTPS_REDIRECTION_CHECK": "Checks if HTTP to HTTPS redirection is configured on ALB",
            "ALB_WAF_ENABLED": "Checks if WAF is enabled on Application Load Balancers",
            "API_GW_ASSOCIATED_WITH_WAF": "Checks if API Gateway stage is associated with WAF Web ACL",
            "API_GW_CACHE_ENABLED_AND_ENCRYPTED": "Checks if API Gateway stages have cache enabled and encrypted",
            "API_GW_EXECUTION_LOGGING_ENABLED": "Checks if API Gateway stages have execution logging enabled",
            "API_GW_SSL_ENABLED": "Checks if API Gateway REST API stages have SSL certificates configured",
            "APPROVED_AMIS_BY_ID": "Checks whether running instances are using specified AMIs",
            "APPROVED_AMIS_BY_TAG": "Checks whether running instances are using specified tagged AMIs",
            "AUTOSCALING_GROUP_ELB_HEALTHCHECK_REQUIRED": "Checks if Auto Scaling groups use ELB health checks",
            "AUTOSCALING_LAUNCH_CONFIG_PUBLIC_IP_DISABLED": "Checks if Auto Scaling group launch configurations have public IP disabled",
            "CLOUDFORMATION_STACK_DRIFT_DETECTION_CHECK": "Checks if CloudFormation stacks have drift detection",
            "CLOUDFORMATION_STACK_NOTIFICATION_CHECK": "Checks if CloudFormation stacks have SNS topic configured",
            "CLOUDFRONT_ACCESSLOGS_ENABLED": "Checks if CloudFront distributions have logging enabled",
            "CLOUDFRONT_ASSOCIATED_WITH_WAF": "Checks if CloudFront distributions are associated with WAF",
            "CLOUDFRONT_CUSTOM_SSL_CERTIFICATE": "Checks if CloudFront distributions use custom SSL certificate",
            "CLOUDFRONT_DEFAULT_ROOT_OBJECT_CONFIGURED": "Checks if CloudFront distributions have a default root object",
            "CLOUDFRONT_ORIGIN_ACCESS_IDENTITY_ENABLED": "Checks if CloudFront distributions have origin access identity enabled",
            "CLOUDFRONT_ORIGIN_FAILOVER_ENABLED": "Checks if CloudFront distributions have origin failover configured",
            "CLOUDFRONT_SNI_ENABLED": "Checks if CloudFront distributions use SNI to serve HTTPS requests",
            "CLOUDFRONT_VIEWER_POLICY_HTTPS": "Checks if CloudFront distributions use HTTPS viewer protocol",
            "CLOUDTRAIL_CLOUDWATCH_LOGS_ENABLED": "Checks if CloudTrail logs are delivered to CloudWatch Logs",
            "CLOUDTRAIL_ENABLED": "Checks if CloudTrail is enabled in your AWS account",
            "CLOUDTRAIL_ENCRYPTION_ENABLED": "Checks if CloudTrail logs are encrypted at rest using KMS",
            "CLOUDTRAIL_S3_DATAEVENTS_ENABLED": "Checks if CloudTrail S3 data events are enabled",
            "CLOUDTRAIL_SECURITY_TRAIL_ENABLED": "Checks if at least one CloudTrail trail has a security best practices trail",
            "CLOUDWATCH_ALARM_ACTION_CHECK": "Checks if CloudWatch alarms have at least one alarm action",
            "CLOUDWATCH_ALARM_ACTION_ENABLED_CHECK": "Checks if CloudWatch alarms have actions enabled",
            "CLOUDWATCH_ALARM_RESOURCE_CHECK": "Checks if CloudWatch alarms have resources configured",
            "CLOUDWATCH_ALARM_SETTINGS_CHECK": "Checks if CloudWatch alarms have valid settings",
            "CLOUDWATCH_LOG_GROUP_ENCRYPTED": "Checks if CloudWatch Log Groups are encrypted with KMS",
            "CMK_BACKING_KEY_ROTATION_ENABLED": "Checks if automatic key rotation is enabled for customer master keys",
            "CW_LOGGROUP_RETENTION_PERIOD_CHECK": "Checks if CloudWatch Log Groups have retention period set",
            "DB_INSTANCE_BACKUP_ENABLED": "Checks if RDS DB instances have backup enabled",
            "DMS_REPLICATION_NOT_PUBLIC": "Checks if DMS replication instances are not public",
            "DYNAMODB_AUTOSCALING_ENABLED": "Checks if DynamoDB tables have Auto Scaling enabled",
            "DYNAMODB_IN_BACKUP_PLAN": "Checks if DynamoDB tables are in a backup plan",
            "DYNAMODB_PITR_ENABLED": "Checks if DynamoDB Point-in-Time Recovery is enabled",
            "DYNAMODB_TABLE_ENCRYPTED_KMS": "Checks if DynamoDB tables are encrypted with KMS",
            "DYNAMODB_TABLE_ENCRYPTION_ENABLED": "Checks if DynamoDB table encryption is enabled",
            "EBS_ENCRYPTED_VOLUMES": "Checks if EBS volumes are encrypted",
            "EBS_IN_BACKUP_PLAN": "Checks if EBS volumes are in a backup plan",
            "EBS_OPTIMIZED_INSTANCE": "Checks if EBS optimization is enabled for EC2 instances",
            "EBS_SNAPSHOT_PUBLIC_RESTORABLE_CHECK": "Checks if EBS snapshots are not publicly restorable",
            "EC2_EBS_ENCRYPTION_BY_DEFAULT": "Checks if EBS encryption is enabled by default",
            "EC2_IMDSV2_CHECK": "Checks if EC2 instances use IMDSv2",
            "EC2_INSTANCE_DETAILED_MONITORING_ENABLED": "Checks if detailed monitoring is enabled for EC2 instances",
            "EC2_INSTANCE_MANAGED_BY_SSM": "Checks if EC2 instances are managed by AWS Systems Manager",
            "EC2_INSTANCE_NO_PUBLIC_IP": "Checks if EC2 instances have public IP addresses",
            "EC2_INSTANCE_PROFILE_ATTACHED": "Checks if EC2 instances have an IAM instance profile attached",
            "EC2_MANAGEDINSTANCE_ASSOCIATION_COMPLIANCE_STATUS_CHECK": "Checks managed instance association compliance",
            "EC2_MANAGEDINSTANCE_PATCH_COMPLIANCE_STATUS_CHECK": "Checks managed instance patch compliance",
            "EC2_SECURITY_GROUP_ATTACHED_TO_ENI": "Checks if security groups are attached to ENIs",
            "EC2_SECURITY_GROUP_ATTACHED_TO_ENI_PERIODIC": "Checks periodically if security groups are attached to ENIs",
            "EC2_STOPPED_INSTANCE": "Checks for EC2 instances that have been stopped for more than allowed days",
            "EC2_VOLUME_INUSE_CHECK": "Checks if EBS volumes are attached to EC2 instances",
            "ECR_PRIVATE_IMAGE_SCANNING_ENABLED": "Checks if ECR private repositories have image scanning enabled",
            "ECR_PRIVATE_LIFECYCLE_POLICY_CONFIGURED": "Checks if ECR private repositories have lifecycle policies",
            "ECR_PRIVATE_TAG_IMMUTABILITY_ENABLED": "Checks if ECR private repositories have tag immutability enabled",
            "ECS_AWSVPC_NETWORKING_ENABLED": "Checks if ECS task definitions use awsvpc networking mode",
            "ECS_CONTAINERS_NONPRIVILEGED": "Checks if ECS containers are non-privileged",
            "ECS_CONTAINERS_READONLY_ACCESS": "Checks if ECS containers have read-only access to root filesystem",
            "ECS_FARGATE_LATEST_PLATFORM_VERSION": "Checks if ECS Fargate services use latest platform version",
            "ECS_NO_ENVIRONMENT_SECRETS": "Checks if ECS task definitions don't have secrets in environment variables",
            "ECS_TASK_DEFINITION_LOG_CONFIGURATION": "Checks if ECS task definitions have log configuration",
            "ECS_TASK_DEFINITION_MEMORY_HARD_LIMIT": "Checks if ECS task definitions have memory hard limits",
            "ECS_TASK_DEFINITION_NONROOT_USER": "Checks if ECS task definitions run as non-root user",
            "ECS_TASK_DEFINITION_PID_MODE_CHECK": "Checks if ECS task definitions use host PID mode",
            "ECS_TASK_DEFINITION_USER_FOR_HOST_MODE_CHECK": "Checks if ECS task definitions use root user with host networking",
            "EFS_ENCRYPTED_CHECK": "Checks if EFS file systems are encrypted",
            "EFS_IN_BACKUP_PLAN": "Checks if EFS file systems are in a backup plan",
            "EIP_ATTACHED": "Checks if all EIPs are attached to EC2 instances or NAT gateways",
            "ELASTICSEARCH_ENCRYPTED_AT_REST": "Checks if Elasticsearch domains are encrypted at rest",
            "ELASTICSEARCH_IN_VPC_ONLY": "Checks if Elasticsearch domains are in a VPC",
            "ELASTICSEARCH_NODE_TO_NODE_ENCRYPTION_CHECK": "Checks if Elasticsearch domains have node-to-node encryption",
            "ELB_ACM_CERTIFICATE_REQUIRED": "Checks if ELB uses ACM certificates",
            "ELB_CROSS_ZONE_LOAD_BALANCING_ENABLED": "Checks if cross-zone load balancing is enabled for Classic Load Balancer",
            "ELB_CUSTOM_SECURITY_POLICY_SSL_CHECK": "Checks if Classic Load Balancer uses custom SSL/TLS cipher suite",
            "ELB_DELETION_PROTECTION_ENABLED": "Checks if ELB deletion protection is enabled",
            "ELB_LOGGING_ENABLED": "Checks if ELB access logging is enabled",
            "ELB_PREDEFINED_SECURITY_POLICY_SSL_CHECK": "Checks if Classic Load Balancer uses predefined security policy",
            "ELB_TLS_HTTPS_LISTENERS_ONLY": "Checks if Classic Load Balancer uses HTTPS/TLS listeners",
            "ELBV2_ACM_CERTIFICATE_REQUIRED": "Checks if ALB/NLB uses ACM certificate",
            "ELBV2_MULTIPLE_AZ": "Checks if ALB/NLB is configured across multiple AZs",
            "EMR_KERBEROS_ENABLED": "Checks if EMR clusters have Kerberos enabled",
            "EMR_MASTER_NO_PUBLIC_IP": "Checks if EMR cluster master nodes have public IPs",
            "ENCRYPTED_VOLUMES": "Checks if attached EBS volumes are encrypted",
            "FMS_SHIELD_RESOURCE_POLICY_CHECK": "Checks if Shield Advanced protections are in place",
            "FMS_WEBACL_RESOURCE_POLICY_CHECK": "Checks if WAF Web ACL is applied to resources",
            "FMS_WEBACL_RULEGROUP_ASSOCIATION_CHECK": "Checks if WAF Web ACL has associated rule groups",
            "GUARDDUTY_ENABLED_CENTRALIZED": "Checks if GuardDuty is enabled in your AWS account",
            "GUARDDUTY_NON_ARCHIVED_FINDINGS": "Checks if GuardDuty has non-archived findings",
            "IAM_CUSTOMER_POLICY_BLOCKED_KMS_ACTIONS": "Checks if IAM customer policies allow KMS decryption without constraints",
            "IAM_GROUP_HAS_USERS_CHECK": "Checks if IAM groups have at least one user",
            "IAM_INLINE_POLICY_BLOCKED_KMS_ACTIONS": "Checks if IAM inline policies allow KMS decryption without constraints",
            "IAM_NO_INLINE_POLICY_CHECK": "Checks if IAM users, roles, or groups have inline policies",
            "IAM_PASSWORD_POLICY": "Checks if IAM password policy meets requirements",
            "IAM_POLICY_BLACKLISTED_CHECK": "Checks if managed IAM policies are not attached to entities",
            "IAM_POLICY_IN_USE": "Checks if IAM policies are attached to entities",
            "IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS": "Checks if IAM policies don't allow admin access",
            "IAM_POLICY_NO_STATEMENTS_WITH_FULL_ACCESS": "Checks if IAM policies don't allow full * access",
            "IAM_ROLE_MANAGED_POLICY_CHECK": "Checks if IAM roles have specific managed policies attached",
            "IAM_ROOT_ACCESS_KEY_CHECK": "Checks if root account has access keys",
            "IAM_USER_GROUP_MEMBERSHIP_CHECK": "Checks if IAM users are members of at least one group",
            "IAM_USER_MFA_ENABLED": "Checks if MFA is enabled for IAM users",
            "IAM_USER_NO_POLICIES_CHECK": "Checks if IAM users have policies directly attached",
            "IAM_USER_UNUSED_CREDENTIALS_CHECK": "Checks if IAM users have unused credentials",
            "INCOMING_SSH_DISABLED": "Checks if security groups don't allow unrestricted SSH access",
            "INSTANCES_IN_VPC": "Checks if EC2 instances are launched in a VPC",
            "INTERNET_GATEWAY_AUTHORIZED_VPC_ONLY": "Checks if internet gateways are only attached to authorized VPCs",
            "KINESIS_STREAM_ENCRYPTED": "Checks if Kinesis streams are encrypted",
            "KMS_CMK_NOT_SCHEDULED_FOR_DELETION": "Checks if KMS CMKs are not scheduled for deletion",
            "LAMBDA_CONCURRENCY_CHECK": "Checks if Lambda function has concurrency limits",
            "LAMBDA_DLQ_CHECK": "Checks if Lambda functions have dead letter queues configured",
            "LAMBDA_FUNCTION_PUBLIC_ACCESS_PROHIBITED": "Checks if Lambda functions are not publicly accessible",
            "LAMBDA_FUNCTION_SETTINGS_CHECK": "Checks if Lambda function settings are as expected",
            "LAMBDA_INSIDE_VPC": "Checks if Lambda functions are inside a VPC",
            "MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS": "Checks if MFA is enabled for IAM users with console access",
            "MULTI_REGION_CLOUDTRAIL_ENABLED": "Checks if multi-region CloudTrail is enabled",
            "NACL_NO_UNRESTRICTED_SSH_RDP": "Checks if NACLs don't allow unrestricted SSH/RDP",
            "NETFW_POLICY_DEFAULT_ACTION_FRAGMENT_PACKETS": "Checks Network Firewall policy default action for fragmented packets",
            "NETFW_POLICY_DEFAULT_ACTION_FULL_PACKETS": "Checks Network Firewall policy default action for full packets",
            "NETFW_POLICY_RULE_GROUP_ASSOCIATED": "Checks if Network Firewall policies have rule groups associated",
            "NETFW_STATELESS_RULE_GROUP_NOT_EMPTY": "Checks if Network Firewall stateless rule groups are not empty",
            "NLB_CROSS_ZONE_LOAD_BALANCING_ENABLED": "Checks if cross-zone load balancing is enabled for NLB",
            "NO_UNRESTRICTED_ROUTE_TO_IGW": "Checks if there are no unrestricted routes to internet gateways",
            "OPENSEARCH_ACCESS_CONTROL_ENABLED": "Checks if OpenSearch domains have access control enabled",
            "OPENSEARCH_AUDIT_LOGGING_ENABLED": "Checks if OpenSearch domains have audit logging enabled",
            "OPENSEARCH_ENCRYPTED_AT_REST": "Checks if OpenSearch domains are encrypted at rest",
            "OPENSEARCH_HTTPS_REQUIRED": "Checks if OpenSearch domains require HTTPS",
            "OPENSEARCH_IN_VPC_ONLY": "Checks if OpenSearch domains are in a VPC",
            "OPENSEARCH_LOGS_TO_CLOUDWATCH": "Checks if OpenSearch domains publish logs to CloudWatch",
            "OPENSEARCH_NODE_TO_NODE_ENCRYPTION_CHECK": "Checks if OpenSearch domains have node-to-node encryption",
            "RDS_AUTOMATIC_MINOR_VERSION_UPGRADE_ENABLED": "Checks if RDS automatic minor version upgrade is enabled",
            "RDS_CLUSTER_DEFAULT_ADMIN_CHECK": "Checks if RDS clusters don't use default admin username",
            "RDS_CLUSTER_DELETION_PROTECTION_ENABLED": "Checks if RDS cluster deletion protection is enabled",
            "RDS_CLUSTER_IAM_AUTHENTICATION_ENABLED": "Checks if RDS clusters have IAM authentication enabled",
            "RDS_CLUSTER_MULTI_AZ_ENABLED": "Checks if RDS clusters have Multi-AZ enabled",
            "RDS_DB_INSTANCE_BACKUP_ENABLED": "Checks if RDS DB instance backup is enabled",
            "RDS_ENHANCED_MONITORING_ENABLED": "Checks if RDS enhanced monitoring is enabled",
            "RDS_IN_BACKUP_PLAN": "Checks if RDS instances are in a backup plan",
            "RDS_INSTANCE_DEFAULT_ADMIN_CHECK": "Checks if RDS instances don't use default admin username",
            "RDS_INSTANCE_DELETION_PROTECTION_ENABLED": "Checks if RDS instance deletion protection is enabled",
            "RDS_INSTANCE_IAM_AUTHENTICATION_ENABLED": "Checks if RDS instances have IAM authentication enabled",
            "RDS_INSTANCE_PUBLIC_ACCESS_CHECK": "Checks if RDS instances are not publicly accessible",
            "RDS_LOGGING_ENABLED": "Checks if RDS logging is enabled",
            "RDS_MULTI_AZ_SUPPORT": "Checks if RDS instances have Multi-AZ support",
            "RDS_SNAPSHOT_ENCRYPTED": "Checks if RDS snapshots are encrypted",
            "RDS_SNAPSHOTS_PUBLIC_PROHIBITED": "Checks if RDS snapshots are not public",
            "RDS_STORAGE_ENCRYPTED": "Checks if RDS storage is encrypted",
            "REDSHIFT_AUDIT_LOGGING_ENABLED": "Checks if Redshift audit logging is enabled",
            "REDSHIFT_BACKUP_ENABLED": "Checks if Redshift backup is enabled",
            "REDSHIFT_CLUSTER_CONFIGURATION_CHECK": "Checks Redshift cluster configuration",
            "REDSHIFT_CLUSTER_KMS_ENABLED": "Checks if Redshift clusters are encrypted with KMS",
            "REDSHIFT_CLUSTER_MAINTENANCESETTINGS_CHECK": "Checks Redshift cluster maintenance settings",
            "REDSHIFT_CLUSTER_PUBLIC_ACCESS_CHECK": "Checks if Redshift clusters are not publicly accessible",
            "REDSHIFT_DEFAULT_ADMIN_CHECK": "Checks if Redshift clusters don't use default admin username",
            "REDSHIFT_DEFAULT_DB_NAME_CHECK": "Checks if Redshift clusters don't use default database name",
            "REDSHIFT_ENHANCED_VPC_ROUTING_ENABLED": "Checks if Redshift enhanced VPC routing is enabled",
            "REDSHIFT_REQUIRE_TLS_SSL": "Checks if Redshift requires TLS/SSL connections",
            "REQUIRED_TAGS": "Checks if resources have required tags",
            "RESTRICTED_COMMON_PORTS": "Checks if security groups restrict common ports",
            "RESTRICTED_INCOMING_TRAFFIC": "Checks if security groups restrict incoming traffic",
            "ROOT_ACCOUNT_HARDWARE_MFA_ENABLED": "Checks if root account has hardware MFA enabled",
            "ROOT_ACCOUNT_MFA_ENABLED": "Checks if root account has MFA enabled",
            "S3_ACCOUNT_LEVEL_PUBLIC_ACCESS_BLOCKS": "Checks if S3 account-level public access blocks are enabled",
            "S3_ACCOUNT_LEVEL_PUBLIC_ACCESS_BLOCKS_PERIODIC": "Checks periodically if S3 account-level public access blocks",
            "S3_BUCKET_ACL_PROHIBITED": "Checks if S3 bucket ACLs are prohibited",
            "S3_BUCKET_BLACKLISTED_ACTIONS_PROHIBITED": "Checks if S3 bucket policies don't allow blacklisted actions",
            "S3_BUCKET_DEFAULT_LOCK_ENABLED": "Checks if S3 bucket default lock is enabled",
            "S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED": "Checks if S3 bucket-level public access is prohibited",
            "S3_BUCKET_LOGGING_ENABLED": "Checks if S3 bucket logging is enabled",
            "S3_BUCKET_POLICY_GRANTEE_CHECK": "Checks S3 bucket policy grantees",
            "S3_BUCKET_POLICY_NOT_MORE_PERMISSIVE": "Checks if S3 bucket policies are not more permissive than expected",
            "S3_BUCKET_PUBLIC_READ_PROHIBITED": "Checks if S3 buckets don't allow public read access",
            "S3_BUCKET_PUBLIC_WRITE_PROHIBITED": "Checks if S3 buckets don't allow public write access",
            "S3_BUCKET_REPLICATION_ENABLED": "Checks if S3 bucket replication is enabled",
            "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED": "Checks if S3 bucket server-side encryption is enabled",
            "S3_BUCKET_SSL_REQUESTS_ONLY": "Checks if S3 buckets require SSL requests only",
            "S3_BUCKET_VERSIONING_ENABLED": "Checks if S3 bucket versioning is enabled",
            "S3_DEFAULT_ENCRYPTION_KMS": "Checks if S3 buckets use KMS for default encryption",
            "S3_EVENT_NOTIFICATIONS_ENABLED": "Checks if S3 event notifications are enabled",
            "S3_LAST_BACKUP_RECOVERY_POINT_CREATED": "Checks if S3 has recent backup recovery point",
            "S3_LIFECYCLE_POLICY_CHECK": "Checks if S3 buckets have lifecycle policies",
            "S3_RESOURCES_PROTECTED_BY_BACKUP_PLAN": "Checks if S3 resources are protected by backup plan",
            "S3_VERSION_LIFECYCLE_POLICY_CHECK": "Checks if S3 version lifecycle policy is configured",
            "SAGEMAKER_ENDPOINT_CONFIGURATION_KMS_KEY_CONFIGURED": "Checks if SageMaker endpoint configurations have KMS key",
            "SAGEMAKER_NOTEBOOK_INSTANCE_KMS_KEY_CONFIGURED": "Checks if SageMaker notebook instances have KMS key",
            "SAGEMAKER_NOTEBOOK_NO_DIRECT_INTERNET_ACCESS": "Checks if SageMaker notebook instances have no direct internet access",
            "SECRETSMANAGER_ROTATION_ENABLED_CHECK": "Checks if Secrets Manager secrets have rotation enabled",
            "SECRETSMANAGER_SCHEDULED_ROTATION_SUCCESS_CHECK": "Checks if Secrets Manager rotation is successful",
            "SECRETSMANAGER_SECRET_PERIODIC_ROTATION": "Checks if Secrets Manager secrets rotate periodically",
            "SECRETSMANAGER_SECRET_UNUSED": "Checks if Secrets Manager secrets are unused",
            "SECRETSMANAGER_USING_CMK": "Checks if Secrets Manager uses CMK for encryption",
            "SECURITYHUB_ENABLED": "Checks if Security Hub is enabled",
            "SERVICE_VPC_ENDPOINT_ENABLED": "Checks if VPC endpoints are enabled for services",
            "SHIELD_ADVANCED_ENABLED_AUTORENEW": "Checks if Shield Advanced has auto-renew enabled",
            "SHIELD_DRT_ACCESS": "Checks if Shield DRT has access to WAF and CloudWatch",
            "SNS_ENCRYPTED_KMS": "Checks if SNS topics are encrypted with KMS",
            "SNS_TOPIC_MESSAGE_DELIVERY_NOTIFICATION_ENABLED": "Checks if SNS topic message delivery notification is enabled",
            "SQS_QUEUE_DLQ_ENABLED": "Checks if SQS queues have dead letter queues",
            "SSM_DOCUMENT_NOT_PUBLIC": "Checks if SSM documents are not public",
            "STORAGEGATEWAY_LAST_BACKUP_RECOVERY_POINT_CREATED": "Checks if Storage Gateway has recent backup recovery point",
            "SUBNET_AUTO_ASSIGN_PUBLIC_IP_DISABLED": "Checks if subnet auto-assign public IP is disabled",
            "VPC_DEFAULT_SECURITY_GROUP_CLOSED": "Checks if VPC default security group is closed",
            "VPC_FLOW_LOGS_ENABLED": "Checks if VPC flow logs are enabled",
            "VPC_NETWORK_ACL_UNUSED_CHECK": "Checks if VPC network ACLs are unused",
            "VPC_PEERING_DNS_RESOLUTION_CHECK": "Checks VPC peering DNS resolution settings",
            "VPC_SG_OPEN_ONLY_TO_AUTHORIZED_PORTS": "Checks if security groups are only open to authorized ports",
            "VPC_VPN_2_TUNNELS_UP": "Checks if VPC VPN has 2 tunnels up",
            "WAFV2_LOGGING_ENABLED": "Checks if WAFv2 web ACL logging is enabled",
            "WAFV2_RULEGROUP_LOGGING_ENABLED": "Checks if WAFv2 rule group logging is enabled",
            "WAFV2_WEBACL_NOT_EMPTY": "Checks if WAFv2 web ACL is not empty",
        }

        return managed_rules.get(
            source_identifier, f"AWS Config managed rule: {source_identifier}"
        )
