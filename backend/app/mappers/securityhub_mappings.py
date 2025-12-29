"""AWS Security Hub control to MITRE ATT&CK technique mappings.

Based on official mappings from the MITRE Center for Threat-Informed Defense
Security Stack Mappings project.

Source: https://center-for-threat-informed-defense.github.io/security-stack-mappings/AWS/
GitHub: https://github.com/center-for-threat-informed-defense/security-stack-mappings
"""

from typing import Optional

# Security Hub managed insights to MITRE technique mappings
# Format: insight_name_pattern -> [(technique_id, confidence)]

SECURITYHUB_INSIGHT_MAPPINGS: dict[str, list[tuple[str, float]]] = {
    # === S3 Bucket Insights ===
    "s3 buckets with public write or read permissions": [
        ("T1530", 0.9),  # Data from Cloud Storage
        ("T1592", 0.75),  # Gather Victim Host Information
        ("T1589", 0.75),  # Gather Victim Identity Information
        ("T1590", 0.75),  # Gather Victim Network Information
        ("T1591", 0.75),  # Gather Victim Org Information
        ("T1580", 0.85),  # Cloud Infrastructure Discovery
    ],
    "s3 buckets with sensitive data": [
        ("T1592", 0.75),
        ("T1589", 0.75),
        ("T1590", 0.75),
        ("T1591", 0.75),
    ],
    # === EC2 Insights ===
    "ec2 instances that have ports accessible from the internet": [("T1580", 0.85)],
    "ec2 instances that are open to the internet": [("T1580", 0.85)],
    "ec2 instances that have missing security patches": [
        ("T1190", 0.85),  # Exploit Public-Facing Application
        ("T1203", 0.75),  # Exploitation for Client Execution
        ("T1068", 0.75),  # Exploitation for Privilege Escalation
        ("T1211", 0.75),  # Exploitation for Defense Evasion
        ("T1212", 0.75),  # Exploitation for Credential Access
        ("T1210", 0.75),  # Exploitation of Remote Services
    ],
    # === IAM/Credential Insights ===
    "aws principals with suspicious access key activity": [("T1078", 0.9)],
    "credentials that may have leaked": [("T1078", 0.9)],
    "aws resources with unauthorized access attempts": [("T1078", 0.85)],
    "iam users with suspicious activity": [("T1078", 0.85)],
}

# CIS AWS Foundations Benchmark checks to MITRE techniques
# Based on official MITRE CTID mappings

CIS_BENCHMARK_MAPPINGS: dict[str, list[tuple[str, float]]] = {
    # Confidence scores based on MITRE CTID Security Stack Mappings
    # T1078.004 (Cloud Accounts) and T1562.008 (Disable Cloud Logs) rated "Significant"
    #
    # Section 3 - Monitoring
    "cis.3.1": [
        ("T1078", 0.85),
        ("T1078.004", 0.85),
    ],  # Unauthorized API calls monitoring
    "cis.3.2": [("T1078", 0.85), ("T1078.004", 0.85)],  # Console sign-in without MFA
    "cis.3.3": [("T1078", 0.9), ("T1078.004", 0.9)],  # Root account usage monitoring
    "cis.3.4": [
        ("T1531", 0.75),  # Account Access Removal
        ("T1098.001", 0.85),  # Additional Cloud Credentials - Significant
    ],  # IAM policy changes
    "cis.3.5": [("T1562", 0.9), ("T1562.008", 0.9)],  # CloudTrail config changes
    "cis.3.6": [
        ("T1110", 0.85),
        ("T1110.001", 0.8),
        ("T1110.003", 0.8),
    ],  # Console auth failures
    "cis.3.7": [("T1562", 0.85), ("T1562.001", 0.85)],  # Disabling CMKs
    "cis.3.8": [
        ("T1530", 0.85),
        ("T1580", 0.8),
    ],  # S3 bucket policy changes
    "cis.3.9": [("T1562", 0.9), ("T1562.001", 0.9)],  # AWS Config changes
    "cis.3.10": [("T1562", 0.85), ("T1562.007", 0.85)],  # Security group changes
    "cis.3.11": [("T1562", 0.85), ("T1562.007", 0.85)],  # NACL changes
    "cis.3.12": [("T1562", 0.85), ("T1562.007", 0.85)],  # Network gateway changes
    "cis.3.13": [("T1562", 0.85), ("T1562.007", 0.85)],  # Route table changes
    "cis.3.14": [("T1562", 0.85), ("T1562.007", 0.85)],  # VPC changes
    # Section 1 - IAM - T1078.004 rated "Significant"
    "cis.1.1": [("T1078", 0.85), ("T1078.004", 0.9)],  # Root account access key
    "cis.1.2": [("T1078", 0.9), ("T1078.004", 0.9)],  # MFA for root
    "cis.1.3": [("T1078", 0.8), ("T1078.004", 0.8)],  # Credentials unused 90 days
    "cis.1.4": [("T1078", 0.8), ("T1078.004", 0.8)],  # Access keys rotated
    "cis.1.5": [("T1110", 0.85), ("T1110.001", 0.8)],  # Password policy - uppercase
    "cis.1.6": [("T1110", 0.85), ("T1110.001", 0.8)],  # Password policy - lowercase
    "cis.1.7": [("T1110", 0.85), ("T1110.001", 0.8)],  # Password policy - symbol
    "cis.1.8": [("T1110", 0.85), ("T1110.001", 0.8)],  # Password policy - number
    "cis.1.9": [("T1110", 0.85), ("T1110.001", 0.8)],  # Password policy - length
    "cis.1.10": [("T1110", 0.85), ("T1110.004", 0.8)],  # Password policy - reuse
    "cis.1.11": [("T1110", 0.85)],  # Password policy - expiry
    "cis.1.12": [("T1078", 0.85), ("T1078.004", 0.9)],  # Root hardware MFA
    "cis.1.13": [("T1078", 0.85), ("T1078.004", 0.85)],  # MFA enabled for console
    "cis.1.14": [("T1098", 0.8), ("T1098.001", 0.85)],  # No policies with admin access
    # Section 2 - Logging - T1562.008 rated "Significant"
    "cis.2.1": [("T1562.008", 0.9)],  # CloudTrail enabled
    "cis.2.2": [("T1562.008", 0.9)],  # CloudTrail log validation
    "cis.2.3": [("T1562.008", 0.85)],  # CloudTrail S3 bucket not public
    "cis.2.4": [("T1562.008", 0.9)],  # CloudTrail to CloudWatch
    "cis.2.5": [("T1562.008", 0.85), ("T1562.001", 0.85)],  # AWS Config enabled
    "cis.2.6": [("T1562.008", 0.85)],  # S3 bucket logging
    "cis.2.7": [("T1562.008", 0.85)],  # CloudTrail KMS encrypted
    "cis.2.8": [("T1078", 0.8), ("T1078.004", 0.8)],  # KMS key rotation
    "cis.2.9": [("T1562.008", 0.85)],  # VPC flow logs enabled
    # Section 4 - Networking - T1562.007 rated "Significant"
    "cis.4.1": [("T1562.007", 0.85)],  # No SSH from 0.0.0.0/0
    "cis.4.2": [("T1562.007", 0.85)],  # No RDP from 0.0.0.0/0
    "cis.4.3": [("T1562.007", 0.85)],  # Default VPC SG restricts all
    "cis.4.4": [("T1562.007", 0.85)],  # VPC peering least privilege
}

# PCI-DSS controls to MITRE techniques
PCI_DSS_MAPPINGS: dict[str, list[tuple[str, float]]] = {
    "pci.cw.1": [("T1078", 0.85)],  # Root user usage
    "pci.iam.1": [("T1078", 0.8)],  # Root access key
    "pci.iam.2": [("T1078", 0.85)],  # IAM policies no admin
    "pci.iam.3": [("T1078", 0.8)],  # Access keys rotated
    "pci.iam.4": [("T1078", 0.9)],  # Root MFA enabled
    "pci.iam.5": [("T1078", 0.9)],  # Virtual MFA for root
    "pci.iam.6": [("T1078", 0.85)],  # MFA for console users
    "pci.iam.7": [("T1078", 0.8)],  # Credentials unused
    "pci.iam.8": [("T1110", 0.85)],  # Password policy
    "pci.cloudtrail.1": [("T1562.008", 0.9)],  # CloudTrail enabled
    "pci.cloudtrail.2": [("T1562.008", 0.85)],  # CloudTrail encrypted
    "pci.cloudtrail.3": [("T1562.008", 0.85)],  # Log file validation
    "pci.cloudtrail.4": [("T1562.008", 0.85)],  # CloudWatch integration
    "pci.config.1": [("T1562", 0.85)],  # AWS Config enabled
    "pci.ec2.1": [("T1486", 0.8)],  # EBS snapshots not public
    "pci.ec2.2": [("T1562.007", 0.85)],  # VPC default SG
    "pci.ec2.3": [("T1562.007", 0.8)],  # SG no unrestricted ingress
    "pci.ec2.4": [("T1562.007", 0.8)],  # SG no unrestricted common ports
    "pci.ec2.5": [("T1562.007", 0.85)],  # VPC flow logs
    "pci.ec2.6": [("T1562.008", 0.8)],  # VPC flow logs
    "pci.s3.1": [("T1530", 0.85)],  # S3 block public access
    "pci.s3.2": [("T1530", 0.8)],  # S3 bucket public read
    "pci.s3.3": [("T1530", 0.8)],  # S3 replication
    "pci.s3.4": [("T1486", 0.8)],  # S3 bucket SSE
    "pci.s3.5": [("T1530", 0.8)],  # S3 bucket public write
    "pci.s3.6": [("T1530", 0.8)],  # S3 bucket level public access
    "pci.kms.1": [("T1486", 0.8)],  # KMS key rotation
    "pci.lambda.1": [("T1530", 0.75)],  # Lambda not public
    "pci.lambda.2": [("T1562.007", 0.75)],  # Lambda in VPC
    "pci.rds.1": [("T1530", 0.85)],  # RDS snapshots not public
    "pci.rds.2": [("T1190", 0.8)],  # RDS not public
    "pci.opensearch.1": [("T1530", 0.8)],  # OpenSearch encrypted
    "pci.opensearch.2": [("T1530", 0.8)],  # OpenSearch in VPC
}

# AWS Foundational Security Best Practices (FSBP) to MITRE techniques
# Confidence scores based on MITRE CTID Security Stack Mappings:
# https://center-for-threat-informed-defense.github.io/security-stack-mappings/AWS/AWSSecurityHub.yaml
# Significant = 0.85-0.9, Partial = 0.65-0.8, Minimal = 0.5-0.6
FSBP_MAPPINGS: dict[str, list[tuple[str, float]]] = {
    # Account
    "fsbp.account.1": [("T1078", 0.8), ("T1078.004", 0.8)],  # Security contact
    # API Gateway
    "fsbp.apigateway.1": [("T1562.008", 0.8)],  # Logging enabled
    "fsbp.apigateway.2": [("T1190", 0.75)],  # SSL
    "fsbp.apigateway.3": [("T1562.008", 0.8)],  # Access logging
    "fsbp.apigateway.4": [("T1562.007", 0.75)],  # WAF association
    # AutoScaling
    "fsbp.autoscaling.1": [("T1496", 0.7)],  # ELB health check
    # CloudTrail
    "fsbp.cloudtrail.1": [("T1562.008", 0.9)],  # Enabled
    "fsbp.cloudtrail.2": [("T1562.008", 0.85)],  # Encryption
    "fsbp.cloudtrail.4": [("T1562.008", 0.85)],  # Log validation
    "fsbp.cloudtrail.5": [("T1562.008", 0.85)],  # CloudWatch integration
    # CodeBuild
    "fsbp.codebuild.1": [("T1552", 0.8)],  # OAuth no secrets
    "fsbp.codebuild.2": [("T1552", 0.8)],  # No plaintext env vars
    # DynamoDB
    "fsbp.dynamodb.1": [("T1485", 0.75)],  # Auto scaling
    "fsbp.dynamodb.2": [("T1485", 0.8)],  # PITR enabled
    "fsbp.dynamodb.3": [("T1485", 0.8)],  # DAX encrypted
    # EC2
    "fsbp.ec2.1": [("T1530", 0.8)],  # EBS no public snapshots
    "fsbp.ec2.2": [("T1562.007", 0.85)],  # Default SG restricts
    "fsbp.ec2.3": [("T1486", 0.8)],  # EBS encryption by default
    "fsbp.ec2.4": [("T1059", 0.75)],  # Stopped instances
    "fsbp.ec2.6": [("T1562.008", 0.8)],  # VPC flow logs
    "fsbp.ec2.7": [("T1486", 0.8)],  # EBS volumes encrypted
    "fsbp.ec2.8": [("T1552.005", 0.85)],  # IMDSv2
    "fsbp.ec2.9": [("T1190", 0.8)],  # No public IP
    "fsbp.ec2.10": [("T1562.007", 0.8)],  # VPC endpoint
    "fsbp.ec2.15": [("T1562.007", 0.75)],  # Subnet no auto public IP
    "fsbp.ec2.16": [("T1562.007", 0.75)],  # Unused NACL
    "fsbp.ec2.17": [("T1190", 0.8)],  # Instance in VPC
    "fsbp.ec2.18": [("T1562.007", 0.8)],  # SG authorized ports only
    "fsbp.ec2.19": [("T1562.007", 0.85)],  # No unrestricted common ports
    # ECS
    "fsbp.ecs.1": [("T1610", 0.75)],  # Task definitions secrets
    "fsbp.ecs.2": [("T1610", 0.75)],  # No public IP
    # EFS
    "fsbp.efs.1": [("T1486", 0.8)],  # Encryption at rest
    "fsbp.efs.2": [("T1485", 0.8)],  # In backup plan
    # EKS
    "fsbp.eks.1": [("T1562.008", 0.8)],  # Logging enabled
    "fsbp.eks.2": [("T1552", 0.85)],  # Secrets encrypted
    # ElastiCache
    "fsbp.elasticache.1": [("T1485", 0.75)],  # Automatic backup
    "fsbp.elasticache.2": [("T1190", 0.75)],  # Minor version auto
    "fsbp.elasticache.3": [("T1190", 0.75)],  # Failover enabled
    "fsbp.elasticache.4": [("T1486", 0.75)],  # Encryption at rest
    "fsbp.elasticache.5": [("T1040", 0.75)],  # Encryption in transit
    "fsbp.elasticache.6": [("T1040", 0.75)],  # Redis earlier versions
    "fsbp.elasticache.7": [("T1562.007", 0.75)],  # Default subnet group
    # Elasticsearch/OpenSearch
    "fsbp.es.1": [("T1486", 0.8)],  # Encryption at rest
    "fsbp.es.2": [("T1190", 0.85)],  # In VPC
    "fsbp.es.3": [("T1040", 0.8)],  # Node-to-node encryption
    "fsbp.es.4": [("T1562.008", 0.8)],  # Error logging
    "fsbp.es.5": [("T1562.008", 0.8)],  # Audit logging
    "fsbp.es.6": [("T1190", 0.8)],  # Fine-grained access
    "fsbp.es.7": [("T1040", 0.8)],  # TLS policy
    "fsbp.es.8": [("T1040", 0.8)],  # Latest TLS
    # ELB
    "fsbp.elb.1": [("T1562.008", 0.8)],  # ALB HTTP redirect
    "fsbp.elb.2": [("T1040", 0.8)],  # SSL certificate
    "fsbp.elb.3": [("T1562.008", 0.75)],  # Access logging
    "fsbp.elb.4": [("T1040", 0.8)],  # Drop invalid headers
    "fsbp.elb.5": [("T1485", 0.75)],  # Deletion protection
    "fsbp.elb.6": [("T1040", 0.8)],  # Desync mitigation
    "fsbp.elb.7": [("T1498", 0.75)],  # Cross-zone load balancing
    "fsbp.elb.8": [("T1040", 0.8)],  # HTTPS listener
    "fsbp.elb.9": [("T1498", 0.75)],  # Multi-AZ
    "fsbp.elb.10": [("T1562.008", 0.75)],  # Connection logging
    "fsbp.elb.12": [("T1040", 0.8)],  # TLS HTTPS
    "fsbp.elb.13": [("T1040", 0.8)],  # Secure listener
    "fsbp.elb.14": [("T1040", 0.8)],  # Secure SSL cipher
    # GuardDuty
    "fsbp.guardduty.1": [("T1562.001", 0.9)],  # Enabled
    # IAM - T1078.004 (Cloud Accounts) rated "Significant" by MITRE CTID
    "fsbp.iam.1": [
        ("T1098", 0.85),
        ("T1098.001", 0.85),
    ],  # No policies with admin access
    "fsbp.iam.2": [
        ("T1078", 0.85),
        ("T1078.004", 0.85),
    ],  # No attached policies to users
    "fsbp.iam.3": [("T1078", 0.85), ("T1078.004", 0.85)],  # Access keys rotated
    "fsbp.iam.4": [("T1078", 0.9), ("T1078.004", 0.9)],  # No root access key
    "fsbp.iam.5": [("T1078", 0.9), ("T1078.004", 0.9)],  # Virtual MFA for root
    "fsbp.iam.6": [("T1078", 0.9), ("T1078.004", 0.9)],  # Hardware MFA for root
    "fsbp.iam.7": [
        ("T1110", 0.85),
        ("T1110.001", 0.8),
        ("T1110.003", 0.8),
    ],  # Password policy
    "fsbp.iam.8": [("T1078", 0.8), ("T1078.004", 0.8)],  # Unused credentials
    "fsbp.iam.21": [
        ("T1078", 0.85),
        ("T1078.004", 0.85),
        ("T1098.001", 0.85),
    ],  # No full admin
    # KMS
    "fsbp.kms.1": [("T1486", 0.8)],  # CMK key rotation
    "fsbp.kms.2": [("T1486", 0.85)],  # No * principals
    "fsbp.kms.3": [("T1486", 0.85)],  # No unintended deletion
    # Lambda
    "fsbp.lambda.1": [("T1190", 0.85)],  # Not public
    "fsbp.lambda.2": [("T1059", 0.75)],  # Supported runtime
    "fsbp.lambda.5": [("T1562.007", 0.75)],  # VPC multi-AZ
    # RDS
    "fsbp.rds.1": [("T1530", 0.85)],  # Snapshots not public
    "fsbp.rds.2": [("T1190", 0.85)],  # Not publicly accessible
    "fsbp.rds.3": [("T1486", 0.8)],  # Encryption at rest
    "fsbp.rds.4": [("T1530", 0.85)],  # Cluster snapshots not public
    "fsbp.rds.5": [("T1485", 0.8)],  # Multi-AZ
    "fsbp.rds.6": [("T1562.008", 0.8)],  # Enhanced monitoring
    "fsbp.rds.7": [("T1485", 0.8)],  # Cluster deletion protection
    "fsbp.rds.8": [("T1485", 0.8)],  # Instance deletion protection
    "fsbp.rds.9": [("T1562.008", 0.8)],  # Logging enabled
    "fsbp.rds.10": [("T1078", 0.8)],  # IAM authentication
    "fsbp.rds.11": [("T1485", 0.75)],  # Backup enabled
    "fsbp.rds.12": [("T1078", 0.75)],  # IAM cluster auth
    "fsbp.rds.13": [("T1190", 0.8)],  # Auto minor upgrade
    "fsbp.rds.14": [("T1485", 0.75)],  # Backtracking
    "fsbp.rds.15": [("T1485", 0.8)],  # Cluster multi-AZ
    "fsbp.rds.16": [("T1530", 0.8)],  # Cluster tags
    "fsbp.rds.17": [("T1530", 0.8)],  # Instance tags
    "fsbp.rds.18": [("T1562.007", 0.75)],  # In VPC
    "fsbp.rds.19": [("T1562.007", 0.75)],  # Event notification
    "fsbp.rds.20": [("T1562.007", 0.75)],  # Security subscription
    "fsbp.rds.21": [("T1562.007", 0.75)],  # Cluster event notification
    "fsbp.rds.22": [("T1562.007", 0.75)],  # Parameter event
    "fsbp.rds.23": [("T1078", 0.75)],  # No default admin
    # Redshift
    "fsbp.redshift.1": [("T1190", 0.85)],  # Not publicly accessible
    "fsbp.redshift.2": [("T1486", 0.8)],  # Encrypted
    "fsbp.redshift.3": [("T1485", 0.75)],  # Snapshots enabled
    "fsbp.redshift.4": [("T1562.008", 0.8)],  # Audit logging
    "fsbp.redshift.6": [("T1190", 0.8)],  # Auto upgrade
    "fsbp.redshift.7": [("T1040", 0.8)],  # Enhanced VPC routing
    "fsbp.redshift.8": [("T1078", 0.75)],  # No default admin
    "fsbp.redshift.9": [("T1040", 0.8)],  # Require SSL
    # S3
    "fsbp.s3.1": [("T1530", 0.9)],  # Block public access account
    "fsbp.s3.2": [("T1530", 0.85)],  # Block public read
    "fsbp.s3.3": [("T1530", 0.85)],  # Block public write
    "fsbp.s3.4": [("T1486", 0.8)],  # SSE enabled
    "fsbp.s3.5": [("T1040", 0.8)],  # Require SSL
    "fsbp.s3.6": [("T1530", 0.85)],  # Bucket level public access
    "fsbp.s3.8": [("T1530", 0.9)],  # Block public access bucket
    "fsbp.s3.9": [("T1562.008", 0.8)],  # Server access logging
    "fsbp.s3.10": [("T1530", 0.85)],  # Bucket versioning
    "fsbp.s3.11": [("T1562.008", 0.75)],  # Event notifications
    "fsbp.s3.12": [("T1530", 0.85)],  # No ACLs
    "fsbp.s3.13": [("T1530", 0.85)],  # Lifecycle policy
    # Secrets Manager
    "fsbp.secretsmanager.1": [("T1552", 0.85)],  # Rotation enabled
    "fsbp.secretsmanager.2": [("T1552", 0.85)],  # Auto rotation
    "fsbp.secretsmanager.3": [("T1552", 0.8)],  # Remove unused
    "fsbp.secretsmanager.4": [("T1552", 0.85)],  # 90-day rotation
    # SNS
    "fsbp.sns.1": [("T1486", 0.75)],  # KMS encryption
    "fsbp.sns.2": [("T1562.008", 0.75)],  # Delivery logging
    # SQS
    "fsbp.sqs.1": [("T1486", 0.75)],  # SSE enabled
    # SSM
    "fsbp.ssm.1": [("T1059", 0.8)],  # EC2 managed by SSM
    "fsbp.ssm.2": [("T1059", 0.8)],  # Patch compliance
    "fsbp.ssm.3": [("T1059", 0.8)],  # Association compliance
    "fsbp.ssm.4": [("T1552", 0.85)],  # Documents not public
    # WAF
    "fsbp.waf.1": [("T1562.007", 0.85)],  # Global rule groups
    "fsbp.waf.2": [("T1562.007", 0.85)],  # Regional rule groups
    "fsbp.waf.3": [("T1562.007", 0.85)],  # Regional rule
    "fsbp.waf.4": [("T1562.007", 0.85)],  # Global rule
    "fsbp.waf.6": [("T1562.008", 0.8)],  # Logging enabled
    "fsbp.waf.7": [("T1562.008", 0.8)],  # Regional logging
    "fsbp.waf.8": [("T1562.007", 0.85)],  # Global web ACL
    "fsbp.waf.10": [("T1562.007", 0.85)],  # Web ACL rule
}


def get_techniques_for_cspm_control(
    control_id: str,
    standard_associations: Optional[list[dict]] = None,
) -> list[tuple[str, float]]:
    """Get MITRE technique mappings for a Security Hub CSPM control.

    CSPM uses standard-agnostic control IDs like 'S3.1', 'IAM.1'.
    This function maps these to MITRE techniques using FSBP as the
    primary source (most comprehensive), with fallback to other standards.

    Args:
        control_id: The CSPM control ID (e.g., 'S3.1', 'IAM.1', 'EC2.18')
        standard_associations: Optional list of standard associations from
            the CSPM API (used to determine which standards the control
            is associated with)

    Returns:
        List of (technique_id, confidence) tuples

    Example:
        >>> get_techniques_for_cspm_control('S3.1')
        [('T1530', 0.9)]
        >>> get_techniques_for_cspm_control('IAM.1')
        [('T1098', 0.85)]
    """
    import structlog

    logger = structlog.get_logger()

    techniques = []

    # Normalise control ID: S3.1 -> s3.1, CIS.3.2 -> cis.3.2
    normalised_id = control_id.lower().replace("-", ".")

    # Check if this is a CIS-specific control ID (e.g., CIS.3.2, cis.1.11)
    # These need to be looked up directly in CIS_BENCHMARK_MAPPINGS
    if normalised_id.startswith("cis."):
        # CIS control ID format: cis.X.Y -> look up as "cis.X.Y"
        cis_key = normalised_id  # Already in correct format: cis.3.2
        if cis_key in CIS_BENCHMARK_MAPPINGS:
            techniques.extend(CIS_BENCHMARK_MAPPINGS[cis_key])
            logger.debug(
                "cspm_control_cis_match",
                control_id=control_id,
                cis_key=cis_key,
                techniques=techniques,
            )
            # Deduplicate and return early
            cis_seen: dict[str, float] = {}
            for tech_id, conf in techniques:
                if tech_id not in cis_seen or conf > cis_seen[tech_id]:
                    cis_seen[tech_id] = conf
            return list(cis_seen.items())

    # Try FSBP first (most comprehensive coverage for service-based IDs)
    fsbp_key = f"fsbp.{normalised_id}"
    found_fsbp = fsbp_key in FSBP_MAPPINGS
    if found_fsbp:
        techniques.extend(FSBP_MAPPINGS[fsbp_key])
        logger.debug(
            "cspm_control_fsbp_match",
            control_id=control_id,
            fsbp_key=fsbp_key,
            techniques=techniques,
        )

    # If no FSBP match and we have standard associations, try other standards
    if not techniques and standard_associations:
        for assoc in standard_associations:
            standards_arn = assoc.get("standards_arn", "")

            # Try CIS
            if "cis" in standards_arn.lower():
                cis_key = f"cis.{normalised_id}"
                if cis_key in CIS_BENCHMARK_MAPPINGS:
                    techniques.extend(CIS_BENCHMARK_MAPPINGS[cis_key])

            # Try PCI-DSS
            if "pci" in standards_arn.lower():
                pci_key = f"pci.{normalised_id}"
                if pci_key in PCI_DSS_MAPPINGS:
                    techniques.extend(PCI_DSS_MAPPINGS[pci_key])

    # Deduplicate, keeping highest confidence per technique
    seen: dict[str, float] = {}
    for tech_id, conf in techniques:
        if tech_id not in seen or conf > seen[tech_id]:
            seen[tech_id] = conf

    return list(seen.items())


def get_techniques_for_security_hub(
    standard_name: str,
    control_id: Optional[str] = None,
    finding_title: Optional[str] = None,
    api_version: Optional[str] = None,
) -> list[tuple[str, float]]:
    """Get MITRE technique mappings for a Security Hub finding.

    Supports both legacy standards-based API and new CSPM API.

    Args:
        standard_name: The security standard (e.g., 'aws-foundational-security-best-practices')
            For CSPM detections, this can be empty or 'cspm'.
        control_id: Optional control ID (e.g., 'IAM.1', 'S3.1')
        finding_title: Optional finding title for insight matching
        api_version: Optional API version marker ('cspm' or 'legacy')

    Returns:
        List of (technique_id, confidence) tuples
    """
    techniques = []

    # If this is a CSPM detection, use the new mapping function
    if api_version == "cspm" and control_id:
        return get_techniques_for_cspm_control(control_id)

    # Check for FSBP controls
    if "foundational" in standard_name.lower() or "fsbp" in standard_name.lower():
        if control_id:
            normalised_id = f"fsbp.{control_id.lower().replace('-', '.')}"
            if normalised_id in FSBP_MAPPINGS:
                techniques.extend(FSBP_MAPPINGS[normalised_id])

    # Check for CIS Benchmark controls
    if "cis" in standard_name.lower():
        if control_id:
            normalised_id = f"cis.{control_id.lower().replace('-', '.')}"
            if normalised_id in CIS_BENCHMARK_MAPPINGS:
                techniques.extend(CIS_BENCHMARK_MAPPINGS[normalised_id])

    # Check for PCI-DSS controls
    if "pci" in standard_name.lower():
        if control_id:
            normalised_id = f"pci.{control_id.lower().replace('-', '.')}"
            if normalised_id in PCI_DSS_MAPPINGS:
                techniques.extend(PCI_DSS_MAPPINGS[normalised_id])

    # Check for managed insight matches
    if finding_title:
        title_lower = finding_title.lower()
        for pattern, techs in SECURITYHUB_INSIGHT_MAPPINGS.items():
            if pattern in title_lower:
                techniques.extend(techs)

    # Deduplicate, keeping highest confidence per technique
    seen: dict[str, float] = {}
    for tech_id, conf in techniques:
        if tech_id not in seen or conf > seen[tech_id]:
            seen[tech_id] = conf

    return list(seen.items())


def get_all_mapped_standards() -> dict[str, list[str]]:
    """Get all mapped security standards and their control IDs."""
    return {
        "fsbp": [k.replace("fsbp.", "") for k in FSBP_MAPPINGS.keys()],
        "cis": [k.replace("cis.", "") for k in CIS_BENCHMARK_MAPPINGS.keys()],
        "pci": [k.replace("pci.", "") for k in PCI_DSS_MAPPINGS.keys()],
    }
