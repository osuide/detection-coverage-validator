# ECS Fargate Backend Module
# Runs the FastAPI backend on ECS Fargate with ALB

variable "environment" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "public_subnet_ids" {
  type = list(string)
}

variable "private_subnet_ids" {
  type = list(string)
}

variable "use_private_subnets" {
  description = "Deploy ECS tasks in private subnets (requires NAT Gateway for outbound internet)"
  type        = bool
  default     = false
}

variable "database_url" {
  type      = string
  sensitive = true
}

variable "redis_url" {
  type = string
}

variable "database_security_group_id" {
  type = string
}

variable "redis_security_group_id" {
  type = string
}

variable "ecr_repository_url" {
  type = string
}

variable "domain_name" {
  type    = string
  default = ""
}

variable "certificate_arn" {
  type    = string
  default = ""
}

variable "enable_https" {
  type        = bool
  description = "Enable HTTPS listener (set to true after certificates are validated)"
  default     = false
}

variable "jwt_secret_key" {
  type      = string
  sensitive = true
}

variable "credential_encryption_key" {
  type        = string
  sensitive   = true
  default     = ""
  description = "Fernet key for encrypting cloud credentials. Required in production."
}

variable "stripe_secret_key" {
  type      = string
  sensitive = true
  default   = ""
}

variable "stripe_webhook_secret" {
  type      = string
  sensitive = true
  default   = ""
}

variable "stripe_price_ids" {
  description = "Stripe price IDs for subscription plans (Individual £29/mo, Pro £250/mo)"
  type = object({
    individual         = string
    pro                = string
    additional_account = string
  })
  default = {
    individual         = ""
    pro                = ""
    additional_account = ""
  }
}

# Cognito / OAuth Configuration
variable "cognito_user_pool_id" {
  type        = string
  description = "Cognito User Pool ID"
  default     = ""
}

variable "cognito_client_id" {
  type        = string
  description = "Cognito Web Client ID"
  default     = ""
}

variable "cognito_domain" {
  type        = string
  description = "Cognito domain URL for OAuth"
  default     = ""
}

variable "cognito_issuer" {
  type        = string
  description = "Cognito issuer URL for JWT verification"
  default     = ""
}

variable "frontend_url" {
  type        = string
  description = "Frontend URL for OAuth callbacks"
  default     = "http://localhost:3001"
}

variable "force_reload_compliance" {
  type        = bool
  description = "Force reload compliance framework data on startup (one-time migration)"
  default     = false
}

variable "cookie_domain" {
  type        = string
  description = "Cookie domain for cross-subdomain auth (e.g., '.a13e.com')"
  default     = ""
}

# OAuth Provider Client IDs (for backend to know which providers are enabled)
variable "google_client_id" {
  type        = string
  description = "Google OAuth Client ID"
  default     = ""
  sensitive   = true
}

# GitHub OAuth (handled by backend directly, not Cognito)
variable "github_client_id" {
  type        = string
  description = "GitHub OAuth Client ID"
  default     = ""
  sensitive   = true
}

variable "github_client_secret" {
  type        = string
  description = "GitHub OAuth Client Secret"
  default     = ""
  sensitive   = true
}

variable "support_api_key" {
  type        = string
  description = "API key for Google Workspace support integration"
  default     = ""
  sensitive   = true
}

variable "initial_admin_password" {
  type        = string
  description = "Initial password for admin portal super admin (admin@a13e.com)"
  default     = ""
  sensitive   = true
}

# Note: Microsoft SSO has been removed from the product

# Google Workspace WIF Configuration
variable "workspace_wif_enabled" {
  type        = bool
  description = "Enable Google Workspace integration via WIF"
  default     = false
}

variable "workspace_gcp_project_number" {
  type        = string
  description = "GCP project number for Workspace WIF"
  default     = ""
}

variable "workspace_wif_pool_id" {
  type        = string
  description = "Workload Identity Pool ID"
  default     = ""
}

variable "workspace_wif_provider_id" {
  type        = string
  description = "Workload Identity Pool Provider ID"
  default     = ""
}

variable "workspace_service_account_email" {
  type        = string
  description = "GCP service account email for Workspace access"
  default     = ""
}

variable "workspace_admin_email" {
  type        = string
  description = "Workspace admin email for domain-wide delegation"
  default     = ""
}

variable "support_crm_spreadsheet_id" {
  type        = string
  description = "Google Sheets ID for support CRM ticket logging"
  default     = ""
}

variable "telemetry_sheet_id" {
  type        = string
  description = "Google Sheets ID for platform telemetry dashboard"
  default     = ""
}

variable "allowed_ips" {
  type        = list(string)
  description = "List of IP addresses (CIDR notation) allowed to access the API. Empty list allows all traffic."
  default     = []
}

variable "ses_domain" {
  type        = string
  description = "SES verified domain for sending emails (used to scope IAM permissions)"
  default     = ""
}

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

# ELB service account for ALB access logs
# See: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/enable-access-logging.html
data "aws_elb_service_account" "main" {}

# S3 bucket for ALB access logs (security/compliance requirement)
resource "random_id" "alb_logs_suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "alb_logs" {
  bucket = "a13e-${var.environment}-alb-logs-${random_id.alb_logs_suffix.hex}"

  tags = {
    Name        = "a13e-${var.environment}-alb-logs"
    Environment = var.environment
    Purpose     = "ALB Access Logs"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  rule {
    id     = "expire-old-logs"
    status = "Enabled"

    expiration {
      days = 365 # Keep logs for 1 year (compliance requirement)
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

resource "aws_s3_bucket_public_access_block" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Bucket policy to allow ALB to write access logs
resource "aws_s3_bucket_policy" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowALBLogs"
        Effect = "Allow"
        Principal = {
          AWS = data.aws_elb_service_account.main.arn
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.alb_logs.arn}/alb-logs/*"
      },
      {
        Sid    = "AllowALBLogDelivery"
        Effect = "Allow"
        Principal = {
          Service = "delivery.logs.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.alb_logs.arn}/alb-logs/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
      {
        Sid    = "AllowALBLogDeliveryAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "delivery.logs.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.alb_logs.arn
      }
    ]
  })
}

# ECS Cluster
resource "aws_ecs_cluster" "main" {
  name = "a13e-${var.environment}-backend"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = {
    Name = "a13e-${var.environment}-backend-cluster"
  }
}

# CloudWatch Log Group
resource "aws_cloudwatch_log_group" "backend" {
  name              = "/ecs/a13e-${var.environment}-backend"
  retention_in_days = 30

  tags = {
    Name = "a13e-${var.environment}-backend-logs"
  }
}

# Security Group for ALB
resource "aws_security_group" "alb" {
  name_prefix = "a13e-${var.environment}-alb-"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "a13e-${var.environment}-alb-sg"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Security Group for ECS Tasks
resource "aws_security_group" "ecs" {
  name_prefix = "a13e-${var.environment}-ecs-"
  vpc_id      = var.vpc_id

  ingress {
    from_port       = 8000
    to_port         = 8000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "a13e-${var.environment}-ecs-sg"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Allow ECS to access RDS
resource "aws_security_group_rule" "ecs_to_rds" {
  type                     = "ingress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.ecs.id
  security_group_id        = var.database_security_group_id
}

# Allow ECS to access Redis
resource "aws_security_group_rule" "ecs_to_redis" {
  type                     = "ingress"
  from_port                = 6379
  to_port                  = 6379
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.ecs.id
  security_group_id        = var.redis_security_group_id
}

# Application Load Balancer
resource "aws_lb" "main" {
  name               = "a13e-${var.environment}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = var.public_subnet_ids

  # Idle timeout - how long to keep connections open waiting for data
  # Default is 60s, keeping it explicit for clarity
  idle_timeout = 60

  enable_deletion_protection = var.environment == "prod"

  # Security: Enable access logs for debugging, security analysis, and compliance
  # Logs include: client IP, request path, latency, response codes
  # Retained for 365 days via lifecycle policy on the S3 bucket
  access_logs {
    bucket  = aws_s3_bucket.alb_logs.id
    prefix  = "alb-logs"
    enabled = true
  }

  tags = {
    Name = "a13e-${var.environment}-alb"
  }

  # Ensure bucket and policy exist before enabling logging
  depends_on = [aws_s3_bucket_policy.alb_logs]
}

# Target Group
resource "aws_lb_target_group" "main" {
  name        = "a13e-${var.environment}-tg"
  port        = 8000
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  # Reduce deregistration delay from default 300s to 30s
  # This speeds up deployments and reduces 504s during target draining
  deregistration_delay = 30

  # Give new targets 30 seconds to warm up before receiving full traffic
  # This helps prevent 504s when new tasks are starting
  slow_start = 30

  health_check {
    enabled             = true
    healthy_threshold   = 2
    interval            = 30
    matcher             = "200"
    path                = "/health"
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 5
    unhealthy_threshold = 3
  }

  tags = {
    Name = "a13e-${var.environment}-tg"
  }
}

# HTTP Listener (redirects to HTTPS when HTTPS is enabled)
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = var.enable_https ? "redirect" : "forward"

    dynamic "redirect" {
      for_each = var.enable_https ? [1] : []
      content {
        port        = "443"
        protocol    = "HTTPS"
        status_code = "HTTP_301"
      }
    }

    target_group_arn = var.enable_https ? null : aws_lb_target_group.main.arn
  }
}

# HTTPS Listener (only when HTTPS is enabled)
resource "aws_lb_listener" "https" {
  count             = var.enable_https ? 1 : 0
  load_balancer_arn = aws_lb.main.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.main.arn
  }
}

# IAM Role for ECS Task Execution
resource "aws_iam_role" "ecs_execution" {
  name = "a13e-${var.environment}-ecs-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_execution" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "ecs_execution_ecr" {
  name = "a13e-${var.environment}-ecs-ecr-policy"
  role = aws_iam_role.ecs_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.backend.arn}:*"
      }
    ]
  })
}

# IAM Role for ECS Task (application permissions)
resource "aws_iam_role" "ecs_task" {
  name = "a13e-${var.environment}-ecs-task-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy" "ecs_task" {
  name = "a13e-${var.environment}-ecs-task-policy"
  role = aws_iam_role.ecs_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadA13ESecrets"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = [
          "arn:aws:secretsmanager:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:secret:dcv/${var.environment}/*",
          "arn:aws:secretsmanager:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:secret:a13e/${var.environment}/*"
        ]
      },
      {
        Sid    = "AssumeCustomerScannerRoles"
        Effect = "Allow"
        Action = [
          "sts:AssumeRole"
        ]
        # Security: Restrict to a13e scanner roles only
        # Allows both naming conventions:
        # - a13e-scanner-* (new convention for GCP WIF)
        # - A13E-ReadOnly (legacy convention used in docs/CloudFormation templates)
        Resource = [
          "arn:aws:iam::*:role/a13e-scanner-*",
          "arn:aws:iam::*:role/A13E-ReadOnly"
        ]
        Condition = {
          StringLike = {
            "sts:ExternalId" = "a13e-*"
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "logs:DescribeQueryDefinitions",
          "logs:DescribeLogGroups",
          "logs:DescribeMetricFilters",
          "events:ListRules",
          "events:DescribeRule",
          "events:ListEventBuses",
          "cloudwatch:DescribeAlarms",
          "guardduty:ListDetectors",
          "guardduty:ListFindings",
          "config:DescribeConfigRules",
          "sts:GetCallerIdentity"
        ]
        Resource = "*"
      },
      {
        # Security: CWE-732 fix - scope SES permissions to verified domain only
        # Prevents sending email from arbitrary identities if credentials are compromised
        Sid    = "SESSendEmail"
        Effect = "Allow"
        Action = [
          "ses:SendEmail",
          "ses:SendRawEmail"
        ]
        # Scope to verified domain identity (email sender) and any email address
        # SES requires permission on both the identity (domain) and recipient
        Resource = var.ses_domain != "" ? [
          "arn:aws:ses:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:identity/${var.ses_domain}",
          "arn:aws:ses:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:identity/*@${var.ses_domain}",
          # Also allow sending to any recipient (required for SES)
          "arn:aws:ses:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:identity/*"
        ] : ["arn:aws:ses:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:identity/*"]
      },
      {
        Sid    = "ECSExec"
        Effect = "Allow"
        Action = [
          "ssmmessages:CreateControlChannel",
          "ssmmessages:CreateDataChannel",
          "ssmmessages:OpenControlChannel",
          "ssmmessages:OpenDataChannel"
        ]
        Resource = "*"
      }
    ]
  })
}

# Secrets Manager - Store sensitive values securely
# These secrets are injected into the ECS container at runtime
resource "aws_secretsmanager_secret" "jwt_secret" {
  name = "a13e/${var.environment}/jwt-secret"

  tags = {
    Name        = "a13e-${var.environment}-jwt-secret"
    Environment = var.environment
  }

  # Prevent accidental deletion - this is the JWT signing key
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_secretsmanager_secret_version" "jwt_secret" {
  secret_id     = aws_secretsmanager_secret.jwt_secret.id
  secret_string = var.jwt_secret_key
}

resource "aws_secretsmanager_secret" "credential_encryption_key" {
  # Always create - key is always provided (either from var or generated random_password)
  name = "a13e/${var.environment}/credential-encryption-key"

  tags = {
    Name        = "a13e-${var.environment}-credential-encryption-key"
    Environment = var.environment
  }

  # Prevent accidental deletion - this key encrypts cloud credentials
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_secretsmanager_secret_version" "credential_encryption_key" {
  secret_id     = aws_secretsmanager_secret.credential_encryption_key.id
  secret_string = var.credential_encryption_key
}

resource "aws_secretsmanager_secret" "stripe_secret_key" {
  count = var.stripe_secret_key != "" ? 1 : 0
  name  = "a13e/${var.environment}/stripe-secret-key"

  tags = {
    Name        = "a13e-${var.environment}-stripe-secret-key"
    Environment = var.environment
  }

  # Prevent accidental deletion - required for billing
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_secretsmanager_secret_version" "stripe_secret_key" {
  count         = var.stripe_secret_key != "" ? 1 : 0
  secret_id     = aws_secretsmanager_secret.stripe_secret_key[0].id
  secret_string = var.stripe_secret_key
}

resource "aws_secretsmanager_secret" "stripe_webhook_secret" {
  count = var.stripe_webhook_secret != "" ? 1 : 0
  name  = "a13e/${var.environment}/stripe-webhook-secret"

  tags = {
    Name        = "a13e-${var.environment}-stripe-webhook-secret"
    Environment = var.environment
  }

  # Prevent accidental deletion - required for billing webhooks
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_secretsmanager_secret_version" "stripe_webhook_secret" {
  count         = var.stripe_webhook_secret != "" ? 1 : 0
  secret_id     = aws_secretsmanager_secret.stripe_webhook_secret[0].id
  secret_string = var.stripe_webhook_secret
}

resource "aws_secretsmanager_secret" "github_client_secret" {
  count = var.github_client_secret != "" ? 1 : 0
  name  = "a13e/${var.environment}/github-client-secret"

  tags = {
    Name        = "a13e-${var.environment}-github-client-secret"
    Environment = var.environment
  }

  # Prevent accidental deletion - required for GitHub SSO
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_secretsmanager_secret_version" "github_client_secret" {
  count         = var.github_client_secret != "" ? 1 : 0
  secret_id     = aws_secretsmanager_secret.github_client_secret[0].id
  secret_string = var.github_client_secret
}

# Support API key secret - ALWAYS exists (not conditional)
# This prevents terraform from trying to delete it when the variable is empty
resource "aws_secretsmanager_secret" "support_api_key" {
  name = "a13e/${var.environment}/support-api-key"

  tags = {
    Name        = "a13e-${var.environment}-support-api-key"
    Environment = var.environment
  }

  # Prevent accidental deletion - this secret is required for support system
  lifecycle {
    prevent_destroy = true
  }
}

# Secret version ALWAYS exists - uses provided value or placeholder
# This ensures ECS can always reference the secret (even if empty/placeholder)
# The backend gracefully handles missing SUPPORT_API_KEY with a 503 response
resource "aws_secretsmanager_secret_version" "support_api_key" {
  secret_id     = aws_secretsmanager_secret.support_api_key.id
  secret_string = var.support_api_key != "" ? var.support_api_key : "NOT_CONFIGURED"
  # Note: No ignore_changes - secret updates when TF_VAR_support_api_key changes
}

# Initial admin password secret - for auto-seeding admin user on first deployment
resource "aws_secretsmanager_secret" "initial_admin_password" {
  name = "a13e/${var.environment}/initial-admin-password"

  tags = {
    Name        = "a13e-${var.environment}-initial-admin-password"
    Environment = var.environment
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_secretsmanager_secret_version" "initial_admin_password" {
  secret_id     = aws_secretsmanager_secret.initial_admin_password.id
  secret_string = var.initial_admin_password != "" ? var.initial_admin_password : "NOT_CONFIGURED"
}

# IAM Policy for ECS Execution Role to read secrets
resource "aws_iam_role_policy" "ecs_execution_secrets" {
  name = "a13e-${var.environment}-ecs-secrets-policy"
  role = aws_iam_role.ecs_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "secretsmanager:GetSecretValue"
      ]
      Resource = concat(
        [aws_secretsmanager_secret.jwt_secret.arn],
        [aws_secretsmanager_secret.support_api_key.arn],           # Always included - support system
        [aws_secretsmanager_secret.initial_admin_password.arn],    # Always included - admin seeding
        [aws_secretsmanager_secret.credential_encryption_key.arn], # Always created - cloud cred encryption
        var.stripe_secret_key != "" ? [aws_secretsmanager_secret.stripe_secret_key[0].arn] : [],
        var.stripe_webhook_secret != "" ? [aws_secretsmanager_secret.stripe_webhook_secret[0].arn] : [],
        var.github_client_secret != "" ? [aws_secretsmanager_secret.github_client_secret[0].arn] : []
      )
    }]
  })
}

# ECS Task Definition
# All environments need adequate resources to handle concurrent scans and API traffic
# Staging was hitting 100% CPU with 512 units, causing 504 timeouts during scans
resource "aws_ecs_task_definition" "backend" {
  family                   = "a13e-${var.environment}-backend"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "1024"
  memory                   = "2048"
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([{
    name  = "backend"
    image = "${var.ecr_repository_url}:latest"

    portMappings = [{
      containerPort = 8000
      hostPort      = 8000
      protocol      = "tcp"
    }]

    # Non-sensitive environment variables
    environment = concat([
      { name = "DATABASE_URL", value = var.database_url },
      { name = "REDIS_URL", value = var.redis_url },
      { name = "ENVIRONMENT", value = var.environment },
      { name = "DEBUG", value = var.environment == "prod" ? "false" : "true" },
      { name = "DISABLE_SCAN_LIMITS", value = var.environment == "prod" ? "false" : "true" },
      { name = "HIBP_FAIL_CLOSED", value = var.environment == "prod" ? "true" : "false" },
      { name = "A13E_DEV_MODE", value = "false" },
      { name = "STRIPE_PRICE_ID_INDIVIDUAL", value = var.stripe_price_ids.individual },
      { name = "STRIPE_PRICE_ID_PRO", value = var.stripe_price_ids.pro },
      { name = "STRIPE_PRICE_ID_ADDITIONAL_ACCOUNT", value = var.stripe_price_ids.additional_account },
      { name = "CORS_ORIGINS", value = var.frontend_url != "" && var.frontend_url != "http://localhost:3001" ? var.frontend_url : "*" },
      { name = "FRONTEND_URL", value = var.frontend_url },
      { name = "FORCE_RELOAD_COMPLIANCE", value = var.force_reload_compliance ? "true" : "false" },
      { name = "COOKIE_DOMAIN", value = var.cookie_domain },
      # Trust X-Forwarded-For headers from ALB (required for correct client IP in audit logs)
      { name = "TRUST_PROXY_HEADERS", value = "true" },
      { name = "TRUSTED_PROXY_CIDRS", value = "10.0.0.0/8" }
      ],
      # Cognito OAuth configuration (only if Cognito is enabled)
      var.cognito_user_pool_id != "" ? [
        { name = "COGNITO_USER_POOL_ID", value = var.cognito_user_pool_id },
        { name = "COGNITO_CLIENT_ID", value = var.cognito_client_id },
        { name = "COGNITO_DOMAIN", value = var.cognito_domain },
        { name = "COGNITO_ISSUER", value = var.cognito_issuer }
      ] : [],
      # Google OAuth (via Cognito)
      var.google_client_id != "" ? [{ name = "GOOGLE_CLIENT_ID", value = var.google_client_id }] : [],
      # GitHub OAuth Client ID (not secret)
      var.github_client_id != "" ? [{ name = "GITHUB_CLIENT_ID", value = var.github_client_id }] : [],
      # SES Email configuration
      [
        { name = "SES_ENABLED", value = "true" },
        { name = "SES_FROM_EMAIL", value = "noreply@a13e.com" },
        { name = "APP_URL", value = var.frontend_url }
      ],
      # Google Workspace WIF configuration (only when enabled)
      var.workspace_wif_enabled ? [
        { name = "WORKSPACE_WIF_ENABLED", value = "true" },
        { name = "WORKSPACE_GCP_PROJECT_NUMBER", value = var.workspace_gcp_project_number },
        { name = "WORKSPACE_WIF_POOL_ID", value = var.workspace_wif_pool_id },
        { name = "WORKSPACE_WIF_PROVIDER_ID", value = var.workspace_wif_provider_id },
        { name = "WORKSPACE_SERVICE_ACCOUNT_EMAIL", value = var.workspace_service_account_email },
        { name = "WORKSPACE_ADMIN_EMAIL", value = var.workspace_admin_email },
        { name = "SUPPORT_CRM_SPREADSHEET_ID", value = var.support_crm_spreadsheet_id },
        { name = "TELEMETRY_SHEET_ID", value = var.telemetry_sheet_id }
      ] : []
    )

    # Sensitive values loaded from Secrets Manager
    # ECS will inject these as environment variables at container startup
    secrets = concat([
      {
        name      = "SECRET_KEY"
        valueFrom = aws_secretsmanager_secret.jwt_secret.arn
      }
      ],
      [{
        name      = "CREDENTIAL_ENCRYPTION_KEY"
        valueFrom = aws_secretsmanager_secret.credential_encryption_key.arn
      }],
      var.stripe_secret_key != "" ? [{
        name      = "STRIPE_SECRET_KEY"
        valueFrom = aws_secretsmanager_secret.stripe_secret_key[0].arn
      }] : [],
      var.stripe_webhook_secret != "" ? [{
        name      = "STRIPE_WEBHOOK_SECRET"
        valueFrom = aws_secretsmanager_secret.stripe_webhook_secret[0].arn
      }] : [],
      var.github_client_secret != "" ? [{
        name      = "GITHUB_CLIENT_SECRET"
        valueFrom = aws_secretsmanager_secret.github_client_secret[0].arn
      }] : [],
      # SUPPORT_API_KEY is ALWAYS included - secret always exists with value or placeholder
      [{
        name      = "SUPPORT_API_KEY"
        valueFrom = aws_secretsmanager_secret.support_api_key.arn
      }],
      # INITIAL_ADMIN_PASSWORD for auto-seeding admin user on first deployment
      [{
        name      = "INITIAL_ADMIN_PASSWORD"
        valueFrom = aws_secretsmanager_secret.initial_admin_password.arn
      }]
    )

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.backend.name
        "awslogs-region"        = data.aws_region.current.region
        "awslogs-stream-prefix" = "backend"
      }
    }

    healthCheck = {
      command     = ["CMD-SHELL", "curl -f http://localhost:8000/health || exit 1"]
      interval    = 30
      timeout     = 5
      retries     = 3
      startPeriod = 60
    }
  }])

  tags = {
    Name = "a13e-${var.environment}-backend-task"
  }
}

# ECS Service
resource "aws_ecs_service" "backend" {
  name            = "a13e-${var.environment}-backend"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.backend.arn
  desired_count   = 1 # Scale up when we have customers
  launch_type     = "FARGATE"

  # Enable ECS Exec for debugging and running scripts
  enable_execute_command = true

  network_configuration {
    # When use_private_subnets=true, ECS runs in private subnets with NAT Gateway
    # (Secure by Design: no public IPs on application workloads)
    # When use_private_subnets=false, ECS runs in public subnets with public IPs
    # (Cost-optimised: no NAT Gateway required for staging)
    subnets          = var.use_private_subnets ? var.private_subnet_ids : var.public_subnet_ids
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = var.use_private_subnets ? false : true
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.main.arn
    container_name   = "backend"
    container_port   = 8000
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  deployment_minimum_healthy_percent = 50
  deployment_maximum_percent         = 200

  tags = {
    Name = "a13e-${var.environment}-backend-service"
  }

  depends_on = [aws_lb_listener.http]
}

# ============================================================================
# WAF Web ACL for API Protection
# ============================================================================

# IP Set for allowed addresses
# NOTE: Always created (no count) to avoid destroy-ordering issues with WAF ACL references.
# When allowed_ips is empty, this is just an empty IP Set and the WAF rule isn't created.
resource "aws_wafv2_ip_set" "api_allowed_ips" {
  name               = "a13e-${var.environment}-api-allowed-ips"
  description        = "IP addresses allowed to access ${var.environment} API"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = var.allowed_ips

  tags = {
    Name        = "a13e-${var.environment}-api-allowed-ips"
    Environment = var.environment
  }
}

# Regional WAF for ALB
resource "aws_wafv2_web_acl" "api" {
  name        = "a13e-${var.environment}-api-waf"
  description = "WAF ACL for A13E ${var.environment} API"
  scope       = "REGIONAL"

  # Default action: block if IP restriction is enabled, allow otherwise
  default_action {
    dynamic "block" {
      for_each = length(var.allowed_ips) > 0 ? [1] : []
      content {}
    }
    dynamic "allow" {
      for_each = length(var.allowed_ips) == 0 ? [1] : []
      content {}
    }
  }

  # Rule 0: Allow /health endpoint from any IP (for deployment health checks)
  # The health endpoint returns minimal info and is safe to expose publicly
  rule {
    name     = "AllowHealthCheckEndpoint"
    priority = 0

    action {
      allow {}
    }

    statement {
      byte_match_statement {
        positional_constraint = "EXACTLY"
        search_string         = "/health"
        field_to_match {
          uri_path {}
        }
        text_transformation {
          priority = 0
          type     = "LOWERCASE"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "a13e-${var.environment}-allow-health-check"
      sampled_requests_enabled   = true
    }
  }

  # Rule 0.5: Allow public access to credential templates (setup scripts)
  # These are non-sensitive bash scripts that users need to download from
  # various environments (Azure Cloud Shell, GCP Cloud Shell, etc.)
  rule {
    name     = "AllowCredentialTemplates"
    priority = 1

    action {
      allow {}
    }

    statement {
      byte_match_statement {
        positional_constraint = "STARTS_WITH"
        search_string         = "/api/v1/credentials/templates/"
        field_to_match {
          uri_path {}
        }
        text_transformation {
          priority = 0
          type     = "LOWERCASE"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "a13e-${var.environment}-allow-templates"
      sampled_requests_enabled   = true
    }
  }

  # Rule 2: Allow traffic from allowlisted IPs (only when IPs specified)
  dynamic "rule" {
    for_each = length(var.allowed_ips) > 0 ? [1] : []
    content {
      name     = "AllowListedIPs"
      priority = 2

      action {
        allow {}
      }

      statement {
        ip_set_reference_statement {
          arn = aws_wafv2_ip_set.api_allowed_ips.arn
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "a13e-${var.environment}-api-allowed-ips"
        sampled_requests_enabled   = true
      }
    }
  }

  # Rule 3: AWS Managed Core Rule Set (CRS) - OWASP Top 10
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 3

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "a13e-${var.environment}-api-crs"
      sampled_requests_enabled   = true
    }
  }

  # Rule 4: Known Bad Inputs
  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 4

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "a13e-${var.environment}-api-known-bad-inputs"
      sampled_requests_enabled   = true
    }
  }

  # Rule 5: SQL Injection Protection
  rule {
    name     = "AWSManagedRulesSQLiRuleSet"
    priority = 5

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "a13e-${var.environment}-api-sqli"
      sampled_requests_enabled   = true
    }
  }

  # Rule 6: Rate Limiting - 2000 requests per 5 minutes per IP
  rule {
    name     = "RateLimitRule"
    priority = 6

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "a13e-${var.environment}-api-rate-limit"
      sampled_requests_enabled   = true
    }
  }

  # Rule 7: Block Anonymous IPs (VPN, Proxy, Tor, Hosting) for Signup Only
  # Fraud prevention: Blocks registration attempts from VPNs, proxies, Tor, and datacentres
  # NOTE: Only applies to POST /api/v1/auth/signup, NOT to:
  # - /auth/accept-invite (invitee may be joining paid org)
  # - OAuth callbacks (can't distinguish login from registration)
  rule {
    name     = "BlockAnonymousIPsForSignup"
    priority = 7

    override_action {
      none {} # Use the rule group's block action
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAnonymousIpList"
        vendor_name = "AWS"

        # Scope: Only apply to POST /api/v1/auth/signup
        scope_down_statement {
          and_statement {
            statement {
              byte_match_statement {
                positional_constraint = "EXACTLY"
                search_string         = "/api/v1/auth/signup"
                field_to_match {
                  uri_path {}
                }
                text_transformation {
                  priority = 0
                  type     = "LOWERCASE"
                }
              }
            }
            statement {
              byte_match_statement {
                positional_constraint = "EXACTLY"
                search_string         = "post"
                field_to_match {
                  method {}
                }
                text_transformation {
                  priority = 0
                  type     = "LOWERCASE"
                }
              }
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "a13e-${var.environment}-anonymous-ip-signup-block"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "a13e-${var.environment}-api-waf"
    sampled_requests_enabled   = true
  }

  tags = {
    Name = "a13e-${var.environment}-api-waf"
  }
}

# Associate WAF with ALB
resource "aws_wafv2_web_acl_association" "api" {
  resource_arn = aws_lb.main.arn
  web_acl_arn  = aws_wafv2_web_acl.api.arn
}

# Outputs
output "alb_dns_name" {
  value = aws_lb.main.dns_name
}

output "alb_zone_id" {
  value = aws_lb.main.zone_id
}

output "api_endpoint" {
  value = var.domain_name != "" ? "https://${var.domain_name}" : "http://${aws_lb.main.dns_name}"
}

output "ecs_cluster_arn" {
  value = aws_ecs_cluster.main.arn
}

output "ecs_service_name" {
  value = aws_ecs_service.backend.name
}

output "ecs_cluster_name" {
  value = aws_ecs_cluster.main.name
}

output "security_group_id" {
  value = aws_security_group.ecs.id
}

output "ecs_security_group_id" {
  value = aws_security_group.ecs.id
}
