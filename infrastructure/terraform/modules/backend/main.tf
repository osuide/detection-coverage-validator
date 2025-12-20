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
  type = object({
    subscriber         = string
    enterprise         = string
    additional_account = string
  })
  default = {
    subscriber         = ""
    enterprise         = ""
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

# Note: Microsoft SSO has been removed from the product

variable "allowed_ips" {
  type        = list(string)
  description = "List of IP addresses (CIDR notation) allowed to access the API. Empty list allows all traffic."
  default     = []
}

data "aws_region" "current" {}

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

  enable_deletion_protection = var.environment == "prod"

  tags = {
    Name = "a13e-${var.environment}-alb"
  }
}

# Target Group
resource "aws_lb_target_group" "main" {
  name        = "a13e-${var.environment}-tg"
  port        = 8000
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

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
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = "*"
      },
      {
        Sid    = "AssumeCustomerScannerRoles"
        Effect = "Allow"
        Action = [
          "sts:AssumeRole"
        ]
        Resource = "arn:aws:iam::*:role/*"
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
        Sid    = "SESSendEmail"
        Effect = "Allow"
        Action = [
          "ses:SendEmail",
          "ses:SendRawEmail"
        ]
        Resource = "*"
      }
    ]
  })
}

# ECS Task Definition
resource "aws_ecs_task_definition" "backend" {
  family                   = "a13e-${var.environment}-backend"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "512"
  memory                   = "1024"
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

    environment = concat([
      { name = "DATABASE_URL", value = var.database_url },
      { name = "REDIS_URL", value = var.redis_url },
      { name = "ENVIRONMENT", value = var.environment },
      { name = "DEBUG", value = var.environment == "prod" ? "false" : "true" },
      { name = "A13E_DEV_MODE", value = "false" },
      { name = "SECRET_KEY", value = var.jwt_secret_key },
      { name = "STRIPE_SECRET_KEY", value = var.stripe_secret_key },
      { name = "STRIPE_WEBHOOK_SECRET", value = var.stripe_webhook_secret },
      { name = "STRIPE_PRICE_ID_SUBSCRIBER", value = var.stripe_price_ids.subscriber },
      { name = "STRIPE_PRICE_ID_ENTERPRISE", value = var.stripe_price_ids.enterprise },
      { name = "STRIPE_PRICE_ID_ADDITIONAL_ACCOUNT", value = var.stripe_price_ids.additional_account },
      { name = "CORS_ORIGINS", value = var.frontend_url != "" && var.frontend_url != "http://localhost:3001" ? var.frontend_url : "*" },
      { name = "FRONTEND_URL", value = var.frontend_url }
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
      # GitHub OAuth (handled by backend directly, not Cognito)
      var.github_client_id != "" ? [{ name = "GITHUB_CLIENT_ID", value = var.github_client_id }] : [],
      var.github_client_secret != "" ? [{ name = "GITHUB_CLIENT_SECRET", value = var.github_client_secret }] : [],
      # SES Email configuration
      [
        { name = "SES_ENABLED", value = "true" },
        { name = "SES_FROM_EMAIL", value = "noreply@a13e.com" },
        { name = "APP_URL", value = var.frontend_url }
    ])

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.backend.name
        "awslogs-region"        = data.aws_region.current.name
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
  desired_count   = var.environment == "prod" ? 2 : 1
  launch_type     = "FARGATE"

  network_configuration {
    # Using public subnets with public IPs to allow outbound internet access
    # (required for Cognito OAuth token exchange - no VPC endpoint available)
    subnets          = var.public_subnet_ids
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = true
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

# IP Set for allowed addresses (only created when IPs are specified)
resource "aws_wafv2_ip_set" "api_allowed_ips" {
  count              = length(var.allowed_ips) > 0 ? 1 : 0
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

  # Rule 0: Allow traffic from allowlisted IPs (highest priority, only when IPs specified)
  dynamic "rule" {
    for_each = length(var.allowed_ips) > 0 ? [1] : []
    content {
      name     = "AllowListedIPs"
      priority = 0

      action {
        allow {}
      }

      statement {
        ip_set_reference_statement {
          arn = aws_wafv2_ip_set.api_allowed_ips[0].arn
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "a13e-${var.environment}-api-allowed-ips"
        sampled_requests_enabled   = true
      }
    }
  }

  # Rule 1: AWS Managed Core Rule Set (CRS) - OWASP Top 10
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1

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

  # Rule 2: Known Bad Inputs
  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 2

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

  # Rule 3: SQL Injection Protection
  rule {
    name     = "AWSManagedRulesSQLiRuleSet"
    priority = 3

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

  # Rule 4: Rate Limiting - 2000 requests per 5 minutes per IP
  rule {
    name     = "RateLimitRule"
    priority = 4

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
