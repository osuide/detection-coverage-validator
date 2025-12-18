variable "environment" {
  type = string
}

variable "vpc_id" {
  type = string
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

variable "ecr_repository_url" {
  type = string
}

# ECS Cluster
resource "aws_ecs_cluster" "main" {
  name = "dcv-${var.environment}-scanner"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = {
    Name = "dcv-${var.environment}-scanner-cluster"
  }
}

# Security Group for Fargate Tasks
resource "aws_security_group" "scanner" {
  name_prefix = "dcv-${var.environment}-scanner-"
  vpc_id      = var.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "dcv-${var.environment}-scanner-sg"
  }
}

# IAM Role for ECS Task Execution
resource "aws_iam_role" "ecs_execution" {
  name = "dcv-${var.environment}-ecs-execution-role"

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

# IAM Role for ECS Task (scanner permissions)
resource "aws_iam_role" "ecs_task" {
  name = "dcv-${var.environment}-ecs-task-role"

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

resource "aws_iam_role_policy" "scanner_permissions" {
  name = "dcv-${var.environment}-scanner-policy"
  role = aws_iam_role.ecs_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
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
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "sts:AssumeRole"
        ]
        Resource = "arn:aws:iam::*:role/DCVScannerRole"
      }
    ]
  })
}

# ECS Task Definition
resource "aws_ecs_task_definition" "scanner" {
  family                   = "dcv-${var.environment}-scanner"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "512"
  memory                   = "1024"
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([{
    name  = "scanner"
    image = "${var.ecr_repository_url}:latest"

    environment = [
      { name = "DATABASE_URL", value = var.database_url },
      { name = "REDIS_URL", value = var.redis_url },
      { name = "ENVIRONMENT", value = var.environment }
    ]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = "/ecs/dcv-${var.environment}-scanner"
        "awslogs-region"        = data.aws_region.current.name
        "awslogs-stream-prefix" = "scanner"
      }
    }
  }])

  tags = {
    Name = "dcv-${var.environment}-scanner-task"
  }
}

data "aws_region" "current" {}

# CloudWatch Log Group
resource "aws_cloudwatch_log_group" "scanner" {
  name              = "/ecs/dcv-${var.environment}-scanner"
  retention_in_days = 30

  tags = {
    Name = "dcv-${var.environment}-scanner-logs"
  }
}

# SQS Queue for scan jobs
resource "aws_sqs_queue" "scan_jobs" {
  name                       = "dcv-${var.environment}-scan-jobs"
  visibility_timeout_seconds = 900  # 15 minutes
  message_retention_seconds  = 86400  # 1 day

  tags = {
    Name = "dcv-${var.environment}-scan-jobs"
  }
}

output "cluster_arn" {
  value = aws_ecs_cluster.main.arn
}

output "task_definition_arn" {
  value = aws_ecs_task_definition.scanner.arn
}

output "sqs_queue_url" {
  value = aws_sqs_queue.scan_jobs.url
}

output "security_group_id" {
  value = aws_security_group.scanner.id
}
