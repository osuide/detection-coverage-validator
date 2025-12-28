# CodeBuild Integration Tests Module
# Runs pytest integration tests inside VPC with access to RDS/Redis

variable "environment" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "private_subnet_ids" {
  type = list(string)
}

variable "database_security_group_id" {
  type = string
}

variable "redis_security_group_id" {
  type = string
}

variable "database_url" {
  type      = string
  sensitive = true
}

variable "redis_url" {
  type      = string
  sensitive = true
}

variable "secret_key" {
  type      = string
  sensitive = true
}

variable "github_repo" {
  type        = string
  description = "GitHub repository in format owner/repo"
}

variable "github_token_secret_arn" {
  type        = string
  description = "ARN of Secrets Manager secret containing GitHub token"
  default     = ""
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Security group for CodeBuild
resource "aws_security_group" "codebuild" {
  name_prefix = "a13e-${var.environment}-codebuild-"
  vpc_id      = var.vpc_id

  # Outbound to anywhere (for pip install, GitHub API, etc.)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "a13e-${var.environment}-codebuild-sg"
  }
}

# Allow CodeBuild to access RDS
resource "aws_security_group_rule" "codebuild_to_rds" {
  type                     = "ingress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.codebuild.id
  security_group_id        = var.database_security_group_id
  description              = "CodeBuild integration tests"
}

# Allow CodeBuild to access Redis
resource "aws_security_group_rule" "codebuild_to_redis" {
  type                     = "ingress"
  from_port                = 6379
  to_port                  = 6379
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.codebuild.id
  security_group_id        = var.redis_security_group_id
  description              = "CodeBuild integration tests"
}

# IAM Role for CodeBuild
resource "aws_iam_role" "codebuild" {
  name = "a13e-${var.environment}-codebuild-integration-tests"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "codebuild.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

# IAM Policy for CodeBuild
resource "aws_iam_role_policy" "codebuild" {
  name = "a13e-${var.environment}-codebuild-policy"
  role = aws_iam_role.codebuild.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = [
          "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/codebuild/a13e-${var.environment}-integration-tests",
          "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/codebuild/a13e-${var.environment}-integration-tests:*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:CreateNetworkInterface",
          "ec2:DescribeDhcpOptions",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DeleteNetworkInterface",
          "ec2:DescribeSubnets",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeVpcs"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:CreateNetworkInterfacePermission"
        ]
        Resource = "arn:aws:ec2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:network-interface/*"
        Condition = {
          StringEquals = {
            "ec2:Subnet" = [for subnet_id in var.private_subnet_ids : "arn:aws:ec2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:subnet/${subnet_id}"]
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = var.github_token_secret_arn != "" ? [var.github_token_secret_arn] : []
      }
    ]
  })
}

# Store secrets in SSM Parameter Store for CodeBuild
resource "aws_ssm_parameter" "database_url" {
  name  = "/a13e/${var.environment}/codebuild/database-url"
  type  = "SecureString"
  value = var.database_url

  tags = {
    Name = "a13e-${var.environment}-codebuild-database-url"
  }
}

resource "aws_ssm_parameter" "redis_url" {
  name  = "/a13e/${var.environment}/codebuild/redis-url"
  type  = "SecureString"
  value = var.redis_url

  tags = {
    Name = "a13e-${var.environment}-codebuild-redis-url"
  }
}

resource "aws_ssm_parameter" "secret_key" {
  name  = "/a13e/${var.environment}/codebuild/secret-key"
  type  = "SecureString"
  value = var.secret_key

  tags = {
    Name = "a13e-${var.environment}-codebuild-secret-key"
  }
}

# Allow CodeBuild to read SSM parameters
resource "aws_iam_role_policy" "codebuild_ssm" {
  name = "a13e-${var.environment}-codebuild-ssm"
  role = aws_iam_role.codebuild.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "ssm:GetParameters",
        "ssm:GetParameter"
      ]
      Resource = [
        aws_ssm_parameter.database_url.arn,
        aws_ssm_parameter.redis_url.arn,
        aws_ssm_parameter.secret_key.arn
      ]
    }]
  })
}

# CodeBuild Project
resource "aws_codebuild_project" "integration_tests" {
  name          = "a13e-${var.environment}-integration-tests"
  description   = "Integration tests for A13E Detection Coverage Validator"
  build_timeout = 15 # minutes
  service_role  = aws_iam_role.codebuild.arn

  artifacts {
    type = "NO_ARTIFACTS"
  }

  environment {
    compute_type                = "BUILD_GENERAL1_SMALL"
    image                       = "aws/codebuild/amazonlinux2-x86_64-standard:5.0"
    type                        = "LINUX_CONTAINER"
    image_pull_credentials_type = "CODEBUILD"

    environment_variable {
      name  = "ENVIRONMENT"
      value = var.environment
    }

    environment_variable {
      name  = "DATABASE_URL"
      value = aws_ssm_parameter.database_url.name
      type  = "PARAMETER_STORE"
    }

    environment_variable {
      name  = "REDIS_URL"
      value = aws_ssm_parameter.redis_url.name
      type  = "PARAMETER_STORE"
    }

    environment_variable {
      name  = "SECRET_KEY"
      value = aws_ssm_parameter.secret_key.name
      type  = "PARAMETER_STORE"
    }
  }

  source {
    type            = "GITHUB"
    location        = "https://github.com/${var.github_repo}.git"
    git_clone_depth = 1
    buildspec       = <<-EOF
      version: 0.2

      env:
        variables:
          TEST_PATH: "tests/integration/"

      phases:
        install:
          runtime-versions:
            python: 3.12
          commands:
            - echo "Installing dependencies..."
            - cd backend
            - pip install -r requirements.txt
            - pip install pytest pytest-asyncio httpx pyotp

        build:
          commands:
            - echo "Running integration tests..."
            - echo "Test path: $TEST_PATH"
            - cd backend
            - PYTHONPATH=. pytest $TEST_PATH -v --tb=short --junitxml=test-results.xml 2>&1 | tee test-output.txt
            - TEST_EXIT=$?
            - echo "Tests completed with exit code $TEST_EXIT"
            - exit $TEST_EXIT

      reports:
        integration-tests:
          files:
            - backend/test-results.xml
          file-format: JUNITXML

      cache:
        paths:
          - '/root/.cache/pip/**/*'
    EOF
  }

  vpc_config {
    vpc_id             = var.vpc_id
    subnets            = var.private_subnet_ids
    security_group_ids = [aws_security_group.codebuild.id]
  }

  logs_config {
    cloudwatch_logs {
      group_name  = "/aws/codebuild/a13e-${var.environment}-integration-tests"
      stream_name = "build-log"
    }
  }

  tags = {
    Name = "a13e-${var.environment}-integration-tests"
  }
}

# IAM Policy for GitHub Actions to trigger CodeBuild
# Attach this policy to your GitHub Actions IAM user
resource "aws_iam_policy" "github_actions_codebuild" {
  name        = "a13e-${var.environment}-github-actions-codebuild"
  description = "Allows GitHub Actions to trigger CodeBuild integration tests"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "StartBuild"
        Effect = "Allow"
        Action = [
          "codebuild:StartBuild",
          "codebuild:BatchGetBuilds"
        ]
        Resource = aws_codebuild_project.integration_tests.arn
      },
      {
        Sid    = "ReadBuildLogs"
        Effect = "Allow"
        Action = [
          "logs:GetLogEvents"
        ]
        Resource = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/codebuild/a13e-${var.environment}-integration-tests:*"
      }
    ]
  })
}

# Outputs
output "project_name" {
  value = aws_codebuild_project.integration_tests.name
}

output "project_arn" {
  value = aws_codebuild_project.integration_tests.arn
}

output "security_group_id" {
  value = aws_security_group.codebuild.id
}

output "github_actions_policy_arn" {
  value       = aws_iam_policy.github_actions_codebuild.arn
  description = "Attach this policy to your GitHub Actions IAM user"
}
