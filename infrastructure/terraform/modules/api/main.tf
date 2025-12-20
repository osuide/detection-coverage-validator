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

# API Lambda Security Group
resource "aws_security_group" "lambda" {
  name_prefix = "dcv-${var.environment}-lambda-"
  vpc_id      = var.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "dcv-${var.environment}-lambda-sg"
  }
}

# IAM Role for Lambda
resource "aws_iam_role" "lambda" {
  name = "dcv-${var.environment}-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_vpc" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

variable "secrets_arns" {
  type        = list(string)
  default     = []
  description = "List of Secrets Manager ARNs the Lambda can access"
}

variable "sqs_queue_arns" {
  type        = list(string)
  default     = []
  description = "List of SQS queue ARNs the Lambda can access"
}

resource "aws_iam_role_policy" "lambda_custom" {
  name = "dcv-${var.environment}-lambda-policy"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      # Secrets Manager - only access specific secrets
      length(var.secrets_arns) > 0 ? [
        {
          Sid    = "SecretsManagerAccess"
          Effect = "Allow"
          Action = [
            "secretsmanager:GetSecretValue"
          ]
          Resource = var.secrets_arns
        }
      ] : [],
      # SQS - only access specific queues
      length(var.sqs_queue_arns) > 0 ? [
        {
          Sid    = "SQSAccess"
          Effect = "Allow"
          Action = [
            "sqs:SendMessage",
            "sqs:ReceiveMessage",
            "sqs:DeleteMessage",
            "sqs:GetQueueAttributes"
          ]
          Resource = var.sqs_queue_arns
        }
      ] : [],
      # CloudWatch Logs (required for Lambda execution)
      [
        {
          Sid    = "CloudWatchLogs"
          Effect = "Allow"
          Action = [
            "logs:CreateLogGroup",
            "logs:CreateLogStream",
            "logs:PutLogEvents"
          ]
          Resource = "arn:aws:logs:*:*:log-group:/aws/lambda/dcv-${var.environment}-*"
        }
      ]
    )
  })
}

# Placeholder for Lambda function - will be deployed via CI/CD
# resource "aws_lambda_function" "api" {
#   function_name = "dcv-${var.environment}-api"
#   role          = aws_iam_role.lambda.arn
#   ...
# }

# API Gateway
resource "aws_apigatewayv2_api" "main" {
  name          = "dcv-${var.environment}-api"
  protocol_type = "HTTP"

  cors_configuration {
    allow_headers = ["*"]
    allow_methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    allow_origins = ["*"]
    max_age       = 3600
  }

  tags = {
    Name = "dcv-${var.environment}-api"
  }
}

resource "aws_apigatewayv2_stage" "main" {
  api_id      = aws_apigatewayv2_api.main.id
  name        = var.environment
  auto_deploy = true
}

output "api_endpoint" {
  value = aws_apigatewayv2_api.main.api_endpoint
}

output "api_id" {
  value = aws_apigatewayv2_api.main.id
}

output "lambda_role_arn" {
  value = aws_iam_role.lambda.arn
}

output "security_group_id" {
  value = aws_security_group.lambda.id
}
