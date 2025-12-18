variable "environment" {
  type = string
}

resource "aws_ecr_repository" "scanner" {
  name                 = "dcv-${var.environment}-scanner"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Name = "dcv-${var.environment}-scanner"
  }
}

resource "aws_ecr_lifecycle_policy" "scanner" {
  repository = aws_ecr_repository.scanner.name

  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep last 10 images"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 10
      }
      action = {
        type = "expire"
      }
    }]
  })
}

output "repository_url" {
  value = aws_ecr_repository.scanner.repository_url
}

output "repository_arn" {
  value = aws_ecr_repository.scanner.arn
}
