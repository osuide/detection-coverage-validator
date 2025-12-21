variable "environment" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "private_subnet_ids" {
  type = list(string)
}

variable "node_type" {
  type = string
}

resource "aws_security_group" "redis" {
  name_prefix = "dcv-${var.environment}-redis-"
  description = "Security group for Redis cache - ingress rules added by backend module"
  vpc_id      = var.vpc_id

  # Ingress rules are added by the backend module using aws_security_group_rule
  # to allow only ECS containers to access Redis (no CIDR blocks)

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "dcv-${var.environment}-redis-sg"
  }
}

resource "aws_elasticache_subnet_group" "main" {
  name       = "dcv-${var.environment}-redis-subnet-group"
  subnet_ids = var.private_subnet_ids
}

resource "aws_elasticache_cluster" "main" {
  cluster_id           = "dcv-${var.environment}-redis"
  engine               = "redis"
  engine_version       = "7.0"
  node_type            = var.node_type
  num_cache_nodes      = 1
  parameter_group_name = "default.redis7"
  port                 = 6379

  subnet_group_name  = aws_elasticache_subnet_group.main.name
  security_group_ids = [aws_security_group.redis.id]

  tags = {
    Name = "dcv-${var.environment}-redis"
  }
}

output "endpoint" {
  value = aws_elasticache_cluster.main.cache_nodes[0].address
}

output "connection_string" {
  value = "redis://${aws_elasticache_cluster.main.cache_nodes[0].address}:6379/0"
}

output "security_group_id" {
  value = aws_security_group.redis.id
}
