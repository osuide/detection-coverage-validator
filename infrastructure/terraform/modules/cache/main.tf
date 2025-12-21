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
  vpc_id      = var.vpc_id

  # Inline ingress is kept for state compatibility but managed externally
  # The actual restrictive rule is aws_security_group_rule.ecs_to_redis in backend module
  # which uses source_security_group_id instead of CIDR blocks
  ingress {
    from_port   = 6379
    to_port     = 6379
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "dcv-${var.environment}-redis-sg"
  }

  lifecycle {
    # Ingress rules are also managed by backend module via aws_security_group_rule
    # Ignore inline changes to prevent recreation of in-use security groups
    ignore_changes = [ingress]
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
