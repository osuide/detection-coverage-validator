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

variable "auth_token" {
  description = "AUTH token for Redis authentication. Must be 16-128 characters."
  type        = string
  sensitive   = true
}

resource "aws_security_group" "redis" {
  name_prefix = "dcv-${var.environment}-redis-"
  vpc_id      = var.vpc_id

  # Security: No inline ingress rules - managed by aws_security_group_rule in backend module
  # This uses source_security_group_id for proper SG-to-SG rules instead of broad CIDR blocks

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

# Using replication group instead of cluster to enable encryption
resource "aws_elasticache_replication_group" "main" {
  replication_group_id = "dcv-${var.environment}-redis"
  description          = "Redis cache for ${var.environment} environment"

  engine               = "redis"
  engine_version       = "7.0"
  node_type            = var.node_type
  num_cache_clusters   = 1
  parameter_group_name = "default.redis7"
  port                 = 6379

  subnet_group_name  = aws_elasticache_subnet_group.main.name
  security_group_ids = [aws_security_group.redis.id]

  # Security: Enable encryption and AUTH
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true # Required for AUTH token
  auth_token                 = var.auth_token

  # Maintenance window (off-peak hours UK time)
  maintenance_window = "sun:03:00-sun:04:00"

  # Auto minor version upgrade for security patches
  auto_minor_version_upgrade = true

  tags = {
    Name = "dcv-${var.environment}-redis"
  }
}

output "endpoint" {
  value = aws_elasticache_replication_group.main.primary_endpoint_address
}

output "connection_string" {
  # Use rediss:// (with double s) for TLS connection
  # Include AUTH token in URL format: rediss://:password@host:port/db
  value     = "rediss://:${var.auth_token}@${aws_elasticache_replication_group.main.primary_endpoint_address}:6379/0"
  sensitive = true
}

output "security_group_id" {
  value = aws_security_group.redis.id
}
