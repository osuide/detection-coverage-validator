variable "environment" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "private_subnet_ids" {
  type = list(string)
}

variable "db_instance_class" {
  type = string
}

variable "db_name" {
  type = string
}

variable "multi_az" {
  description = "Enable Multi-AZ deployment for high availability (automatic failover)"
  type        = bool
  default     = false
}

resource "random_password" "db_password" {
  length  = 32
  special = false
}

resource "aws_security_group" "db" {
  name_prefix = "dcv-${var.environment}-db-"
  vpc_id      = var.vpc_id

  # Security: No inline ingress rules - managed by aws_security_group_rule in backend module
  # This uses source_security_group_id for proper SG-to-SG rules instead of broad CIDR blocks

  # Security: No egress rules needed for RDS
  # AWS Security Groups are stateful - return traffic for allowed inbound connections
  # is automatically permitted. RDS only responds to queries, it doesn't initiate
  # outbound connections to the internet.
  # Removing 0.0.0.0/0 egress improves defense-in-depth.

  tags = {
    Name = "dcv-${var.environment}-db-sg"
  }
}

resource "aws_db_subnet_group" "main" {
  name       = "dcv-${var.environment}-db-subnet-group"
  subnet_ids = var.private_subnet_ids

  tags = {
    Name = "dcv-${var.environment}-db-subnet-group"
  }
}

# Custom parameter group for PostgreSQL audit logging
# Security: Enables logging for compliance and security analysis
resource "aws_db_parameter_group" "postgres" {
  name   = "dcv-${var.environment}-postgres15"
  family = "postgres15"

  # Log all DDL statements (CREATE, ALTER, DROP)
  parameter {
    name  = "log_statement"
    value = "ddl"
  }

  # Log all connections
  parameter {
    name  = "log_connections"
    value = "1"
  }

  # Log all disconnections
  parameter {
    name  = "log_disconnections"
    value = "1"
  }

  # Log duration of completed statements (for performance analysis)
  parameter {
    name  = "log_duration"
    value = "1"
  }

  # Log statements that take longer than 1 second (slow query logging)
  parameter {
    name  = "log_min_duration_statement"
    value = "1000"
  }

  # Log hostname in addition to IP address
  parameter {
    name  = "log_hostname"
    value = "0"
  }

  # Log lock waits (for deadlock analysis)
  parameter {
    name  = "log_lock_waits"
    value = "1"
  }

  tags = {
    Name        = "dcv-${var.environment}-postgres15"
    Environment = var.environment
    Purpose     = "PostgreSQL Audit Logging"
  }
}

resource "aws_db_instance" "main" {
  identifier     = "dcv-${var.environment}-db"
  engine         = "postgres"
  engine_version = "15.15"
  instance_class = var.db_instance_class

  allocated_storage     = 20
  max_allocated_storage = 100
  storage_type          = "gp3"
  storage_encrypted     = true

  db_name  = var.db_name
  username = "dcv_admin"
  password = random_password.db_password.result

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.db.id]
  parameter_group_name   = aws_db_parameter_group.postgres.name

  # High Availability
  multi_az = var.multi_az

  # Auto minor version upgrade for security patches
  auto_minor_version_upgrade = true

  backup_retention_period = 7
  skip_final_snapshot     = var.environment != "prod"
  deletion_protection     = var.environment == "prod"

  tags = {
    Name = "dcv-${var.environment}-db"
  }
}

resource "aws_secretsmanager_secret" "db_password" {
  name = "dcv/${var.environment}/db-password"
}

resource "aws_secretsmanager_secret_version" "db_password" {
  secret_id = aws_secretsmanager_secret.db_password.id
  secret_string = jsonencode({
    username = aws_db_instance.main.username
    password = random_password.db_password.result
    host     = aws_db_instance.main.address
    port     = aws_db_instance.main.port
    dbname   = var.db_name
  })
}

output "endpoint" {
  value = aws_db_instance.main.address
}

output "connection_string" {
  value     = "postgresql+asyncpg://${aws_db_instance.main.username}:${random_password.db_password.result}@${aws_db_instance.main.address}:${aws_db_instance.main.port}/${var.db_name}"
  sensitive = true
}

output "security_group_id" {
  value = aws_security_group.db.id
}
