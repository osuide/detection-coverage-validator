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

resource "random_password" "db_password" {
  length  = 32
  special = false
}

resource "aws_security_group" "db" {
  name_prefix = "dcv-${var.environment}-db-"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 5432
    to_port     = 5432
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

resource "aws_db_instance" "main" {
  identifier     = "dcv-${var.environment}-db"
  engine         = "postgres"
  engine_version = "15.4"
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
