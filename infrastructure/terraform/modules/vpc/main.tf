# VPC Module with optional NAT Gateway
# Supports both cost-optimised (public subnets) and Secure by Design (private subnets) architectures

variable "environment" {
  type = string
}

variable "vpc_cidr" {
  type = string
}

variable "enable_nat_gateway" {
  description = "Enable NAT Gateway for private subnet internet access"
  type        = bool
  default     = false
}

variable "single_nat_gateway" {
  description = "Use single NAT Gateway (cost-optimised) vs multi-AZ (HA for production)"
  type        = bool
  default     = true
}

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_region" "current" {}

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "a13e-${var.environment}-vpc"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "a13e-${var.environment}-igw"
  }
}

# Public subnets (for ALB)
resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name = "a13e-${var.environment}-public-${count.index + 1}"
    Type = "public"
  }
}

# Private subnets (for ECS, RDS, ElastiCache)
resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + 10)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "a13e-${var.environment}-private-${count.index + 1}"
    Type = "private"
  }
}

# Public route table (routes to internet gateway)
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "a13e-${var.environment}-public-rt"
  }
}

# Private route table (no internet route - uses VPC endpoints)
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "a13e-${var.environment}-private-rt"
  }
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# =============================================================================
# NAT Gateway (Optional - for Secure by Design production architecture)
# =============================================================================
# Enables ECS tasks in private subnets to access external APIs (Stripe, HIBP, etc.)
# Multi-AZ deployment uses one NAT Gateway per AZ for high availability

# Elastic IP for NAT Gateway
resource "aws_eip" "nat" {
  count  = var.enable_nat_gateway ? (var.single_nat_gateway ? 1 : length(aws_subnet.public)) : 0
  domain = "vpc"

  tags = {
    Name = var.single_nat_gateway ? "a13e-${var.environment}-nat-eip" : "a13e-${var.environment}-nat-eip-${count.index + 1}"
  }

  depends_on = [aws_internet_gateway.main]
}

# NAT Gateway
resource "aws_nat_gateway" "main" {
  count         = var.enable_nat_gateway ? (var.single_nat_gateway ? 1 : length(aws_subnet.public)) : 0
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id

  tags = {
    Name = var.single_nat_gateway ? "a13e-${var.environment}-nat" : "a13e-${var.environment}-nat-${count.index + 1}"
  }

  depends_on = [aws_internet_gateway.main]
}

# Route to NAT Gateway for private subnets
# When single_nat_gateway=true, all private subnets route through one NAT
# When single_nat_gateway=false, each AZ has its own NAT for HA
resource "aws_route" "private_nat" {
  count                  = var.enable_nat_gateway ? 1 : 0
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.main[0].id
}

# Security group for VPC Endpoints - REMOVED
# Previously used for interface VPC endpoints, no longer needed.
# See comment block below for details on why endpoints were removed.

# S3 Gateway Endpoint (FREE) - Keep this as it has no cost
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${data.aws_region.current.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]

  tags = {
    Name = "a13e-${var.environment}-s3-endpoint"
  }
}

# =============================================================================
# Interface VPC Endpoints REMOVED (December 2025)
# =============================================================================
#
# Previously had 5 interface endpoints costing ~$72/month:
# - ECR API, ECR DKR, CloudWatch Logs, Secrets Manager, SSM
#
# These were removed because:
# 1. Backend ECS runs in PUBLIC subnets with public IPs (for external API access)
# 2. Scanner module was never deployed (0 running services)
# 3. RDS/Redis in private subnets don't need outbound internet access
#
# If future workloads need private subnet internet access, options are:
# - NAT Gateway (~$32/mo + data transfer) - simpler, general internet access
# - VPC Endpoints - for specific AWS services only, better security isolation
#
# See CLAUDE.md "Infrastructure Architecture" section for details.
# =============================================================================

output "vpc_id" {
  value = aws_vpc.main.id
}

output "public_subnet_ids" {
  value = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  value = aws_subnet.private[*].id
}

# output "vpc_endpoints_security_group_id" removed - security group no longer exists

output "nat_gateway_ids" {
  description = "IDs of the NAT Gateways (empty if NAT Gateway not enabled)"
  value       = var.enable_nat_gateway ? aws_nat_gateway.main[*].id : []
}

output "nat_public_ips" {
  description = "Public IPs of NAT Gateways (useful for whitelisting with third-party services)"
  value       = var.enable_nat_gateway ? aws_eip.nat[*].public_ip : []
}
