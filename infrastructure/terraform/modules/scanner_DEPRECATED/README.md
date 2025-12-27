# Scanner Module (DEPRECATED)

**Status:** Deprecated and removed from infrastructure (December 2025)

## Why This Was Removed

1. **Never actively used** - The scanner ECS cluster had 0 running services
2. **Scans run inline** - All scans execute on the backend ECS tasks via `ScanService.execute_scan()`
3. **Cost savings** - Removing this eliminated the need for ~$72/month in VPC endpoints

## Original Purpose

This module was designed to run scan jobs as separate Fargate tasks in private subnets, with:
- Dedicated ECS cluster for scan workloads
- SQS queue for job distribution
- IAM roles for cross-account scanning

## If You Need Dedicated Scan Workers in Future

Options to consider:
1. **Run on existing backend cluster** - Add task definitions to the backend ECS cluster
2. **Use Lambda** - For short-running scans (<15 min)
3. **Re-enable this module** - But add NAT Gateway for internet access (~$32/mo)

## Files

- `main.tf` - Original Terraform configuration (preserved for reference)
