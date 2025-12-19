# A13E Detection Coverage Validator - Claude Code Instructions

## Language Requirements

**All text content must use UK English spelling and conventions.** This applies to:
- User-facing content (UI text, documentation, error messages)
- Code comments and docstrings
- Remediation templates and security guidance
- API responses and messages

Common UK English spellings to use:
- colour (not color)
- organisation (not organization)
- authorised (not authorized)
- defence (not defense)
- analyse (not analyze)
- behaviour (not behavior)
- favour (not favor)
- honour (not honor)
- centre (not center)
- licence (noun) / license (verb)
- practise (verb) / practice (noun)
- travelling (not traveling)
- modelling (not modeling)
- catalogue (not catalog)
- cheque (not check, for payments)
- programme (not program, for schedules/events)

## Project Context

This is a **multi-cloud security detection coverage validator** that:
- Scans **AWS and GCP** environments for existing security detections
- Maps detections to MITRE ATT&CK framework
- Identifies coverage gaps and provides remediation guidance
- Provides technique-specific detection strategies with IaC templates

**Cloud Support**: AWS & GCP are included in all subscription plans.

## Remediation Template Requirements

Every MITRE ATT&CK technique template should provide:
- **AWS**: CloudFormation + Terraform templates
- **GCP**: Terraform templates (primary IaC for GCP)
- Both in simplified 3-step format with clear comments
- CloudWatch/Cloud Logging queries where applicable

## Key Components

- **Backend**: FastAPI with PostgreSQL, located in `/backend`
- **Frontend**: React with TypeScript, located in `/frontend`
- **Infrastructure**: Terraform for AWS, located in `/infrastructure/terraform`
- **Documentation**: User guides in `/docs/user-guide`
- **Remediation Templates**: `/backend/app/data/remediation_templates`

## Coding Standards

- Python: Follow PEP 8, use type hints
- TypeScript: Strict mode enabled, use interfaces over types
- All API endpoints should be documented with OpenAPI schemas
- Tests should be placed adjacent to the code they test
