# A13E Detection Coverage Validator

A multi-cloud security detection coverage analysis platform that maps your existing security detections to the MITRE ATT&CK framework and identifies coverage gaps.

## Overview

A13E automatically discovers security detections across your AWS and GCP environments, maps them to MITRE ATT&CK techniques with confidence scoring, and provides actionable insights to improve your security posture.

### Key Features

- **Multi-Cloud Support**: AWS and GCP with unified coverage analysis
- **Automated Discovery**: Scans 15+ detection sources across both clouds
- **MITRE ATT&CK Mapping**: Pattern-based mapping covering 350+ cloud techniques
- **Coverage Analysis**: Interactive heatmap across 12 tactics
- **Gap Identification**: Risk-prioritised gaps with remediation guidance
- **Compliance Mapping**: CIS Controls v8 and NIST 800-53 Rev 5
- **IaC Templates**: CloudFormation and Terraform remediation templates
- **Team Collaboration**: Role-based access control with SSO support

## Detection Sources

### AWS
| Service | What's Discovered |
|---------|-------------------|
| GuardDuty | Managed threat detection findings |
| Security Hub | FSBP, CIS, PCI-DSS, NIST standards |
| EventBridge | CloudTrail-based detection rules |
| CloudWatch Logs | Insights queries and metric filters |
| CloudWatch Alarms | Metric threshold alerts |
| Config Rules | Compliance rules |
| Inspector | Vulnerability findings |
| Macie | Sensitive data findings |
| Lambda | Custom detection functions |

### GCP
| Service | What's Discovered |
|---------|-------------------|
| Security Command Center | Threat findings and notifications |
| Cloud Logging | Log sinks and log-based metrics |
| Eventarc | Audit log event triggers |
| Cloud Monitoring | Alert policies |
| Cloud Functions | Custom detection functions |
| Chronicle | SIEM detection rules |

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                      Frontend (React + Vite)                         │
│                         Tailwind CSS                                 │
├─────────────────────────────────────────────────────────────────────┤
│                    Application Load Balancer                         │
├─────────────────────────────────────────────────────────────────────┤
│                      Backend (FastAPI + ECS)                         │
│         ┌──────────┬──────────┬──────────┬──────────┐               │
│         │ Scanners │ Mappers  │ Analyzers│ Services │               │
│         │ AWS/GCP  │ ATT&CK   │ Coverage │ Auth/Team│               │
│         └──────────┴──────────┴──────────┴──────────┘               │
├─────────────────────────────────────────────────────────────────────┤
│              PostgreSQL (RDS)          Redis (ElastiCache)           │
└─────────────────────────────────────────────────────────────────────┘
```

## Subscription Plans

| Plan | Price | Accounts | Team | Key Features |
|------|-------|----------|------|--------------|
| **Free** | £0 | 1 | 1 | Coverage heatmap, gap analysis, 30-day retention |
| **Individual** | £29/mo | 6 | 3 | Scheduled scans, API access, 90-day retention |
| **Pro** | £250/mo | 500 | 10 | Organisation scanning, auto-discovery, 1-year retention |
| **Enterprise** | Custom | Unlimited | Unlimited | SSO, dedicated support, custom integrations |

## Quick Start

### Prerequisites

- Python 3.12+
- Node.js 20+
- Docker & Docker Compose
- PostgreSQL 15+
- Redis 7+

### Local Development

```bash
# Clone the repository
git clone https://github.com/osuide/detection-coverage-validator.git
cd detection-coverage-validator

# Start database and Redis
docker-compose up -d postgres redis

# Backend setup
cd backend
python3.12 -m venv .venv312
source .venv312/bin/activate
pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --reload --port 8000

# Frontend setup (new terminal)
cd frontend
npm install
npm run dev
```

### Environment Variables

```bash
# Backend (.env)
DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/dcv
REDIS_URL=redis://localhost:6379/0
SECRET_KEY=your-secret-key-at-least-32-characters

# Optional
AWS_REGION=eu-west-2
STRIPE_SECRET_KEY=sk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...
```

## Project Structure

```
├── backend/                    # Python FastAPI application
│   ├── app/
│   │   ├── api/               # REST API routes
│   │   ├── core/              # Config, security, auth
│   │   ├── models/            # SQLAlchemy models
│   │   ├── schemas/           # Pydantic schemas
│   │   ├── services/          # Business logic
│   │   ├── scanners/          # AWS and GCP scanners
│   │   │   ├── aws/           # AWS detection scanners
│   │   │   └── gcp/           # GCP detection scanners
│   │   ├── analyzers/         # Coverage and gap analysis
│   │   └── data/              # MITRE data, remediation templates
│   ├── alembic/               # Database migrations
│   └── tests/                 # pytest tests
├── frontend/                   # React + TypeScript application
│   ├── src/
│   │   ├── components/        # Reusable components
│   │   ├── pages/             # Page components
│   │   ├── services/          # API clients
│   │   └── stores/            # Zustand state stores
│   └── public/
│       └── docs/              # User documentation (markdown)
├── infrastructure/             # Terraform infrastructure
│   └── terraform/
│       ├── modules/           # Reusable modules
│       └── environments/      # Environment configs
└── docs/                       # Additional documentation
    └── user-guide/            # User guides
```

## API Documentation

Once running locally:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## Authentication

- Email/password with MFA (TOTP)
- Google SSO (via AWS Cognito)
- GitHub OAuth
- WebAuthn/Passkeys
- API keys for programmatic access

## User Roles

| Role | Capabilities |
|------|--------------|
| **Owner** | Full control, billing, ownership transfer |
| **Admin** | Manage accounts, scans, team members |
| **Member** | Run scans, view and update data |
| **Viewer** | Read-only access |

## Coverage Methodology

Coverage is calculated by mapping detections to MITRE ATT&CK techniques:

- **Covered** (≥60% confidence): Strong detection capability
- **Partial** (40-60%): Some detection, gaps exist
- **Uncovered** (<40%): Weak or no detection

A13E covers **12 MITRE ATT&CK tactics** that can be detected through cloud logs. Reconnaissance and Resource Development are excluded as they occur outside your cloud environment.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `pytest` (backend), `npm test` (frontend)
5. Submit a pull request

## Support

- Documentation: https://a13e.com/docs
- Email: support@a13e.com
- Issues: https://github.com/osuide/detection-coverage-validator/issues

## License

MIT
