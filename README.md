# Detection Coverage Validator

A multi-cloud security detection coverage analysis platform that provides visibility into MITRE ATT&CK coverage across AWS environments.

## Overview

Detection Coverage Validator automatically discovers security detections in your cloud environment, maps them to MITRE ATT&CK techniques, and provides actionable coverage insights.

### Key Features

- **Automated Discovery**: Scans AWS CloudWatch Logs Insights queries and EventBridge rules
- **MITRE ATT&CK Mapping**: Pattern-based mapping with confidence scoring
- **Coverage Analysis**: Tactic and technique coverage visualization
- **Gap Identification**: Risk-prioritized security gaps
- **Dashboard**: Interactive coverage heatmap and reports

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Frontend (React)                         │
├─────────────────────────────────────────────────────────────────┤
│                      API Gateway + Lambda                        │
├──────────────┬──────────────┬──────────────┬───────────────────┤
│   Scanner    │    Mapper    │   Analyzer   │    Reporter       │
│   (Fargate)  │   (Lambda)   │   (Lambda)   │    (Lambda)       │
├──────────────┴──────────────┴──────────────┴───────────────────┤
│                    PostgreSQL (RDS) + Redis                      │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+
- Docker & Docker Compose
- AWS CLI configured
- Terraform 1.5+

### Local Development

```bash
# Clone the repository
git clone https://github.com/osuide/detection-coverage-validator.git
cd detection-coverage-validator

# Start local services
docker-compose up -d

# Backend setup
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --reload

# Frontend setup (new terminal)
cd frontend
npm install
npm run dev
```

### AWS Deployment

```bash
cd infrastructure/terraform
terraform init
terraform plan
terraform apply
```

## Project Structure

```
├── backend/                 # Python FastAPI application
│   ├── app/
│   │   ├── api/            # REST API endpoints
│   │   ├── core/           # Configuration, security
│   │   ├── models/         # SQLAlchemy models
│   │   ├── scanners/       # Cloud detection scanners
│   │   ├── mappers/        # MITRE mapping engine
│   │   └── analyzers/      # Coverage analysis
│   ├── alembic/            # Database migrations
│   └── tests/              # pytest tests
├── frontend/               # React application
│   ├── src/
│   │   ├── components/     # React components
│   │   ├── pages/          # Page components
│   │   └── services/       # API clients
├── infrastructure/         # Terraform + Docker
│   ├── terraform/          # AWS infrastructure
│   └── docker/             # Container definitions
└── agents/                 # Design documents
```

## API Documentation

Once running, access the API documentation at:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## Configuration

Environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | - |
| `REDIS_URL` | Redis connection string | - |
| `AWS_REGION` | Default AWS region | eu-west-2 |
| `CONFIDENCE_THRESHOLD_COVERED` | Threshold for "covered" | 0.6 |
| `CONFIDENCE_THRESHOLD_PARTIAL` | Threshold for "partial" | 0.4 |

## License

MIT
