# A13E Detection Coverage Validator - High-Level Design Document

**Document Version:** 1.1
**Last Updated:** 25 December 2025
**Classification:** Internal
**Author:** Architecture Team

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [System Overview](#2-system-overview)
3. [Architecture Principles](#3-architecture-principles)
4. [System Context](#4-system-context)
5. [Component Architecture](#5-component-architecture)
6. [Data Architecture](#6-data-architecture)
7. [Integration Architecture](#7-integration-architecture)
8. [Security Architecture](#8-security-architecture)
9. [Deployment Architecture](#9-deployment-architecture)
10. [Key Workflows](#10-key-workflows)
11. [Non-Functional Requirements](#11-non-functional-requirements)
12. [Technology Stack](#12-technology-stack)
13. [Remediation Template Architecture](#13-remediation-template-architecture)
14. [Security Hardening](#14-security-hardening)

---

## 1. Executive Summary

### 1.1 Purpose

The A13E Detection Coverage Validator (DCV) is a multi-cloud Security-as-a-Service (SaaS) platform that enables organisations to assess their security detection coverage against the MITRE ATT&CK framework. The platform scans AWS and GCP environments, discovers existing security detections, maps them to MITRE ATT&CK techniques, and provides actionable remediation guidance for coverage gaps.

### 1.2 Business Context

Security teams face significant challenges in understanding their detection coverage:
- **Visibility Gap**: No unified view of detections across cloud providers
- **Mapping Complexity**: Manual correlation of detections to threat frameworks is time-consuming
- **Compliance Burden**: Demonstrating compliance coverage requires extensive documentation
- **Remediation Uncertainty**: Teams lack clear guidance on prioritising detection improvements

A13E DCV addresses these challenges by providing automated detection discovery, intelligent MITRE ATT&CK mapping, and prescriptive remediation templates.

### 1.3 Key Capabilities

| Capability | Description |
|------------|-------------|
| **Multi-Cloud Scanning** | Automated discovery of security detections across AWS and GCP |
| **MITRE ATT&CK Mapping** | Intelligent mapping of detections to techniques with confidence scoring |
| **Compliance Frameworks** | Coverage analysis against CIS, NIST CSF, PCI-DSS, ISO 27001, SOC 2 |
| **Service-Aware Coverage** | Novel coverage model combining technique and service scope |
| **Remediation Guidance** | Infrastructure-as-Code templates (CloudFormation, Terraform) for gap closure |
| **Threat Intelligence** | Integration with MITRE threat groups, campaigns, and software |
| **Multi-Tenancy** | Organisation-scoped isolation with role-based access control |

### 1.4 Target Users

- **Security Engineers**: Primary users configuring scans and analysing coverage
- **Security Architects**: Reviewing compliance posture and remediation priorities
- **Compliance Officers**: Generating audit-ready reports
- **CISOs/Security Leaders**: Dashboard consumers for executive oversight

---

## 2. System Overview

### 2.1 System Context Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              EXTERNAL ACTORS                                     │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │   Security   │    │   Security   │    │  Compliance  │    │    CISO/     │  │
│  │   Engineer   │    │   Architect  │    │   Officer    │    │   Leader     │  │
│  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘    └──────┬───────┘  │
│         │                   │                   │                   │           │
│         └───────────────────┴───────────────────┴───────────────────┘           │
│                                      │                                           │
│                                      ▼                                           │
│                          ┌─────────────────────┐                                │
│                          │    Web Browser /    │                                │
│                          │      API Client     │                                │
│                          └──────────┬──────────┘                                │
│                                      │                                           │
└──────────────────────────────────────┼──────────────────────────────────────────┘
                                       │
                                       │ HTTPS
                                       ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│                           A13E DETECTION COVERAGE VALIDATOR                       │
│ ┌──────────────────────────────────────────────────────────────────────────────┐ │
│ │                              PRESENTATION TIER                                │ │
│ │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐              │ │
│ │  │  React Frontend │  │   CloudFront    │  │  Lambda@Edge    │              │ │
│ │  │   (S3 Hosted)   │  │      CDN        │  │ (Security Hdrs) │              │ │
│ │  └─────────────────┘  └─────────────────┘  └─────────────────┘              │ │
│ └──────────────────────────────────────────────────────────────────────────────┘ │
│ ┌──────────────────────────────────────────────────────────────────────────────┐ │
│ │                              APPLICATION TIER                                 │ │
│ │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐              │ │
│ │  │  FastAPI Backend│  │   ECS Fargate   │  │   Application   │              │ │
│ │  │   (REST API)    │  │   (Containers)  │  │   Load Balancer │              │ │
│ │  └─────────────────┘  └─────────────────┘  └─────────────────┘              │ │
│ └──────────────────────────────────────────────────────────────────────────────┘ │
│ ┌──────────────────────────────────────────────────────────────────────────────┐ │
│ │                                 DATA TIER                                     │ │
│ │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐              │ │
│ │  │   RDS PostgreSQL│  │ ElastiCache Redis│  │  S3 (Assets)   │              │ │
│ │  │   (Primary DB)  │  │   (Cache/Queue)  │  │                │              │ │
│ │  └─────────────────┘  └─────────────────┘  └─────────────────┘              │ │
│ └──────────────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       │
        ┌──────────────────────────────┼──────────────────────────────┐
        │                              │                              │
        ▼                              ▼                              ▼
┌───────────────────┐    ┌───────────────────┐    ┌───────────────────┐
│   CUSTOMER AWS    │    │   CUSTOMER GCP    │    │ EXTERNAL SERVICES │
│     ACCOUNTS      │    │     PROJECTS      │    │                   │
├───────────────────┤    ├───────────────────┤    ├───────────────────┤
│ • CloudWatch      │    │ • Cloud Logging   │    │ • MITRE ATT&CK    │
│ • EventBridge     │    │ • Eventarc        │    │ • Stripe Billing  │
│ • GuardDuty       │    │ • Security Cmd Ctr│    │ • AWS Cognito     │
│ • Config          │    │ • Chronicle       │    │ • OAuth Providers │
│ • SecurityHub     │    │ • Cloud Monitoring│    │ • HIBP API        │
│ • Organizations   │    │ • Resource Manager│    │                   │
└───────────────────┘    └───────────────────┘    └───────────────────┘
```

### 2.2 Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **Multi-tenant SaaS model** | Enables scalable delivery whilst maintaining data isolation |
| **Serverless containers (Fargate)** | Eliminates infrastructure management overhead |
| **Service-aware coverage model** | Prevents false positives from detections without service scope |
| **Async scanning architecture** | Allows long-running scans without blocking API responses |
| **JWT with httpOnly cookies** | Balances security (XSS protection) with usability |

---

## 3. Architecture Principles

### 3.1 Guiding Principles

| Principle | Description | Implementation |
|-----------|-------------|----------------|
| **Security First** | Security is not an afterthought but a primary design constraint | Zero-trust RBAC, encryption at rest/transit, audit logging |
| **Cloud Native** | Leverage managed services to reduce operational burden | ECS Fargate, RDS, ElastiCache, CloudFront |
| **Multi-Tenancy** | Organisation-level isolation with shared infrastructure | Row-level filtering by `organization_id` |
| **API-First** | All functionality exposed via RESTful APIs | OpenAPI-documented endpoints |
| **Infrastructure as Code** | All infrastructure defined declaratively | Terraform modules for AWS resources |
| **Observability** | Comprehensive logging, metrics, and tracing | Structured logs, CloudWatch metrics, X-Ray |

### 3.2 Architectural Constraints

- **AWS Region**: Primary deployment in `eu-west-2` (London) for GDPR compliance
- **Data Residency**: Customer detection data remains within the deployment region
- **Credential Handling**: Customer credentials never stored permanently; temporary STS tokens used
- **UK English**: All user-facing content uses UK English spelling conventions

---

## 4. System Context

### 4.1 External Systems Integration

```
                                ┌─────────────────────────┐
                                │     A13E DCV System     │
                                └───────────┬─────────────┘
                                            │
        ┌───────────────────────────────────┼───────────────────────────────────┐
        │                                   │                                   │
        ▼                                   ▼                                   ▼
┌───────────────────┐           ┌───────────────────┐           ┌───────────────────┐
│   CLOUD PROVIDERS │           │   IDENTITY/AUTH   │           │   BUSINESS SVC    │
├───────────────────┤           ├───────────────────┤           ├───────────────────┤
│                   │           │                   │           │                   │
│  AWS              │           │  AWS Cognito      │           │  Stripe           │
│  ├─ STS           │           │  ├─ User Pool     │           │  ├─ Checkout      │
│  ├─ Organizations │           │  ├─ Identity Pool │           │  ├─ Subscriptions │
│  ├─ CloudWatch    │           │  └─ OAuth IDPs    │           │  └─ Webhooks      │
│  ├─ EventBridge   │           │     ├─ Google     │           │                   │
│  ├─ GuardDuty     │           │     ├─ GitHub     │           │  MITRE ATT&CK     │
│  ├─ Config        │           │     └─ Microsoft  │           │  ├─ STIX Data     │
│  └─ SecurityHub   │           │                   │           │  └─ Threat Intel  │
│                   │           │                   │           │                   │
│  GCP              │           │                   │           │  Have I Been Pwned│
│  ├─ Cloud Logging │           │                   │           │  └─ Breach Check  │
│  ├─ Eventarc      │           │                   │           │                   │
│  ├─ SCC           │           │                   │           │                   │
│  └─ Chronicle     │           │                   │           │                   │
│                   │           │                   │           │                   │
└───────────────────┘           └───────────────────┘           └───────────────────┘
```

### 4.2 Integration Patterns

| Integration | Pattern | Protocol | Authentication |
|-------------|---------|----------|----------------|
| AWS Services | REST API | HTTPS | STS AssumeRole (temporary credentials) |
| GCP Services | REST API | HTTPS | Service Account impersonation |
| AWS Cognito | OAuth 2.0/OIDC | HTTPS | Authorization Code + PKCE |
| Stripe | Webhooks | HTTPS | HMAC-SHA256 signature verification |
| MITRE ATT&CK | Data Download | HTTPS | None (public STIX data) |
| HIBP | REST API | HTTPS | k-Anonymity (hash prefix only) |

---

## 5. Component Architecture

### 5.1 Logical Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              PRESENTATION LAYER                                  │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌────────────────────────────────────────────────────────────────────────────┐ │
│  │                           REACT FRONTEND                                    │ │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐      │ │
│  │  │  Dashboard   │ │   Coverage   │ │  Compliance  │ │    Gaps      │      │ │
│  │  │    Page      │ │   Heatmap    │ │   Reports    │ │  Remediation │      │ │
│  │  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘      │ │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐      │ │
│  │  │   Accounts   │ │  Detections  │ │   Settings   │ │    Admin     │      │ │
│  │  │  Management  │ │   Browser    │ │    Panel     │ │    Portal    │      │ │
│  │  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘      │ │
│  └────────────────────────────────────────────────────────────────────────────┘ │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       │ REST API (JSON)
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              APPLICATION LAYER                                   │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌────────────────────────────────────────────────────────────────────────────┐ │
│  │                            API GATEWAY                                      │ │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐      │ │
│  │  │     Auth     │ │   Accounts   │ │    Scans     │ │  Detections  │      │ │
│  │  │   Routes     │ │   Routes     │ │   Routes     │ │   Routes     │      │ │
│  │  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘      │ │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐      │ │
│  │  │   Coverage   │ │  Compliance  │ │    Gaps      │ │   Billing    │      │ │
│  │  │   Routes     │ │   Routes     │ │   Routes     │ │   Routes     │      │ │
│  │  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘      │ │
│  └────────────────────────────────────────────────────────────────────────────┘ │
│                                                                                  │
│  ┌────────────────────────────────────────────────────────────────────────────┐ │
│  │                         BUSINESS SERVICES                                   │ │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐      │ │
│  │  │    Auth      │ │    Scan      │ │   Coverage   │ │  Compliance  │      │ │
│  │  │   Service    │ │   Service    │ │   Service    │ │   Service    │      │ │
│  │  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘      │ │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐      │ │
│  │  │     Gap      │ │   MITRE      │ │   Billing    │ │Notification  │      │ │
│  │  │   Service    │ │Sync Service  │ │   Service    │ │   Service    │      │ │
│  │  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘      │ │
│  └────────────────────────────────────────────────────────────────────────────┘ │
│                                                                                  │
│  ┌────────────────────────────────────────────────────────────────────────────┐ │
│  │                          SCANNER ENGINE                                     │ │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐      │ │
│  │  │  CloudWatch  │ │ EventBridge  │ │  GuardDuty   │ │   Config     │      │ │
│  │  │   Scanner    │ │   Scanner    │ │   Scanner    │ │   Scanner    │      │ │
│  │  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘      │ │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐      │ │
│  │  │ SecurityHub  │ │ GCP Logging  │ │  Eventarc    │ │     SCC      │      │ │
│  │  │   Scanner    │ │   Scanner    │ │   Scanner    │ │   Scanner    │      │ │
│  │  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘      │ │
│  └────────────────────────────────────────────────────────────────────────────┘ │
│                                                                                  │
│  ┌────────────────────────────────────────────────────────────────────────────┐ │
│  │                          MAPPING ENGINE                                     │ │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐      │ │
│  │  │   Pattern    │ │   Vendor     │ │  Indicator   │ │   Service    │      │ │
│  │  │   Mapper     │ │   Mapper     │ │   Library    │ │   Mapper     │      │ │
│  │  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘      │ │
│  └────────────────────────────────────────────────────────────────────────────┘ │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                                 DATA LAYER                                       │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐              │
│  │                  │  │                  │  │                  │              │
│  │    PostgreSQL    │  │      Redis       │  │   S3 Storage     │              │
│  │   (Primary DB)   │  │   (Cache/Queue)  │  │    (Assets)      │              │
│  │                  │  │                  │  │                  │              │
│  │  • Users/Orgs    │  │  • Sessions      │  │  • Reports       │              │
│  │  • Detections    │  │  • Rate Limits   │  │  • Terraform     │              │
│  │  • Scans         │  │  • MITRE Cache   │  │    State         │              │
│  │  • Compliance    │  │  • Job Queues    │  │  • Audit Logs    │              │
│  │  • MITRE Data    │  │                  │  │                  │              │
│  │                  │  │                  │  │                  │              │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘              │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 5.2 Component Responsibilities

| Component | Responsibility | Key Technologies |
|-----------|---------------|------------------|
| **React Frontend** | User interface, state management, API integration | React 18, TypeScript, Zustand, Tailwind CSS |
| **API Gateway** | Request routing, authentication, rate limiting | FastAPI, JWT, Redis |
| **Business Services** | Core business logic, domain orchestration | Python, async/await |
| **Scanner Engine** | Cloud detection discovery, credential handling | AWS SDK, GCP SDK |
| **Mapping Engine** | Detection-to-technique mapping, confidence scoring | Pattern matching, NLP |
| **PostgreSQL** | Persistent storage, ACID transactions | SQLAlchemy ORM, Alembic |
| **Redis** | Session cache, rate limiting, job queues | aioredis |
| **S3** | Static assets, reports, Terraform state | boto3 |

---

## 6. Data Architecture

### 6.1 Conceptual Data Model

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           ORGANISATION DOMAIN                                    │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐                    │
│  │     User     │────▶│Organisation- │◀────│ Organisation │                    │
│  │              │     │   Member     │     │              │                    │
│  └──────────────┘     └──────────────┘     └──────────────┘                    │
│         │                    │                    │                             │
│         │                    │                    │                             │
│         ▼                    │                    ▼                             │
│  ┌──────────────┐            │             ┌──────────────┐                    │
│  │  UserSession │            │             │ Subscription │                    │
│  └──────────────┘            │             └──────────────┘                    │
│                              │                                                  │
└──────────────────────────────┼──────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                            CLOUD ACCOUNT DOMAIN                                  │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐                    │
│  │Cloud Account │────▶│     Scan     │────▶│  Detection   │                    │
│  │              │     │              │     │              │                    │
│  └──────────────┘     └──────────────┘     └──────────────┘                    │
│         │                                         │                             │
│         │                                         │                             │
│         ▼                                         ▼                             │
│  ┌──────────────┐                          ┌──────────────┐                    │
│  │   Cloud      │                          │  Detection   │                    │
│  │ Credential   │                          │   Mapping    │                    │
│  └──────────────┘                          └──────────────┘                    │
│                                                   │                             │
└───────────────────────────────────────────────────┼─────────────────────────────┘
                                                    │
                                                    ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                             MITRE ATT&CK DOMAIN                                  │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐                    │
│  │    Tactic    │◀────│  Technique   │────▶│Threat Group  │                    │
│  │              │     │              │     │              │                    │
│  └──────────────┘     └──────────────┘     └──────────────┘                    │
│                              │                    │                             │
│                              │                    │                             │
│                              ▼                    ▼                             │
│                       ┌──────────────┐     ┌──────────────┐                    │
│                       │   Software   │     │   Campaign   │                    │
│                       │              │     │              │                    │
│                       └──────────────┘     └──────────────┘                    │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
                                                    │
                                                    ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                            COMPLIANCE DOMAIN                                     │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐                    │
│  │  Compliance  │────▶│  Compliance  │────▶│   Control    │                    │
│  │  Framework   │     │   Control    │     │  Technique   │                    │
│  │              │     │              │     │   Mapping    │                    │
│  └──────────────┘     └──────────────┘     └──────────────┘                    │
│                              │                                                  │
│                              ▼                                                  │
│                       ┌──────────────┐                                         │
│                       │  Compliance  │                                         │
│                       │   Snapshot   │                                         │
│                       └──────────────┘                                         │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 6.2 Data Classification

| Classification | Examples | Protection Measures |
|---------------|----------|---------------------|
| **Critical** | Cloud credentials, API secrets | Fernet encryption, Secrets Manager |
| **Confidential** | User emails, detection configs | Row-level isolation, TLS |
| **Internal** | MITRE mappings, compliance rules | Standard access controls |
| **Public** | Technique descriptions, pricing | Cached, CDN-served |

### 6.3 Data Retention Policy

| Tier | Scan History | Detection Data | Compliance Snapshots |
|------|-------------|----------------|---------------------|
| FREE | 30 days | 30 days | Latest only |
| INDIVIDUAL | 90 days | 90 days | 90 days |
| PRO | 365 days | 365 days | 365 days |
| ENTERPRISE | Unlimited | Unlimited | Unlimited |

---

## 7. Integration Architecture

### 7.1 Cloud Provider Integration

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          A13E SCANNING ARCHITECTURE                              │
└─────────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       │ 1. Scan Request
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              SCAN ORCHESTRATOR                                   │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │  1. Validate organisation ownership                                      │   │
│  │  2. Check scan quota (tier limits)                                       │   │
│  │  3. Resolve target regions (ALL/SELECTED/AUTO)                          │   │
│  │  4. Queue background scan job                                            │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       │ 2. AssumeRole
                                       ▼
┌────────────────────────────┐    ┌────────────────────────────┐
│      CUSTOMER AWS          │    │      CUSTOMER GCP          │
│        ACCOUNT             │    │        PROJECT             │
│ ┌────────────────────────┐ │    │ ┌────────────────────────┐ │
│ │     IAM Role           │ │    │ │   Service Account      │ │
│ │  arn:aws:iam::         │ │    │ │   a13e-scanner@        │ │
│ │  CUSTOMER:role/        │ │    │ │   project.iam.gsvc.com │ │
│ │  A13EScanner           │ │    │ │                        │ │
│ │                        │ │    │ │                        │ │
│ │  Trust: A13E Account   │ │    │ │  Impersonation from    │ │
│ │  (123080274263)        │ │    │ │  A13E Service Account  │ │
│ └────────────────────────┘ │    │ └────────────────────────┘ │
└────────────────────────────┘    └────────────────────────────┘
              │                                 │
              │ 3. Temporary Credentials        │
              │    (1-hour TTL)                 │
              ▼                                 ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                             SCANNER WORKERS                                      │
│                                                                                  │
│  AWS Scanners:                          GCP Scanners:                           │
│  ┌──────────────┐ ┌──────────────┐     ┌──────────────┐ ┌──────────────┐       │
│  │ CloudWatch   │ │ EventBridge  │     │Cloud Logging │ │  Eventarc    │       │
│  │ Logs Insights│ │    Rules     │     │    Sinks     │ │  Triggers    │       │
│  └──────────────┘ └──────────────┘     └──────────────┘ └──────────────┘       │
│  ┌──────────────┐ ┌──────────────┐     ┌──────────────┐ ┌──────────────┐       │
│  │  GuardDuty   │ │ Config Rules │     │     SCC      │ │  Chronicle   │       │
│  │  Detectors   │ │              │     │   Findings   │ │    Rules     │       │
│  └──────────────┘ └──────────────┘     └──────────────┘ └──────────────┘       │
│  ┌──────────────┐ ┌──────────────┐                                              │
│  │ SecurityHub  │ │   Service    │                                              │
│  │  Standards   │ │  Discovery   │                                              │
│  └──────────────┘ └──────────────┘                                              │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       │ 4. Raw Detections
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                             MAPPING ENGINE                                       │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │  For each detection:                                                     │   │
│  │    1. Check vendor-specific mappings (GuardDuty, SCC, etc.)             │   │
│  │    2. Parse CloudTrail events from EventBridge patterns                  │   │
│  │    3. Extract target_services from rules/patterns                        │   │
│  │    4. Match against indicator library (keywords)                         │   │
│  │    5. Return MappingResult with technique_id + confidence                │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       │ 5. Persisted Detections
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              DATABASE                                            │
│  ┌───────────────────┐  ┌───────────────────┐  ┌───────────────────┐          │
│  │    Detections     │  │ DetectionMappings │  │  CoverageSnapshot │          │
│  │  (target_services)│  │  (confidence)     │  │   (historical)    │          │
│  └───────────────────┘  └───────────────────┘  └───────────────────┘          │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 7.2 Authentication Flow

```
┌──────────┐           ┌──────────┐           ┌──────────┐           ┌──────────┐
│  Browser │           │ Frontend │           │ Backend  │           │ Cognito  │
└────┬─────┘           └────┬─────┘           └────┬─────┘           └────┬─────┘
     │                      │                      │                      │
     │ 1. Click Login       │                      │                      │
     │─────────────────────▶│                      │                      │
     │                      │                      │                      │
     │                      │ 2. POST /auth/login  │                      │
     │                      │─────────────────────▶│                      │
     │                      │                      │                      │
     │                      │                      │ 3. Verify Password   │
     │                      │                      │     (BCrypt)         │
     │                      │                      │                      │
     │                      │                      │ 4. Check MFA        │
     │                      │                      │                      │
     │                      │ 5. {access_token,    │                      │
     │                      │    requires_mfa}     │                      │
     │                      │◀─────────────────────│                      │
     │                      │                      │                      │
     │                      │ 6. Set-Cookie:       │                      │
     │ 7. Store token       │    refresh_token     │                      │
     │    (memory only)     │◀─────────────────────│                      │
     │◀─────────────────────│                      │                      │
     │                      │                      │                      │
     │ 8. API Request       │                      │                      │
     │   + Authorization:   │                      │                      │
     │     Bearer {token}   │                      │                      │
     │─────────────────────▶│                      │                      │
     │                      │ 9. Forward +         │                      │
     │                      │    Auth Header       │                      │
     │                      │─────────────────────▶│                      │
     │                      │                      │ 10. JWT Decode       │
     │                      │                      │     + RBAC Check     │
     │                      │                      │                      │
     │                      │ 11. Response         │                      │
     │                      │◀─────────────────────│                      │
     │ 12. Display          │                      │                      │
     │◀─────────────────────│                      │                      │
     │                      │                      │                      │
```

---

## 8. Security Architecture

### 8.1 Security Layers

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              SECURITY LAYERS                                     │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │ EDGE LAYER                                                               │   │
│  │  • AWS WAF (DDoS, rate limiting, geo-blocking)                          │   │
│  │  • CloudFront (TLS termination, caching)                                │   │
│  │  • Lambda@Edge (CSP, security headers)                                   │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                       │                                         │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │ TRANSPORT LAYER                                                          │   │
│  │  • TLS 1.2+ enforcement                                                  │   │
│  │  • Certificate management (ACM)                                          │   │
│  │  • HTTPS-only communication                                              │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                       │                                         │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │ APPLICATION LAYER                                                        │   │
│  │  • JWT authentication with httpOnly cookies                              │   │
│  │  • RBAC (Owner > Admin > Member > Viewer)                               │   │
│  │  • CSRF protection (double-submit cookie)                                │   │
│  │  • Input validation (Pydantic schemas)                                   │   │
│  │  • Output encoding (React auto-escapes all content)                      │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                       │                                         │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │ DATA LAYER                                                               │   │
│  │  • Encryption at rest (KMS)                                              │   │
│  │  • Credential encryption (Fernet)                                        │   │
│  │  • Row-level tenant isolation                                            │   │
│  │  • Audit logging (immutable)                                             │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 8.2 Threat Model Summary

| Threat | Mitigation |
|--------|------------|
| **Credential Theft** | Temporary STS tokens (1-hour TTL), encrypted storage |
| **Session Hijacking** | httpOnly cookies, optional IP/UA binding |
| **XSS Attacks** | CSP headers, React output encoding, safe HTML practices |
| **CSRF Attacks** | Double-submit cookie pattern |
| **SQL Injection** | SQLAlchemy ORM parameterised queries |
| **Brute Force** | Rate limiting (5 attempts/30 min), account lockout |
| **Data Exfiltration** | Row-level isolation, audit logging |
| **Privilege Escalation** | Explicit RBAC (no implicit hierarchy) |

---

## 9. Deployment Architecture

### 9.1 AWS Infrastructure

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                                AWS REGION (eu-west-2)                            │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                               VPC (10.0.0.0/16)                          │   │
│  │                                                                          │   │
│  │  ┌──────────────────────────┐  ┌──────────────────────────┐            │   │
│  │  │   PUBLIC SUBNET AZ-A    │  │   PUBLIC SUBNET AZ-B    │            │   │
│  │  │      (10.0.0.0/24)      │  │      (10.0.1.0/24)      │            │   │
│  │  │                          │  │                          │            │   │
│  │  │  ┌──────────────────┐   │  │  ┌──────────────────┐   │            │   │
│  │  │  │       ALB        │   │  │  │       ALB        │   │            │   │
│  │  │  │  (Target Group)  │   │  │  │  (Target Group)  │   │            │   │
│  │  │  └──────────────────┘   │  │  └──────────────────┘   │            │   │
│  │  │                          │  │                          │            │   │
│  │  └──────────────────────────┘  └──────────────────────────┘            │   │
│  │                                                                          │   │
│  │  ┌──────────────────────────┐  ┌──────────────────────────┐            │   │
│  │  │   PRIVATE SUBNET AZ-A   │  │   PRIVATE SUBNET AZ-B   │            │   │
│  │  │     (10.0.10.0/24)      │  │     (10.0.11.0/24)      │            │   │
│  │  │                          │  │                          │            │   │
│  │  │  ┌──────────────────┐   │  │  ┌──────────────────┐   │            │   │
│  │  │  │   ECS Fargate    │   │  │  │   ECS Fargate    │   │            │   │
│  │  │  │    (Backend)     │   │  │  │    (Backend)     │   │            │   │
│  │  │  └──────────────────┘   │  │  └──────────────────┘   │            │   │
│  │  │                          │  │                          │            │   │
│  │  │  ┌──────────────────┐   │  │  ┌──────────────────┐   │            │   │
│  │  │  │   RDS Primary    │   │  │  │   RDS Standby    │   │            │   │
│  │  │  │   PostgreSQL     │   │  │  │   (Multi-AZ)     │   │            │   │
│  │  │  └──────────────────┘   │  │  └──────────────────┘   │            │   │
│  │  │                          │  │                          │            │   │
│  │  │  ┌──────────────────┐   │  │  ┌──────────────────┐   │            │   │
│  │  │  │   ElastiCache    │   │  │  │   ElastiCache    │   │            │   │
│  │  │  │     Redis        │   │  │  │    (Replica)     │   │            │   │
│  │  │  └──────────────────┘   │  │  └──────────────────┘   │            │   │
│  │  │                          │  │                          │            │   │
│  │  └──────────────────────────┘  └──────────────────────────┘            │   │
│  │                                                                          │   │
│  │  ┌──────────────────────────────────────────────────────────────────┐  │   │
│  │  │                         VPC ENDPOINTS                             │  │   │
│  │  │  • S3 Gateway         • ECR API        • CloudWatch Logs         │  │   │
│  │  │  • DynamoDB Gateway   • ECR DKR        • Secrets Manager         │  │   │
│  │  └──────────────────────────────────────────────────────────────────┘  │   │
│  │                                                                          │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                         GLOBAL SERVICES                                  │   │
│  │                                                                          │   │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐       │   │
│  │  │ CloudFront │  │     S3     │  │   Route53  │  │    WAF     │       │   │
│  │  │    CDN     │  │  Frontend  │  │    DNS     │  │            │       │   │
│  │  └────────────┘  └────────────┘  └────────────┘  └────────────┘       │   │
│  │                                                                          │   │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐       │   │
│  │  │  Cognito   │  │    ECR     │  │  Secrets   │  │    SES     │       │   │
│  │  │ User Pool  │  │  Registry  │  │  Manager   │  │   Email    │       │   │
│  │  └────────────┘  └────────────┘  └────────────┘  └────────────┘       │   │
│  │                                                                          │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 9.2 CI/CD Pipeline

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   GitHub     │────▶│  GitHub      │────▶│   Build &    │────▶│   Deploy     │
│   Push       │     │  Actions     │     │    Test      │     │              │
└──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
                            │                    │                    │
                            ▼                    ▼                    ▼
                     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
                     │  Linting     │     │  Unit Tests  │     │  Terraform   │
                     │  (Ruff/ESLint│     │  (pytest)    │     │   Apply      │
                     └──────────────┘     └──────────────┘     └──────────────┘
                            │                    │                    │
                            ▼                    ▼                    ▼
                     ┌──────────────┐     ┌──────────────┐     │  ECS Deploy  │
                     │  Security    │     │  Docker      │     │  (Fargate)   │
                     │  Scanning    │     │  Build/Push  │     └──────────────┘
                     └──────────────┘     └──────────────┘            │
                                                                      ▼
                                                               ┌──────────────┐
                                                               │   Verify     │
                                                               │  Health      │
                                                               └──────────────┘
```

---

## 10. Key Workflows

### 10.1 Scan Execution Workflow

```
                         ┌─────────────────────────────────┐
                         │     User Initiates Scan         │
                         └─────────────────────────────────┘
                                        │
                                        ▼
                         ┌─────────────────────────────────┐
                         │   Validate Account Ownership    │
                         │   Check Scan Quota (Tier)       │
                         └─────────────────────────────────┘
                                        │
                                        ▼
                         ┌─────────────────────────────────┐
                         │   Create Scan Record (PENDING)  │
                         │   Queue Background Job          │
                         └─────────────────────────────────┘
                                        │
                         ┌──────────────┴──────────────┐
                         ▼                             ▼
              ┌────────────────────┐        ┌────────────────────┐
              │  AWS Credential    │        │  GCP Credential    │
              │  (STS AssumeRole)  │        │  (Service Account) │
              └────────────────────┘        └────────────────────┘
                         │                             │
                         └──────────────┬──────────────┘
                                        ▼
                         ┌─────────────────────────────────┐
                         │   Discover Target Regions       │
                         │   (ALL / SELECTED / AUTO)       │
                         └─────────────────────────────────┘
                                        │
                                        ▼
                         ┌─────────────────────────────────┐
                         │   For Each Region:              │
                         │   • Run CloudWatch Scanner      │
                         │   • Run EventBridge Scanner     │
                         │   • Run GuardDuty Scanner       │
                         │   • Run Config Scanner          │
                         │   • Run SecurityHub Scanner     │
                         │   • Run Service Discovery       │
                         └─────────────────────────────────┘
                                        │
                                        ▼
                         ┌─────────────────────────────────┐
                         │   Map Detections to MITRE       │
                         │   • Vendor-specific mappings    │
                         │   • CloudTrail event mapping    │
                         │   • Indicator library matching  │
                         │   • Extract target_services     │
                         └─────────────────────────────────┘
                                        │
                                        ▼
                         ┌─────────────────────────────────┐
                         │   Persist Detections            │
                         │   • Detect drift (new/removed)  │
                         │   • Store target_services       │
                         │   • Update health status        │
                         └─────────────────────────────────┘
                                        │
                                        ▼
                         ┌─────────────────────────────────┐
                         │   Recalculate Compliance        │
                         │   • Technique coverage          │
                         │   • Service coverage            │
                         │   • Control status              │
                         └─────────────────────────────────┘
                                        │
                                        ▼
                         ┌─────────────────────────────────┐
                         │   Update Scan (COMPLETED)       │
                         │   Send Notifications            │
                         └─────────────────────────────────┘
```

### 10.2 Service-Aware Coverage Calculation

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        SERVICE-AWARE COVERAGE MODEL                              │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  Traditional Model:                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │  coverage = covered_techniques / total_techniques                        │   │
│  │                                                                          │   │
│  │  Problem: Control 3.5 "Securely Dispose of Data" shows 100% coverage    │   │
│  │           with only S3 deletion detection, but data exists in RDS,      │   │
│  │           DynamoDB, EBS, etc.                                            │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                                                                  │
│  Service-Aware Model:                                                            │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │  effective_coverage = (technique_coverage + service_coverage) / 2        │   │
│  │                                                                          │   │
│  │  Where:                                                                  │   │
│  │    technique_coverage = covered_techniques / mapped_techniques           │   │
│  │    service_coverage = covered_services / in_scope_services              │   │
│  │                                                                          │   │
│  │  in_scope_services = discovered_services ∩ control_required_services    │   │
│  │  covered_services = services with at least one detection                │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                                                                  │
│  Example:                                                                        │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │  Account has: S3, RDS, DynamoDB, EBS                                    │   │
│  │  Control requires: S3, RDS, DynamoDB, EBS, EFS (EFS not discovered)     │   │
│  │  Detections exist for: S3, RDS                                          │   │
│  │                                                                          │   │
│  │  in_scope_services = [S3, RDS, DynamoDB, EBS] (4 services)             │   │
│  │  covered_services = [S3, RDS] (2 services)                              │   │
│  │  service_coverage = 2/4 = 50%                                           │   │
│  │                                                                          │   │
│  │  technique_coverage = 80% (existing)                                    │   │
│  │  effective_coverage = (80% + 50%) / 2 = 65% → PARTIAL                   │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 11. Non-Functional Requirements

### 11.1 Performance

| Metric | Target | Measurement |
|--------|--------|-------------|
| API Response Time (P95) | < 500ms | CloudWatch Metrics |
| Page Load Time | < 3s | Lighthouse |
| Scan Duration (single account) | < 10 minutes | Scan timestamps |
| Concurrent Users | 1,000+ | Load testing |

### 11.2 Availability

| Metric | Target | Implementation |
|--------|--------|----------------|
| Uptime | 99.9% | Multi-AZ deployment |
| RTO (Recovery Time Objective) | < 5 minutes | RDS Multi-AZ failover |
| RPO (Recovery Point Objective) | < 1 hour | Automated backups |

### 11.3 Scalability

| Dimension | Approach |
|-----------|----------|
| **Horizontal** | ECS auto-scaling, read replicas |
| **Vertical** | Instance type upgrades |
| **Data** | PostgreSQL partitioning, Redis clustering |

### 11.4 Compliance

| Standard | Status |
|----------|--------|
| GDPR | Compliant (eu-west-2 residency) |
| SOC 2 Type II | In progress |
| ISO 27001 | Planned |

---

## 12. Technology Stack

### 12.1 Summary

| Layer | Technology | Version |
|-------|------------|---------|
| **Frontend** | React | 18.x |
| | TypeScript | 5.x |
| | Zustand | 4.x |
| | Tailwind CSS | 3.x |
| | Vite | 5.x |
| **Backend** | Python | 3.11 |
| | FastAPI | 0.100+ |
| | SQLAlchemy | 2.0+ |
| | Pydantic | 2.0+ |
| | Alembic | 1.x |
| **Database** | PostgreSQL | 15.x |
| | Redis | 7.x |
| **Infrastructure** | Terraform | 1.5+ |
| | AWS ECS Fargate | - |
| | AWS RDS | - |
| | AWS ElastiCache | - |
| | AWS CloudFront | - |
| | AWS Cognito | - |

---

## 13. Remediation Template Architecture

### 13.1 Template Coverage

A13E includes 260+ remediation templates covering MITRE ATT&CK techniques with Infrastructure-as-Code implementations.

| Template Type | Count | Description |
|--------------|-------|-------------|
| **AWS CloudFormation** | 260+ | Native AWS IaC templates |
| **AWS Terraform** | 260+ | HashiCorp Terraform for AWS |
| **GCP Terraform** | 150+ | HashiCorp Terraform for GCP |

### 13.2 Detection Pattern Types

Templates implement two primary detection patterns:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          DETECTION PATTERN TYPES                                 │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌──────────────────────────────────────────┐  ┌─────────────────────────────┐ │
│  │      EVENTBRIDGE PATTERN                 │  │    METRIC FILTER PATTERN    │ │
│  │      (Real-time Event Detection)         │  │    (Volume-based Detection) │ │
│  │                                          │  │                             │ │
│  │  Use for:                                │  │  Use for:                   │ │
│  │  • Individual API calls via CloudTrail   │  │  • Aggregated metrics       │ │
│  │  • Security-critical events              │  │  • Threshold-based alerts   │ │
│  │  • Real-time alerting requirements       │  │  • stats count() queries    │ │
│  │                                          │  │  • Rate-based detection     │ │
│  │  Components:                             │  │                             │ │
│  │  • EventBridge Rule                      │  │  Components:                │ │
│  │  • Dead Letter Queue (SQS)               │  │  • CloudWatch Metric Filter │ │
│  │  • SNS Topic with KMS encryption         │  │  • CloudWatch Alarm         │ │
│  │  • Retry Policy (8 attempts)             │  │  • SNS Topic                │ │
│  │  • Input Transformer                     │  │                             │ │
│  │  • Scoped SNS Topic Policy               │  │                             │ │
│  │                                          │  │                             │ │
│  └──────────────────────────────────────────┘  └─────────────────────────────┘ │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 13.3 EventBridge Best Practices

All EventBridge-based templates follow these security best practices:

| Feature | Implementation | Purpose |
|---------|---------------|---------|
| **Dead Letter Queue** | SQS with 14-day retention | Capture failed event deliveries |
| **Retry Policy** | 8 attempts, 1-hour max age | Ensure delivery during transient failures |
| **SNS Encryption** | KMS (`alias/aws/sns`) | Encrypt alerts at rest |
| **Scoped SNS Policy** | `AWS:SourceAccount` + `aws:SourceArn` conditions | Prevent confused deputy attacks |
| **Input Transformer** | Human-readable alert format | Improve alert actionability |

### 13.4 Template Quality Improvements (December 2025)

Recent improvements to remediation templates:

| Improvement | Templates Affected | Commit |
|-------------|-------------------|--------|
| SNS encryption (KMS) | 253 templates | `cd9f88a` |
| Alert fatigue fixes | 236 templates | `ed7080b` |
| EventBridge pattern upgrades | 7 techniques | `05946ab`, `6385324`, etc. |
| Missing SNS topic policies | 18 templates | `c0aa7dd` |

---

## 14. Security Hardening

### 14.1 Authentication Security

| Control | Implementation |
|---------|---------------|
| **Password Hashing** | BCrypt with 12 rounds |
| **JWT Tokens** | HS256, 30-minute expiry, httpOnly refresh cookies |
| **MFA** | TOTP with encrypted secret storage (Fernet) |
| **Session Binding** | Optional IP/UA fingerprint binding |
| **Breach Detection** | HIBP k-Anonymity password checking |

### 14.2 API Security

| Control | Implementation |
|---------|---------------|
| **Rate Limiting** | 5 auth attempts/30 min, 100 API calls/min |
| **Input Validation** | Pydantic schemas with strict typing |
| **RBAC** | Explicit role matching (non-hierarchical) |
| **API Key Scoping** | Keys scoped to organisation, validated per-request |
| **Admin Separation** | Admin tokens rejected on user endpoints |

### 14.3 Multi-Tenancy Isolation

| Layer | Isolation Mechanism |
|-------|---------------------|
| **Database** | Row-level `organization_id` filtering on all queries |
| **API** | AuthContext dependency enforces org scope |
| **Cloud Accounts** | Global registry prevents cross-org account reuse |
| **Credentials** | Fernet encryption, never stored permanently |

### 14.4 Recent Security Fixes (December 2025)

| Fix | Description | Commit |
|-----|-------------|--------|
| Account Auth | Fixed account ownership validation | `ec1c167` |
| API Key Lookup | Fixed org-scoped API key validation | `ec1c167` |
| Admin IP Trust | Fixed trusted IP bypass logic | `ec1c167` |
| MFA Bypass | Fixed MFA enforcement on org settings | `3fcac95` |
| Domain Verification | Fixed email domain ownership checks | `3fcac95` |

---

## Appendices

### A. Glossary

| Term | Definition |
|------|------------|
| **Detection** | A security monitoring rule, alarm, or finding in a cloud environment |
| **Technique** | A MITRE ATT&CK technique (e.g., T1078 Valid Accounts) |
| **Tactic** | A MITRE ATT&CK tactic category (e.g., Initial Access) |
| **Coverage** | The percentage of techniques with at least one detection |
| **Service-Aware Coverage** | Coverage model incorporating cloud service scope |
| **Confidence Score** | Mapping certainty (0.4 - 1.0) |

### B. References

- MITRE ATT&CK Framework: https://attack.mitre.org/
- CIS Benchmarks: https://www.cisecurity.org/cis-benchmarks
- NIST Cybersecurity Framework: https://www.nist.gov/cyberframework

---

**Document Control**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 24 Dec 2025 | Architecture Team | Initial release |
| 1.1 | 25 Dec 2025 | Architecture Team | Added Remediation Template Architecture (§13), Security Hardening (§14) |
