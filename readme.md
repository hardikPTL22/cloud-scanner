# Cloud Scanner — AWS Security & GRC Platform

A full-stack **AWS Cloud Security Posture Management (CSPM) and GRC Compliance platform** designed to detect cloud misconfigurations, assess risk, and support audit-ready compliance reporting.

This project focuses on **real-world security controls**, **governance visibility**, and **continuous compliance tracking**, rather than simple rule-based scanning.

---

## Overview

Cloud Scanner helps security teams and students:

- Detect AWS misconfigurations across critical services
- Translate technical findings into **GRC-aligned compliance insights**
- Track **risk posture trends across scans**
- Generate **audit-ready compliance reports**

The platform is built with a **production-oriented architecture** using FastAPI, React, Docker, and AWS SDK.

---

## Architecture

```
┌────────────┐      ┌──────────────┐      ┌──────────────┐
│  React UI  │ ───▶ │ FastAPI API  │ ───▶ │ AWS Services │
│ (GRC Dash) │      │  (Scanner)   │      │  (boto3)    │
└────────────┘      └──────────────┘      └──────────────┘
       │                     │
       │                     └── MongoDB (Scan History & Metadata)
       │
       └── Compliance Reports (PDF / CSV / JSON)
```

---

## Core Features

### AWS Security Scanning
- Multi-service misconfiguration detection:
  - IAM
  - S3
  - EC2
  - RDS
  - CloudTrail
  - VPC & networking checks
- Secure **AWS STS-based credential validation**
- Principle-of-least-privilege friendly scanning

### File Scanning
- S3 file-level scanning
- Malware and suspicious file detection
- Hash-based analysis and metadata reporting

### GRC & Compliance
- **ISO 27001–aligned control mapping**
- Risk-weighted compliance scoring
- Centralized **GRC dashboard**
- Non-compliant control tracking with remediation context
- Compliance score calculation per scan

### Compliance Trend Analysis
- Track compliance posture across multiple scans
- Identify improvement or degradation over time
- Supports audit readiness and continuous monitoring

### Reporting
- Export scan and compliance data in:
  - PDF (audit-ready)
  - CSV
  - JSON
- Designed for security reviews and governance reporting

---

## Tech Stack

### Backend
- FastAPI (Python)
- boto3 (AWS SDK)
- Pydantic
- MongoDB
- STS-based authentication

### Frontend
- React + TypeScript
- TanStack Router & Query
- shadcn/ui
- Recharts (GRC trend visualization)

### Infrastructure
- Docker & Docker Compose
- Environment-based configuration

---

## API Highlights

| Endpoint | Description |
|--------|------------|
| `POST /api/scan` | Run AWS service scans |
| `GET /api/scans` | Scan history |
| `GET /api/scans/{scan_id}` | Scan details |
| `GET /api/grc/{scan_id}` | GRC compliance dashboard |
| `GET /api/reports/*` | Report downloads |

---

## Local Setup

### Prerequisites
- Docker & Docker Compose
- AWS credentials with read-only permissions

### Run the Platform
```bash
docker compose up --build
```

Frontend and backend services will start automatically.

---

## Security Design Considerations

- No AWS credentials stored persistently
- Uses short-lived STS validation
- Scan metadata separated from credentials
- Designed for **read-only cloud assessment**

---

## Project Status

**Actively evolving**

This project is being extended with advanced GRC and AI-driven capabilities.

---

## Roadmap

- ISO ↔ NIST ↔ CIS control mapping engine
- Risk acceptance & exception tracking
- AI-assisted misconfiguration prioritization
- LLM-based remediation guidance
- Compliance maturity scoring model
- Scheduled scans & alerting
- Role-based access control (RBAC)

---

## Why This Project Matters

This is not just a scanner — it is a **GRC-oriented security platform** that bridges:

> **Technical cloud misconfigurations ↔ Governance, Risk, and Compliance**

It reflects how modern cloud security teams actually operate.

---

## Author

**Hardik Patel**  
Cybersecurity | Cloud & GRC  
GitHub: https://github.com/hardikPTL22

---

## Disclaimer

This tool is intended for **educational and defensive security purposes only**.  
Only scan AWS environments you own or have explicit permission