# CLOUDWATCH — AI-Powered AWS Cloud Security Posture Management

> **Connect your AWS account → Click Scan → Get a security score, prioritized findings in plain English, and a professional PDF report — all in under 10 minutes.**

![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?logo=fastapi)
![React](https://img.shields.io/badge/React-18-61DAFB?logo=react)
![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?logo=typescript)
![Claude AI](https://img.shields.io/badge/Claude-AI-E8651A)

---

## What Is CLOUDWATCH?

CLOUDWATCH is an AI-powered **Cloud Security Posture Management (CSPM)** tool that automatically audits AWS environments for misconfigurations, over-privileged IAM roles, suspicious CloudTrail activity, and CIS Benchmark violations — then uses Claude AI to prioritize findings and generate professional security reports.

**Replaces:** AWS Security Hub (expensive), Prowler (complex CLI), Scout Suite (no AI)  
**Target users:** AWS users, DevOps teams, cloud security analysts, freelance consultants  
**Key differentiator:** AI-powered risk prioritization + plain English findings + beautiful UI

---

## Features

### 6 Security Modules

| Module | What It Checks |
|---|---|
| **Misconfiguration Scanner** | S3 public access/encryption/versioning, EC2 security groups (SSH/RDP/DB ports open to internet), RDS public access/encryption, Lambda secrets in env vars, VPC flow logs |
| **IAM Auditor** | Root MFA, root access keys, user MFA, access key age/rotation, wildcard policies, privilege escalation, password policy |
| **CIS Benchmark v2.0** | 30+ automated checks across IAM, Storage, Logging, Monitoring, Networking with % compliance score |
| **CloudTrail Analyzer** | Upload JSON logs → 8 detection rules (root usage, mass deletion, recon, brute force, security tool disabling) → IP reputation → Claude AI analysis |
| **AI Risk Prioritizer** | Claude AI enriches all findings with plain English, generates fix roadmap (Today/This Week/Month), identifies risk chains |
| **Security Score + Reports** | 0-100 security score with A-F grade, professional PDF and Word (.docx) audit reports |

### Security Score
```
Start: 100 points
Critical finding: -15
High finding:     -8
Medium finding:   -3
Low finding:      -1
Min score:        0

Grade: A (90-100) | B (75-89) | C (60-74) | D (40-59) | F (0-39)
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11 + FastAPI |
| Frontend | React 18 + TypeScript + Tailwind CSS + Recharts |
| Database | SQLite + SQLAlchemy |
| AWS SDK | boto3 |
| AI Engine | Anthropic Claude API (claude-sonnet-4-6) |
| Encryption | cryptography (Fernet/PBKDF2) |
| Reports | ReportLab (PDF) + python-docx (Word) |
| TI Feeds | AbuseIPDB (CloudTrail IP reputation) |

---

## Prerequisites

- Python 3.11+
- Node.js 18+
- An AWS IAM user with the read-only policy below
- Anthropic API key (free tier available at [console.anthropic.com](https://console.anthropic.com))

---

## Setup

### 1. Clone the repo

```bash
git clone https://github.com/YOUR_USERNAME/cloudwatch.git
cd cloudwatch
```

### 2. Backend setup

```bash
cd backend
python -m venv venv
venv\Scripts\activate      # Windows
# source venv/bin/activate  # macOS/Linux

pip install -r requirements.txt

cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY
```

### 3. Frontend setup

```bash
cd ../frontend
npm install
```

### 4. Run

```bash
# Terminal 1 — Backend (port 8001)
cd backend
python -m uvicorn main:app --reload --port 8001

# Terminal 2 — Frontend
cd frontend
npm run dev
```

Open **http://localhost:5173**

Or use the provided script:
```powershell
.\start.ps1
```

---

## AWS IAM Setup

Create a dedicated IAM user for CLOUDWATCH with **read-only** permissions. Attach the policy in `iam_policy.json`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CloudWatchReadOnly",
      "Effect": "Allow",
      "Action": [
        "s3:List*", "s3:GetBucket*",
        "ec2:Describe*",
        "rds:Describe*",
        "iam:List*", "iam:Get*", "iam:GenerateCredentialReport",
        "lambda:List*", "lambda:Get*",
        "cloudtrail:Describe*", "cloudtrail:GetTrailStatus",
        "logs:Describe*",
        "cloudwatch:DescribeAlarms",
        "config:Describe*",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

> CLOUDWATCH **never modifies** any AWS resource. All API calls are read-only.

---

## Usage

1. **Add AWS Account** → Settings → Enter Access Key + Secret Key → Test Connection
2. **Start Scan** → New Scan → Select modules → Click Start
3. **View Results** → Findings tab (filterable) → IAM tab → CIS Benchmark tab
4. **Analyze CloudTrail** → Scan Results → CloudTrail tab → Upload JSON export
5. **Run AI Analysis** → AI Insights tab → Run AI Analysis
6. **Download Report** → PDF or Word button (top right of results page)

---

## Project Structure

```
cloudwatch/
├── backend/
│   ├── main.py                    # FastAPI app
│   ├── models.py                  # SQLAlchemy models
│   ├── database.py                # DB initialization
│   ├── config.py                  # Settings
│   ├── requirements.txt
│   ├── modules/
│   │   ├── aws/                   # Credential encryption, session, permissions
│   │   ├── scanner/               # S3, EC2, RDS, Lambda, VPC scanners + orchestrator
│   │   ├── iam/                   # Root, users, policies, password policy
│   │   ├── cis/                   # CIS Benchmark v2.0 checker
│   │   ├── cloudtrail/            # Parser, detection rules, IP checker, AI analyst
│   │   ├── ai/                    # Claude enrichment, risk prioritizer
│   │   └── reports/               # PDF generator, Word generator, score calculator
│   └── routers/
│       ├── aws_config.py          # AWS account management
│       ├── scans.py               # Scan lifecycle
│       ├── cloudtrail.py          # CloudTrail upload + analysis
│       ├── ai_analyze.py          # AI risk prioritization
│       └── reports.py             # PDF + Word download
└── frontend/
    └── src/
        ├── pages/                 # Dashboard, NewScan, ScanResults, ScanHistory, Settings
        ├── components/            # Sidebar, ScoreCircle, SeverityBadge
        └── api.ts                 # Typed API client
```

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/aws/connect` | Add + validate AWS account |
| GET | `/api/aws/accounts` | List configured accounts |
| POST | `/api/scans/start` | Start a security scan |
| GET | `/api/scans/{id}/status` | Poll scan progress |
| GET | `/api/scans/{id}/findings` | Get findings (filterable) |
| POST | `/api/cloudtrail/{id}/analyze` | Upload + analyze CloudTrail logs |
| POST | `/api/ai/{id}/prioritize` | Run AI risk prioritization |
| GET | `/api/reports/{id}/pdf` | Download PDF report |
| GET | `/api/reports/{id}/word` | Download Word report |

Interactive API docs: **http://localhost:8001/docs**

---

## Security & Privacy

- AWS credentials encrypted with **AES-256 (Fernet)** using machine-specific key derivation (PBKDF2HMAC)
- Credentials **never leave your machine** — stored locally in SQLite only
- All AWS API calls are **read-only** — CLOUDWATCH cannot modify, delete, or create any resource
- Only anonymized finding summaries are sent to the Claude API for AI enrichment

---

## What This Project Demonstrates

| Skill | Implementation |
|---|---|
| **Cloud Security** | AWS CSPM, IAM analysis, CIS Benchmark, threat detection |
| **Python/FastAPI** | Async APIs, background tasks, file uploads, streaming responses |
| **React/TypeScript** | Multi-tab UI, real-time polling, file uploads, chart visualization |
| **AI Integration** | Claude API for security analysis, batch enrichment, structured JSON output |
| **Cryptography** | PBKDF2 key derivation, Fernet symmetric encryption |
| **AWS SDK** | boto3 across 8+ services, multi-region scanning, pagination |
| **Report Generation** | ReportLab PDF with custom layouts, python-docx Word documents |
| **Database Design** | SQLAlchemy ORM, relational schema, encrypted credential storage |

---

## Built By

**Manahil Khan** — Cloud Security Portfolio Project (SaaS)

> Part of a complete cybersecurity portfolio: GRC ✓ | VANTAGE (Pentest) ✓ | SENTINEL (Blue Team) ✓ | CLOUDWATCH (Cloud) ✓
