# GRC Guardian - Autonomous GRC Compliance Guardian

[![Security](https://img.shields.io/badge/OWASP%20LLM-compliant-brightgreen)](docs/SECURITY_COVERAGE.md)
[![Tests](https://img.shields.io/badge/tests-63%2B-green)]()
[![Evidence](https://img.shields.io/badge/evidence-signed%20%26%20hashed-brightgreen)]()
[![Python](https://img.shields.io/badge/python-3.12+-blue)]()
[![Status](https://img.shields.io/badge/status-production--ready-success)]()

## Overview

**GRC Guardian** is an enterprise-grade autonomous compliance scanner that combines AWS Bedrock (Claude 3.5 Sonnet) with deterministic validation. Built with defense-in-depth architecture, it provides audit-ready evidence with cryptographic integrity guarantees and implements comprehensive OWASP LLM Top 10 security controls.

### 🎯 Core Design Principles

- ✅ **Deterministic Compliance Engine**: AWS Config is the source of truth (not LLM)
- ✅ **AI Orchestration**: Bedrock (Claude) plans and explains, but never evaluates compliance
- ✅ **Never-Crash Guarantee**: Invalid LLM plans trigger repair → fallback (9 core rules)
- ✅ **Evidence-Based Audit Trail**: Every run produces cryptographically signed artifacts
- ✅ **Security-First**: Implements all OWASP LLM + Agentic AI Top 10 controls

### 🚀 Key Features

#### **Security & Reliability**
- **Multi-Layer Prompt Injection Defense**: 5 security layers including input filtering, Bedrock Guardrails, and risk flagging
- **Hallucination Prevention**: Response guard validates LLM output against ground truth
- **Sensitive Data Redaction**: Automatic filtering of AWS keys, tokens, credentials
- **Graceful Guardrail Handling**: User-friendly messages instead of 500 errors
- **Read-Only by Design**: No AWS modifications - audit only

#### **Natural Language Interface**
- **Contextual Responses**: Ask "show non-compliant S3 buckets" → get specific answers
- **Complete Listings**: Shows ALL resources (e.g., all 6 non-compliant, not just 1)
- **Clean Output**: Natural language without markdown formatting
- **Deterministic Filtering**: Python handles logic, LLM only generates explanations

#### **Enterprise Features**
- **Web Dashboard**: Professional UI with compliance charts and filtering
- **Bedrock Guardrails**: AWS-managed prompt injection + PII filtering
- **Evidence Integrity**: SHA256 hashes + HMAC-SHA256 signatures
- **Security Regression Log**: Append-only JSONL tracks all security events
- **CSV Export**: One-click download for auditors
- **Function Calling**: Structured LLM outputs with schema validation

### System Architecture

The system combines:
1. **AWS Config** - Ground truth for infrastructure state and compliance rules
2. **FastAPI Service** - REST API for triggering scans, retrieving reports
3. **Agent Layer** - Planner, validator, and orchestrator for multi-step compliance workflows
4. **RAG System** - Ingests and retrieves control framework cards (SOC 2, ISO 27001, NIST, etc.)
5. **Evidence System** - Generates tamper-evident compliance artifacts
6. **Report Renderer** - Produces human-readable compliance reports

## Project Structure

```
grc-guardian/
├── api/
│   ├── app/           # FastAPI service endpoints
│   └── tests/         # API integration tests
├── agent/             # Agentic orchestration (planner/validator/orchestrator)
├── tools/             # Inspection modules
│   ├── aws_config     # AWS Config rule evaluator
│   ├── s3_inspector   # S3 bucket compliance checks
│   └── iam_inspector  # IAM policy analysis
├── rag/               # Control card ingestion and retrieval
├── evidence/          # Evidence writer, manifest hashing/signing
├── reports/           # Report renderers (JSON, HTML, PDF)
├── infra/             # Terraform for simulated AWS organization
├── scripts/           # Utility scripts for setup and maintenance
└── docs/              # Architecture and design documentation
```

## 🔒 Security Compliance Coverage

**See [SECURITY_COVERAGE.md](docs/SECURITY_COVERAGE.md) for complete matrices with tests and evidence.**

### OWASP GenAI LLM Top 10 (2025) - Summary

| Risk | Key Controls | Status |
|------|-------------|---------|
| LLM01: Prompt Injection | Input filtering (15+ patterns) + Bedrock Guardrails + Risk flagging | ✅ **Implemented** |
| LLM02: Insecure Output | Output redaction + Hallucination guard + Guard flags | ✅ **Implemented** |
| LLM03: Training Data Poisoning | Use pre-trained Bedrock models only | ✅ **N/A** |
| LLM04: Model DoS | Rate limiting (10/60s) + Max tokens + Size limits | ✅ **Implemented** |
| LLM05: Supply Chain | Pinned dependencies + Evidence signing | ✅ **Implemented** |
| LLM06: Sensitive Info Disclosure | Output redaction + PII guardrails | ✅ **Implemented** |
| LLM07: Insecure Plugin Design | Tool allowlist (2 tools only) | ✅ **Implemented** |
| LLM08: Excessive Agency | Read-only tools + JSON schema validation | ✅ **Implemented** |
| LLM09: Overreliance | Deterministic tools + Evidence + Citations | ✅ **Implemented** |
| LLM10: Model Theft | Use AWS Bedrock managed models | ✅ **N/A** |

### OWASP Agentic AI Top 10 (2026) - Summary

| Risk | Key Controls | Status |
|------|-------------|---------|
| AAI01: Prompt Injection in Agents | Stateless design + Input filtering + Guardrails | ✅ **Implemented** |
| AAI02: Insecure Tool Design | Tool allowlist + Read-only APIs + RAG validation | ✅ **Implemented** |
| AAI03: Unbounded Consumption | Max 1 repair + Deterministic fallback + Pagination | ✅ **Implemented** |
| AAI04: Agent Poisoning | Stateless architecture + Immutable tools | ✅ **N/A** |
| AAI05: Lack of Auditability | Security regression log + Evidence artifacts | ✅ **Implemented** |
| AAI06: Insufficient Tool Authorization | IAM least privilege + Tool allowlist | ✅ **Implemented** |
| AAI07: Prompt Leakage | Output filtering + Guardrails | ✅ **Implemented** |
| AAI08: Lack of Output Validation | JSON schema + Hallucination guard + Repair/fallback | ✅ **Implemented** |
| AAI09: Insecure Memory | Stateless architecture | ✅ **N/A** |
| AAI10: Insufficient Monitoring | Security logs + Structured logging + Run tracking | ✅ **Implemented** |

**Coverage:** 40 controls, 63+ tests, 7 evidence artifact types

## 📖 How to Run the Demo

**Want to see it in action?** Follow the [3-5 minute demo script](docs/DEMO_SCRIPT.md):

1. **Show misconfigured resources** (public S3, no MFA)
2. **Run compliance scan** via API → Get findings + evidence
3. **Show evidence artifacts** (plan, findings, manifest with SHA256)
4. **Demonstrate prompt injection blocking** → Security log entry
5. **Fix a misconfiguration** → Re-scan shows improvement
6. **Explain why this is enterprise-grade** (OWASP coverage, never-crash, auditability)

**Key Demo Points:**
- ✅ Bedrock Guardrails block malicious prompts
- ✅ Fallback plan ensures never-crash guarantee
- ✅ Every scan produces signed evidence artifacts
- ✅ Security regression log tracks all incidents

## 🏗️ Architecture Quick View

```
User Request
    ↓
┌─────────────────────────────────────────┐
│ FastAPI API (api/app/)                  │
│   • API key auth                        │
│   • Rate limiting (10/60s)              │
│   • Input filter (injection detection)  │
│   • Risk flagging                       │
└──────────────┬──────────────────────────┘
               ↓
┌─────────────────────────────────────────┐
│ Agent Orchestrator (agent/)             │
│   • Bedrock LLM planner                 │
│   • JSON schema validator               │
│   • Repair logic (max 1 attempt)        │
│   • Deterministic fallback (9 rules)    │
└──────┬──────────────────────┬───────────┘
       ↓                      ↓
┌──────────────┐    ┌─────────────────────┐
│ Bedrock      │    │ Deterministic Tools │
│ + Guardrails │    │   • AWS Config (RO) │
│   • PII      │    │   • RAG (local)     │
│   • Attacks  │    │   • No mutations    │
└──────────────┘    └──────────┬──────────┘
                               ↓
                    ┌──────────────────────┐
                    │ Response Processing  │
                    │   • Hallucination    │
                    │     guard            │
                    │   • Output filter    │
                    │   • Evidence writer  │
                    └──────────────────────┘
```

**Key Insight:** Even if LLM is compromised, tools are deterministic and read-only.

For detailed architecture, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## 🚀 Getting Started

### Prerequisites

- **Python 3.11+**
- **AWS Account** with Config enabled
- **Terraform 1.5+** (for simulated org)
- **AWS CLI** configured
- **Optional:** Bedrock Guardrails (see [setup guide](scripts/bedrock_guardrails_setup.md))

### Quick Start

```bash
# 1. Create virtual environment and install dependencies
make venv
make install

# 2. Run tests (63+ tests)
make test

# 3. Deploy simulated AWS org (optional)
cd infra/terraform
terraform init
terraform apply  # Creates compliant + non-compliant resources

# 4. Set environment variables
cp .env.example .env
# Edit .env with your AWS region, Bedrock model ID, guardrail ID (optional)

# 5. Start the API service
make run  # Starts on http://localhost:8000

# 6. Access the dashboard
# Open browser: http://localhost:8000
# The dashboard provides a visual interface for running scans and viewing results
```

### 🖥️ Using the Web Dashboard (NEW!)

GRC Guardian now includes a professional web dashboard for easy compliance scanning:

1. **Open dashboard**: Navigate to `http://localhost:8000` in your browser
2. **Configure API**: Enter your API key (default: `dev-key-change-in-production`)
3. **Run scan**: Enter compliance query, select framework (NIST 800-53, SOC 2, ISO 27001), click "Run Compliance Scan"
4. **View results**:
   - Compliance score gauge chart
   - Compliant/Non-Compliant counts
   - Filterable findings table (by status and severity)
   - Download buttons for JSON/CSV exports
5. **Download artifacts**: One-click download of findings in JSON or CSV format

**Dashboard Features:**
- 📊 Real-time compliance score visualization with Chart.js
- 📋 Interactive findings table with status/severity filters
- 📥 One-click artifact download (JSON/CSV)
- 🎨 Clean, professional UI with Tailwind CSS
- 🚀 Zero build tools - vanilla JavaScript for simplicity
- 🔐 Secure - integrates with existing API authentication

### 📡 Using the API Directly

```bash
# Run a compliance scan via curl
curl -X POST http://localhost:8000/api/v1/ask \
  -H "Content-Type: application/json" \
  -H "X-API-Key: dev-key-change-in-production" \
  -d '{"prompt": "Check S3 and IAM compliance", "scope": "prod"}'
```

### Run Linting & Formatting

```bash
make lint    # Run ruff linter
make format  # Format code
```

## 📊 Evidence and Audit Trail

Each compliance scan generates a unique `RUN-ID` with tamper-evident artifacts:

```
api/app/data/runs/RUN-20260217-143022-a1b2c3/
├── plan.json                 # Execution plan (LLM or fallback)
├── findings.json             # Compliance findings (deterministic)
├── findings.csv              # CSV format for auditors
├── report.json               # Human-readable explanation
├── manifest.json             # SHA256 hashes of all files
├── manifest.sig              # HMAC signature of manifest
└── guardrails_event.json     # Guardrail blocks (if any)
```

**Security Regression Log:**
```bash
# Append-only JSONL with all security events
tail -f api/app/data/security_regressions.jsonl
```

**Example Events:**
- `prompt_injection_suspected` - Input filter detected attack
- `guardrail_blocked` - Bedrock Guardrails intervened
- `planner_json_repaired` - LLM plan was fixed
- `fallback_invoked` - Used deterministic fallback
- `output_guard_stripped` - Hallucinated resources removed

**CSV Export for Auditors:**
```bash
# Option 1: CSV generated automatically during scan (best-effort)
# Check if findings.csv exists in run directory

# Option 2: On-demand CSV export from any completed run
curl -X GET "http://localhost:8000/api/v1/runs/RUN-{run_id}/export?format=csv" \
  -H "X-API-Key: dev-key-change-in-production" \
  -o findings.csv

# Option 3: Export as JSON
curl -X GET "http://localhost:8000/api/v1/runs/RUN-{run_id}/export?format=json" \
  -H "X-API-Key: dev-key-change-in-production" \
  -o findings.json
```

**CSV Format:** Deterministic columns (run_id, resource_id, resource_type, rule_name, status, severity, description, timestamp, region)

**Verification:**
```bash
# Verify evidence integrity
python -m evidence.manifest verify api/app/data/runs/RUN-{run_id}
```

## 🔐 Security Proof Links

**Want to verify our security claims?**

- 📖 **[SECURITY_COVERAGE.md](docs/SECURITY_COVERAGE.md)** - Complete OWASP matrices with tests and evidence
- 🎯 **[THREAT_MODEL.md](docs/THREAT_MODEL.md)** - STRIDE analysis + mitigations
- 🎬 **[DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md)** - 3-5 minute walkthrough
- 🏗️ **[ARCHITECTURE.md](docs/ARCHITECTURE.md)** - System design and data flow

**Key Test Files:**
- `agent/tests/test_bedrock_integration.py` - Guardrails, fallback, hallucination guard
- `api/app/tests/test_input_filter.py` - Injection detection
- `api/app/tests/test_output_filter.py` - Redaction and hallucination removal
- `agent/tests/test_orchestrator.py` - Repair and fallback logic
- `evidence/tests/test_signer.py` - HMAC signing

## 🛠️ Development

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed system architecture and data flow diagrams.

### Project Structure

```
grc-guardian/
├── frontend/              # Web dashboard (HTML/JS/Tailwind CSS)
├── api/app/               # FastAPI service (auth, rate limit, filtering)
├── agent/                 # Orchestrator (planner, validator, fallback)
├── tools/                 # Deterministic tools (AWS Config, RAG)
├── evidence/              # Evidence writer, manifest, signing, CSV export
├── rag/                   # RAG system with control cards
├── infra/terraform/       # Simulated AWS org infrastructure
├── scripts/               # Setup scripts (Bedrock Guardrails)
└── docs/                  # Security coverage, threat model, demo
```

## License

MIT License - See LICENSE file for details

## Contributing

Contributions welcome! Please read CONTRIBUTING.md for guidelines.
