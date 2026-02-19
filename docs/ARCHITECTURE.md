# GRC Guardian - System Architecture

## Overview

GRC Guardian is a hybrid compliance system that combines deterministic rule evaluation with agentic orchestration. The system uses AWS Config as the authoritative source of truth while leveraging Bedrock (Claude) for intelligent planning and workflow orchestration.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         User / Compliance Team                          │
└───────────────────────────┬─────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                          FastAPI Service                                │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │  REST Endpoints: /scan, /reports, /evidence, /status             │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└───────────────────────────┬─────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      Agent Orchestration Layer                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────────┐ │
│  │   Planner    │──│  Validator   │──│     Orchestrator             │ │
│  │  (Bedrock)   │  │  (Bedrock)   │  │  (Workflow Coordinator)      │ │
│  └──────────────┘  └──────────────┘  └──────────────────────────────┘ │
└───────────────┬──────────────────────────────┬──────────────────────────┘
                │                              │
                ▼                              ▼
┌───────────────────────────────┐  ┌─────────────────────────────────────┐
│      RAG System               │  │    Inspection Tools                 │
│  ┌─────────────────────────┐  │  │  ┌──────────────────────────────┐  │
│  │  Control Card Store     │  │  │  │   aws_config (truth source)  │  │
│  │  - SOC 2, ISO 27001     │  │  │  │   s3_inspector               │  │
│  │  - NIST, PCI-DSS        │  │  │  │   iam_inspector              │  │
│  │  - Custom frameworks    │  │  │  └──────────────────────────────┘  │
│  └─────────────────────────┘  │  └─────────────┬───────────────────────┘
│  Vector Store (ChromaDB)      │                │
└───────────────────────────────┘                │
                                                  ▼
                                    ┌─────────────────────────────────────┐
                                    │      AWS Infrastructure             │
                                    │  ┌──────────────────────────────┐  │
                                    │  │  AWS Config (Rules Engine)   │  │
                                    │  │  S3 Buckets                  │  │
                                    │  │  IAM Policies                │  │
                                    │  │  CloudTrail                  │  │
                                    │  └──────────────────────────────┘  │
                                    └─────────────┬───────────────────────┘
                                                  │
                                                  ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        Evidence & Reporting                             │
│  ┌──────────────────────┐  ┌─────────────────────────────────────────┐ │
│  │  Evidence Writer     │  │  Report Renderers                       │ │
│  │  - Manifest hashing  │  │  - JSON (machine-readable)              │ │
│  │  - Digital signing   │  │  - HTML (human-readable)                │ │
│  │  - RUN-ID tracking   │  │  - PDF (executive summary)              │ │
│  └──────────────────────┘  └─────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
```

## Component Responsibilities

### 1. FastAPI Service (`api/`)
- **Purpose**: REST API gateway for all GRC operations
- **Responsibilities**:
  - Accept scan requests with control framework selection
  - Return compliance status and reports
  - Provide evidence artifact retrieval
  - Stream real-time scan progress
- **Key Endpoints**:
  - `POST /api/v1/scan` - Trigger compliance scan
  - `GET /api/v1/reports/{run_id}` - Retrieve compliance report
  - `GET /api/v1/evidence/{run_id}` - Download evidence bundle
  - `GET /api/v1/status/{run_id}` - Check scan status

### 2. Agent Orchestration Layer (`agent/`)
- **Planner**: Uses Bedrock to decompose compliance requirements into actionable tasks
- **Validator**: Reviews scan results for completeness and accuracy
- **Orchestrator**: Coordinates multi-step workflows (scan → validate → report)
- **Key Principle**: Agents plan and explain; they do NOT make compliance decisions

### 3. Inspection Tools (`tools/`)
- **aws_config**: Queries AWS Config for compliance rule evaluation (DETERMINISTIC)
- **s3_inspector**: Checks S3 bucket encryption, public access, versioning
- **iam_inspector**: Analyzes IAM policies for least-privilege violations
- **Design**: All tools return structured evidence, not boolean pass/fail

### 4. RAG System (`rag/`)
- **Purpose**: Retrieve relevant control cards for compliance frameworks
- **Ingestion**: Processes control cards (markdown/JSON) into vector embeddings
- **Retrieval**: Finds relevant controls based on scan context
- **Storage**: ChromaDB for vector similarity search

### 5. Evidence System (`evidence/`)
- **Evidence Writer**: Stores raw inspection results with metadata
- **Manifest Generator**: Creates SHA-256 hash of all evidence files
- **Digital Signer**: Signs manifest with private key for tamper-evidence
- **Storage Format**:
  ```
  evidence/
    runs/
      RUN-20240217-143522/
        manifest.json
        manifest.sig
        raw_findings.json
        aws_config_snapshot.json
  ```

### 6. Report Renderers (`reports/`)
- **JSON Renderer**: Machine-readable compliance results
- **HTML Renderer**: Interactive dashboard with drill-down
- **PDF Renderer**: Executive summary for auditors

## Data Flow

### Compliance Scan Workflow

```
1. User Request
   └─> POST /api/v1/scan {"framework": "SOC2", "scope": "production"}

2. Planner Agent (Bedrock)
   └─> Decomposes SOC 2 into control categories
   └─> Returns: [AccessControls, Logging, Encryption, ...]

3. RAG Retrieval
   └─> Fetches SOC 2 control cards from vector store
   └─> Returns: Control definitions and acceptance criteria

4. Orchestrator
   └─> For each control category:
       ├─> Selects appropriate inspection tool
       ├─> aws_config.evaluate_rules(control_id)
       ├─> s3_inspector.check_encryption()
       └─> iam_inspector.check_policies()

5. AWS Config (Truth Source)
   └─> Returns compliance state: {compliant: true/false, evidence: {...}}

6. Evidence Writer
   └─> Stores findings with RUN-ID
   └─> Generates manifest.json
   └─> Signs manifest with private key

7. Validator Agent (Bedrock)
   └─> Reviews completeness of scan
   └─> Identifies missing controls or ambiguous results
   └─> Generates human-readable explanations

8. Report Renderer
   └─> Generates HTML/PDF report
   └─> Returns report URL to user

9. Response
   └─> {"run_id": "RUN-20240217-143522", "status": "complete",
        "report_url": "/reports/RUN-20240217-143522.html"}
```

## Key Design Decisions

### 1. AWS Config as Truth Source
- **Rationale**: AWS Config provides auditable, timestamped configuration snapshots
- **Benefit**: Compliance decisions are deterministic and reproducible
- **Trade-off**: Limited to AWS infrastructure (not multi-cloud)

### 2. Bedrock for Planning Only
- **Rationale**: LLMs are non-deterministic; unsuitable for compliance decisions
- **Benefit**: Agents improve workflow efficiency without introducing risk
- **Guardrail**: All compliance pass/fail decisions come from AWS Config rules

### 3. Evidence Signing
- **Rationale**: Regulatory audits require tamper-evident artifacts
- **Benefit**: Digital signatures prove evidence integrity
- **Implementation**: RSA-2048 signing with timestamping

### 4. RUN-ID Isolation
- **Rationale**: Each scan is independent and auditable
- **Benefit**: Historical compliance state is preserved
- **Storage**: S3 with versioning and lifecycle policies

## Security Considerations

### OWASP LLM Top 10 Mitigations
- **Prompt Injection**: Bedrock agents use structured input/output schemas
- **Excessive Agency**: Agents cannot modify infrastructure (read-only tools)
- **Sensitive Data Exposure**: All credentials stored in AWS Secrets Manager
- **Insecure Output Handling**: Agent responses are validated before execution

### OWASP Agentic AI Top 10 Mitigations
- **Unbounded Actions**: Tool execution timeout and retry limits
- **Agent State Poisoning**: Stateless agent design (no persistent memory)
- **Insufficient Monitoring**: CloudWatch logs for all agent invocations
- **Agent Workflow Hijacking**: Input validation and schema enforcement

## Infrastructure Setup

The `infra/` directory contains Terraform for:
- Simulated AWS Organization with multiple accounts
- AWS Config rules for common compliance frameworks
- S3 buckets with various compliance states (for testing)
- IAM roles with deliberate misconfigurations (for validation)

## Future Enhancements

1. **Multi-Cloud Support**: Extend to Azure, GCP via OpenTofu
2. **Real-Time Monitoring**: Continuous compliance vs. point-in-time scans
3. **Remediation Workflows**: Automated fix generation (human-approved)
4. **Custom Frameworks**: UI for uploading proprietary control cards
5. **API Rate Limiting**: Prevent abuse of scan endpoints

## References

- [AWS Config Rules](https://docs.aws.amazon.com/config/latest/developerguide/evaluate-config.html)
- [Amazon Bedrock Agents](https://docs.aws.amazon.com/bedrock/latest/userguide/agents.html)
- [OWASP LLM Top 10 (2025)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [OWASP Agentic AI Top 10 (2026)](https://owasp.org/www-project-top-10-for-agentic-ai/)
