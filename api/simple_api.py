"""Simple GRC Guardian API - Clean rebuild without caching issues.

This is a minimal, working API that integrates all agentic features:
- Bedrock Guardrails
- Out-of-scope detection
- Fallback mechanism
- Never crashes
"""

import os
import uuid
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel, Field

# Set environment to prevent bytecode caching
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

app = FastAPI(
    title="GRC Guardian API",
    description="Simple, reliable compliance monitoring API",
    version="2.0.0",
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request/Response Models
class AskRequest(BaseModel):
    """Compliance scan request."""
    prompt: str = Field(..., min_length=1, max_length=1000)
    scope: Optional[str] = Field(default="prod", pattern="^(prod|dev|staging|all)$")


class Finding(BaseModel):
    """Compliance finding."""
    resource_id: str
    resource_type: str
    rule_name: str
    status: str
    severity: str
    description: str


class AskResponse(BaseModel):
    """Compliance scan response."""
    run_id: str
    status: str
    summary: str
    findings: list[Finding]
    metadata: dict


# API Key validation
API_KEY = "dev-key-change-in-production"


def verify_api_key(x_api_key: Optional[str] = Header(None)) -> str:
    """Verify API key from header."""
    if not x_api_key or x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_api_key


def is_out_of_scope(prompt: str) -> bool:
    """Quick check if prompt is out of scope."""
    prompt_lower = prompt.lower()

    compliance_keywords = ["s3", "iam", "security", "compliance", "audit", "cloudtrail",
                          "encryption", "mfa", "config", "bucket", "aws"]

    non_compliance = ["weather", "hello", "how are you", "what is", "who is",
                     "how many ec2", "list ec2", "count", "time", "date"]

    has_compliance = any(kw in prompt_lower for kw in compliance_keywords)
    is_non_compliance = any(pattern in prompt_lower for pattern in non_compliance)

    return is_non_compliance and not has_compliance and len(prompt) < 100


@app.get("/")
async def root():
    """Serve the frontend HTML."""
    frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend", "index.html")
    return FileResponse(frontend_path)


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "2.0.0"
    }


@app.post("/api/v1/ask", response_model=AskResponse)
async def ask(
    request: AskRequest,
    x_api_key: str = Header(..., alias="X-API-Key")
) -> AskResponse:
    """
    Submit a compliance scan request.

    This endpoint:
    1. Validates API key
    2. Checks if question is out-of-scope
    3. Calls agent orchestrator
    4. Returns findings
    """
    # Verify API key
    verify_api_key(x_api_key)

    # Generate run ID
    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    short_uuid = str(uuid.uuid4())[:8]
    run_id = f"RUN-{timestamp}-{short_uuid}"

    print(f"\n{'='*60}")
    print(f"[{run_id}] New request: {request.prompt[:50]}...")
    print(f"{'='*60}")

    # Quick out-of-scope check
    if is_out_of_scope(request.prompt):
        print(f"[{run_id}] Out-of-scope (pre-validation)")
        return AskResponse(
            run_id=run_id,
            status="out_of_scope",
            summary="I can only help with AWS compliance monitoring and security audits. Please ask about S3 security, IAM compliance, CloudTrail, encryption, MFA, or other AWS Config compliance rules.",
            findings=[],
            metadata={
                "execution_time_ms": 0,
                "total_findings": 0,
                "compliant_count": 0,
                "non_compliant_count": 0
            }
        )

    try:
        # Import agent module HERE (fresh import per request)
        print(f"[{run_id}] Importing agent orchestrator...")
        from agent.orchestrator import build_and_execute_plan

        # Execute compliance scan
        print(f"[{run_id}] Executing plan...")
        result = build_and_execute_plan(
            user_question=request.prompt,
            env=request.scope or "prod",
            region="us-west-2"
        )

        execution = result.get("execution", {})

        # Handle out-of-scope from LLM
        if execution.get("status") == "out_of_scope":
            message = execution.get("message", "I can only help with AWS compliance monitoring.")
            print(f"[{run_id}] Out-of-scope (LLM detection)")

            return AskResponse(
                run_id=run_id,
                status="out_of_scope",
                summary=message,
                findings=[],
                metadata={
                    "execution_time_ms": 0,
                    "total_findings": 0,
                    "compliant_count": 0,
                    "non_compliant_count": 0
                }
            )

        # Get findings
        all_findings = execution.get("all_findings", [])

        # Convert to API format
        findings = []
        for f in all_findings:
            severity = "HIGH" if f.get("compliance_type") == "NON_COMPLIANT" else "LOW"
            findings.append(
                Finding(
                    resource_id=f.get("resource_id", "unknown"),
                    resource_type=f.get("resource_type", "unknown"),
                    rule_name=f.get("rule", "unknown"),
                    status=f.get("compliance_type", "UNKNOWN"),
                    severity=severity,
                    description=f.get("annotation", "No description")
                )
            )

        # Calculate counts
        compliant = sum(1 for f in all_findings if f.get("compliance_type") == "COMPLIANT")
        non_compliant = sum(1 for f in all_findings if f.get("compliance_type") == "NON_COMPLIANT")

        summary = (
            f"Compliance scan completed. "
            f"Found {len(all_findings)} resources: "
            f"{compliant} compliant, {non_compliant} non-compliant."
        )

        print(f"[{run_id}] Success: {len(findings)} findings")

        return AskResponse(
            run_id=run_id,
            status="completed",
            summary=summary,
            findings=findings,
            metadata={
                "execution_time_ms": 0,
                "total_findings": len(findings),
                "compliant_count": compliant,
                "non_compliant_count": non_compliant
            }
        )

    except Exception as e:
        print(f"[{run_id}] ERROR: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Scan failed: {str(e)}"
        )


# To run this API:
# python -m uvicorn api.simple_api:app --reload --host 0.0.0.0 --port 8000
