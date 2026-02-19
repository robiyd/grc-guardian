"""Pydantic schemas for API request/response models."""

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


class AskRequest(BaseModel):
    """Request schema for POST /ask endpoint."""

    prompt: str = Field(
        ...,
        min_length=1,
        max_length=8192,
        description="Compliance question or scan request",
        examples=["Scan all S3 buckets for public access violations"],
    )

    framework: Optional[str] = Field(
        default=None,
        description="Compliance framework (e.g., SOC2, ISO27001, NIST)",
        examples=["SOC2"],
    )

    scope: Optional[str] = Field(
        default=None,
        description="Scope of the scan (e.g., production, all)",
        examples=["production"],
    )

    @field_validator("prompt")
    @classmethod
    def prompt_must_not_be_empty(cls, v: str) -> str:
        """Validate prompt is not just whitespace."""
        if not v.strip():
            raise ValueError("Prompt cannot be empty or whitespace only")
        return v.strip()


class Finding(BaseModel):
    """Individual compliance finding."""

    resource_id: str = Field(..., description="AWS resource identifier")
    resource_type: str = Field(..., description="Resource type (e.g., S3::Bucket)")
    rule_name: str = Field(..., description="Config rule or control name")
    status: str = Field(..., description="COMPLIANT, NON_COMPLIANT, or NOT_APPLICABLE")
    severity: Optional[str] = Field(default=None, description="HIGH, MEDIUM, LOW")
    description: Optional[str] = Field(default=None, description="Finding details")


class AskResponse(BaseModel):
    """Response schema for POST /ask endpoint."""

    run_id: str = Field(..., description="Unique run identifier")
    summary: str = Field(..., description="High-level summary of compliance status")
    findings: list[Finding] = Field(
        default_factory=list, description="List of compliance findings"
    )
    evidence_links: list[str] = Field(
        default_factory=list, description="URLs to evidence artifacts"
    )
    timestamp: datetime = Field(
        default_factory=datetime.utcnow, description="Response timestamp"
    )


class RunMetadata(BaseModel):
    """Metadata for a compliance run."""

    run_id: str
    prompt: str
    framework: Optional[str] = None
    scope: Optional[str] = None
    status: str = Field(
        ..., description="PENDING, IN_PROGRESS, COMPLETED, or FAILED"
    )
    created_at: datetime
    completed_at: Optional[datetime] = None
    summary: Optional[str] = None
    findings_count: int = 0
    evidence_links: list[str] = Field(default_factory=list)


class HealthResponse(BaseModel):
    """Response schema for GET /health endpoint."""

    status: str = Field(default="ok", description="Health status")
    timestamp: datetime = Field(
        default_factory=datetime.utcnow, description="Health check timestamp"
    )
    version: str = Field(default="0.1.0", description="API version")


class ErrorResponse(BaseModel):
    """Error response schema."""

    error: str = Field(..., description="Error type")
    message: str = Field(..., description="Error message")
    run_id: Optional[str] = Field(default=None, description="Run ID if available")
    timestamp: datetime = Field(
        default_factory=datetime.utcnow, description="Error timestamp"
    )
