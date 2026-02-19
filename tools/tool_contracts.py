"""Tool contracts - typed inputs and outputs for all tools.

This module defines the data contracts for tool execution:
- Input parameters (typed)
- Output structure (normalized findings)
- Evidence metadata format
"""

from datetime import datetime
from typing import Any, Literal, Optional, TypedDict


class ToolInput(TypedDict, total=False):
    """Base tool input parameters."""

    region: str
    env: Optional[str]


class AWSConfigEvalInput(ToolInput):
    """Input parameters for aws_config_eval tool."""

    rules: list[str]  # List of Config rule names to evaluate
    resource_type: Optional[str]  # Filter by resource type (e.g., AWS::S3::Bucket)


class RAGRetrieveInput(ToolInput):
    """Input parameters for rag_retrieve tool."""

    framework: Optional[str]  # Compliance framework (SOC2, ISO27001, etc.)
    category: Optional[str]  # Control category
    query: Optional[str]  # Natural language query


class Evidence(TypedDict):
    """Evidence metadata for a finding."""

    source: str  # Source of the finding (e.g., "aws_config")
    rule_arn: Optional[str]  # ARN of the Config rule
    region: str  # AWS region
    account_id: Optional[str]  # AWS account ID
    recorded_at: Optional[str]  # When evidence was recorded


class Finding(TypedDict):
    """Normalized finding structure (output from all tools)."""

    rule: str  # Rule or control name
    compliance_type: Literal["COMPLIANT", "NON_COMPLIANT", "NOT_APPLICABLE", "INSUFFICIENT_DATA"]
    resource_type: str  # AWS resource type (e.g., AWS::S3::Bucket)
    resource_id: str  # Resource identifier
    timestamp: str  # ISO 8601 timestamp
    annotation: Optional[str]  # Human-readable description
    evidence: Evidence  # Evidence metadata


class ToolResult(TypedDict):
    """Result from tool execution."""

    tool_name: str  # Name of the tool that was executed
    status: Literal["success", "error"]  # Execution status
    findings: list[Finding]  # List of normalized findings
    error: Optional[str]  # Error message if status is "error"
    metadata: dict[str, Any]  # Additional tool-specific metadata


# Type aliases for clarity
ComplianceType = Literal["COMPLIANT", "NON_COMPLIANT", "NOT_APPLICABLE", "INSUFFICIENT_DATA"]
ToolStatus = Literal["success", "error"]


def create_finding(
    rule: str,
    compliance_type: ComplianceType,
    resource_type: str,
    resource_id: str,
    timestamp: Optional[datetime] = None,
    annotation: Optional[str] = None,
    evidence_source: str = "aws_config",
    rule_arn: Optional[str] = None,
    region: str = "us-west-2",
    account_id: Optional[str] = None,
) -> Finding:
    """
    Create a normalized finding object.

    Args:
        rule: Rule or control name
        compliance_type: Compliance status
        resource_type: AWS resource type
        resource_id: Resource identifier
        timestamp: When the finding was recorded (defaults to now)
        annotation: Human-readable description
        evidence_source: Source of the evidence
        rule_arn: ARN of the Config rule
        region: AWS region
        account_id: AWS account ID

    Returns:
        Normalized Finding object
    """
    if timestamp is None:
        timestamp = datetime.utcnow()

    return Finding(
        rule=rule,
        compliance_type=compliance_type,
        resource_type=resource_type,
        resource_id=resource_id,
        timestamp=timestamp.isoformat() + "Z" if isinstance(timestamp, datetime) else timestamp,
        annotation=annotation,
        evidence=Evidence(
            source=evidence_source,
            rule_arn=rule_arn,
            region=region,
            account_id=account_id,
            recorded_at=timestamp.isoformat() + "Z" if isinstance(timestamp, datetime) else None,
        ),
    )


def create_tool_result(
    tool_name: str,
    findings: list[Finding],
    status: ToolStatus = "success",
    error: Optional[str] = None,
    **metadata: Any,
) -> ToolResult:
    """
    Create a tool result object.

    Args:
        tool_name: Name of the tool
        findings: List of findings
        status: Execution status
        error: Error message if failed
        **metadata: Additional tool-specific metadata

    Returns:
        ToolResult object
    """
    return ToolResult(
        tool_name=tool_name,
        status=status,
        findings=findings,
        error=error,
        metadata=metadata,
    )
