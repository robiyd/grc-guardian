"""API route handlers."""

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import Response

from .auth import verify_api_key
from .config import settings
from .dependencies import (
    get_input_validator,
    get_output_filter,
    get_rate_limiter,
    get_run_storage,
    get_security_logger,
    is_out_of_scope_quick,
)
from .logging_config import get_logger_with_run_id, logger
from .rate_limit import check_rate_limit
from .schemas import (
    AskRequest,
    AskResponse,
    ErrorResponse,
    Finding,
    HealthResponse,
    RunMetadata,
)
from .input_filter import InputValidator
from .storage import RunStorage

router = APIRouter()


def generate_run_id() -> str:
    """Generate a unique run ID."""
    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    short_uuid = str(uuid.uuid4())[:8]
    return f"RUN-{timestamp}-{short_uuid}"


@router.post("/ask", response_model=AskResponse, status_code=status.HTTP_200_OK)
async def ask_endpoint(
    request: AskRequest,
    api_key: str = Depends(verify_api_key),
    _rate_limit: None = Depends(check_rate_limit),
    input_validator: InputValidator = Depends(get_input_validator),
    run_storage: RunStorage = Depends(get_run_storage),
) -> AskResponse:
    """
    Submit a compliance query or scan request.

    This endpoint:
    1. Validates API key
    2. Checks rate limits
    3. Validates input for size and prompt injection
    4. Creates a unique RUN-ID
    5. Orchestrates the agent (stub for now)
    6. Returns findings and evidence links

    Args:
        request: Ask request with prompt and optional framework/scope
        api_key: Validated API key from header
        _rate_limit: Rate limit check dependency

    Returns:
        AskResponse with run_id, summary, findings, and evidence links

    Raises:
        HTTPException: 400 for validation errors, 413 for size limit
    """
    # Generate run ID
    run_id = generate_run_id()
    run_logger = get_logger_with_run_id(run_id)

    run_logger.info(
        "Received compliance request",
        extra={
            "prompt_length": len(request.prompt),
            "framework": request.framework,
            "scope": request.scope,
        },
    )

    try:
        # Validate input with risk assessment
        risk_info = input_validator.validate_with_risk(request.prompt, run_id=run_id)

        # Log risk information for downstream processing
        if risk_info.has_risk:
            run_logger.warning(
                "Request flagged with security risk",
                extra={
                    "risk_type": risk_info.risk_type,
                    "risk_level": risk_info.risk_level,
                    "matched_text": risk_info.matched_text,
                },
            )
            # Note: We log but don't block - Bedrock Guardrails will make final decision

        # Create run metadata
        run_metadata = RunMetadata(
            run_id=run_id,
            prompt=request.prompt,
            framework=request.framework,
            scope=request.scope,
            status="IN_PROGRESS",
            created_at=datetime.utcnow(),
        )

        # Save initial run metadata
        run_storage.save_run(run_metadata)

        # Check if out-of-scope EARLY (before calling LLM)
        if is_out_of_scope_quick(request.prompt):
            run_logger.info("Request detected as out-of-scope via pre-validation")

            # Return out-of-scope response immediately
            return AskResponse(
                run_id=run_id,
                summary="I can only help with AWS compliance monitoring and security audits. Please ask about S3 security, IAM compliance, CloudTrail, encryption, MFA, or other AWS Config compliance rules.",
                findings=[],
                evidence_links=[],
            )

        # Call agent orchestrator
        run_logger.info("Orchestrating compliance scan with agent")

        # Import agent module inside function for fresh import
        # This avoids caching issues - each request gets fresh code
        from agent import build_and_execute_plan
        from evidence.writer import EvidenceWriter
        from evidence.manifest import generate_manifest
        from evidence.signer import sign_manifest

        # Execute the plan (with guardrail handling)
        try:
            result = build_and_execute_plan(
                user_question=request.prompt,
                env=request.scope or "prod",
                region=settings.bedrock_region,
            )

            plan = result["plan"]
            execution = result["execution"]

        except Exception as plan_error:
            # Check if guardrails blocked during planning
            error_msg = str(plan_error).lower()
            if "guardrail" in error_msg or "blocked" in error_msg or "policy" in error_msg:
                run_logger.warning(f"Request blocked by security guardrails: {plan_error}")

                # Return user-friendly blocked message
                return AskResponse(
                    run_id=run_id,
                    summary=(
                        "Your request was blocked by our security policy. "
                        "Please rephrase your question using different wording.\n\n"
                        "Try these instead:\n"
                        "- 'show security issues'\n"
                        "- 'list failing resources'\n"
                        "- 'what resources need attention'\n"
                        "- 'compliance summary'"
                    ),
                    findings=[],
                    evidence_links=[],
                )
            else:
                # Re-raise if not a guardrail block
                raise

        # Handle out-of-scope response from LLM
        if execution.get("status") == "out_of_scope":
            run_logger.info("Request detected as out-of-scope by LLM")
            message = execution.get("message", "I can only help with AWS compliance monitoring.")

            return AskResponse(
                run_id=run_id,
                summary=message,
                findings=[],
                evidence_links=[],
            )

        all_findings = execution["all_findings"]
        all_citations = execution.get("citations", [])

        # Convert findings to API schema format
        findings = []
        for f in all_findings:
            severity = "HIGH" if f.get("compliance_type") == "NON_COMPLIANT" else "LOW"
            findings.append(
                Finding(
                    resource_id=f.get("resource_id", "unknown"),
                    resource_type=f.get("resource_type", "unknown"),
                    rule_name=f.get("rule", "unknown"),
                    status=f.get("compliance_type", "NOT_APPLICABLE"),
                    severity=severity,
                    description=f.get("annotation", "No description"),
                )
            )

        # Calculate compliance counts (deterministic - source of truth)
        compliant_count = sum(1 for f in all_findings if f.get("compliance_type") == "COMPLIANT")
        non_compliant_count = sum(1 for f in all_findings if f.get("compliance_type") == "NON_COMPLIANT")

        # Deterministically filter findings based on user question (security: don't rely on LLM for filtering)
        def filter_findings_by_question(findings: list, question: str) -> tuple[list, dict]:
            """
            Deterministically filter findings based on user question keywords.

            Returns: (filtered_findings, context_metadata)
            """
            question_lower = question.lower()

            # Detect what user is asking for
            wants_non_compliant = any(word in question_lower for word in ["non-compliant", "non compliant", "noncompliant", "not compliant", "failing", "failed", "violated", "violations", "issues", "problems", "vulnerable", "insecure"])
            wants_compliant = any(word in question_lower for word in ["compliant", "passing", "passed", "good", "secure", "safe"]) and not wants_non_compliant

            # Filter based on detected intent
            if wants_non_compliant:
                filtered = [f for f in findings if f.get("compliance_type") == "NON_COMPLIANT"]
                filter_type = "non_compliant_only"
            elif wants_compliant:
                filtered = [f for f in findings if f.get("compliance_type") == "COMPLIANT"]
                filter_type = "compliant_only"
            else:
                filtered = findings  # Return all
                filter_type = "all"

            metadata = {
                "filter_type": filter_type,
                "filtered_count": len(filtered),
                "total_count": len(findings),
                "wants_non_compliant": wants_non_compliant,
                "wants_compliant": wants_compliant
            }

            return filtered, metadata

        # Filter findings deterministically
        relevant_findings, filter_metadata = filter_findings_by_question(all_findings, request.prompt)

        run_logger.info(
            f"Filtered findings: {filter_metadata['filter_type']}, "
            f"{filter_metadata['filtered_count']}/{filter_metadata['total_count']} relevant"
        )

        # Early return if no matching resources found
        if len(relevant_findings) == 0 and (filter_metadata.get("wants_non_compliant") or filter_metadata.get("wants_compliant")):
            # User asked for specific type but none found - give helpful answer
            if filter_metadata.get("wants_non_compliant"):
                summary = "Great news! No security issues found. All resources are secure and meet compliance requirements."
            else:
                summary = "No compliant resources found. All resources have compliance issues that need to be addressed. Please review the findings below."

            # Skip LLM call and return early
            return AskResponse(
                run_id=run_id,
                summary=summary,
                findings=findings,
                evidence_links=[],
                timestamp=datetime.utcnow(),
            )

        # Use LLM explainer to generate contextual summary
        summary = ""
        try:
            from agent.bedrock_client import create_bedrock_client
            from .output_filter import response_guard

            run_logger.info("Generating contextual explanation with LLM explainer")
            bedrock_client = create_bedrock_client()

            # Pass ALL relevant findings (not truncated) + metadata for validation
            explanation = bedrock_client.llm_explainer(
                findings_json=relevant_findings,  # Filtered findings
                control_cards=all_citations,
                context={
                    "user_question": request.prompt,
                    "total_findings": len(all_findings),
                    "compliant_count": compliant_count,
                    "non_compliant_count": non_compliant_count,
                    "filter_applied": filter_metadata["filter_type"],
                    "expected_count": len(relevant_findings)
                }
            )

            # Security: Validate LLM output against actual findings (prevents hallucination)
            explanation = response_guard(explanation, relevant_findings, run_id=run_id)

            # Extract summary and validate it makes sense
            llm_summary = explanation.get("summary", "")

            # Check if guardrails blocked the request
            if "blocked by safety policy" in llm_summary.lower() or "blocked by security policy" in llm_summary.lower():
                run_logger.warning("Bedrock Guardrails blocked explainer, using deterministic fallback")
                raise ValueError("Guardrails blocked LLM explainer")

            # If LLM returns empty/nonsensical response or wrong data, use deterministic fallback
            if not llm_summary or len(llm_summary) < 10:
                raise ValueError("LLM response too short or empty")

            # Check if LLM is confused (mentioning wrong compliance type)
            if filter_metadata["filter_type"] == "non_compliant_only":
                if any(phrase in llm_summary.lower() for phrase in ["all resources shown are actually compliant", "no non-compliant", "all compliant"]):
                    run_logger.warning("LLM confused about compliance type, using deterministic fallback")
                    raise ValueError("LLM response doesn't match filter type")

            # Build natural language summary (clean, no markdown)
            if filter_metadata["filter_type"] == "non_compliant_only":
                if len(relevant_findings) == 0:
                    summary = "Great news! All resources are compliant. No security issues found."
                else:
                    # Clean up LLM summary by removing markdown
                    clean_summary = llm_summary.replace("**", "").replace("*", "")
                    summary = f"{clean_summary}\n\nSummary: Found {len(relevant_findings)} security {'issue' if len(relevant_findings) == 1 else 'issues'} that need attention."
            elif filter_metadata["filter_type"] == "compliant_only":
                if len(relevant_findings) == 0:
                    summary = "No compliant resources found. All resources have compliance issues that need to be addressed."
                else:
                    clean_summary = llm_summary.replace("**", "").replace("*", "")
                    summary = f"{clean_summary}\n\nSummary: {len(relevant_findings)} {'resource is' if len(relevant_findings) == 1 else 'resources are'} compliant and secure."
            else:
                # Clean general summary
                summary = llm_summary.replace("**", "").replace("*", "")

            run_logger.info("LLM explainer generated contextual summary (validated)")

        except Exception as e:
            # Check if this is a guardrail block
            error_msg = str(e).lower()
            if "guardrail" in error_msg or "blocked" in error_msg or "policy" in error_msg or "safety" in error_msg:
                run_logger.warning(f"LLM explainer blocked by security guardrails: {e}")

                # Return user-friendly blocked message
                return AskResponse(
                    run_id=run_id,
                    summary=(
                        "Your request was blocked by our security policy. "
                        "Please rephrase your question using different wording.\n\n"
                        "Try these instead:\n"
                        "- 'show security issues'\n"
                        "- 'list failing resources'\n"
                        "- 'what resources need attention'\n"
                        "- 'compliance summary'"
                    ),
                    findings=[],
                    evidence_links=[],
                )

            run_logger.warning(f"LLM explainer failed, using fallback summary: {e}")

            # Deterministic natural language fallback
            if filter_metadata["filter_type"] == "non_compliant_only":
                if len(relevant_findings) == 0:
                    summary = "Great news! All resources are compliant. No security issues or violations found."
                elif len(relevant_findings) <= 10:
                    # List all resources naturally with human-readable descriptions
                    def get_friendly_description(finding):
                        """Convert technical finding to user-friendly description."""
                        rule = finding.get('rule', '')
                        res_id = finding.get('resource_id', 'unknown')
                        res_type = finding.get('resource_type', 'Resource')

                        # Map rules to friendly descriptions
                        friendly_rules = {
                            's3-bucket-public-read-prohibited': f"S3 bucket {res_id} is publicly accessible",
                            's3-bucket-public-write-prohibited': f"S3 bucket {res_id} allows public write access",
                            's3-bucket-server-side-encryption-enabled': f"S3 bucket {res_id} lacks encryption",
                            's3-bucket-versioning-enabled': f"S3 bucket {res_id} has versioning disabled",
                            'root-account-mfa-enabled': "Root account doesn't have MFA enabled",
                            'iam-user-mfa-enabled': f"IAM user {res_id} doesn't have MFA enabled",
                            'access-keys-rotated': f"Access keys for {res_id} haven't been rotated in 90+ days",
                            'iam-password-policy': "Password policy doesn't meet security requirements",
                            'cloudtrail-enabled': "CloudTrail logging is not enabled"
                        }

                        return friendly_rules.get(rule, f"{res_type} {res_id} has a compliance issue")

                    resource_list = []
                    for idx, f in enumerate(relevant_findings, 1):
                        description = get_friendly_description(f)
                        resource_list.append(f"{idx}. {description}")

                    summary = (
                        f"Found {len(relevant_findings)} security {'issue' if len(relevant_findings) == 1 else 'issues'} that need attention:\n\n"
                        + "\n".join(resource_list)
                        + f"\n\nPlease review and fix {'this issue' if len(relevant_findings) == 1 else 'these issues'} to improve your security posture."
                    )
                else:
                    # Summarize for large lists with friendly descriptions
                    def get_friendly_description(finding):
                        """Convert technical finding to user-friendly description."""
                        rule = finding.get('rule', '')
                        res_id = finding.get('resource_id', 'unknown')
                        res_type = finding.get('resource_type', 'Resource')

                        friendly_rules = {
                            's3-bucket-public-read-prohibited': f"S3 bucket {res_id} is publicly accessible",
                            's3-bucket-public-write-prohibited': f"S3 bucket {res_id} allows public write access",
                            's3-bucket-server-side-encryption-enabled': f"S3 bucket {res_id} lacks encryption",
                            's3-bucket-versioning-enabled': f"S3 bucket {res_id} has versioning disabled",
                            'root-account-mfa-enabled': "Root account doesn't have MFA enabled",
                            'iam-user-mfa-enabled': f"IAM user {res_id} doesn't have MFA enabled",
                            'access-keys-rotated': f"Access keys for {res_id} haven't been rotated in 90+ days",
                            'iam-password-policy': "Password policy doesn't meet security requirements",
                            'cloudtrail-enabled': "CloudTrail logging is not enabled"
                        }

                        return friendly_rules.get(rule, f"{res_type} {res_id} has a compliance issue")

                    sample_list = []
                    for idx, f in enumerate(relevant_findings[:5], 1):
                        description = get_friendly_description(f)
                        sample_list.append(f"{idx}. {description}")

                    summary = (
                        f"Found {len(relevant_findings)} security issues that need attention.\n\n"
                        f"Top 5 issues:\n"
                        + "\n".join(sample_list)
                        + f"\n\n... and {len(relevant_findings) - 5} more issues."
                        + f"\n\nPlease review and fix all {len(relevant_findings)} issues to improve your security posture."
                    )

            elif filter_metadata["filter_type"] == "compliant_only":
                if len(relevant_findings) == 0:
                    summary = "No compliant resources found. All resources have compliance issues that need to be addressed."
                else:
                    summary = f"Found {len(relevant_findings)} secure {'resource' if len(relevant_findings) == 1 else 'resources'} that meet compliance requirements. These are properly configured and secure."

            else:
                # General summary - provide clean overview
                compliance_score = int((compliant_count / len(all_findings) * 100) if all_findings else 0)

                summary = (
                    f"Compliance Scan Results:\n\n"
                    f"Total resources scanned: {len(all_findings)}\n"
                    f"Secure resources: {compliant_count}\n"
                    f"Resources with issues: {non_compliant_count}\n\n"
                    f"Compliance score: {compliance_score}%\n\n"
                    f"View the detailed findings table below for complete information."
                )

        # Write evidence artifacts
        evidence_writer = EvidenceWriter(
            base_path=settings.evidence_base_path,
            s3_bucket=settings.evidence_s3_bucket,
            s3_region=settings.bedrock_region,
        )

        # Write plan, findings, and report
        evidence_writer.write_plan(run_id, plan)
        evidence_writer.write_findings(run_id, all_findings)

        # Write CSV for auditors (safe - won't crash if fails)
        csv_path, csv_s3_uri = evidence_writer.write_findings_csv(run_id, all_findings)

        report = {
            "run_id": run_id,
            "summary": summary,
            "execution": execution,
            "compliant_count": compliant_count,
            "non_compliant_count": non_compliant_count,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
        evidence_writer.write_report(run_id, report)

        # Generate and sign manifest
        run_dir = evidence_writer.get_run_directory(run_id)
        manifest = generate_manifest(
            run_id=run_id,
            run_dir=run_dir,
            evidence_version=settings.evidence_version,
            additional_metadata={
                "prompt": request.prompt,
                "framework": request.framework,
                "scope": request.scope,
            },
        )
        evidence_writer.write_manifest(run_id, manifest)

        # Sign manifest
        signature = sign_manifest(manifest, settings.signing_key)
        evidence_writer.write_signature(run_id, signature)

        # Evidence links
        evidence_links = [
            f"/api/v1/evidence/{run_id}/manifest.json",
            f"/api/v1/evidence/{run_id}/manifest.sig",
            f"/api/v1/evidence/{run_id}/findings.json",
            f"/api/v1/evidence/{run_id}/plan.json",
            f"/api/v1/evidence/{run_id}/report.json",
        ]

        # Add CSV link if successfully created
        if csv_path is not None:
            evidence_links.append(f"/api/v1/evidence/{run_id}/findings.csv")

        run_logger.info(
            "Evidence artifacts written",
            extra={
                "run_id": run_id,
                "artifacts_count": len(evidence_writer.list_artifacts(run_id)),
            },
        )

        # Update run metadata as completed
        run_storage.update_run(
            run_id,
            status="COMPLETED",
            completed_at=datetime.utcnow(),
            summary=summary,
            findings_count=len(findings),
            evidence_links=evidence_links,
        )

        run_logger.info(
            "Compliance scan completed",
            extra={"findings_count": len(findings)},
        )

        return AskResponse(
            run_id=run_id,
            summary=summary,
            findings=findings,
            evidence_links=evidence_links,
            timestamp=datetime.utcnow(),
        )

    except HTTPException:
        # Re-raise HTTP exceptions (validation errors)
        raise
    except Exception as e:
        # Check if this is a guardrail block (final safety net)
        error_msg = str(e).lower()
        if "guardrail" in error_msg or "blocked" in error_msg or "policy" in error_msg or "safety" in error_msg:
            run_logger.warning(f"Request blocked by security guardrails: {e}")

            # Return user-friendly blocked message
            return AskResponse(
                run_id=run_id,
                summary=(
                    "Your request was blocked by our security policy. "
                    "Please rephrase your question using different wording.\n\n"
                    "Try these instead:\n"
                    "- 'show security issues'\n"
                    "- 'list failing resources'\n"
                    "- 'what resources need attention'\n"
                    "- 'compliance summary'"
                ),
                findings=[],
                evidence_links=[],
            )

        run_logger.error(f"Unexpected error during compliance scan: {e}")

        # Update run as failed
        run_storage.update_run(
            run_id,
            status="FAILED",
            completed_at=datetime.utcnow(),
            summary=f"Scan failed: {str(e)}",
        )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during compliance scan",
        )


@router.get(
    "/runs/{run_id}",
    response_model=RunMetadata,
    responses={404: {"model": ErrorResponse}},
)
async def get_run_endpoint(
    run_id: str,
    api_key: str = Depends(verify_api_key),
) -> RunMetadata:
    """
    Retrieve run metadata by run ID.

    Args:
        run_id: Unique run identifier
        api_key: Validated API key from header

    Returns:
        RunMetadata for the specified run

    Raises:
        HTTPException: 404 if run not found
    """
    logger.info(f"Retrieving run metadata: {run_id}")

    run_metadata = run_storage.get_run(run_id)

    if not run_metadata:
        logger.warning(f"Run not found: {run_id}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Run not found: {run_id}",
        )

    logger.info(f"Run metadata retrieved: {run_id}")
    return run_metadata


@router.get("/runs/{run_id}/export")
async def export_run_endpoint(
    run_id: str,
    format: str = Query("json", regex="^(json|csv)$"),
    api_key: str = Depends(verify_api_key),
) -> Response:
    """
    Export run findings in requested format (JSON or CSV).

    This endpoint allows on-demand conversion of findings to CSV,
    useful if the CSV artifact wasn't generated during the scan.

    Args:
        run_id: Unique run identifier
        format: Export format ('json' or 'csv')
        api_key: Validated API key from header

    Returns:
        Response with findings in requested format

    Raises:
        HTTPException: 404 if run not found, 500 if export fails
    """
    logger.info(f"Exporting run {run_id} in {format} format")

    from evidence.writer import EvidenceWriter

    evidence_writer = EvidenceWriter(
        base_path=settings.evidence_base_path,
        s3_bucket=settings.evidence_s3_bucket,
        s3_region=settings.bedrock_region,
    )

    # Check if run exists
    if not evidence_writer.run_exists(run_id):
        logger.warning(f"Run not found for export: {run_id}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Run not found: {run_id}",
        )

    run_dir = evidence_writer.get_run_directory(run_id)
    findings_json_path = run_dir / "findings.json"

    if not findings_json_path.exists():
        logger.error(f"Findings file not found for run: {run_id}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Findings not found for run: {run_id}",
        )

    try:
        # Load findings from JSON file
        import json
        with open(findings_json_path, "r", encoding="utf-8") as f:
            findings_data = json.load(f)

        findings = findings_data.get("findings", [])

        if format == "json":
            # Return JSON format
            logger.info(f"Returning JSON export for run: {run_id}")
            return Response(
                content=json.dumps(findings_data, indent=2, ensure_ascii=False),
                media_type="application/json",
                headers={
                    "Content-Disposition": f'attachment; filename="{run_id}_findings.json"'
                },
            )

        else:  # format == "csv"
            # Convert to CSV format
            from evidence.csv_writer import findings_to_csv

            csv_content = findings_to_csv(findings, run_id, include_header=True)

            logger.info(f"Returning CSV export for run: {run_id}")
            return Response(
                content=csv_content,
                media_type="text/csv",
                headers={
                    "Content-Disposition": f'attachment; filename="{run_id}_findings.csv"'
                },
            )

    except Exception as e:
        logger.error(f"Failed to export run {run_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to export run: {str(e)}",
        )


@router.get("/health", response_model=HealthResponse)
async def health_endpoint() -> HealthResponse:
    """
    Health check endpoint.

    Returns:
        HealthResponse with status and version info
    """
    return HealthResponse(
        status="ok",
        timestamp=datetime.utcnow(),
        version=settings.api_version,
    )
