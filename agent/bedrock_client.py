"""Bedrock client with Guardrails support.

This module provides a Bedrock client that:
- Integrates AWS Bedrock Guardrails for prompt injection protection
- Handles guardrail blocking responses gracefully
- Returns safe fallback responses when content is blocked
- Logs security events
"""

import json
from typing import Any, Optional

import boto3
from botocore.exceptions import ClientError


class GuardrailBlockedException(Exception):
    """Exception raised when Bedrock Guardrails blocks a request."""

    def __init__(self, intervention_type: str, message: str) -> None:
        """
        Initialize guardrail blocked exception.

        Args:
            intervention_type: Type of guardrail intervention (e.g., "BLOCKED")
            message: Details about why content was blocked
        """
        self.intervention_type = intervention_type
        self.message = message
        super().__init__(f"Guardrail blocked: {intervention_type} - {message}")


class BedrockClient:
    """Bedrock client with guardrail support."""

    def __init__(
        self,
        region: str = "us-west-2",
        model_id: str = "anthropic.claude-3-5-sonnet-20241022-v2:0",
        guardrail_id: Optional[str] = None,
        guardrail_version: str = "1",
    ) -> None:
        """
        Initialize Bedrock client.

        Args:
            region: AWS region
            model_id: Bedrock model ID
            guardrail_id: Optional guardrail ID for protection
            guardrail_version: Guardrail version (default: "1")
        """
        self.region = region
        self.model_id = model_id
        self.guardrail_id = guardrail_id
        self.guardrail_version = guardrail_version

        self.client = boto3.client("bedrock-runtime", region_name=region)

        if guardrail_id:
            print(
                f"INFO: Bedrock client initialized with guardrail: {guardrail_id} version {guardrail_version}"
            )
        else:
            print("WARNING: Bedrock client initialized WITHOUT guardrails")

    def _build_request_body(
        self,
        messages: list[dict[str, str]],
        max_tokens: int = 2000,
        temperature: float = 0.0,
        system_prompt: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Build request body for Bedrock API.

        Args:
            messages: List of message dicts with role and content
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature
            system_prompt: Optional system prompt

        Returns:
            Request body dictionary
        """
        body = {
            "anthropic_version": "bedrock-2023-05-31",
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }

        if system_prompt:
            body["system"] = system_prompt

        return body

    def build_bedrock_request(
        self,
        body: dict[str, Any],
        use_guardrails: bool = True,
    ) -> dict[str, Any]:
        """
        Build Bedrock API request with optional guardrails.

        Centralizes request creation so tests can verify guardrails are applied.

        Args:
            body: Request body
            use_guardrails: Whether to include guardrail parameters

        Returns:
            Complete request parameters for invoke_model
        """
        invoke_params = {
            "modelId": self.model_id,
            "body": json.dumps(body),
        }

        # Add guardrails if configured and requested
        if use_guardrails and self.guardrail_id:
            invoke_params["guardrailIdentifier"] = self.guardrail_id
            invoke_params["guardrailVersion"] = self.guardrail_version

        return invoke_params

    def _invoke_with_guardrails(
        self,
        body: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Invoke Bedrock model with guardrails.

        Args:
            body: Request body

        Returns:
            Response from Bedrock

        Raises:
            GuardrailBlockedException: If guardrails block the content
            ClientError: For other Bedrock API errors
        """
        invoke_params = self.build_bedrock_request(body, use_guardrails=True)

        try:
            response = self.client.invoke_model(**invoke_params)

            response_body = json.loads(response["body"].read())

            # Check for guardrail interventions
            if "amazon-bedrock-guardrailAction" in response.get("ResponseMetadata", {}).get(
                "HTTPHeaders", {}
            ):
                action = response["ResponseMetadata"]["HTTPHeaders"][
                    "amazon-bedrock-guardrailAction"
                ]
                if action == "GUARDRAIL_INTERVENED":
                    # Content was blocked by guardrails
                    raise GuardrailBlockedException(
                        intervention_type="BLOCKED",
                        message="Content blocked by Bedrock Guardrails",
                    )

            return response_body

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")

            # Check if this is a guardrail block
            if error_code == "ValidationException" and "guardrail" in str(e).lower():
                raise GuardrailBlockedException(
                    intervention_type="BLOCKED",
                    message="Content blocked by Bedrock Guardrails",
                )

            raise

    @staticmethod
    def get_compliance_plan_schema() -> dict:
        """
        JSON schema for Claude function calling.

        This schema enforces that every aws_config_check step MUST have rules.
        Claude cannot generate a response that doesn't match this schema.

        Returns:
            Function calling schema for compliance plan generation
        """
        return {
            "name": "generate_compliance_plan",
            "description": "Generate a compliance scanning plan for AWS resources. If question is not about compliance, return error='OUT_OF_SCOPE'. Otherwise return a plan with scope, env, region, and steps with rules.",
            "input_schema": {
                "type": "object",
                "properties": {
                    # Out-of-scope response (optional - only if not about compliance)
                    "error": {
                        "type": "string",
                        "enum": ["OUT_OF_SCOPE"],
                        "description": "Set to OUT_OF_SCOPE if question is not about AWS compliance. Otherwise omit this field."
                    },
                    "message": {
                        "type": "string",
                        "description": "Error message explaining why question is out of scope (only if error=OUT_OF_SCOPE)"
                    },
                    "user_question_topic": {
                        "type": "string",
                        "description": "Brief description of what user asked about (only if error=OUT_OF_SCOPE)"
                    },
                    # Normal compliance plan structure (required if not out-of-scope)
                    "scope": {
                        "type": "string",
                        "enum": ["S3", "IAM", "CloudTrail", "ALL", "GENERAL"],
                        "description": "Compliance scope (required if question is about compliance)"
                    },
                    "env": {
                        "type": "string",
                        "enum": ["prod", "dev", "staging", "all"],
                        "description": "Target environment (required if question is about compliance)"
                    },
                    "region": {
                        "type": "string",
                        "description": "AWS region (required if question is about compliance)"
                    },
                    "steps": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "step_number": {
                                    "type": "integer",
                                    "description": "Step sequence number"
                                },
                                "tool": {
                                    "type": "string",
                                    "enum": ["aws_config_eval"],
                                    "description": "Tool to use (must be aws_config_eval)"
                                },
                                "description": {
                                    "type": "string",
                                    "description": "Step description"
                                },
                                "params": {
                                    "type": "object",
                                    "properties": {
                                        "rules": {
                                            "type": "array",
                                            "items": {
                                                "type": "string",
                                                "enum": [
                                                    "s3-bucket-public-read-prohibited",
                                                    "s3-bucket-public-write-prohibited",
                                                    "s3-bucket-server-side-encryption-enabled",
                                                    "s3-bucket-versioning-enabled",
                                                    "root-account-mfa-enabled",
                                                    "iam-user-mfa-enabled",
                                                    "access-keys-rotated",
                                                    "iam-password-policy",
                                                    "cloudtrail-enabled"
                                                ]
                                            },
                                            "minItems": 1,
                                            "description": "AWS Config rules to check (at least 1 required)"
                                        }
                                    },
                                    "required": ["rules"],
                                    "additionalProperties": False,
                                    "description": "Step parameters with rules"
                                }
                            },
                            "required": ["step_number", "tool", "description", "params"]
                        },
                        "description": "Steps to execute (required if question is about compliance)"
                    }
                },
                "required": []  # No fields are required at top level - allows either out-of-scope or normal response
            }
        }

    def create_completion_with_guardrails(
        self,
        system_prompt: str,
        user_prompt: str,
        use_function_calling: bool = True,
    ) -> dict:
        """
        Create completion with Bedrock Guardrails and optional function calling.

        Args:
            system_prompt: System instructions for the LLM
            user_prompt: User's question/request
            use_function_calling: Enable function calling with schema enforcement (default True)

        Returns:
            dict with keys:
                - content: LLM response as JSON string
                - stop_reason: Stop reason from Bedrock
                - usage: Token usage stats
                Or error dict if guardrails block:
                - error: "GUARDRAIL_BLOCKED"
                - message: Error message
                - details: Detailed error information
        """
        try:
            # Build messages (converse API requires content as list of content blocks)
            messages = [
                {
                    "role": "user",
                    "content": [
                        {"text": user_prompt}
                    ]
                }
            ]

            # Build tool configuration if function calling enabled
            tool_config = None
            if use_function_calling:
                schema = self.get_compliance_plan_schema()
                tool_config = {
                    "tools": [{
                        "toolSpec": {
                            "name": schema["name"],
                            "description": schema["description"],
                            "inputSchema": {
                                "json": schema["input_schema"]
                            }
                        }
                    }],
                    "toolChoice": {
                        "tool": {"name": schema["name"]}
                    }
                }

            # Build guardrail config
            guardrail_config = None
            if self.guardrail_id and self.guardrail_version:
                guardrail_config = {
                    "guardrailIdentifier": self.guardrail_id,
                    "guardrailVersion": self.guardrail_version,
                    "trace": "enabled"
                }

            # Call Bedrock converse API
            response = self.client.converse(
                modelId=self.model_id,
                messages=messages,
                system=[{"text": system_prompt}],
                inferenceConfig={
                    "maxTokens": 4096,
                    "temperature": 0.3
                },
                toolConfig=tool_config,
                guardrailConfig=guardrail_config
            )

            # Extract tool use response if function calling enabled
            if use_function_calling:
                for content_block in response["output"]["message"]["content"]:
                    if "toolUse" in content_block:
                        tool_input = content_block["toolUse"]["input"]
                        return {
                            "content": json.dumps(tool_input),
                            "stop_reason": response.get("stopReason"),
                            "usage": response.get("usage", {})
                        }

            # Extract text response (fallback if no tool use)
            text_content = ""
            for content_block in response["output"]["message"]["content"]:
                if "text" in content_block:
                    text_content += content_block["text"]

            return {
                "content": text_content,
                "stop_reason": response.get("stopReason"),
                "usage": response.get("usage", {})
            }

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            error_message = e.response.get("Error", {}).get("Message", str(e))

            # Check for guardrail intervention
            if error_code == "ValidationException":
                if "Guardrail" in error_message or "intervened" in error_message:
                    print(f"[WARN] Bedrock Guardrails BLOCKED request")
                    return {
                        "error": "GUARDRAIL_BLOCKED",
                        "message": "Input blocked by security guardrails",
                        "details": error_message
                    }

            # Re-raise other errors
            raise

    def llm_planner(
        self,
        question: str,
        allowed_tools: list[str],
        schema_hint: str,
        context: Optional[dict[str, Any]] = None,
    ) -> str:
        """
        Invoke Bedrock for plan generation with guardrails.

        Args:
            question: User's compliance question
            allowed_tools: List of allowed tool names
            schema_hint: JSON schema hint for plan structure
            context: Optional context (env, region, risk flags)

        Returns:
            Generated plan as JSON string (or safe error JSON if blocked)
        """
        context = context or {}
        env = context.get("env", "prod")
        region = context.get("region", "us-west-2")
        risk_flags = context.get("risk_flags", {})

        system_prompt = f"""You are a compliance planning agent for AWS security and compliance monitoring.

You have access to exactly 9 AWS Config rules:

1. s3-bucket-public-read-prohibited - Checks S3 buckets are not publicly readable
2. s3-bucket-public-write-prohibited - Checks S3 buckets are not publicly writable
3. s3-bucket-server-side-encryption-enabled - Checks S3 encryption is enabled
4. s3-bucket-versioning-enabled - Checks S3 versioning is enabled
5. root-account-mfa-enabled - Checks root account has MFA
6. iam-user-mfa-enabled - Checks IAM users have MFA
7. access-keys-rotated - Checks access keys are rotated within 90 days
8. iam-password-policy - Checks password policy meets requirements
9. cloudtrail-enabled - Checks CloudTrail logging is enabled

IMPORTANT: First determine if the question is about AWS compliance, security audits, or AWS Config rules.

If the question is NOT about compliance/security (examples: weather, general knowledge, EC2 instances count, unrelated topics), respond with:
{{
  "error": "OUT_OF_SCOPE",
  "message": "I can only help with AWS compliance monitoring and security audits. Please ask about S3 security, IAM compliance, CloudTrail, encryption, MFA, or other AWS Config compliance rules.",
  "user_question_topic": "brief description of what user asked about"
}}

If the question IS about compliance/security, generate a JSON plan with:
- scope: scan scope
- env: environment (prod/dev/staging/all)
- region: AWS region
- steps: array of steps with tool, description, params

For compliance questions, choose rules relevant to the user's question:
- S3 questions → use rules 1-4
- IAM questions → use rules 5-8
- General/broad questions → use all 9 rules

Available tools: {', '.join(allowed_tools)}

Schema requirements: {schema_hint}

Return ONLY valid JSON, no markdown, no explanation."""

        user_content = f"Create a compliance scan plan for: {question}\nEnvironment: {env}\nRegion: {region}"

        # Add risk flag warnings if present
        if risk_flags.get("has_risk"):
            user_content += f"\n\nSECURITY NOTE: Input flagged as {risk_flags.get('risk_type', 'unknown')}"

        messages = [
            {
                "role": "user",
                "content": user_content,
            }
        ]

        body = self._build_request_body(
            messages=messages,
            max_tokens=1200,  # Increased to avoid truncation
            temperature=0.0,
            system_prompt=system_prompt,
        )

        try:
            response = self._invoke_with_guardrails(body)

            # Extract content
            content = response.get("content", [{}])[0].get("text", "")
            return content

        except GuardrailBlockedException as e:
            # Return safe JSON error object that signals fallback
            print(f"WARNING: Planner blocked by guardrails: {e.message}")

            return json.dumps({
                "error": "GUARDRAIL_BLOCKED",
                "reason": "policy_violation",
                "fallback": "use_fallback_plan",
            })

    def llm_explainer(
        self,
        findings_json: list[dict[str, Any]],
        control_cards: list[dict[str, Any]],
        context: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """
        Produce human-friendly summary and remediation steps.

        MUST NOT invent findings - only reference resources that exist in findings_json.

        Args:
            findings_json: List of compliance findings (deterministic)
            control_cards: List of control card references from RAG
            context: Optional additional context (should include 'user_question')

        Returns:
            Structured explanation with summary, risks, remediations, citations
        """
        context = context or {}
        user_question = context.get("user_question", "")
        expected_count = context.get("expected_count", len(findings_json))
        filter_applied = context.get("filter_applied", "all")

        # Extract resource IDs for validation
        resource_ids = {f.get("resource_id", "") for f in findings_json}

        system_prompt = """You are a compliance explanation agent that provides clear, natural language answers.

CRITICAL RULES:
1. Write in plain, natural language - NO markdown, NO bold (**), NO asterisks
2. Use simple, conversational tone - avoid technical jargon
3. If user asks to "list" or "show all", mention ALL resources found
4. Include specific resource names/IDs in your answer
5. Only reference resources that actually exist in the findings
6. Do not invent or hallucinate resources
7. Be direct and specific
8. NO formatting characters - just clean text

Examples of good answers:
- User: "which S3 bucket is public?"
  → "The publicly accessible S3 bucket is org-prod-assets-public-599233349951. This bucket allows public read access which is a security risk."

- User: "list non-compliant resources"
  → "Here are the 3 non-compliant resources found:
     1. bucket-name-1 is publicly accessible (security risk)
     2. bucket-name-2 has no encryption enabled
     3. iam-user-bob doesn't have MFA enabled"

- User: "are there any issues?"
  → "Yes, found 2 security issues: bucket-xyz is publicly accessible and user-abc doesn't have MFA enabled."

Generate a structured report with:
- summary: Plain text answer directly addressing the user's question (NO markdown)
- top_risks: Array of highest severity issues with evidence_ids
- remediations: Array of actionable steps per resource
- citations: Array of control references

Return ONLY valid JSON, no markdown in any field."""

        # Determine how many findings to include based on count
        # For small sets (<=20), include all; for larger sets, include summary + sample
        findings_count = len(findings_json)
        if findings_count <= 20:
            findings_summary = json.dumps(findings_json, indent=2)
            findings_note = f"All {findings_count} findings provided below."
        else:
            # For large sets, include first 15 + metadata about total
            findings_summary = json.dumps(findings_json[:15], indent=2)
            findings_note = f"Showing 15 of {findings_count} findings. Summarize patterns and mention total count."

        control_summary = json.dumps(control_cards[:5], indent=2) if control_cards else "[]"

        user_context = f"User's question: {user_question}\n" if user_question else ""
        filter_context = f"Filter applied: {filter_applied}\nExpected resource count: {expected_count}\n"

        user_message = f"""{user_context}{filter_context}{findings_note}

Findings:
{findings_summary}

Control Cards:
{control_summary}

Generate a structured JSON report that lists ALL resources answering the user's question."""

        messages = [
            {
                "role": "user",
                "content": user_message,
            }
        ]

        body = self._build_request_body(
            messages=messages,
            max_tokens=1500,
            temperature=0.3,
            system_prompt=system_prompt,
        )

        try:
            response = self._invoke_with_guardrails(body)

            # Extract content
            content = response.get("content", [{}])[0].get("text", "")

            # Try to parse as JSON
            try:
                explanation = json.loads(content)
            except json.JSONDecodeError:
                # Fallback if not valid JSON
                explanation = {
                    "summary": content[:500],
                    "top_risks": [],
                    "remediations": [],
                    "citations": [],
                }

            return explanation

        except GuardrailBlockedException as e:
            # Return safe refusal response
            print(f"WARNING: Explainer blocked by guardrails: {e.message}")

            return {
                "summary": "Request blocked by safety policy.",
                "top_risks": [],
                "remediations": [],
                "citations": [],
            }

    def invoke_planner(
        self,
        user_question: str,
        env: str,
        region: str,
    ) -> str:
        """
        Legacy invoke_planner for backward compatibility.

        Args:
            user_question: User's compliance question
            env: Environment to scan
            region: AWS region

        Returns:
            Generated plan as JSON string
        """
        return self.llm_planner(
            question=user_question,
            allowed_tools=["aws_config_eval", "rag_retrieve"],
            schema_hint="requires scope, env, region, steps array with tool/description/params",
            context={"env": env, "region": region},
        )

    def invoke_explainer(
        self,
        findings: list[dict[str, Any]],
        context: Optional[str] = None,
    ) -> str:
        """
        Legacy invoke_explainer for backward compatibility.

        Args:
            findings: List of compliance findings
            context: Optional additional context

        Returns:
            Human-readable explanation (or JSON-formatted dict as string)
        """
        context_dict = {}
        if context:
            context_dict["additional_context"] = context

        result = self.llm_explainer(
            findings_json=findings,
            control_cards=[],  # No control cards in legacy mode
            context=context_dict,
        )

        # Return as JSON string for backward compatibility
        return json.dumps(result, indent=2)


def create_bedrock_client(
    region: Optional[str] = None,
    model_id: Optional[str] = None,
    guardrail_id: Optional[str] = None,
    guardrail_version: Optional[str] = None,
) -> BedrockClient:
    """
    Create Bedrock client with configuration from settings.

    Args:
        region: Override default region
        model_id: Override default model ID
        guardrail_id: Override default guardrail ID
        guardrail_version: Override default guardrail version

    Returns:
        Configured BedrockClient
    """
    from api.app.config import settings

    return BedrockClient(
        region=region or settings.bedrock_region,
        model_id=model_id or settings.bedrock_model_id,
        guardrail_id=guardrail_id or settings.bedrock_guardrail_id,
        guardrail_version=guardrail_version or settings.bedrock_guardrail_version,
    )
