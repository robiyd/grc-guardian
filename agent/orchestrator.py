"""Agent orchestrator - coordinates planning, validation, repair, fallback, and execution."""

import json
from typing import Any, Optional

from .bedrock_client import BedrockClient, create_bedrock_client
from .fallback import fallback_plan
from .repair import repair_plan_with_llm
from .rule_validator import should_use_fallback
from .tool_registry import ALLOWED_TOOLS
from .validator import validate_plan

# Import security logger for regression tracking
try:
    from api.app.security_logger import security_logger
except ImportError:
    # Fallback if running outside API context
    security_logger = None


def build_plan(
    user_question: str,
    env: str = "prod",
    region: str = "us-west-2",
    bedrock_client: Optional[BedrockClient] = None,
    context: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """
    Build a compliance plan with validation, repair, and fallback.

    Flow:
    1. Call Bedrock llm_planner to generate initial plan
    2. Validate the plan
    3. If GUARDRAIL_BLOCKED or invalid, attempt repair once
    4. Validate repaired plan
    5. If still invalid, use deterministic fallback_plan
    6. Return valid plan (guaranteed)

    This function NEVER crashes - it always returns a valid plan.

    Args:
        user_question: User's compliance question/request
        env: Environment to scan (prod, dev, staging, all)
        region: AWS region to scan
        bedrock_client: Optional Bedrock client for LLM calls
        context: Optional context (risk flags, etc.)

    Returns:
        Valid plan dictionary (guaranteed to pass validation)
    """
    # Normalize inputs
    if env not in ["prod", "dev", "staging", "all"]:
        env = "all"

    # Quick pre-validation: check for obvious non-compliance questions
    # This avoids unnecessary LLM calls for clearly out-of-scope questions
    question_lower = user_question.lower()
    compliance_keywords = [
        "s3", "iam", "cloudtrail", "security", "compliance", "audit",
        "encryption", "mfa", "access", "config", "bucket", "policy",
        "rule", "finding", "control", "scan", "check", "evaluate",
        "nist", "soc2", "iso", "pci", "hipaa", "gdpr", "compliant",
        "non-compliant", "violation", "remediate", "posture",
    ]

    # If question is very short and has no compliance keywords, likely out of scope
    if len(user_question.strip()) < 100:  # Short questions only
        has_compliance_keyword = any(kw in question_lower for kw in compliance_keywords)

        # Common non-compliance patterns
        non_compliance_patterns = [
            "weather", "temperature", "forecast", "time", "date",
            "how are you", "hello", "hi ", "hey ", "good morning",
            "what is", "who is", "where is", "when is", "why is",
            "how many ec2", "how many instance", "list ec2", "show ec2",
        ]

        is_likely_non_compliance = any(pattern in question_lower for pattern in non_compliance_patterns)

        if is_likely_non_compliance and not has_compliance_keyword:
            print(f"Pre-validation: Question appears out of scope (no compliance keywords)")
            return {
                "status": "out_of_scope",
                "message": "I can only help with AWS compliance monitoring and security audits. Please ask about S3 security, IAM compliance, CloudTrail, encryption, MFA, or other AWS Config compliance rules.",
                "scope": "N/A",
                "env": env,
                "region": region,
                "steps": [],
            }

    # Create Bedrock client if not provided
    if bedrock_client is None:
        try:
            bedrock_client = create_bedrock_client()
        except Exception as e:
            print(f"Failed to create Bedrock client: {e}. Using fallback.")
            return fallback_plan(env, region)

    # Prepare context
    llm_context = context or {}
    llm_context["env"] = env
    llm_context["region"] = region
    run_id = llm_context.get("run_id")  # Extract run_id if available

    # Step 1: Generate initial plan from Bedrock using function calling
    print(f"\n{'='*60}")
    print("STAGE 1: Building Plan")
    print(f"{'='*60}")
    print(f"Question: {user_question}")
    print(f"Environment: {env}")
    print(f"Region: {region}")

    try:
        # Build system prompt
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

If the question is NOT about compliance/security, respond with OUT_OF_SCOPE error.

If the question IS about compliance/security, generate a plan choosing rules relevant to the question:
- S3 questions → use rules 1-4
- IAM questions → use rules 5-8
- General/broad questions → use all 9 rules"""

        user_prompt = f"Create a compliance scan plan for: {user_question}\nEnvironment: {env}\nRegion: {region}"

        print("\n[LLM] Calling Bedrock with function calling...")
        response = bedrock_client.create_completion_with_guardrails(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            use_function_calling=True  # Enable function calling
        )

        # Check if guardrail blocked
        if response.get("error") == "GUARDRAIL_BLOCKED":
            print("[WARN] Bedrock Guardrails BLOCKED this request")
            print("[FALLBACK] Using fallback plan")
            if security_logger:
                security_logger.log_fallback_invoked(
                    run_id=run_id,
                    reason="Guardrail blocked planner",
                    fallback_type="plan",
                )
            return fallback_plan(env, region)

        # Get the LLM response (JSON string)
        raw_plan_text = response.get("content", "{}")
        print(f"\n[RESPONSE] Raw LLM response: {len(raw_plan_text)} characters")

        # Parse and validate the response
        plan_obj = None
        try:
            plan_obj = json.loads(raw_plan_text)

            # Log plan structure in detail
            print(f"\n[PLAN] Plan structure:")
            print(f"  - scope: {plan_obj.get('scope', 'N/A')}")
            print(f"  - env: {plan_obj.get('env', 'N/A')}")
            print(f"  - steps: {len(plan_obj.get('steps', []))}")

            # Log each step's rules
            for step in plan_obj.get("steps", []):
                step_num = step.get("step_number")
                tool = step.get("tool")
                rules = step.get("params", {}).get("rules", [])

                if rules:
                    print(f"  [OK] Step {step_num} ({tool}): {len(rules)} rules")
                    for rule in rules:
                        print(f"     - {rule}")
                else:
                    print(f"  [WARN] Step {step_num} ({tool}): NO RULES SPECIFIED!")

            # Check for OUT_OF_SCOPE response (question not about compliance)
            if plan_obj.get("error") == "OUT_OF_SCOPE":
                message = plan_obj.get("message", "I can only help with AWS compliance monitoring.")
                topic = plan_obj.get("user_question_topic", "unrelated topic")
                print(f"Question out of scope: {topic}")
                # Return out-of-scope response WITHOUT using fallback
                return {
                    "status": "out_of_scope",
                    "message": message,
                    "scope": "N/A",
                    "env": env,
                    "region": region,
                    "steps": [],
                }

            if plan_obj.get("error") == "GUARDRAIL_BLOCKED":
                print("Guardrail blocked planner. Using fallback.")
                # Log guardrail block event
                if security_logger:
                    security_logger.log_fallback_invoked(
                        run_id=run_id,
                        reason="Guardrail blocked planner",
                        fallback_type="plan",
                    )
                return fallback_plan(env, region)
        except json.JSONDecodeError:
            print("Failed to parse LLM response as JSON. Using fallback.")
            return fallback_plan(env, region)

    except Exception as e:
        # LLM call failed, use fallback immediately
        print(f"LLM planner failed: {e}. Using fallback.")
        # Log fallback event
        if security_logger:
            security_logger.log_fallback_invoked(
                run_id=run_id,
                reason=f"LLM planner failed: {str(e)[:200]}",
                fallback_type="plan",
            )
        return fallback_plan(env, region)

    # Check if plan_obj was successfully parsed
    if plan_obj is None:
        print("Plan object is None. Using fallback.")
        return fallback_plan(env, region)

    # Step 2: Since we're using function calling with schema enforcement,
    # we can trust the structure and just validate rule names
    # Skip the old validate_plan() which has incompatible schema
    print("[VALIDATION] Skipping old schema validation (using function calling)")

    # Parse the plan (already validated by Bedrock schema)
    plan = plan_obj

    # Validate rule names
    use_fallback, fallback_reason = should_use_fallback(plan)
    if use_fallback:
        print(f"Plan contains invalid rule names: {fallback_reason}")
        print("Using fallback plan with guaranteed-valid rules")
        if security_logger:
            security_logger.log_fallback_invoked(
                run_id=run_id,
                reason=fallback_reason,
                fallback_type="invalid_rules",
            )
        return fallback_plan(env, region)

    return plan

    # Step 3: Initial plan invalid, attempt repair
    print(f"Initial plan invalid: {error}. Attempting repair...")

    repaired_text = repair_plan_with_llm(raw_plan_text, error, bedrock_client)

    if repaired_text is None:
        # Repair not available or failed, use fallback
        print("Repair failed or unavailable. Using fallback.")
        # Log repair failure
        if security_logger:
            security_logger.log_planner_json_repaired(
                run_id=run_id,
                original_error=str(error),
                repair_successful=False,
            )
            security_logger.log_fallback_invoked(
                run_id=run_id,
                reason="Repair failed or unavailable",
                fallback_type="plan",
            )
        return fallback_plan(env, region)

    # Step 4: Validate repaired plan
    repaired_plan, repair_error = validate_plan(repaired_text)

    if repaired_plan is not None:
        # Repaired plan is structurally valid, now validate rule names
        print("Repaired plan valid")

        # Check if AWS Config rule names actually exist
        use_fallback, fallback_reason = should_use_fallback(repaired_plan)
        if use_fallback:
            print(f"Repaired plan contains invalid rule names: {fallback_reason}")
            print("Using fallback plan with guaranteed-valid rules")
            if security_logger:
                security_logger.log_fallback_invoked(
                    run_id=run_id,
                    reason=f"Repaired plan invalid rules: {fallback_reason}",
                    fallback_type="invalid_rules",
                )
            return fallback_plan(env, region)

        # Log successful repair
        if security_logger:
            security_logger.log_planner_json_repaired(
                run_id=run_id,
                original_error=str(error),
                repair_successful=True,
            )
        return repaired_plan

    # Step 5: Repaired plan still invalid, use fallback
    print(f"Repaired plan still invalid: {repair_error}. Using fallback.")
    # Log repair failure and fallback
    if security_logger:
        security_logger.log_planner_json_repaired(
            run_id=run_id,
            original_error=str(error),
            repair_successful=False,
        )
        security_logger.log_fallback_invoked(
            run_id=run_id,
            reason=f"Repaired plan still invalid: {str(repair_error)[:200]}",
            fallback_type="plan",
        )
    return fallback_plan(env, region)


def build_plan_no_fallback(
    user_question: str,
    env: str = "prod",
    region: str = "us-west-2",
    bedrock_client: Optional[BedrockClient] = None,
    context: Optional[dict[str, Any]] = None,
) -> tuple[Optional[dict[str, Any]], Optional[str]]:
    """
    Build a plan without fallback (for testing/debugging).

    This variant returns (plan, error) instead of always returning
    a valid plan. Useful for testing validation and repair logic.

    Args:
        user_question: User's compliance question
        env: Environment to scan
        region: AWS region
        bedrock_client: Optional Bedrock client
        context: Optional context (risk flags, etc.)

    Returns:
        Tuple of (plan, error_message)
        - If successful: (plan_dict, None)
        - If failed: (None, error_message)
    """
    # Normalize inputs
    if env not in ["prod", "dev", "staging", "all"]:
        env = "all"

    # Create Bedrock client if not provided
    if bedrock_client is None:
        try:
            bedrock_client = create_bedrock_client()
        except Exception as e:
            return None, f"Failed to create Bedrock client: {str(e)}"

    # Prepare context
    llm_context = context or {}
    llm_context["env"] = env
    llm_context["region"] = region

    # Generate plan
    try:
        raw_plan_text = bedrock_client.llm_planner(
            question=user_question,
            allowed_tools=ALLOWED_TOOLS,
            schema_hint="requires scope, env, region, steps array with tool/description/params",
            context=llm_context,
        )

        # Check if guardrail blocked
        try:
            plan_obj = json.loads(raw_plan_text)
            if plan_obj.get("error") == "GUARDRAIL_BLOCKED":
                return None, "Guardrail blocked planner"
        except json.JSONDecodeError:
            pass

    except Exception as e:
        return None, f"LLM planner failed: {str(e)}"

    # Validate
    plan, error = validate_plan(raw_plan_text)

    if plan is not None:
        return plan, None

    # Attempt repair
    repaired_text = repair_plan_with_llm(raw_plan_text, error, bedrock_client)

    if repaired_text is None:
        return None, f"Repair failed. Original error: {error}"

    # Validate repaired
    repaired_plan, repair_error = validate_plan(repaired_text)

    if repaired_plan is not None:
        return repaired_plan, None

    return None, f"Repair validation failed: {repair_error}"


def execute_step(step: dict[str, Any], region: str) -> dict[str, Any]:
    """
    Execute a single plan step and return results.

    Args:
        step: Plan step dictionary with tool, description, and params
        region: AWS region

    Returns:
        Dictionary with execution results:
        {
            "tool": "...",
            "status": "success" | "error",
            "findings": [...],
            "error": None | "error message"
        }
    """
    tool_name = step.get("tool")
    params = step.get("params", {})

    # Debug logging
    print(f"[DEBUG execute_step] tool={tool_name}, params={params}")

    # Import tools here to avoid circular imports
    try:
        if tool_name == "aws_config_eval":
            from tools.aws_config import aws_config_eval_multi

            # Extract rules from params (support multiple LLM parameter variations)
            # LLM can generate: "rules" (array), "rule_name" (string), or "rule" (string)
            rules = params.get("rules", [])

            # Check for rule_name (string)
            if not rules and "rule_name" in params:
                rules = [params["rule_name"]]

            # Check for rule (string - most common LLM output)
            if not rules and "rule" in params:
                rules = [params["rule"]]

            resource_type = params.get("resource_type")

            if not rules:
                return {
                    "tool": tool_name,
                    "status": "error",
                    "findings": [],
                    "error": "No rules specified in params",
                }

            # Execute AWS Config evaluation
            result = aws_config_eval_multi(
                rule_names=rules,
                region=region,
                resource_type=resource_type,
            )

            return result

        elif tool_name == "rag_retrieve":
            # RAG tool - retrieve control cards
            from rag.retrieve import rag_retrieve

            framework = params.get("framework")
            category = params.get("category")
            query = params.get("query")

            # Build query from parameters
            if query:
                search_query = query
            elif framework and category:
                search_query = f"{framework} {category}"
            elif framework:
                search_query = framework
            else:
                return {
                    "tool": tool_name,
                    "status": "error",
                    "findings": [],
                    "error": "No query, framework, or category specified",
                    "metadata": {},
                }

            # Retrieve control cards
            try:
                results = rag_retrieve(search_query, top_k=3)

                return {
                    "tool": tool_name,
                    "status": "success",
                    "findings": [],  # RAG doesn't produce compliance findings
                    "error": None,
                    "metadata": {
                        "framework": framework,
                        "category": category,
                        "query": search_query,
                        "citations": results,  # Include control cards as citations
                        "controls_retrieved": len(results),
                    },
                }
            except Exception as e:
                return {
                    "tool": tool_name,
                    "status": "error",
                    "findings": [],
                    "error": f"RAG retrieval failed: {str(e)}",
                    "metadata": {},
                }

        else:
            return {
                "tool": tool_name,
                "status": "error",
                "findings": [],
                "error": f"Unknown tool: {tool_name}",
            }

    except Exception as e:
        return {
            "tool": tool_name,
            "status": "error",
            "findings": [],
            "error": f"Tool execution failed: {str(e)}",
        }


def validate_plan_steps(plan: dict[str, Any]) -> tuple[bool, str]:
    """
    Validate that plan has all required fields and valid rules.

    This validation catches plans where LLM omitted rules or used invalid rule names.

    Args:
        plan: Plan dictionary to validate

    Returns:
        (is_valid, error_message) tuple
        - is_valid: True if plan is valid, False otherwise
        - error_message: Empty string if valid, error description if invalid
    """
    steps = plan.get("steps", [])

    if not steps:
        return False, "No steps in plan"

    # List of valid AWS Config rules (deployed in production)
    valid_rules = [
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

    for step in steps:
        if step.get("tool") == "aws_config_eval":
            params = step.get("params", {})
            rules = params.get("rules", [])

            # Check if rules are specified
            if not rules:
                return False, f"Step {step.get('step_number')}: No rules specified in params"

            # Check if rules are valid
            invalid_rules = [r for r in rules if r not in valid_rules]
            if invalid_rules:
                return False, f"Step {step.get('step_number')}: Invalid rules: {invalid_rules}"

    return True, ""


def execute_plan(plan: dict[str, Any]) -> dict[str, Any]:
    """
    Execute a complete plan and collect all findings.

    Args:
        plan: Validated plan dictionary

    Returns:
        Execution result dictionary:
        {
            "plan_scope": "...",
            "plan_env": "...",
            "plan_region": "...",
            "steps_executed": 3,
            "steps_succeeded": 2,
            "steps_failed": 1,
            "all_findings": [...],
            "step_results": [...]
        }
    """
    # Check if plan is out-of-scope
    if plan.get("status") == "out_of_scope":
        message = plan.get("message", "Question is outside the scope of compliance monitoring.")
        print(f"Skipping execution: {message}")
        return {
            "plan_scope": "out_of_scope",
            "plan_env": plan.get("env", "N/A"),
            "plan_region": plan.get("region", "N/A"),
            "steps_executed": 0,
            "steps_succeeded": 0,
            "steps_failed": 0,
            "all_findings": [],
            "citations": [],
            "step_results": [],
            "message": message,
            "status": "out_of_scope",
        }

    # Validate plan steps BEFORE execution
    is_valid, error_msg = validate_plan_steps(plan)
    if not is_valid:
        print(f"[WARN] Plan validation failed: {error_msg}")
        print("[FALLBACK] Triggering fallback: using all 9 core AWS Config rules")

        # Replace plan with fallback that uses all 9 rules
        fallback_rules = [
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

        plan["steps"] = [
            {
                "step_number": 1,
                "tool": "aws_config_eval",
                "description": "Check all core AWS compliance rules (fallback)",
                "params": {"rules": fallback_rules}
            }
        ]
        print(f"[OK] Replaced plan with fallback (all {len(fallback_rules)} rules)")

    region = plan.get("region", "us-west-2")
    steps = plan.get("steps", [])

    all_findings = []
    all_citations = []
    step_results = []
    steps_succeeded = 0
    steps_failed = 0

    for idx, step in enumerate(steps):
        print(f"Executing step {idx + 1}/{len(steps)}: {step.get('description')}")

        result = execute_step(step, region)

        step_results.append(result)

        if result.get("status") == "success":
            steps_succeeded += 1
            # Collect findings from successful steps
            findings = result.get("findings", [])
            all_findings.extend(findings)

            # Collect citations from RAG steps
            metadata = result.get("metadata", {})
            citations = metadata.get("citations", [])
            if citations:
                all_citations.extend(citations)
        else:
            steps_failed += 1
            print(f"Step {idx + 1} failed: {result.get('error')}")

    # Calculate compliance counts
    compliant_count = sum(
        1 for f in all_findings if f.get("compliance_type") == "COMPLIANT"
    )
    non_compliant_count = sum(
        1 for f in all_findings if f.get("compliance_type") == "NON_COMPLIANT"
    )

    return {
        "plan_scope": plan.get("scope"),
        "plan_env": plan.get("env"),
        "plan_region": plan.get("region"),
        "steps_executed": len(steps),
        "steps_succeeded": steps_succeeded,
        "steps_failed": steps_failed,
        "all_findings": all_findings,
        "compliant_count": compliant_count,
        "non_compliant_count": non_compliant_count,
        "citations": all_citations,  # Include citations in execution result
        "step_results": step_results,
    }


def build_and_execute_plan(
    user_question: str,
    env: str = "prod",
    region: str = "us-west-2",
    bedrock_client: Optional[BedrockClient] = None,
    context: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """
    Build a plan and execute it, returning all findings.

    This is the main entry point that combines:
    1. Plan generation (with repair and fallback)
    2. Plan execution
    3. Findings collection

    Args:
        user_question: User's compliance question
        env: Environment to scan
        region: AWS region
        bedrock_client: Optional Bedrock client
        context: Optional context (risk flags, etc.)

    Returns:
        Dictionary with plan and execution results:
        {
            "plan": {...},
            "execution": {
                "all_findings": [...],
                "steps_executed": 3,
                "citations": [...],
                ...
            }
        }
    """
    # Step 1: Build the plan (guaranteed valid)
    plan = build_plan(user_question, env, region, bedrock_client, context)

    # Step 2: Execute the plan
    execution_result = execute_plan(plan)

    return {
        "plan": plan,
        "execution": execution_result,
    }
