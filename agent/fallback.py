"""Deterministic fallback plan when LLM fails.

This module provides a guaranteed-valid fallback plan that runs
the 9 core AWS Config rules defined in the Terraform infrastructure.
"""

from typing import Any


# The 9 core Config rules from infra/terraform/config.tf
CORE_CONFIG_RULES = [
    "s3-bucket-public-read-prohibited",
    "s3-bucket-public-write-prohibited",
    "s3-bucket-server-side-encryption-enabled",
    "s3-bucket-versioning-enabled",
    "root-account-mfa-enabled",
    "iam-user-mfa-enabled",
    "access-keys-rotated",
    "iam-password-policy",
    "cloudtrail-enabled",
]


def fallback_plan(env: str, region: str) -> dict[str, Any]:
    """
    Generate a deterministic fallback plan.

    This plan always runs the 9 core AWS Config rules
    and never fails validation.

    Args:
        env: Environment to scan (prod, dev, staging, all)
        region: AWS region to scan

    Returns:
        Valid plan dictionary that will pass all validations
    """
    # Normalize env to allowed values
    if env not in ["prod", "dev", "staging", "all"]:
        env = "all"

    plan = {
        "scope": "comprehensive-fallback",
        "env": env,
        "region": region,
        "explanation": (
            "Fallback plan: LLM planner failed validation. "
            "Running comprehensive baseline scan with 9 core AWS Config rules."
        ),
        "steps": [
            {
                "tool": "aws_config_eval",
                "description": f"Evaluate all 9 core AWS Config rules in {env} environment",
                "params": {
                    "rules": CORE_CONFIG_RULES,
                    "env": env,
                },
            }
        ],
    }

    return plan


def fallback_plan_with_rag(
    env: str, region: str, framework: str = "General"
) -> dict[str, Any]:
    """
    Generate a fallback plan with RAG retrieval step.

    This variant includes a RAG step to retrieve control cards
    before running Config evaluation.

    Args:
        env: Environment to scan
        region: AWS region to scan
        framework: Compliance framework (optional)

    Returns:
        Valid plan dictionary with RAG + Config evaluation
    """
    if env not in ["prod", "dev", "staging", "all"]:
        env = "all"

    plan = {
        "scope": "comprehensive-fallback-with-rag",
        "env": env,
        "region": region,
        "explanation": (
            f"Fallback plan: Running {framework} compliance scan with "
            "RAG-enhanced control cards and 9 core Config rules."
        ),
        "steps": [
            {
                "tool": "rag_retrieve",
                "description": f"Retrieve {framework} control cards",
                "params": {
                    "framework": framework,
                    "query": "compliance requirements",
                },
            },
            {
                "tool": "aws_config_eval",
                "description": f"Evaluate all 9 core AWS Config rules in {env}",
                "params": {
                    "rules": CORE_CONFIG_RULES,
                    "env": env,
                },
            },
        ],
    }

    return plan


def get_core_rules() -> list[str]:
    """
    Get the list of core Config rules.

    Returns:
        List of Config rule names
    """
    return CORE_CONFIG_RULES.copy()
