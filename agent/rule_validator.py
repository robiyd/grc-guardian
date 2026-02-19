"""AWS Config rule name validator.

Validates that rule names in plans actually exist in AWS Config deployment.
"""

from typing import Any

# Core AWS Config rules that MUST exist (from Terraform infra/terraform/config.tf)
VALID_CONFIG_RULES = {
    "s3-bucket-public-read-prohibited",
    "s3-bucket-public-write-prohibited",
    "s3-bucket-server-side-encryption-enabled",
    "s3-bucket-versioning-enabled",
    "root-account-mfa-enabled",
    "iam-user-mfa-enabled",
    "access-keys-rotated",
    "iam-password-policy",
    "cloudtrail-enabled",
}


def validate_rule_names(plan: dict[str, Any]) -> tuple[bool, list[str]]:
    """
    Validate that all AWS Config rule names in the plan actually exist.

    Args:
        plan: Plan dictionary with steps

    Returns:
        Tuple of (is_valid, list_of_invalid_rules)
        - is_valid: True if all rules exist and at least one rule is specified, False otherwise
        - list_of_invalid_rules: List of rule names that don't exist (or "NO_RULES" if none specified)
    """
    invalid_rules = []

    steps = plan.get("steps", [])
    for step in steps:
        tool = step.get("tool")
        if tool != "aws_config_eval":
            continue

        params = step.get("params", {})

        # Collect all rules from different parameter variations
        all_rules = []

        # Check 'rules' parameter (array)
        rules = params.get("rules", [])
        all_rules.extend(rules)

        # Check 'rule_name' parameter (string)
        rule_name = params.get("rule_name")
        if rule_name:
            all_rules.append(rule_name)

        # Check 'rule' parameter (string - most common LLM output)
        rule = params.get("rule")
        if rule:
            all_rules.append(rule)

        # If no rules specified at all, this is invalid
        if not all_rules:
            invalid_rules.append("NO_RULES_SPECIFIED")
            continue

        # Validate each rule name
        for rule in all_rules:
            if rule not in VALID_CONFIG_RULES:
                invalid_rules.append(rule)

    is_valid = len(invalid_rules) == 0
    return is_valid, invalid_rules


def should_use_fallback(plan: dict[str, Any]) -> tuple[bool, str]:
    """
    Determine if fallback plan should be used due to invalid rule names.

    Args:
        plan: Plan dictionary

    Returns:
        Tuple of (use_fallback, reason)
    """
    is_valid, invalid_rules = validate_rule_names(plan)

    if not is_valid:
        reason = f"Invalid AWS Config rule names: {', '.join(invalid_rules)}"
        return True, reason

    return False, ""
