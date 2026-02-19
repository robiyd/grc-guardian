"""AWS Config evaluator - deterministic compliance findings from AWS Config.

This module provides functions to:
- Query AWS Config for rule compliance status
- Fetch detailed compliance information for resources
- Normalize findings into a stable, deterministic format
"""

from datetime import datetime
from typing import Any, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from .tool_contracts import ComplianceType, Finding, ToolResult, create_finding, create_tool_result


def create_config_client(region: str = "us-west-2") -> Any:
    """
    Create AWS Config client.

    Args:
        region: AWS region

    Returns:
        boto3 Config client
    """
    return boto3.client("config", region_name=region)


def aws_config_eval(
    rule_name: str,
    region: str = "us-west-2",
    resource_type: Optional[str] = None,
    config_client: Optional[Any] = None,
) -> list[Finding]:
    """
    Evaluate a single AWS Config rule and return normalized findings.

    This function:
    1. Queries AWS Config for compliance details
    2. Fetches both compliant and non-compliant resources
    3. Normalizes results into stable Finding structures

    Args:
        rule_name: Name of the AWS Config rule to evaluate
        region: AWS region to query
        resource_type: Optional filter by resource type
        config_client: Optional boto3 client (for testing/mocking)

    Returns:
        List of normalized Finding objects

    Raises:
        ClientError: If AWS Config API call fails
        BotoCoreError: If boto3 fails
    """
    if config_client is None:
        config_client = create_config_client(region)

    findings: list[Finding] = []

    try:
        # Get compliance details for the rule
        response = config_client.get_compliance_details_by_config_rule(
            ConfigRuleName=rule_name,
            ComplianceTypes=["COMPLIANT", "NON_COMPLIANT"],
            Limit=100,  # Max results per page
        )

        evaluation_results = response.get("EvaluationResults", [])

        # Get rule ARN for evidence
        rule_arn = None
        try:
            rule_response = config_client.describe_config_rules(
                ConfigRuleNames=[rule_name]
            )
            if rule_response.get("ConfigRules"):
                rule_arn = rule_response["ConfigRules"][0].get("ConfigRuleArn")
        except Exception:
            # Rule ARN is optional, continue without it
            pass

        # Process each evaluation result
        for result in evaluation_results:
            eval_result_id = result.get("EvaluationResultIdentifier", {})
            resource_id_obj = eval_result_id.get("EvaluationResultQualifier", {})

            # Extract resource information
            res_type = resource_id_obj.get("ResourceType", "Unknown")
            res_id = resource_id_obj.get("ResourceId", "Unknown")

            # Filter by resource type if specified
            if resource_type and res_type != resource_type:
                continue

            # Extract compliance information
            compliance_type = result.get("ComplianceType", "NOT_APPLICABLE")

            # Normalize compliance type to our enum
            if compliance_type not in ["COMPLIANT", "NON_COMPLIANT", "NOT_APPLICABLE", "INSUFFICIENT_DATA"]:
                compliance_type = "NOT_APPLICABLE"

            # Extract timestamp
            config_rule_invoked_time = result.get("ConfigRuleInvokedTime")
            if config_rule_invoked_time:
                if isinstance(config_rule_invoked_time, datetime):
                    timestamp = config_rule_invoked_time
                else:
                    timestamp = datetime.utcnow()
            else:
                timestamp = datetime.utcnow()

            # Extract annotation (human-readable description)
            annotation = result.get("Annotation")
            if not annotation:
                # Generate default annotation based on compliance type
                if compliance_type == "NON_COMPLIANT":
                    annotation = f"Resource {res_id} failed compliance check: {rule_name}"
                elif compliance_type == "COMPLIANT":
                    annotation = f"Resource {res_id} passed compliance check: {rule_name}"
                else:
                    annotation = f"Resource {res_id} compliance status: {compliance_type}"

            # Get account ID from resource ID if available (e.g., arn:aws:s3:::bucket-name)
            account_id = None
            if res_id.startswith("arn:aws:"):
                parts = res_id.split(":")
                if len(parts) >= 5:
                    account_id = parts[4]

            # Create normalized finding
            finding = create_finding(
                rule=rule_name,
                compliance_type=compliance_type,
                resource_type=res_type,
                resource_id=res_id,
                timestamp=timestamp,
                annotation=annotation,
                evidence_source="aws_config",
                rule_arn=rule_arn,
                region=region,
                account_id=account_id,
            )

            findings.append(finding)

        # Handle pagination if there are more results
        next_token = response.get("NextToken")
        while next_token:
            response = config_client.get_compliance_details_by_config_rule(
                ConfigRuleName=rule_name,
                ComplianceTypes=["COMPLIANT", "NON_COMPLIANT"],
                Limit=100,
                NextToken=next_token,
            )

            for result in response.get("EvaluationResults", []):
                eval_result_id = result.get("EvaluationResultIdentifier", {})
                resource_id_obj = eval_result_id.get("EvaluationResultQualifier", {})

                res_type = resource_id_obj.get("ResourceType", "Unknown")
                res_id = resource_id_obj.get("ResourceId", "Unknown")

                if resource_type and res_type != resource_type:
                    continue

                compliance_type = result.get("ComplianceType", "NOT_APPLICABLE")
                if compliance_type not in ["COMPLIANT", "NON_COMPLIANT", "NOT_APPLICABLE", "INSUFFICIENT_DATA"]:
                    compliance_type = "NOT_APPLICABLE"

                config_rule_invoked_time = result.get("ConfigRuleInvokedTime")
                timestamp = config_rule_invoked_time if isinstance(config_rule_invoked_time, datetime) else datetime.utcnow()

                annotation = result.get("Annotation") or f"Resource {res_id} compliance status: {compliance_type}"

                account_id = None
                if res_id.startswith("arn:aws:"):
                    parts = res_id.split(":")
                    if len(parts) >= 5:
                        account_id = parts[4]

                finding = create_finding(
                    rule=rule_name,
                    compliance_type=compliance_type,
                    resource_type=res_type,
                    resource_id=res_id,
                    timestamp=timestamp,
                    annotation=annotation,
                    evidence_source="aws_config",
                    rule_arn=rule_arn,
                    region=region,
                    account_id=account_id,
                )

                findings.append(finding)

            next_token = response.get("NextToken")

    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        error_msg = e.response.get("Error", {}).get("Message", str(e))

        # Handle specific error cases
        if error_code == "NoSuchConfigRuleException":
            # Rule doesn't exist - return empty findings with annotation
            return []
        elif error_code == "InvalidParameterValueException":
            raise ValueError(f"Invalid parameter for rule {rule_name}: {error_msg}")
        else:
            raise

    except BotoCoreError as e:
        raise RuntimeError(f"AWS Config API error: {str(e)}")

    # Sort findings for deterministic output (by resource_id then compliance_type)
    findings.sort(key=lambda f: (f["resource_id"], f["compliance_type"]))

    return findings


def aws_config_eval_multi(
    rule_names: list[str],
    region: str = "us-west-2",
    resource_type: Optional[str] = None,
    config_client: Optional[Any] = None,
) -> ToolResult:
    """
    Evaluate multiple AWS Config rules and return combined results.

    Args:
        rule_names: List of Config rule names to evaluate
        region: AWS region to query
        resource_type: Optional filter by resource type
        config_client: Optional boto3 client (for testing/mocking)

    Returns:
        ToolResult with combined findings from all rules
    """
    all_findings: list[Finding] = []
    errors: list[str] = []

    for rule_name in rule_names:
        try:
            findings = aws_config_eval(rule_name, region, resource_type, config_client)
            all_findings.extend(findings)
        except Exception as e:
            errors.append(f"{rule_name}: {str(e)}")

    # Determine overall status
    status = "success" if not errors else "error"
    error_msg = "; ".join(errors) if errors else None

    return create_tool_result(
        tool_name="aws_config_eval",
        findings=all_findings,
        status=status,
        error=error_msg,
        rules_evaluated=len(rule_names),
        rules_succeeded=len(rule_names) - len(errors),
        rules_failed=len(errors),
        region=region,
    )


def get_rule_compliance_summary(
    rule_name: str,
    region: str = "us-west-2",
    config_client: Optional[Any] = None,
) -> dict[str, int]:
    """
    Get compliance summary counts for a rule.

    Args:
        rule_name: Name of the AWS Config rule
        region: AWS region
        config_client: Optional boto3 client

    Returns:
        Dictionary with compliance counts:
        {
            "COMPLIANT": 5,
            "NON_COMPLIANT": 2,
            "NOT_APPLICABLE": 0,
            "INSUFFICIENT_DATA": 0
        }
    """
    findings = aws_config_eval(rule_name, region, None, config_client)

    summary = {
        "COMPLIANT": 0,
        "NON_COMPLIANT": 0,
        "NOT_APPLICABLE": 0,
        "INSUFFICIENT_DATA": 0,
    }

    for finding in findings:
        compliance_type = finding["compliance_type"]
        summary[compliance_type] = summary.get(compliance_type, 0) + 1

    return summary
