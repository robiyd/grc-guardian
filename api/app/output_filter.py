"""Output filtering and sanitization."""

import re
from typing import Any, Optional

from .logging_config import logger
from .security_logger import security_logger

# Patterns for sensitive data that should be redacted
SENSITIVE_PATTERNS = [
    # AWS access keys
    (r"AKIA[0-9A-Z]{16}", "AWS_ACCESS_KEY_REDACTED"),
    # AWS secret keys (basic pattern)
    (r"[A-Za-z0-9/+=]{40}", "AWS_SECRET_KEY_REDACTED"),
    # API keys (common patterns)
    (r"api[_-]?key[_-]?[=:]\s*['\"]?([a-zA-Z0-9_-]{20,})['\"]?", "API_KEY_REDACTED"),
    # Bearer tokens
    (r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", "BEARER_TOKEN_REDACTED"),
    # Private keys
    (r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]+?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----", "PRIVATE_KEY_REDACTED"),
    # Email addresses (partial redaction)
    (r"([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", r"\1@***"),
]

# Compile patterns
COMPILED_SENSITIVE_PATTERNS = [
    (re.compile(pattern, re.IGNORECASE | re.MULTILINE), replacement)
    for pattern, replacement in SENSITIVE_PATTERNS
]


def response_guard(
    explainer_output: dict[str, Any],
    findings_json: list[dict[str, Any]],
    run_id: Optional[str] = None,
) -> dict[str, Any]:
    """
    Validate explainer output against actual findings to prevent hallucination.

    Removes/flags any resource IDs mentioned by the explainer that are not
    present in findings_json. Logs these incidents for regression tracking.

    Args:
        explainer_output: Output from llm_explainer
        findings_json: Actual compliance findings (source of truth)
        run_id: Optional run ID for logging

    Returns:
        Guarded explainer output with hallucinations removed/flagged
    """
    # Extract valid resource IDs from findings
    valid_resource_ids = {f.get("resource_id", "") for f in findings_json if f.get("resource_id")}

    # Track guard actions
    guard_actions = []
    hallucinations_detected = False

    # Check top_risks for hallucinated resources
    if "top_risks" in explainer_output:
        filtered_risks = []
        for risk in explainer_output["top_risks"]:
            # Check evidence_ids if present
            if "evidence_ids" in risk:
                valid_evidence = []
                for eid in risk["evidence_ids"]:
                    if eid in valid_resource_ids:
                        valid_evidence.append(eid)
                    else:
                        hallucinations_detected = True
                        guard_actions.append({
                            "type": "removed_hallucinated_evidence",
                            "resource_id": eid,
                            "context": "top_risks",
                        })

                risk["evidence_ids"] = valid_evidence

            filtered_risks.append(risk)

        explainer_output["top_risks"] = filtered_risks

    # Check remediations for hallucinated resources
    if "remediations" in explainer_output:
        filtered_remediations = []
        for remediation in explainer_output["remediations"]:
            resource_id = remediation.get("resource_id")

            if resource_id and resource_id not in valid_resource_ids:
                # Hallucinated resource - remove this remediation
                hallucinations_detected = True
                guard_actions.append({
                    "type": "removed_hallucinated_remediation",
                    "resource_id": resource_id,
                })
            else:
                filtered_remediations.append(remediation)

        explainer_output["remediations"] = filtered_remediations

    # Add guard metadata if hallucinations detected
    if hallucinations_detected:
        explainer_output["output_guard_flags"] = {
            "hallucinations_detected": True,
            "guard_actions": guard_actions,
            "action_count": len(guard_actions),
        }

        # Log to security regressions using dedicated method
        security_logger.log_output_guard_stripped(
            run_id=run_id,
            stripped_count=len(guard_actions),
            stripped_types=[a["type"] for a in guard_actions],
        )

        logger.warning(
            "Explainer hallucinations detected and removed",
            extra={
                "run_id": run_id,
                "hallucination_count": len(guard_actions),
            },
        )

    return explainer_output


class OutputFilter:
    """Filters and sanitizes output responses."""

    def __init__(self) -> None:
        """Initialize output filter."""
        pass

    def redact_sensitive_data(self, text: str) -> str:
        """
        Redact sensitive data from text.

        Args:
            text: Text to sanitize

        Returns:
            Sanitized text with sensitive data redacted
        """
        if not text:
            return text

        original_text = text
        redaction_count = 0

        for pattern, replacement in COMPILED_SENSITIVE_PATTERNS:
            matches = pattern.findall(text)
            if matches:
                redaction_count += len(matches)
                text = pattern.sub(replacement, text)

        if redaction_count > 0:
            logger.info(
                "Sensitive data redacted from output",
                extra={"redaction_count": redaction_count},
            )

        return text

    def sanitize_dict(self, data: dict[str, Any]) -> dict[str, Any]:
        """
        Recursively sanitize dictionary values.

        Args:
            data: Dictionary to sanitize

        Returns:
            Sanitized dictionary
        """
        sanitized = {}

        for key, value in data.items():
            if isinstance(value, str):
                sanitized[key] = self.redact_sensitive_data(value)
            elif isinstance(value, dict):
                sanitized[key] = self.sanitize_dict(value)
            elif isinstance(value, list):
                sanitized[key] = self.sanitize_list(value)
            else:
                sanitized[key] = value

        return sanitized

    def sanitize_list(self, data: list[Any]) -> list[Any]:
        """
        Recursively sanitize list values.

        Args:
            data: List to sanitize

        Returns:
            Sanitized list
        """
        sanitized = []

        for item in data:
            if isinstance(item, str):
                sanitized.append(self.redact_sensitive_data(item))
            elif isinstance(item, dict):
                sanitized.append(self.sanitize_dict(item))
            elif isinstance(item, list):
                sanitized.append(self.sanitize_list(item))
            else:
                sanitized.append(item)

        return sanitized

    def filter_response(self, response_data: Any) -> Any:
        """
        Filter and sanitize response data.

        Args:
            response_data: Response data to filter

        Returns:
            Filtered response data
        """
        if isinstance(response_data, dict):
            return self.sanitize_dict(response_data)
        elif isinstance(response_data, list):
            return self.sanitize_list(response_data)
        elif isinstance(response_data, str):
            return self.redact_sensitive_data(response_data)
        else:
            return response_data


# Global output filter instance
output_filter = OutputFilter()
