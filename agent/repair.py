"""Plan repair logic using LLM.

This module provides functionality to repair invalid plans by
sending them back to the LLM with error context.
"""

from typing import Optional

from .schema import PLAN_SCHEMA
from .tool_registry import list_all_tools


def build_repair_prompt(bad_text: str, error_message: str) -> str:
    """
    Build a repair prompt for the LLM.

    This prompt includes:
    - The invalid plan text
    - The validation error
    - Schema requirements
    - List of allowed tools

    Args:
        bad_text: The invalid JSON text
        error_message: Validation error message

    Returns:
        Repair prompt for LLM
    """
    allowed_tools = list_all_tools()
    tools_list = ", ".join(allowed_tools)

    prompt = f"""The following compliance plan JSON failed validation:

ERROR: {error_message}

INVALID PLAN:
```json
{bad_text}
```

Please repair this plan to match the required schema:

REQUIREMENTS:
1. Must be valid JSON
2. Required fields: scope, env, region, steps
3. env must be one of: prod, dev, staging, all
4. region must match AWS region pattern (e.g., us-west-2, eu-central-1)
5. steps must be a non-empty array
6. Each step must have: tool, description
7. Each step.tool must be one of: {tools_list}

SCHEMA:
{PLAN_SCHEMA}

Return ONLY the corrected JSON plan, with no explanation or markdown.
"""
    return prompt


def repair_plan_with_llm(
    bad_text: str, error_message: str, bedrock_client: Optional[any] = None
) -> Optional[str]:
    """
    Attempt to repair an invalid plan using LLM.

    This is currently a STUB that returns None.
    In production, this will:
    1. Build a repair prompt with error context
    2. Call Bedrock (Claude) to fix the JSON
    3. Return the repaired JSON text

    Args:
        bad_text: The invalid JSON text from LLM
        error_message: Validation error message
        bedrock_client: Optional Bedrock client (for future use)

    Returns:
        Repaired JSON text if successful, None if repair fails or not implemented

    Example future implementation:
        ```python
        if bedrock_client:
            repair_prompt = build_repair_prompt(bad_text, error_message)
            response = bedrock_client.invoke_model(
                modelId="anthropic.claude-3-5-sonnet-20241022-v2:0",
                body=json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "messages": [{"role": "user", "content": repair_prompt}],
                    "max_tokens": 2000,
                    "temperature": 0.0,
                })
            )
            repaired = extract_json_from_response(response)
            return repaired
        ```
    """
    # STUB: Return None for now
    # In production, this will call Bedrock with repair prompt
    # For testing, tests can mock this function to return valid JSON

    # Log that repair was attempted (in real implementation)
    # logger.info(f"Repair attempt (STUB): {error_message[:100]}")

    return None


def extract_json_from_response(response_text: str) -> Optional[str]:
    """
    Extract JSON from LLM response.

    LLMs sometimes return JSON wrapped in markdown code blocks or
    with additional text. This function extracts the JSON portion.

    Args:
        response_text: Raw LLM response text

    Returns:
        Extracted JSON text or None if not found
    """
    import re

    # Try to find JSON in markdown code blocks
    json_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", response_text, re.DOTALL)
    if json_match:
        return json_match.group(1)

    # Try to find JSON object directly
    json_match = re.search(r"\{.*\}", response_text, re.DOTALL)
    if json_match:
        return json_match.group(0)

    # If no JSON found, return the text as-is
    return response_text.strip() if response_text.strip() else None
