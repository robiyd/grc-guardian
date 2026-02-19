"""Plan validator - parse JSON and validate against schema."""

import json
from typing import Any, Optional

import jsonschema
from jsonschema import ValidationError

from .schema import PLAN_SCHEMA
from .tool_registry import is_valid_tool


class PlanValidationError(Exception):
    """Exception raised when plan validation fails."""

    def __init__(self, message: str, raw_text: Optional[str] = None) -> None:
        """
        Initialize validation error.

        Args:
            message: Error message
            raw_text: Raw text that failed validation (optional)
        """
        super().__init__(message)
        self.message = message
        self.raw_text = raw_text


def parse_json(raw_text: str) -> tuple[Optional[dict[str, Any]], Optional[str]]:
    """
    Parse JSON text.

    Args:
        raw_text: Raw JSON text to parse

    Returns:
        Tuple of (parsed_dict, error_message)
        - If successful: (dict, None)
        - If failed: (None, error_message)
    """
    try:
        parsed = json.loads(raw_text)
        if not isinstance(parsed, dict):
            return None, "Parsed JSON is not an object/dict"
        return parsed, None
    except json.JSONDecodeError as e:
        return None, f"JSON parse error: {e.msg} at line {e.lineno}, col {e.colno}"
    except Exception as e:
        return None, f"Unexpected parse error: {str(e)}"


def validate_schema(plan: dict[str, Any]) -> tuple[bool, Optional[str]]:
    """
    Validate plan against JSON schema.

    Args:
        plan: Parsed plan dictionary

    Returns:
        Tuple of (is_valid, error_message)
        - If valid: (True, None)
        - If invalid: (False, error_message)
    """
    try:
        jsonschema.validate(instance=plan, schema=PLAN_SCHEMA)
        return True, None
    except ValidationError as e:
        # Format validation error message
        path = " -> ".join(str(p) for p in e.path) if e.path else "root"
        error_msg = f"Schema validation failed at '{path}': {e.message}"
        return False, error_msg
    except Exception as e:
        return False, f"Schema validation error: {str(e)}"


def validate_tools(plan: dict[str, Any]) -> tuple[bool, Optional[str]]:
    """
    Validate that all tools in steps are registered.

    Args:
        plan: Parsed plan dictionary

    Returns:
        Tuple of (is_valid, error_message)
        - If all tools valid: (True, None)
        - If unknown tool found: (False, error_message)
    """
    steps = plan.get("steps", [])
    if not steps:
        return False, "Plan must have at least one step"

    for idx, step in enumerate(steps):
        tool_name = step.get("tool")
        if not tool_name:
            return False, f"Step {idx} is missing 'tool' field"

        if not is_valid_tool(tool_name):
            return False, f"Unknown tool '{tool_name}' in step {idx}. Tool not registered."

    return True, None


def validate_plan(
    raw_text: str,
) -> tuple[Optional[dict[str, Any]], Optional[str]]:
    """
    Parse and validate a plan.

    This is the main validation function that:
    1. Parses JSON
    2. Validates against schema
    3. Validates tools are registered

    Args:
        raw_text: Raw JSON text from LLM

    Returns:
        Tuple of (plan, error_message)
        - If valid: (plan_dict, None)
        - If invalid: (None, error_message)
    """
    # Step 1: Parse JSON
    plan, parse_error = parse_json(raw_text)
    if parse_error:
        return None, parse_error

    # Step 2: Validate schema
    schema_valid, schema_error = validate_schema(plan)
    if not schema_valid:
        return None, schema_error

    # Step 3: Validate tools
    tools_valid, tools_error = validate_tools(plan)
    if not tools_valid:
        return None, tools_error

    # All validations passed
    return plan, None


def is_valid_plan(raw_text: str) -> bool:
    """
    Check if a plan is valid (convenience function).

    Args:
        raw_text: Raw JSON text to validate

    Returns:
        True if plan is valid, False otherwise
    """
    plan, error = validate_plan(raw_text)
    return plan is not None and error is None
