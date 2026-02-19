"""Tool registry for allowed agent tools.

This registry defines which tools the agent can use in plans.
Each tool must be explicitly registered here to be valid.
"""

from typing import Any

# Registry of allowed tools
ALLOWED_TOOLS = {
    "aws_config_eval": {
        "name": "aws_config_eval",
        "description": "Evaluate AWS Config rules for compliance",
        "category": "inspection",
        "params": {
            "rules": {
                "type": "array",
                "description": "List of Config rule names to evaluate",
                "required": False,
            },
            "resource_type": {
                "type": "string",
                "description": "Filter by resource type (e.g., AWS::S3::Bucket)",
                "required": False,
            },
        },
    },
    "rag_retrieve": {
        "name": "rag_retrieve",
        "description": "Retrieve control cards from RAG system",
        "category": "knowledge",
        "params": {
            "framework": {
                "type": "string",
                "description": "Compliance framework (SOC2, ISO27001, NIST, etc.)",
                "required": False,
            },
            "category": {
                "type": "string",
                "description": "Control category (access-control, encryption, etc.)",
                "required": False,
            },
            "query": {
                "type": "string",
                "description": "Natural language query for control cards",
                "required": False,
            },
        },
    },
}


def is_valid_tool(tool_name: str) -> bool:
    """
    Check if a tool is registered in the allowed tools.

    Args:
        tool_name: Name of the tool to check

    Returns:
        True if tool is allowed, False otherwise
    """
    return tool_name in ALLOWED_TOOLS


def get_tool_info(tool_name: str) -> dict[str, Any] | None:
    """
    Get information about a tool.

    Args:
        tool_name: Name of the tool

    Returns:
        Tool information dict or None if not found
    """
    return ALLOWED_TOOLS.get(tool_name)


def list_all_tools() -> list[str]:
    """
    Get list of all registered tool names.

    Returns:
        List of tool names
    """
    return list(ALLOWED_TOOLS.keys())


def get_tools_by_category(category: str) -> list[str]:
    """
    Get tools filtered by category.

    Args:
        category: Tool category (inspection, knowledge, etc.)

    Returns:
        List of tool names in that category
    """
    return [
        name
        for name, info in ALLOWED_TOOLS.items()
        if info.get("category") == category
    ]
