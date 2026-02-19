"""Strict JSON Schema for Agent Plan output.

This schema enforces:
- Required fields: scope, env, region, steps
- Each step must reference a valid tool from tool_registry
- No unknown tools allowed
- All fields are explicitly typed
"""

# JSON Schema for Plan validation
PLAN_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "required": ["scope", "env", "region", "steps"],
    "additionalProperties": False,
    "properties": {
        "scope": {
            "type": "string",
            "description": "Scope of the compliance scan (e.g., 'all', 'production', 's3-only')",
            "minLength": 1,
        },
        "env": {
            "type": "string",
            "description": "Environment to scan (e.g., 'prod', 'dev', 'staging')",
            "enum": ["prod", "dev", "staging", "all"],
        },
        "region": {
            "type": "string",
            "description": "AWS region to scan",
            "pattern": "^(us|eu|ap|sa|ca|me|af)-(north|south|east|west|central|northeast|southeast)-[1-9]$",
        },
        "steps": {
            "type": "array",
            "description": "Ordered list of steps to execute",
            "minItems": 1,
            "maxItems": 20,
            "items": {
                "type": "object",
                "required": ["tool", "description"],
                "additionalProperties": False,
                "properties": {
                    "tool": {
                        "type": "string",
                        "description": "Tool name from tool_registry",
                        "minLength": 1,
                    },
                    "description": {
                        "type": "string",
                        "description": "Human-readable step description",
                        "minLength": 1,
                        "maxLength": 500,
                    },
                    "params": {
                        "type": "object",
                        "description": "Optional tool-specific parameters",
                        "additionalProperties": True,
                    },
                },
            },
        },
        "explanation": {
            "type": "string",
            "description": "Optional explanation of the plan",
            "maxLength": 2000,
        },
    },
}


# Example valid plan
EXAMPLE_VALID_PLAN = {
    "scope": "s3-buckets",
    "env": "prod",
    "region": "us-west-2",
    "steps": [
        {
            "tool": "rag_retrieve",
            "description": "Retrieve SOC 2 S3 control cards",
            "params": {"framework": "SOC2", "category": "access-control"},
        },
        {
            "tool": "aws_config_eval",
            "description": "Evaluate S3 public access rules",
            "params": {
                "rules": [
                    "s3-bucket-public-read-prohibited",
                    "s3-bucket-public-write-prohibited",
                ]
            },
        },
    ],
    "explanation": "Scan production S3 buckets for SOC 2 compliance in us-west-2",
}


# Example invalid plans (for testing)
EXAMPLE_INVALID_PLAN_MISSING_FIELD = {
    # Missing 'region' field
    "scope": "all",
    "env": "prod",
    "steps": [{"tool": "aws_config_eval", "description": "Eval config rules"}],
}

EXAMPLE_INVALID_PLAN_UNKNOWN_TOOL = {
    "scope": "all",
    "env": "prod",
    "region": "us-west-2",
    "steps": [
        {
            "tool": "unknown_tool_that_doesnt_exist",  # Invalid tool
            "description": "This will fail validation",
        }
    ],
}

EXAMPLE_INVALID_PLAN_BAD_ENV = {
    "scope": "all",
    "env": "production",  # Should be 'prod', not 'production'
    "region": "us-west-2",
    "steps": [{"tool": "aws_config_eval", "description": "Eval config rules"}],
}
