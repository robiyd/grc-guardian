"""GRC Guardian Agent - Planner, Validator, and Orchestrator.

This package provides the agent core that:
- Generates compliance plans using LLM (with fallback)
- Validates plans against strict JSON schema
- Repairs invalid plans
- Orchestrates compliance workflows
"""

from .orchestrator import build_and_execute_plan, build_plan
from .schema import PLAN_SCHEMA
from .tool_registry import list_all_tools
from .validator import validate_plan

__all__ = [
    "build_plan",
    "build_and_execute_plan",
    "validate_plan",
    "PLAN_SCHEMA",
    "list_all_tools",
]

__version__ = "0.1.0"
