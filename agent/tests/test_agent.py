"""Tests for agent core - schema, validation, repair, and orchestration."""

import json
from unittest.mock import patch

import pytest

from agent.fallback import fallback_plan, get_core_rules
from agent.orchestrator import build_plan, llm_planner
from agent.repair import build_repair_prompt, repair_plan_with_llm
from agent.schema import (
    EXAMPLE_INVALID_PLAN_BAD_ENV,
    EXAMPLE_INVALID_PLAN_MISSING_FIELD,
    EXAMPLE_INVALID_PLAN_UNKNOWN_TOOL,
    EXAMPLE_VALID_PLAN,
)
from agent.tool_registry import is_valid_tool, list_all_tools
from agent.validator import validate_plan, validate_schema, validate_tools


class TestSchema:
    """Test JSON schema validation."""

    def test_valid_plan_passes_schema(self):
        """Test that example valid plan passes schema validation."""
        plan_text = json.dumps(EXAMPLE_VALID_PLAN)
        plan, error = validate_plan(plan_text)

        assert plan is not None, f"Valid plan should pass: {error}"
        assert error is None
        assert plan["scope"] == "s3-buckets"
        assert plan["env"] == "prod"
        assert plan["region"] == "us-west-2"

    def test_schema_rejects_missing_field(self):
        """Test that schema rejects plan missing required field (region)."""
        plan_text = json.dumps(EXAMPLE_INVALID_PLAN_MISSING_FIELD)
        plan, error = validate_plan(plan_text)

        assert plan is None
        assert error is not None
        assert "region" in error.lower() or "required" in error.lower()

    def test_schema_rejects_bad_env(self):
        """Test that schema rejects invalid env value."""
        plan_text = json.dumps(EXAMPLE_INVALID_PLAN_BAD_ENV)
        plan, error = validate_plan(plan_text)

        assert plan is None
        assert error is not None
        assert "env" in error.lower() or "production" in error.lower()

    def test_schema_requires_scope_env_region(self):
        """Test that schema requires scope, env, and region fields."""
        incomplete_plan = {
            "steps": [{"tool": "aws_config_eval", "description": "Test"}]
        }
        plan_text = json.dumps(incomplete_plan)
        plan, error = validate_plan(plan_text)

        assert plan is None
        assert error is not None
        # Should mention one of the missing required fields
        assert any(
            field in error.lower() for field in ["scope", "env", "region", "required"]
        )


class TestToolRegistry:
    """Test tool registry validation."""

    def test_schema_rejects_unknown_tool(self):
        """Test that validation rejects unknown tools."""
        plan_text = json.dumps(EXAMPLE_INVALID_PLAN_UNKNOWN_TOOL)
        plan, error = validate_plan(plan_text)

        assert plan is None
        assert error is not None
        assert "unknown" in error.lower() or "tool" in error.lower()

    def test_allowed_tools_registered(self):
        """Test that expected tools are registered."""
        allowed = list_all_tools()

        assert "aws_config_eval" in allowed
        assert "rag_retrieve" in allowed

    def test_is_valid_tool_checks_registry(self):
        """Test that is_valid_tool correctly checks registry."""
        assert is_valid_tool("aws_config_eval") is True
        assert is_valid_tool("rag_retrieve") is True
        assert is_valid_tool("nonexistent_tool") is False
        assert is_valid_tool("") is False


class TestValidator:
    """Test plan validator."""

    def test_parse_invalid_json(self):
        """Test that validator catches invalid JSON."""
        invalid_json = '{"scope": "test", invalid json here}'
        plan, error = validate_plan(invalid_json)

        assert plan is None
        assert error is not None
        assert "json" in error.lower() or "parse" in error.lower()

    def test_validate_tools_rejects_unregistered(self):
        """Test that validate_tools rejects unregistered tools."""
        plan_dict = {
            "scope": "test",
            "env": "prod",
            "region": "us-west-2",
            "steps": [
                {"tool": "fake_tool_123", "description": "This should fail"}
            ],
        }

        tools_valid, error = validate_tools(plan_dict)

        assert tools_valid is False
        assert error is not None
        assert "fake_tool_123" in error

    def test_validate_tools_accepts_registered(self):
        """Test that validate_tools accepts registered tools."""
        plan_dict = {
            "scope": "test",
            "env": "prod",
            "region": "us-west-2",
            "steps": [
                {"tool": "aws_config_eval", "description": "Valid tool"},
                {"tool": "rag_retrieve", "description": "Another valid tool"},
            ],
        }

        tools_valid, error = validate_tools(plan_dict)

        assert tools_valid is True
        assert error is None


class TestFallback:
    """Test fallback plan generation."""

    def test_fallback_plan_is_always_valid(self):
        """Test that fallback plan always passes validation."""
        plan = fallback_plan("prod", "us-west-2")
        plan_text = json.dumps(plan)

        validated_plan, error = validate_plan(plan_text)

        assert validated_plan is not None, f"Fallback plan should be valid: {error}"
        assert error is None

    def test_fallback_includes_core_rules(self):
        """Test that fallback plan includes all 9 core Config rules."""
        plan = fallback_plan("prod", "us-west-2")
        core_rules = get_core_rules()

        # Check that plan includes aws_config_eval step
        assert len(plan["steps"]) > 0
        config_step = plan["steps"][0]
        assert config_step["tool"] == "aws_config_eval"

        # Check that all 9 core rules are included
        rules_in_plan = config_step["params"]["rules"]
        assert len(rules_in_plan) == 9
        for rule in core_rules:
            assert rule in rules_in_plan

    def test_fallback_normalizes_invalid_env(self):
        """Test that fallback normalizes invalid env to 'all'."""
        plan = fallback_plan("invalid-env", "us-west-2")

        assert plan["env"] == "all"


class TestRepair:
    """Test plan repair logic."""

    def test_repair_prompt_includes_error(self):
        """Test that repair prompt includes the validation error."""
        bad_text = '{"invalid": "plan"}'
        error_msg = "Missing required field: region"

        prompt = build_repair_prompt(bad_text, error_msg)

        assert error_msg in prompt
        assert bad_text in prompt
        assert "schema" in prompt.lower()

    def test_repair_prompt_lists_allowed_tools(self):
        """Test that repair prompt lists allowed tools."""
        bad_text = '{"scope": "test"}'
        error_msg = "Invalid tool"

        prompt = build_repair_prompt(bad_text, error_msg)

        # Should mention the allowed tools
        allowed_tools = list_all_tools()
        for tool in allowed_tools:
            assert tool in prompt

    def test_repair_with_llm_stub_returns_none(self):
        """Test that repair stub returns None (not implemented)."""
        result = repair_plan_with_llm("bad json", "error message")

        assert result is None


class TestOrchestrator:
    """Test orchestrator build_plan logic."""

    def test_valid_plan_returned_immediately(self):
        """Test that valid plan from LLM is returned without repair."""
        # LLM returns valid plan (default behavior)
        plan = build_plan("Test question", "prod", "us-west-2")

        assert plan is not None
        assert "scope" in plan
        assert "steps" in plan
        assert len(plan["steps"]) > 0

    def test_invalid_json_repairs_then_ok(self):
        """Test that invalid JSON gets repaired and then succeeds."""

        # Mock llm_planner to return invalid JSON
        def mock_llm_invalid(question, env, region):
            return '{"scope": "test", invalid json'

        # Mock repair to return valid JSON
        def mock_repair_valid(bad_text, error, client=None):
            return json.dumps(
                {
                    "scope": "repaired",
                    "env": "prod",
                    "region": "us-west-2",
                    "steps": [
                        {"tool": "aws_config_eval", "description": "Repaired step"}
                    ],
                }
            )

        with patch("agent.orchestrator.llm_planner", side_effect=mock_llm_invalid):
            with patch(
                "agent.orchestrator.repair_plan_with_llm",
                side_effect=mock_repair_valid,
            ):
                plan = build_plan("Test", "prod", "us-west-2")

                assert plan is not None
                assert plan["scope"] == "repaired"

    def test_invalid_twice_uses_fallback(self):
        """Test that if repair also fails, fallback is used."""

        # Mock llm_planner to return invalid JSON
        def mock_llm_invalid(question, env, region):
            return '{"invalid": "first attempt"}'

        # Mock repair to also return invalid JSON
        def mock_repair_also_invalid(bad_text, error, client=None):
            return '{"still": "invalid", "missing": "required fields"}'

        with patch("agent.orchestrator.llm_planner", side_effect=mock_llm_invalid):
            with patch(
                "agent.orchestrator.repair_plan_with_llm",
                side_effect=mock_repair_also_invalid,
            ):
                plan = build_plan("Test", "prod", "us-west-2")

                # Should use fallback
                assert plan is not None
                assert "fallback" in plan["scope"]
                assert plan["env"] == "prod"
                assert plan["region"] == "us-west-2"

                # Fallback should have 9 core rules
                assert len(plan["steps"]) > 0
                config_step = plan["steps"][0]
                assert len(config_step["params"]["rules"]) == 9

    def test_llm_exception_uses_fallback(self):
        """Test that LLM exception triggers immediate fallback."""

        # Mock llm_planner to raise exception
        def mock_llm_crash(question, env, region):
            raise Exception("Bedrock API error")

        with patch("agent.orchestrator.llm_planner", side_effect=mock_llm_crash):
            plan = build_plan("Test", "dev", "eu-west-1")

            # Should use fallback
            assert plan is not None
            assert "fallback" in plan["scope"]
            assert plan["env"] == "dev"
            assert plan["region"] == "eu-west-1"


class TestIntegration:
    """Integration tests for full agent flow."""

    def test_build_plan_never_crashes(self):
        """Test that build_plan never crashes, always returns valid plan."""
        # Try various inputs that could cause issues
        test_cases = [
            ("", "prod", "us-west-2"),
            ("Test question", "invalid-env", "us-west-2"),
            ("Very long question " * 100, "prod", "us-west-2"),
            ("Question with unicode 你好", "dev", "ap-southeast-1"),
        ]

        for question, env, region in test_cases:
            plan = build_plan(question, env, region)

            # Must return a valid plan
            assert plan is not None
            assert "scope" in plan
            assert "env" in plan
            assert "region" in plan
            assert "steps" in plan
            assert len(plan["steps"]) > 0

            # Validate against schema
            plan_text = json.dumps(plan)
            validated_plan, error = validate_plan(plan_text)
            assert validated_plan is not None, f"Plan should be valid: {error}"

    def test_fallback_plan_matches_terraform_rules(self):
        """Test that fallback plan includes all 9 Terraform Config rules."""
        expected_rules = [
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

        plan = fallback_plan("prod", "us-west-2")
        rules_in_plan = plan["steps"][0]["params"]["rules"]

        assert len(rules_in_plan) == len(expected_rules)
        for rule in expected_rules:
            assert rule in rules_in_plan, f"Missing rule: {rule}"
