"""Tests for Bedrock integration (planner + explainer) with guardrails and fallback."""

import json
from unittest.mock import Mock, patch

import pytest

from agent.bedrock_client import BedrockClient
from agent.orchestrator import build_plan, build_plan_no_fallback
from api.app.output_filter import response_guard


class TestBedrockRequestIncludesGuardrails:
    """Test that guardrails are included in Bedrock requests when env vars are set."""

    @patch("agent.bedrock_client.boto3")
    def test_bedrock_request_includes_guardrails_when_env_set(self, mock_boto3):
        """Test that guardrail parameters are included when configured."""
        # Mock boto3 client
        mock_bedrock_client = Mock()
        mock_boto3.client.return_value = mock_bedrock_client

        # Mock successful response
        mock_response = {
            "body": Mock(
                read=lambda: json.dumps({
                    "content": [{"text": '{"scope": "test", "env": "prod"}'}]
                })
            ),
            "ResponseMetadata": {"HTTPHeaders": {}},
        }
        mock_bedrock_client.invoke_model.return_value = mock_response

        # Create client with guardrails
        client = BedrockClient(
            region="us-west-2",
            guardrail_id="test-guardrail-123",
            guardrail_version="2",
        )

        # Build request using helper
        body = {"test": "body"}
        request = client.build_bedrock_request(body, use_guardrails=True)

        # Verify guardrail parameters are present
        assert "guardrailIdentifier" in request
        assert request["guardrailIdentifier"] == "test-guardrail-123"
        assert "guardrailVersion" in request
        assert request["guardrailVersion"] == "2"

    @patch("agent.bedrock_client.boto3")
    def test_llm_planner_uses_guardrails(self, mock_boto3):
        """Test that llm_planner includes guardrails in actual calls."""
        # Mock boto3 client
        mock_bedrock_client = Mock()
        mock_boto3.client.return_value = mock_bedrock_client

        # Mock successful response
        valid_plan = {
            "scope": "s3-compliance",
            "env": "prod",
            "region": "us-west-2",
            "steps": [{"tool": "aws_config_eval", "description": "test", "params": {"rules": ["test-rule"]}}],
        }
        mock_response = {
            "body": Mock(read=lambda: json.dumps({"content": [{"text": json.dumps(valid_plan)}]})),
            "ResponseMetadata": {"HTTPHeaders": {}},
        }
        mock_bedrock_client.invoke_model.return_value = mock_response

        client = BedrockClient(
            region="us-west-2",
            guardrail_id="test-guardrail-123",
            guardrail_version="2",
        )

        # Call llm_planner
        client.llm_planner(
            question="test question",
            allowed_tools=["aws_config_eval"],
            schema_hint="test schema",
            context={"env": "prod", "region": "us-west-2"},
        )

        # Verify invoke_model was called with guardrails
        assert mock_bedrock_client.invoke_model.called
        call_args = mock_bedrock_client.invoke_model.call_args
        assert "guardrailIdentifier" in call_args.kwargs
        assert call_args.kwargs["guardrailIdentifier"] == "test-guardrail-123"
        assert "guardrailVersion" in call_args.kwargs
        assert call_args.kwargs["guardrailVersion"] == "2"


class TestPlannerGuardrailBlockTriggersFallback:
    """Test that guardrail blocks trigger fallback plan."""

    @patch("agent.orchestrator.create_bedrock_client")
    def test_planner_guardrail_block_triggers_fallback(self, mock_create_client):
        """Test that GUARDRAIL_BLOCKED error triggers fallback."""
        # Mock Bedrock client that returns GUARDRAIL_BLOCKED
        mock_client = Mock()
        mock_client.llm_planner.return_value = json.dumps({
            "error": "GUARDRAIL_BLOCKED",
            "reason": "policy_violation",
            "fallback": "use_fallback_plan",
        })
        mock_create_client.return_value = mock_client

        # Build plan
        plan = build_plan(
            user_question="malicious prompt",
            env="prod",
            region="us-west-2",
        )

        # Verify fallback plan is used
        assert plan is not None
        assert plan["scope"] == "s3-iam-logging-compliance"  # Fallback plan scope
        assert plan["env"] == "prod"
        assert plan["region"] == "us-west-2"
        assert len(plan["steps"]) == 9  # Fallback has 9 core rules

    @patch("agent.orchestrator.create_bedrock_client")
    def test_no_crash_on_guardrail_block(self, mock_create_client):
        """Test that system never crashes on guardrail block."""
        # Mock Bedrock client that raises exception
        mock_client = Mock()
        mock_client.llm_planner.side_effect = Exception("Guardrail blocked")
        mock_create_client.return_value = mock_client

        # Build plan - should not crash
        plan = build_plan(
            user_question="test",
            env="prod",
            region="us-west-2",
        )

        # Verify we get fallback plan
        assert plan is not None
        assert "scope" in plan
        assert "steps" in plan


class TestPlannerInvalidJsonRepairsThenOk:
    """Test that invalid JSON repairs then succeeds (existing behavior with Bedrock)."""

    @patch("agent.orchestrator.create_bedrock_client")
    @patch("agent.repair.repair_plan_with_llm")
    def test_planner_invalid_json_repairs_then_ok(self, mock_repair, mock_create_client):
        """Test that invalid plan is repaired and succeeds."""
        # Mock Bedrock client that returns invalid JSON first
        mock_client = Mock()
        mock_client.llm_planner.return_value = "NOT VALID JSON"
        mock_create_client.return_value = mock_client

        # Mock repair that returns valid plan
        valid_plan = {
            "scope": "repaired-plan",
            "env": "prod",
            "region": "us-west-2",
            "steps": [
                {
                    "tool": "aws_config_eval",
                    "description": "test",
                    "params": {"rules": ["s3-bucket-public-read-prohibited"]},
                }
            ],
        }
        mock_repair.return_value = json.dumps(valid_plan)

        # Build plan - should repair and succeed
        plan, error = build_plan_no_fallback(
            user_question="test",
            env="prod",
            region="us-west-2",
            bedrock_client=mock_client,
        )

        # Verify plan was repaired
        assert plan is not None
        assert error is None
        assert plan["scope"] == "repaired-plan"


class TestExplainerCannotInventFindings:
    """Test that explainer cannot invent findings (response_guard)."""

    def test_explainer_cannot_invent_findings(self):
        """Test that output_filter removes hallucinated resources."""
        # Real findings with known resource IDs
        findings_json = [
            {
                "resource_id": "bucket-1",
                "resource_type": "AWS::S3::Bucket",
                "rule": "s3-bucket-public-read-prohibited",
                "compliance_type": "NON_COMPLIANT",
            },
            {
                "resource_id": "bucket-2",
                "resource_type": "AWS::S3::Bucket",
                "rule": "s3-bucket-encryption-enabled",
                "compliance_type": "COMPLIANT",
            },
        ]

        # Explainer output that mentions an unknown resource
        explainer_output = {
            "summary": "Found compliance issues",
            "top_risks": [
                {
                    "title": "Public S3 bucket",
                    "severity": 9,
                    "evidence_ids": ["bucket-1", "bucket-999"],  # bucket-999 is hallucinated
                }
            ],
            "remediations": [
                {
                    "resource_id": "bucket-1",
                    "steps": ["Enable encryption"],
                },
                {
                    "resource_id": "bucket-999",  # Hallucinated resource
                    "steps": ["Fix this"],
                },
            ],
            "citations": [],
        }

        # Apply response guard
        guarded_output = response_guard(explainer_output, findings_json, run_id="TEST-123")

        # Verify hallucinated resources are removed
        assert "output_guard_flags" in guarded_output
        assert guarded_output["output_guard_flags"]["hallucinations_detected"] is True
        assert guarded_output["output_guard_flags"]["action_count"] == 2  # 1 evidence + 1 remediation

        # Verify bucket-999 is removed from evidence_ids
        risk_evidence = guarded_output["top_risks"][0]["evidence_ids"]
        assert "bucket-1" in risk_evidence
        assert "bucket-999" not in risk_evidence

        # Verify hallucinated remediation is removed
        remediation_ids = [r["resource_id"] for r in guarded_output["remediations"]]
        assert "bucket-1" in remediation_ids
        assert "bucket-999" not in remediation_ids

    def test_response_guard_allows_valid_resources(self):
        """Test that response_guard allows valid resource references."""
        findings_json = [
            {"resource_id": "bucket-1", "rule": "test", "compliance_type": "NON_COMPLIANT"},
            {"resource_id": "bucket-2", "rule": "test", "compliance_type": "COMPLIANT"},
        ]

        explainer_output = {
            "summary": "Test",
            "top_risks": [{"title": "Test", "evidence_ids": ["bucket-1"]}],
            "remediations": [{"resource_id": "bucket-1", "steps": ["Fix"]}],
            "citations": [],
        }

        # Apply guard
        guarded_output = response_guard(explainer_output, findings_json)

        # Verify no hallucinations detected
        assert "output_guard_flags" not in guarded_output
        assert len(guarded_output["top_risks"]) == 1
        assert len(guarded_output["remediations"]) == 1

    def test_response_guard_handles_missing_resource_ids(self):
        """Test that response_guard handles missing resource IDs gracefully."""
        findings_json = [
            {"resource_type": "AWS::S3::Bucket", "rule": "test", "compliance_type": "COMPLIANT"}
        ]

        explainer_output = {
            "summary": "Test",
            "top_risks": [],
            "remediations": [{"resource_id": "any-id", "steps": ["Fix"]}],
            "citations": [],
        }

        # Apply guard - should remove remediation since no valid resource_ids exist
        guarded_output = response_guard(explainer_output, findings_json)

        # Verify hallucinated remediation is removed
        assert len(guarded_output["remediations"]) == 0
        assert guarded_output["output_guard_flags"]["hallucinations_detected"] is True


class TestLLMExplainerStructure:
    """Test llm_explainer output structure."""

    @patch("agent.bedrock_client.boto3")
    def test_llm_explainer_returns_structured_output(self, mock_boto3):
        """Test that llm_explainer returns properly structured dict."""
        # Mock boto3 client
        mock_bedrock_client = Mock()
        mock_boto3.client.return_value = mock_bedrock_client

        # Mock response with structured JSON
        response_json = {
            "summary": "Test summary",
            "top_risks": [{"title": "Risk 1", "severity": 8, "evidence_ids": ["r1"]}],
            "remediations": [{"resource_id": "r1", "steps": ["Step 1"]}],
            "citations": [{"control_id": "AC-2", "source_path": "test.md"}],
        }
        mock_response = {
            "body": Mock(read=lambda: json.dumps({"content": [{"text": json.dumps(response_json)}]})),
            "ResponseMetadata": {"HTTPHeaders": {}},
        }
        mock_bedrock_client.invoke_model.return_value = mock_response

        client = BedrockClient(region="us-west-2")

        # Call llm_explainer
        result = client.llm_explainer(
            findings_json=[{"resource_id": "r1", "rule": "test", "compliance_type": "NON_COMPLIANT"}],
            control_cards=[],
        )

        # Verify structure
        assert isinstance(result, dict)
        assert "summary" in result
        assert "top_risks" in result
        assert "remediations" in result
        assert "citations" in result

    @patch("agent.bedrock_client.boto3")
    def test_llm_explainer_guardrail_block_returns_safe_response(self, mock_boto3):
        """Test that llm_explainer returns safe response when guardrail blocks."""
        from botocore.exceptions import ClientError

        # Mock boto3 client
        mock_bedrock_client = Mock()
        mock_boto3.client.return_value = mock_bedrock_client

        # Mock guardrail block
        error_response = {
            "Error": {
                "Code": "ValidationException",
                "Message": "Guardrail blocked the request",
            }
        }
        mock_bedrock_client.invoke_model.side_effect = ClientError(error_response, "invoke_model")

        client = BedrockClient(
            region="us-west-2",
            guardrail_id="test-guardrail",
            guardrail_version="1",
        )

        # Call llm_explainer - should return safe response
        result = client.llm_explainer(findings_json=[], control_cards=[])

        # Verify safe response structure
        assert isinstance(result, dict)
        assert result["summary"] == "Request blocked by safety policy."
        assert result["top_risks"] == []
        assert result["remediations"] == []
        assert result["citations"] == []


class TestEndToEndWithGuardrails:
    """Test end-to-end flow with guardrails enabled."""

    @patch("agent.orchestrator.create_bedrock_client")
    def test_successful_plan_with_guardrails_enabled(self, mock_create_client):
        """Test successful plan generation when guardrails allow content."""
        # Mock Bedrock client with guardrails that returns valid plan
        mock_client = Mock()
        valid_plan = {
            "scope": "test-scope",
            "env": "prod",
            "region": "us-west-2",
            "steps": [
                {
                    "tool": "aws_config_eval",
                    "description": "Test evaluation",
                    "params": {"rules": ["s3-bucket-public-read-prohibited"]},
                }
            ],
        }
        mock_client.llm_planner.return_value = json.dumps(valid_plan)
        mock_create_client.return_value = mock_client

        # Build plan
        plan = build_plan(
            user_question="legitimate question",
            env="prod",
            region="us-west-2",
        )

        # Verify valid plan is returned
        assert plan is not None
        assert plan["scope"] == "test-scope"
        assert len(plan["steps"]) == 1
        assert plan["steps"][0]["tool"] == "aws_config_eval"

    @patch("agent.orchestrator.create_bedrock_client")
    def test_fallback_when_bedrock_unavailable(self, mock_create_client):
        """Test that fallback works when Bedrock client creation fails."""
        # Mock client creation failure
        mock_create_client.side_effect = Exception("Bedrock not available")

        # Build plan - should use fallback
        plan = build_plan(
            user_question="test",
            env="prod",
            region="us-west-2",
        )

        # Verify fallback plan is used
        assert plan is not None
        assert plan["scope"] == "s3-iam-logging-compliance"
        assert len(plan["steps"]) == 9
