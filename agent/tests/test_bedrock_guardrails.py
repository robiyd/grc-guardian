"""Tests for Bedrock Guardrails integration."""

import json
from unittest.mock import MagicMock, Mock, patch

import pytest

from agent.bedrock_client import BedrockClient, GuardrailBlockedException


class TestGuardrailConfiguration:
    """Test guardrail configuration."""

    def test_client_with_guardrails_includes_parameters(self):
        """Test that guardrail parameters are included when configured."""
        client = BedrockClient(
            region="us-west-2",
            guardrail_id="test-guardrail-id",
            guardrail_version="1",
        )

        assert client.guardrail_id == "test-guardrail-id"
        assert client.guardrail_version == "1"

    def test_client_without_guardrails_has_none(self):
        """Test that client works without guardrails."""
        client = BedrockClient(
            region="us-west-2",
            guardrail_id=None,
        )

        assert client.guardrail_id is None

    @patch("agent.bedrock_client.boto3")
    def test_guardrail_params_passed_to_invoke(self, mock_boto3):
        """Test that guardrail params are passed to Bedrock API."""
        # Mock boto3 client
        mock_bedrock_client = Mock()
        mock_boto3.client.return_value = mock_bedrock_client

        # Mock successful response
        mock_response = {
            "body": Mock(read=lambda: json.dumps({"content": [{"text": "test"}]})),
            "ResponseMetadata": {"HTTPHeaders": {}},
        }
        mock_bedrock_client.invoke_model.return_value = mock_response

        client = BedrockClient(
            region="us-west-2",
            guardrail_id="test-guardrail-id",
            guardrail_version="2",
        )

        # Invoke planner
        try:
            client.invoke_planner(
                user_question="test question",
                env="prod",
                region="us-west-2",
            )
        except Exception:
            pass  # We're just checking the call, not the result

        # Verify guardrail parameters were passed
        call_args = mock_bedrock_client.invoke_model.call_args
        assert call_args is not None
        assert "guardrailIdentifier" in call_args.kwargs
        assert call_args.kwargs["guardrailIdentifier"] == "test-guardrail-id"
        assert "guardrailVersion" in call_args.kwargs
        assert call_args.kwargs["guardrailVersion"] == "2"

    @patch("agent.bedrock_client.boto3")
    def test_no_guardrail_params_when_not_configured(self, mock_boto3):
        """Test that guardrail params are not passed when not configured."""
        # Mock boto3 client
        mock_bedrock_client = Mock()
        mock_boto3.client.return_value = mock_bedrock_client

        # Mock successful response
        mock_response = {
            "body": Mock(read=lambda: json.dumps({"content": [{"text": "test"}]})),
            "ResponseMetadata": {"HTTPHeaders": {}},
        }
        mock_bedrock_client.invoke_model.return_value = mock_response

        client = BedrockClient(
            region="us-west-2",
            guardrail_id=None,  # No guardrail
        )

        # Invoke planner
        try:
            client.invoke_planner(
                user_question="test question",
                env="prod",
                region="us-west-2",
            )
        except Exception:
            pass

        # Verify guardrail parameters were NOT passed
        call_args = mock_bedrock_client.invoke_model.call_args
        assert call_args is not None
        assert "guardrailIdentifier" not in call_args.kwargs
        assert "guardrailVersion" not in call_args.kwargs


class TestGuardrailBlocking:
    """Test guardrail blocking behavior."""

    @patch("agent.bedrock_client.boto3")
    def test_guardrail_block_via_header(self, mock_boto3):
        """Test detection of guardrail block via response header."""
        # Mock boto3 client
        mock_bedrock_client = Mock()
        mock_boto3.client.return_value = mock_bedrock_client

        # Mock response with guardrail intervention header
        mock_response = {
            "body": Mock(read=lambda: json.dumps({"content": [{"text": ""}]})),
            "ResponseMetadata": {
                "HTTPHeaders": {
                    "amazon-bedrock-guardrailAction": "GUARDRAIL_INTERVENED",
                }
            },
        }
        mock_bedrock_client.invoke_model.return_value = mock_response

        client = BedrockClient(
            region="us-west-2",
            guardrail_id="test-guardrail-id",
            guardrail_version="1",
        )

        # Should raise GuardrailBlockedException
        with pytest.raises(GuardrailBlockedException) as exc_info:
            client.invoke_planner(
                user_question="malicious prompt",
                env="prod",
                region="us-west-2",
            )

        assert exc_info.value.intervention_type == "BLOCKED"
        assert "guardrail" in str(exc_info.value).lower()

    @patch("agent.bedrock_client.boto3")
    def test_guardrail_block_via_validation_exception(self, mock_boto3):
        """Test detection of guardrail block via ValidationException."""
        from botocore.exceptions import ClientError

        # Mock boto3 client
        mock_bedrock_client = Mock()
        mock_boto3.client.return_value = mock_bedrock_client

        # Mock ValidationException with guardrail message
        error_response = {
            "Error": {
                "Code": "ValidationException",
                "Message": "Guardrail blocked the request",
            }
        }
        mock_bedrock_client.invoke_model.side_effect = ClientError(
            error_response, "invoke_model"
        )

        client = BedrockClient(
            region="us-west-2",
            guardrail_id="test-guardrail-id",
            guardrail_version="1",
        )

        # Should raise GuardrailBlockedException
        with pytest.raises(GuardrailBlockedException) as exc_info:
            client.invoke_planner(
                user_question="malicious prompt",
                env="prod",
                region="us-west-2",
            )

        assert exc_info.value.intervention_type == "BLOCKED"


class TestSafeFallback:
    """Test safe fallback behavior when guardrails block content."""

    @patch("agent.bedrock_client.boto3")
    def test_planner_returns_safe_json_on_block(self, mock_boto3):
        """Test that planner returns safe JSON error when blocked."""
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
        mock_bedrock_client.invoke_model.side_effect = ClientError(
            error_response, "invoke_model"
        )

        client = BedrockClient(
            region="us-west-2",
            guardrail_id="test-guardrail-id",
            guardrail_version="1",
        )

        # Should return safe JSON error (not raise)
        result = client.invoke_planner(
            user_question="malicious prompt",
            env="prod",
            region="us-west-2",
        )

        # Verify it's valid JSON with error structure
        result_dict = json.loads(result)
        assert "error" in result_dict
        assert result_dict["error"] == "guardrail_blocked"
        assert "message" in result_dict

    @patch("agent.bedrock_client.boto3")
    def test_explainer_returns_safe_message_on_block(self, mock_boto3):
        """Test that explainer returns safe refusal message when blocked."""
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
        mock_bedrock_client.invoke_model.side_effect = ClientError(
            error_response, "invoke_model"
        )

        client = BedrockClient(
            region="us-west-2",
            guardrail_id="test-guardrail-id",
            guardrail_version="1",
        )

        # Should return safe refusal message (not raise)
        result = client.invoke_explainer(
            findings=[{"rule": "test", "status": "NON_COMPLIANT"}],
            context="test context",
        )

        # Verify it's a safe message
        assert "unable to generate explanation" in result.lower()
        assert "security restrictions" in result.lower()

    @patch("agent.bedrock_client.boto3")
    def test_no_crash_on_guardrail_intervention(self, mock_boto3):
        """Test that guardrail intervention never crashes the system."""
        from botocore.exceptions import ClientError

        # Mock boto3 client
        mock_bedrock_client = Mock()
        mock_boto3.client.return_value = mock_bedrock_client

        # Mock various guardrail block scenarios
        error_response = {
            "Error": {
                "Code": "ValidationException",
                "Message": "Guardrail blocked the request",
            }
        }
        mock_bedrock_client.invoke_model.side_effect = ClientError(
            error_response, "invoke_model"
        )

        client = BedrockClient(
            region="us-west-2",
            guardrail_id="test-guardrail-id",
            guardrail_version="1",
        )

        # Both should return safe responses without crashing
        planner_result = client.invoke_planner(
            user_question="test",
            env="prod",
            region="us-west-2",
        )
        assert planner_result is not None

        explainer_result = client.invoke_explainer(findings=[], context=None)
        assert explainer_result is not None


class TestEndToEndIntegration:
    """Test end-to-end integration with guardrails."""

    @patch("agent.bedrock_client.boto3")
    def test_successful_invocation_with_guardrails(self, mock_boto3):
        """Test successful invocation when guardrails allow content."""
        # Mock boto3 client
        mock_bedrock_client = Mock()
        mock_boto3.client.return_value = mock_bedrock_client

        # Mock successful response (no block)
        mock_response = {
            "body": Mock(
                read=lambda: json.dumps({
                    "content": [{"text": '{"scope": "test", "env": "prod"}'}]
                })
            ),
            "ResponseMetadata": {"HTTPHeaders": {}},
        }
        mock_bedrock_client.invoke_model.return_value = mock_response

        client = BedrockClient(
            region="us-west-2",
            guardrail_id="test-guardrail-id",
            guardrail_version="1",
        )

        # Should succeed
        result = client.invoke_planner(
            user_question="legitimate question",
            env="prod",
            region="us-west-2",
        )

        assert result is not None
        assert "scope" in result

    def test_create_client_from_settings(self):
        """Test creating client with settings defaults."""
        from agent.bedrock_client import create_bedrock_client

        # Should not raise
        client = create_bedrock_client()
        assert client is not None
        assert isinstance(client, BedrockClient)
