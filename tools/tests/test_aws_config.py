"""Tests for AWS Config evaluator with mocked boto3 responses."""

from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber

from tools.aws_config import (
    aws_config_eval,
    aws_config_eval_multi,
    create_config_client,
    get_rule_compliance_summary,
)
from tools.tool_contracts import Finding


class TestAWSConfigEval:
    """Test aws_config_eval function with mocked responses."""

    def test_eval_returns_normalized_findings(self):
        """Test that evaluation returns normalized findings."""
        # Create mock client
        mock_client = MagicMock()

        # Mock describe_config_rules response
        mock_client.describe_config_rules.return_value = {
            "ConfigRules": [
                {
                    "ConfigRuleArn": "arn:aws:config:us-west-2:123456789012:config-rule/config-rule-abcdef",
                    "ConfigRuleName": "s3-bucket-public-read-prohibited",
                }
            ]
        }

        # Mock get_compliance_details_by_config_rule response
        mock_client.get_compliance_details_by_config_rule.return_value = {
            "EvaluationResults": [
                {
                    "EvaluationResultIdentifier": {
                        "EvaluationResultQualifier": {
                            "ResourceType": "AWS::S3::Bucket",
                            "ResourceId": "my-test-bucket",
                        }
                    },
                    "ComplianceType": "NON_COMPLIANT",
                    "ConfigRuleInvokedTime": datetime(2024, 1, 15, 10, 30, 0),
                    "Annotation": "Bucket allows public read access",
                },
                {
                    "EvaluationResultIdentifier": {
                        "EvaluationResultQualifier": {
                            "ResourceType": "AWS::S3::Bucket",
                            "ResourceId": "my-private-bucket",
                        }
                    },
                    "ComplianceType": "COMPLIANT",
                    "ConfigRuleInvokedTime": datetime(2024, 1, 15, 10, 30, 0),
                },
            ]
        }

        # Call function
        findings = aws_config_eval(
            rule_name="s3-bucket-public-read-prohibited",
            region="us-west-2",
            config_client=mock_client,
        )

        # Assertions
        assert len(findings) == 2
        assert all(isinstance(f, dict) for f in findings)

        # Check first finding (non-compliant)
        finding1 = findings[1]  # Sorted, so private bucket comes first
        assert finding1["rule"] == "s3-bucket-public-read-prohibited"
        assert finding1["compliance_type"] == "COMPLIANT"
        assert finding1["resource_type"] == "AWS::S3::Bucket"
        assert finding1["resource_id"] == "my-private-bucket"
        assert "timestamp" in finding1
        assert finding1["evidence"]["source"] == "aws_config"
        assert finding1["evidence"]["region"] == "us-west-2"

    def test_eval_handles_pagination(self):
        """Test that evaluation handles pagination correctly."""
        mock_client = MagicMock()

        # Mock describe_config_rules
        mock_client.describe_config_rules.return_value = {"ConfigRules": []}

        # Mock paginated responses
        mock_client.get_compliance_details_by_config_rule.side_effect = [
            {
                "EvaluationResults": [
                    {
                        "EvaluationResultIdentifier": {
                            "EvaluationResultQualifier": {
                                "ResourceType": "AWS::S3::Bucket",
                                "ResourceId": "bucket-1",
                            }
                        },
                        "ComplianceType": "COMPLIANT",
                        "ConfigRuleInvokedTime": datetime(2024, 1, 15, 10, 0, 0),
                    }
                ],
                "NextToken": "token123",
            },
            {
                "EvaluationResults": [
                    {
                        "EvaluationResultIdentifier": {
                            "EvaluationResultQualifier": {
                                "ResourceType": "AWS::S3::Bucket",
                                "ResourceId": "bucket-2",
                            }
                        },
                        "ComplianceType": "NON_COMPLIANT",
                        "ConfigRuleInvokedTime": datetime(2024, 1, 15, 10, 0, 0),
                    }
                ],
            },
        ]

        findings = aws_config_eval(
            rule_name="test-rule",
            region="us-west-2",
            config_client=mock_client,
        )

        # Should have findings from both pages
        assert len(findings) == 2
        assert mock_client.get_compliance_details_by_config_rule.call_count == 2

    def test_eval_filters_by_resource_type(self):
        """Test that evaluation filters by resource type."""
        mock_client = MagicMock()
        mock_client.describe_config_rules.return_value = {"ConfigRules": []}

        mock_client.get_compliance_details_by_config_rule.return_value = {
            "EvaluationResults": [
                {
                    "EvaluationResultIdentifier": {
                        "EvaluationResultQualifier": {
                            "ResourceType": "AWS::S3::Bucket",
                            "ResourceId": "my-bucket",
                        }
                    },
                    "ComplianceType": "COMPLIANT",
                    "ConfigRuleInvokedTime": datetime(2024, 1, 15, 10, 0, 0),
                },
                {
                    "EvaluationResultIdentifier": {
                        "EvaluationResultQualifier": {
                            "ResourceType": "AWS::IAM::User",
                            "ResourceId": "my-user",
                        }
                    },
                    "ComplianceType": "NON_COMPLIANT",
                    "ConfigRuleInvokedTime": datetime(2024, 1, 15, 10, 0, 0),
                },
            ]
        }

        # Filter by S3 buckets only
        findings = aws_config_eval(
            rule_name="test-rule",
            region="us-west-2",
            resource_type="AWS::S3::Bucket",
            config_client=mock_client,
        )

        # Should only return S3 bucket findings
        assert len(findings) == 1
        assert findings[0]["resource_type"] == "AWS::S3::Bucket"

    def test_eval_handles_missing_rule(self):
        """Test that evaluation handles missing rules gracefully."""
        mock_client = MagicMock()

        # Simulate NoSuchConfigRuleException
        error_response = {
            "Error": {
                "Code": "NoSuchConfigRuleException",
                "Message": "Config rule not found",
            }
        }
        mock_client.get_compliance_details_by_config_rule.side_effect = ClientError(
            error_response, "GetComplianceDetailsByConfigRule"
        )

        findings = aws_config_eval(
            rule_name="nonexistent-rule",
            region="us-west-2",
            config_client=mock_client,
        )

        # Should return empty list for missing rule
        assert findings == []

    def test_eval_sorts_findings_deterministically(self):
        """Test that findings are sorted deterministically."""
        mock_client = MagicMock()
        mock_client.describe_config_rules.return_value = {"ConfigRules": []}

        mock_client.get_compliance_details_by_config_rule.return_value = {
            "EvaluationResults": [
                {
                    "EvaluationResultIdentifier": {
                        "EvaluationResultQualifier": {
                            "ResourceType": "AWS::S3::Bucket",
                            "ResourceId": "zebra-bucket",
                        }
                    },
                    "ComplianceType": "COMPLIANT",
                    "ConfigRuleInvokedTime": datetime(2024, 1, 15, 10, 0, 0),
                },
                {
                    "EvaluationResultIdentifier": {
                        "EvaluationResultQualifier": {
                            "ResourceType": "AWS::S3::Bucket",
                            "ResourceId": "alpha-bucket",
                        }
                    },
                    "ComplianceType": "NON_COMPLIANT",
                    "ConfigRuleInvokedTime": datetime(2024, 1, 15, 10, 0, 0),
                },
            ]
        }

        findings = aws_config_eval(
            rule_name="test-rule",
            region="us-west-2",
            config_client=mock_client,
        )

        # Should be sorted by resource_id
        assert findings[0]["resource_id"] == "alpha-bucket"
        assert findings[1]["resource_id"] == "zebra-bucket"

    def test_eval_generates_default_annotation(self):
        """Test that default annotations are generated when missing."""
        mock_client = MagicMock()
        mock_client.describe_config_rules.return_value = {"ConfigRules": []}

        mock_client.get_compliance_details_by_config_rule.return_value = {
            "EvaluationResults": [
                {
                    "EvaluationResultIdentifier": {
                        "EvaluationResultQualifier": {
                            "ResourceType": "AWS::S3::Bucket",
                            "ResourceId": "test-bucket",
                        }
                    },
                    "ComplianceType": "NON_COMPLIANT",
                    "ConfigRuleInvokedTime": datetime(2024, 1, 15, 10, 0, 0),
                    # Note: No Annotation field
                }
            ]
        }

        findings = aws_config_eval(
            rule_name="test-rule",
            region="us-west-2",
            config_client=mock_client,
        )

        # Should generate default annotation
        assert findings[0]["annotation"] is not None
        assert "test-bucket" in findings[0]["annotation"]
        assert "failed" in findings[0]["annotation"].lower()


class TestAWSConfigEvalMulti:
    """Test aws_config_eval_multi function."""

    def test_eval_multi_combines_results(self):
        """Test that eval_multi combines results from multiple rules."""
        with patch("tools.aws_config.aws_config_eval") as mock_eval:
            # Mock findings for two rules
            mock_eval.side_effect = [
                [
                    {
                        "rule": "rule-1",
                        "compliance_type": "COMPLIANT",
                        "resource_type": "AWS::S3::Bucket",
                        "resource_id": "bucket-1",
                        "timestamp": "2024-01-15T10:00:00Z",
                        "annotation": "Test",
                        "evidence": {"source": "aws_config", "region": "us-west-2"},
                    }
                ],
                [
                    {
                        "rule": "rule-2",
                        "compliance_type": "NON_COMPLIANT",
                        "resource_type": "AWS::S3::Bucket",
                        "resource_id": "bucket-2",
                        "timestamp": "2024-01-15T10:00:00Z",
                        "annotation": "Test",
                        "evidence": {"source": "aws_config", "region": "us-west-2"},
                    }
                ],
            ]

            result = aws_config_eval_multi(
                rule_names=["rule-1", "rule-2"],
                region="us-west-2",
            )

            assert result["status"] == "success"
            assert len(result["findings"]) == 2
            assert result["metadata"]["rules_evaluated"] == 2
            assert result["metadata"]["rules_succeeded"] == 2

    def test_eval_multi_handles_partial_failures(self):
        """Test that eval_multi handles partial failures."""
        with patch("tools.aws_config.aws_config_eval") as mock_eval:
            # First rule succeeds, second fails
            mock_eval.side_effect = [
                [
                    {
                        "rule": "rule-1",
                        "compliance_type": "COMPLIANT",
                        "resource_type": "AWS::S3::Bucket",
                        "resource_id": "bucket-1",
                        "timestamp": "2024-01-15T10:00:00Z",
                        "annotation": "Test",
                        "evidence": {"source": "aws_config", "region": "us-west-2"},
                    }
                ],
                RuntimeError("Rule 2 failed"),
            ]

            result = aws_config_eval_multi(
                rule_names=["rule-1", "rule-2"],
                region="us-west-2",
            )

            assert result["status"] == "error"
            assert len(result["findings"]) == 1  # Only successful rule's findings
            assert result["error"] is not None
            assert "rule-2" in result["error"]


class TestComplianceSummary:
    """Test get_rule_compliance_summary function."""

    def test_summary_counts_compliance_types(self):
        """Test that summary correctly counts compliance types."""
        with patch("tools.aws_config.aws_config_eval") as mock_eval:
            mock_eval.return_value = [
                {
                    "rule": "test-rule",
                    "compliance_type": "COMPLIANT",
                    "resource_type": "AWS::S3::Bucket",
                    "resource_id": "bucket-1",
                    "timestamp": "2024-01-15T10:00:00Z",
                    "annotation": "Test",
                    "evidence": {"source": "aws_config", "region": "us-west-2"},
                },
                {
                    "rule": "test-rule",
                    "compliance_type": "COMPLIANT",
                    "resource_type": "AWS::S3::Bucket",
                    "resource_id": "bucket-2",
                    "timestamp": "2024-01-15T10:00:00Z",
                    "annotation": "Test",
                    "evidence": {"source": "aws_config", "region": "us-west-2"},
                },
                {
                    "rule": "test-rule",
                    "compliance_type": "NON_COMPLIANT",
                    "resource_type": "AWS::S3::Bucket",
                    "resource_id": "bucket-3",
                    "timestamp": "2024-01-15T10:00:00Z",
                    "annotation": "Test",
                    "evidence": {"source": "aws_config", "region": "us-west-2"},
                },
            ]

            summary = get_rule_compliance_summary(
                rule_name="test-rule",
                region="us-west-2",
            )

            assert summary["COMPLIANT"] == 2
            assert summary["NON_COMPLIANT"] == 1
            assert summary["NOT_APPLICABLE"] == 0
            assert summary["INSUFFICIENT_DATA"] == 0
