"""Tests for CSV evidence export."""

import csv
from io import StringIO
from pathlib import Path
import tempfile

import pytest

from evidence.csv_writer import findings_to_csv, write_csv_file, _determine_severity


def test_findings_to_csv_basic():
    """Test basic CSV generation with sample findings."""
    findings = [
        {
            "resource_id": "bucket-1",
            "resource_type": "AWS::S3::Bucket",
            "rule": "s3-bucket-public-read-prohibited",
            "compliance_type": "NON_COMPLIANT",
            "annotation": "Bucket allows public read access",
            "region": "us-west-2",
        },
        {
            "resource_id": "bucket-2",
            "resource_type": "AWS::S3::Bucket",
            "rule": "s3-bucket-server-side-encryption-enabled",
            "compliance_type": "COMPLIANT",
            "annotation": "Bucket has encryption enabled",
            "region": "us-west-2",
        },
    ]

    csv_content = findings_to_csv(findings, run_id="RUN-TEST-001", include_header=True)

    # Parse CSV
    csv_reader = csv.DictReader(StringIO(csv_content))
    rows = list(csv_reader)

    assert len(rows) == 2

    # Check first row
    assert rows[0]["run_id"] == "RUN-TEST-001"
    assert rows[0]["resource_id"] == "bucket-1"
    assert rows[0]["resource_type"] == "AWS::S3::Bucket"
    assert rows[0]["rule_name"] == "s3-bucket-public-read-prohibited"
    assert rows[0]["status"] == "NON_COMPLIANT"
    assert rows[0]["severity"] == "HIGH"
    assert rows[0]["description"] == "Bucket allows public read access"
    assert rows[0]["region"] == "us-west-2"

    # Check second row
    assert rows[1]["status"] == "COMPLIANT"
    assert rows[1]["severity"] == "LOW"


def test_csv_columns_deterministic():
    """Test that CSV columns are in deterministic order."""
    findings = [
        {
            "resource_id": "test-resource",
            "resource_type": "AWS::Test::Resource",
            "rule": "test-rule",
            "compliance_type": "NON_COMPLIANT",
        }
    ]

    csv_content = findings_to_csv(findings, run_id="RUN-TEST-002", include_header=True)

    # Extract header line
    header_line = csv_content.split("\n")[0]

    expected_columns = [
        "run_id",
        "resource_id",
        "resource_type",
        "rule_name",
        "status",
        "severity",
        "description",
        "timestamp",
        "region",
    ]

    assert header_line == ",".join(expected_columns)


def test_determine_severity_non_compliant():
    """Test severity determination for NON_COMPLIANT findings."""
    finding = {"compliance_type": "NON_COMPLIANT"}
    assert _determine_severity(finding) == "HIGH"


def test_determine_severity_compliant():
    """Test severity determination for COMPLIANT findings."""
    finding = {"compliance_type": "COMPLIANT"}
    assert _determine_severity(finding) == "LOW"


def test_determine_severity_not_applicable():
    """Test severity determination for NOT_APPLICABLE findings."""
    finding = {"compliance_type": "NOT_APPLICABLE"}
    assert _determine_severity(finding) == "LOW"


def test_determine_severity_explicit():
    """Test that explicit severity overrides computed severity."""
    finding = {
        "compliance_type": "NON_COMPLIANT",
        "severity": "MEDIUM",  # Explicit severity
    }
    assert _determine_severity(finding) == "MEDIUM"


def test_determine_severity_unknown():
    """Test severity determination for unknown status."""
    finding = {"compliance_type": "UNKNOWN"}
    assert _determine_severity(finding) == "MEDIUM"


def test_csv_handles_missing_fields():
    """Test CSV generation with missing optional fields."""
    findings = [
        {
            "resource_id": "minimal-resource",
            "rule": "minimal-rule",
            # Missing: resource_type, compliance_type, annotation, region, timestamp
        }
    ]

    csv_content = findings_to_csv(findings, run_id="RUN-TEST-003", include_header=True)

    csv_reader = csv.DictReader(StringIO(csv_content))
    rows = list(csv_reader)

    assert len(rows) == 1
    assert rows[0]["resource_id"] == "minimal-resource"
    assert rows[0]["rule_name"] == "minimal-rule"
    assert rows[0]["resource_type"] == ""
    assert rows[0]["description"] == ""
    assert rows[0]["region"] == ""
    assert rows[0]["timestamp"] != ""  # Should have default timestamp


def test_csv_no_header():
    """Test CSV generation without header row."""
    findings = [
        {
            "resource_id": "test-resource",
            "rule": "test-rule",
            "compliance_type": "COMPLIANT",
        }
    ]

    csv_content = findings_to_csv(findings, run_id="RUN-TEST-004", include_header=False)

    # Should not start with column names
    assert not csv_content.startswith("run_id,resource_id")

    # Should start with data
    assert csv_content.startswith("RUN-TEST-004,test-resource")


def test_write_csv_file():
    """Test writing CSV to file."""
    findings = [
        {
            "resource_id": "bucket-test",
            "resource_type": "AWS::S3::Bucket",
            "rule": "test-rule",
            "compliance_type": "NON_COMPLIANT",
            "annotation": "Test finding",
        }
    ]

    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "test_findings.csv"

        write_csv_file(findings, run_id="RUN-TEST-005", output_path=output_path)

        # Verify file was created
        assert output_path.exists()

        # Verify content
        with open(output_path, "r", encoding="utf-8") as f:
            content = f.read()

        assert "run_id,resource_id" in content
        assert "RUN-TEST-005" in content
        assert "bucket-test" in content


def test_csv_escapes_special_characters():
    """Test that CSV properly escapes commas and quotes."""
    findings = [
        {
            "resource_id": "resource-with-comma",
            "resource_type": "AWS::Test::Type",
            "rule": "test-rule",
            "compliance_type": "NON_COMPLIANT",
            "annotation": 'Description with "quotes" and, commas',
        }
    ]

    csv_content = findings_to_csv(findings, run_id="RUN-TEST-006", include_header=True)

    # Parse back to verify escaping worked
    csv_reader = csv.DictReader(StringIO(csv_content))
    rows = list(csv_reader)

    assert len(rows) == 1
    assert rows[0]["description"] == 'Description with "quotes" and, commas'


def test_csv_handles_unicode():
    """Test CSV generation with Unicode characters."""
    findings = [
        {
            "resource_id": "resource-unicode",
            "resource_type": "AWS::Test::Type",
            "rule": "test-rule",
            "compliance_type": "NON_COMPLIANT",
            "annotation": "Description with émojis 🔒 and speciål çhars",
            "region": "eu-cëntral-1",
        }
    ]

    csv_content = findings_to_csv(findings, run_id="RUN-TEST-007", include_header=True)

    # Parse back to verify Unicode handling
    csv_reader = csv.DictReader(StringIO(csv_content))
    rows = list(csv_reader)

    assert len(rows) == 1
    assert "émojis 🔒" in rows[0]["description"]
    assert rows[0]["region"] == "eu-cëntral-1"


def test_csv_empty_findings():
    """Test CSV generation with empty findings list."""
    findings = []

    csv_content = findings_to_csv(findings, run_id="RUN-TEST-008", include_header=True)

    # Should have header only
    lines = csv_content.strip().split("\n")
    assert len(lines) == 1
    assert lines[0].startswith("run_id,resource_id")


def test_csv_timestamp_consistency():
    """Test that findings without timestamp get a default timestamp."""
    findings = [
        {
            "resource_id": "resource-1",
            "rule": "test-rule",
            # No timestamp
        },
        {
            "resource_id": "resource-2",
            "rule": "test-rule",
            "timestamp": "2026-01-01T00:00:00Z",  # Explicit timestamp
        },
    ]

    csv_content = findings_to_csv(findings, run_id="RUN-TEST-009", include_header=True)

    csv_reader = csv.DictReader(StringIO(csv_content))
    rows = list(csv_reader)

    # First row should have auto-generated timestamp
    assert rows[0]["timestamp"] != ""
    assert "Z" in rows[0]["timestamp"]  # Should be UTC

    # Second row should have explicit timestamp
    assert rows[1]["timestamp"] == "2026-01-01T00:00:00Z"
