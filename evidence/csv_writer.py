"""CSV export for compliance findings.

Converts compliance findings to CSV format for auditor consumption.
"""

import csv
from datetime import datetime
from io import StringIO
from pathlib import Path
from typing import Any


def findings_to_csv(
    findings: list[dict[str, Any]],
    run_id: str,
    include_header: bool = True,
) -> str:
    """
    Convert findings to CSV format.

    Args:
        findings: List of finding dictionaries
        run_id: Run identifier
        include_header: Whether to include CSV header row

    Returns:
        CSV string with findings
    """
    # Define columns in deterministic order
    columns = [
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

    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=columns, extrasaction="ignore")

    if include_header:
        writer.writeheader()

    # Get current timestamp for findings without one
    default_timestamp = datetime.utcnow().isoformat() + "Z"

    for finding in findings:
        row = {
            "run_id": run_id,
            "resource_id": finding.get("resource_id", ""),
            "resource_type": finding.get("resource_type", ""),
            "rule_name": finding.get("rule", finding.get("rule_name", "")),
            "status": finding.get("compliance_type", finding.get("status", "")),
            "severity": _determine_severity(finding),
            "description": finding.get("annotation", finding.get("description", "")),
            "timestamp": finding.get("timestamp", default_timestamp),
            "region": finding.get("region", ""),
        }
        writer.writerow(row)

    return output.getvalue()


def _determine_severity(finding: dict[str, Any]) -> str:
    """
    Determine severity from finding.

    Args:
        finding: Finding dictionary

    Returns:
        Severity level (HIGH, MEDIUM, LOW)
    """
    # Check if severity is already present
    if "severity" in finding:
        return finding["severity"]

    # Determine from compliance_type
    compliance_type = finding.get("compliance_type", finding.get("status", ""))

    if compliance_type == "NON_COMPLIANT":
        return "HIGH"
    elif compliance_type == "COMPLIANT":
        return "LOW"
    elif compliance_type == "NOT_APPLICABLE":
        return "LOW"
    else:
        return "MEDIUM"


def write_csv_file(
    findings: list[dict[str, Any]],
    run_id: str,
    output_path: Path,
) -> None:
    """
    Write findings to CSV file.

    Args:
        findings: List of finding dictionaries
        run_id: Run identifier
        output_path: Path to output CSV file
    """
    csv_content = findings_to_csv(findings, run_id, include_header=True)

    with open(output_path, "w", encoding="utf-8", newline="") as f:
        f.write(csv_content)
