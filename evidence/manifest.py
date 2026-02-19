"""Manifest generator - create SHA256 hashes of evidence artifacts.

This module generates a manifest.json file containing:
- SHA256 hash of each artifact
- Metadata (timestamp, run_id, version)
- File sizes and names

The manifest ensures evidence integrity and enables audit trail verification.
"""

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any


def compute_file_sha256(file_path: Path) -> str:
    """
    Compute SHA256 hash of a file.

    Args:
        file_path: Path to file

    Returns:
        Hex string of SHA256 hash
    """
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        # Read in 8KB chunks for memory efficiency
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


def compute_string_sha256(content: str) -> str:
    """
    Compute SHA256 hash of a string.

    Args:
        content: String content

    Returns:
        Hex string of SHA256 hash
    """
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def generate_manifest(
    run_id: str,
    run_dir: Path,
    evidence_version: str = "1.0.0",
    additional_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Generate manifest with SHA256 hashes of all artifacts.

    Args:
        run_id: Run identifier
        run_dir: Path to run directory containing artifacts
        evidence_version: Evidence format version
        additional_metadata: Optional additional metadata to include

    Returns:
        Manifest dictionary with file hashes and metadata
    """
    # Expected artifact files (in deterministic order)
    artifact_files = [
        "plan.json",
        "findings.json",
        "findings.csv",  # CSV format for auditors
        "report.json",
        "guardrails_event.json",  # Optional, only present if guardrails blocked
    ]

    files = []
    total_size_bytes = 0

    # Compute hash for each artifact
    for filename in artifact_files:
        file_path = run_dir / filename

        if not file_path.exists():
            # Skip missing files (they may not all be present)
            continue

        file_size = file_path.stat().st_size
        file_hash = compute_file_sha256(file_path)

        files.append(
            {
                "filename": filename,
                "sha256": file_hash,
                "size_bytes": file_size,
            }
        )

        total_size_bytes += file_size

    # Generate manifest
    manifest = {
        "version": evidence_version,
        "run_id": run_id,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "files": files,
        "summary": {
            "total_files": len(files),
            "total_size_bytes": total_size_bytes,
        },
    }

    # Add additional metadata if provided
    if additional_metadata:
        manifest["metadata"] = additional_metadata

    return manifest


def verify_manifest(run_dir: Path, manifest: dict[str, Any]) -> tuple[bool, list[str]]:
    """
    Verify that file hashes match manifest.

    Args:
        run_dir: Path to run directory
        manifest: Manifest dictionary

    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    errors = []

    for file_entry in manifest.get("files", []):
        filename = file_entry["filename"]
        expected_hash = file_entry["sha256"]

        file_path = run_dir / filename

        if not file_path.exists():
            errors.append(f"File missing: {filename}")
            continue

        actual_hash = compute_file_sha256(file_path)

        if actual_hash != expected_hash:
            errors.append(
                f"Hash mismatch for {filename}: expected {expected_hash}, got {actual_hash}"
            )

    is_valid = len(errors) == 0
    return is_valid, errors


def get_manifest_canonical_json(manifest: dict[str, Any]) -> str:
    """
    Get canonical JSON representation of manifest.

    This ensures consistent formatting for signing:
    - Keys sorted alphabetically
    - No extra whitespace
    - Consistent encoding

    Args:
        manifest: Manifest dictionary

    Returns:
        Canonical JSON string
    """
    return json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_manifest_hash(manifest: dict[str, Any]) -> str:
    """
    Compute SHA256 hash of manifest itself.

    Uses canonical JSON representation for consistency.

    Args:
        manifest: Manifest dictionary

    Returns:
        Hex string of SHA256 hash
    """
    canonical_json = get_manifest_canonical_json(manifest)
    return compute_string_sha256(canonical_json)
