"""Tests for evidence module - writer, manifest, and signer."""

import json
import tempfile
from pathlib import Path

import pytest

from evidence.manifest import (
    compute_file_sha256,
    compute_manifest_hash,
    generate_manifest,
    get_manifest_canonical_json,
    verify_manifest,
)
from evidence.signer import sign_manifest, verify_signature
from evidence.writer import EvidenceWriter


class TestEvidenceWriter:
    """Test evidence writer functionality."""

    def test_write_local_creates_expected_files(self):
        """Test that writer creates all expected files locally."""
        with tempfile.TemporaryDirectory() as tmpdir:
            writer = EvidenceWriter(base_path=tmpdir)

            run_id = "RUN-20240117-123456-test"

            # Write artifacts
            plan = {"scope": "test", "env": "prod", "region": "us-west-2", "steps": []}
            findings = [
                {
                    "rule": "test-rule",
                    "compliance_type": "COMPLIANT",
                    "resource_id": "test-resource",
                }
            ]
            report = {"summary": "Test report", "compliant_count": 1}

            writer.write_plan(run_id, plan)
            writer.write_findings(run_id, findings)
            writer.write_report(run_id, report)

            # Verify files exist
            run_dir = writer.get_run_directory(run_id)
            assert (run_dir / "plan.json").exists()
            assert (run_dir / "findings.json").exists()
            assert (run_dir / "report.json").exists()

            # Verify content
            with open(run_dir / "plan.json") as f:
                loaded_plan = json.load(f)
                assert loaded_plan["scope"] == "test"

    def test_write_findings_sorts_deterministically(self):
        """Test that findings are sorted deterministically."""
        with tempfile.TemporaryDirectory() as tmpdir:
            writer = EvidenceWriter(base_path=tmpdir)

            run_id = "RUN-test-sort"

            # Write findings in random order
            findings = [
                {"rule": "rule-2", "resource_id": "zebra"},
                {"rule": "rule-1", "resource_id": "alpha"},
                {"rule": "rule-3", "resource_id": "beta"},
            ]

            writer.write_findings(run_id, findings)

            # Read back
            run_dir = writer.get_run_directory(run_id)
            with open(run_dir / "findings.json") as f:
                loaded = json.load(f)

            # Should be sorted by resource_id, then rule
            assert loaded["findings"][0]["resource_id"] == "alpha"
            assert loaded["findings"][1]["resource_id"] == "beta"
            assert loaded["findings"][2]["resource_id"] == "zebra"

    def test_run_exists_check(self):
        """Test run existence check."""
        with tempfile.TemporaryDirectory() as tmpdir:
            writer = EvidenceWriter(base_path=tmpdir)

            run_id = "RUN-existence-test"

            assert not writer.run_exists(run_id)

            writer.write_plan(run_id, {"test": "data"})

            assert writer.run_exists(run_id)

    def test_list_artifacts(self):
        """Test listing artifacts in a run."""
        with tempfile.TemporaryDirectory() as tmpdir:
            writer = EvidenceWriter(base_path=tmpdir)

            run_id = "RUN-list-test"

            writer.write_plan(run_id, {})
            writer.write_findings(run_id, [])
            writer.write_report(run_id, {})

            artifacts = writer.list_artifacts(run_id)

            # Should be sorted alphabetically
            assert artifacts == ["findings.json", "plan.json", "report.json"]


class TestManifest:
    """Test manifest generation and verification."""

    def test_manifest_hashes_stable(self):
        """Test that manifest hashes are stable for same content."""
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)

            # Write test file
            test_file = run_dir / "plan.json"
            with open(test_file, "w") as f:
                json.dump({"test": "data"}, f, sort_keys=True)

            # Compute hash twice
            hash1 = compute_file_sha256(test_file)
            hash2 = compute_file_sha256(test_file)

            assert hash1 == hash2

            # Different content should produce different hash
            with open(test_file, "w") as f:
                json.dump({"test": "different"}, f, sort_keys=True)

            hash3 = compute_file_sha256(test_file)
            assert hash3 != hash1

    def test_manifest_includes_all_files(self):
        """Test that manifest includes all expected files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            run_id = "RUN-manifest-test"

            # Create test files
            for filename in ["plan.json", "findings.json", "report.json"]:
                with open(run_dir / filename, "w") as f:
                    json.dump({"file": filename}, f)

            # Generate manifest
            manifest = generate_manifest(run_id, run_dir, evidence_version="1.0.0")

            # Check structure
            assert manifest["version"] == "1.0.0"
            assert manifest["run_id"] == run_id
            assert "timestamp" in manifest
            assert len(manifest["files"]) == 3

            # Check each file has required fields
            for file_entry in manifest["files"]:
                assert "filename" in file_entry
                assert "sha256" in file_entry
                assert "size_bytes" in file_entry
                assert len(file_entry["sha256"]) == 64  # SHA256 is 64 hex chars

    def test_manifest_verification_success(self):
        """Test that manifest verification succeeds for valid files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)

            # Create test file
            test_file = run_dir / "plan.json"
            with open(test_file, "w") as f:
                json.dump({"test": "data"}, f)

            # Generate manifest
            manifest = generate_manifest("RUN-test", run_dir)

            # Verify should succeed
            is_valid, errors = verify_manifest(run_dir, manifest)
            assert is_valid
            assert len(errors) == 0

    def test_manifest_verification_detects_tampering(self):
        """Test that manifest verification detects file tampering."""
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)

            # Create and hash file
            test_file = run_dir / "plan.json"
            with open(test_file, "w") as f:
                json.dump({"test": "original"}, f)

            manifest = generate_manifest("RUN-test", run_dir)

            # Tamper with file
            with open(test_file, "w") as f:
                json.dump({"test": "tampered"}, f)

            # Verification should fail
            is_valid, errors = verify_manifest(run_dir, manifest)
            assert not is_valid
            assert len(errors) > 0
            assert "mismatch" in errors[0].lower()

    def test_canonical_json_is_deterministic(self):
        """Test that canonical JSON is deterministic."""
        manifest1 = {"z": 1, "a": 2, "m": 3}
        manifest2 = {"a": 2, "m": 3, "z": 1}  # Same data, different order

        json1 = get_manifest_canonical_json(manifest1)
        json2 = get_manifest_canonical_json(manifest2)

        # Should be identical (keys sorted)
        assert json1 == json2


class TestSigner:
    """Test manifest signing and verification."""

    def test_signature_is_deterministic(self):
        """Test that signatures are deterministic for same input."""
        manifest = {"run_id": "test", "files": []}
        signing_key = "test-key"

        sig1 = sign_manifest(manifest, signing_key)
        sig2 = sign_manifest(manifest, signing_key)

        assert sig1 == sig2

    def test_signature_verification_succeeds(self):
        """Test that valid signatures verify successfully."""
        manifest = {"run_id": "test", "version": "1.0.0"}
        signing_key = "secret-key"

        signature = sign_manifest(manifest, signing_key)
        is_valid = verify_signature(manifest, signature, signing_key)

        assert is_valid

    def test_signature_verification_fails_for_wrong_key(self):
        """Test that signature verification fails with wrong key."""
        manifest = {"run_id": "test"}
        signing_key = "correct-key"
        wrong_key = "wrong-key"

        signature = sign_manifest(manifest, signing_key)
        is_valid = verify_signature(manifest, signature, wrong_key)

        assert not is_valid

    def test_signature_verification_fails_for_tampered_manifest(self):
        """Test that signature verification fails for tampered manifest."""
        manifest = {"run_id": "test", "value": "original"}
        signing_key = "key"

        signature = sign_manifest(manifest, signing_key)

        # Tamper with manifest
        manifest["value"] = "tampered"

        is_valid = verify_signature(manifest, signature, signing_key)

        assert not is_valid

    def test_different_keys_produce_different_signatures(self):
        """Test that different keys produce different signatures."""
        manifest = {"test": "data"}

        sig1 = sign_manifest(manifest, "key1")
        sig2 = sign_manifest(manifest, "key2")

        assert sig1 != sig2


class TestIntegration:
    """Integration tests for complete evidence workflow."""

    def test_complete_evidence_workflow(self):
        """Test complete workflow: write -> manifest -> sign."""
        with tempfile.TemporaryDirectory() as tmpdir:
            writer = EvidenceWriter(base_path=tmpdir)
            run_id = "RUN-20240117-integration"
            signing_key = "integration-test-key"

            # Step 1: Write artifacts
            plan = {"scope": "integration", "env": "test", "region": "us-west-2", "steps": []}
            findings = [{"rule": "test", "compliance_type": "COMPLIANT", "resource_id": "r1"}]
            report = {"summary": "Integration test", "total": 1}

            writer.write_plan(run_id, plan)
            writer.write_findings(run_id, findings)
            writer.write_report(run_id, report)

            # Step 2: Generate manifest
            run_dir = writer.get_run_directory(run_id)
            manifest = generate_manifest(run_id, run_dir)

            assert len(manifest["files"]) == 3
            writer.write_manifest(run_id, manifest)

            # Step 3: Sign manifest
            signature = sign_manifest(manifest, signing_key)
            writer.write_signature(run_id, signature)

            # Step 4: Verify everything
            artifacts = writer.list_artifacts(run_id)
            expected = ["findings.json", "manifest.json", "manifest.sig", "plan.json", "report.json"]
            assert artifacts == expected

            # Verify manifest
            is_valid, errors = verify_manifest(run_dir, manifest)
            assert is_valid

            # Verify signature
            assert verify_signature(manifest, signature, signing_key)
