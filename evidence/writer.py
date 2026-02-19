"""Evidence writer - persist audit artifacts per RUN-ID.

This module writes compliance scan artifacts to local storage and optionally to S3:
- plan.json - The execution plan
- findings.json - All compliance findings
- report.json - Summary report
- manifest.json - SHA256 hashes of all artifacts
- manifest.sig - HMAC signature of manifest
"""

import json
from pathlib import Path
from typing import Any, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError


class EvidenceWriter:
    """Writer for compliance evidence artifacts."""

    def __init__(
        self,
        base_path: str,
        s3_bucket: Optional[str] = None,
        s3_region: str = "us-west-2",
    ) -> None:
        """
        Initialize evidence writer.

        Args:
            base_path: Local base path for evidence storage
            s3_bucket: Optional S3 bucket name for remote storage
            s3_region: AWS region for S3 bucket
        """
        self.base_path = Path(base_path)
        self.s3_bucket = s3_bucket
        self.s3_region = s3_region
        self.s3_client = None

        if self.s3_bucket:
            try:
                self.s3_client = boto3.client("s3", region_name=s3_region)
            except Exception as e:
                print(f"Warning: Failed to initialize S3 client: {e}")
                self.s3_client = None

    def _ensure_run_directory(self, run_id: str) -> Path:
        """
        Ensure run directory exists.

        Args:
            run_id: Unique run identifier

        Returns:
            Path to run directory
        """
        run_dir = self.base_path / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        return run_dir

    def _write_json_file(
        self, run_dir: Path, filename: str, data: Any, sort_keys: bool = True
    ) -> Path:
        """
        Write JSON data to file with deterministic formatting.

        Args:
            run_dir: Run directory path
            filename: Name of the file to write
            data: Data to serialize as JSON
            sort_keys: Whether to sort JSON keys (for determinism)

        Returns:
            Path to written file
        """
        file_path = run_dir / filename

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=sort_keys, ensure_ascii=False)
            f.write("\n")  # Ensure newline at end

        return file_path

    def _upload_to_s3(self, local_path: Path, run_id: str) -> Optional[str]:
        """
        Upload file to S3 bucket.

        Args:
            local_path: Local file path
            run_id: Run identifier

        Returns:
            S3 URI if successful, None otherwise
        """
        if not self.s3_client or not self.s3_bucket:
            return None

        try:
            # S3 key: runs/{run_id}/{filename}
            s3_key = f"runs/{run_id}/{local_path.name}"

            self.s3_client.upload_file(
                str(local_path),
                self.s3_bucket,
                s3_key,
                ExtraArgs={"ServerSideEncryption": "AES256"},
            )

            s3_uri = f"s3://{self.s3_bucket}/{s3_key}"
            print(f"Uploaded to S3: {s3_uri}")
            return s3_uri

        except (ClientError, BotoCoreError) as e:
            print(f"Warning: Failed to upload {local_path.name} to S3: {e}")
            return None

    def write_plan(self, run_id: str, plan: dict[str, Any]) -> tuple[Path, Optional[str]]:
        """
        Write plan.json artifact.

        Args:
            run_id: Run identifier
            plan: Plan dictionary

        Returns:
            Tuple of (local_path, s3_uri)
        """
        run_dir = self._ensure_run_directory(run_id)
        local_path = self._write_json_file(run_dir, "plan.json", plan, sort_keys=True)
        s3_uri = self._upload_to_s3(local_path, run_id)
        return local_path, s3_uri

    def write_findings(
        self, run_id: str, findings: list[dict[str, Any]]
    ) -> tuple[Path, Optional[str]]:
        """
        Write findings.json artifact.

        Args:
            run_id: Run identifier
            findings: List of finding dictionaries

        Returns:
            Tuple of (local_path, s3_uri)
        """
        run_dir = self._ensure_run_directory(run_id)

        # Sort findings for determinism (by resource_id, then rule)
        sorted_findings = sorted(
            findings, key=lambda f: (f.get("resource_id", ""), f.get("rule", ""))
        )

        findings_data = {
            "run_id": run_id,
            "total_findings": len(sorted_findings),
            "findings": sorted_findings,
        }

        local_path = self._write_json_file(
            run_dir, "findings.json", findings_data, sort_keys=True
        )
        s3_uri = self._upload_to_s3(local_path, run_id)
        return local_path, s3_uri

    def write_findings_csv(
        self, run_id: str, findings: list[dict[str, Any]]
    ) -> tuple[Optional[Path], Optional[str]]:
        """
        Write findings as CSV file for auditors.

        This method is safe - if CSV writing fails, it returns None
        and does not crash the overall process.

        Args:
            run_id: Run identifier
            findings: List of finding dictionaries

        Returns:
            Tuple of (local_path, s3_uri) or (None, None) if failed
        """
        try:
            from .csv_writer import write_csv_file

            run_dir = self._ensure_run_directory(run_id)
            csv_path = run_dir / "findings.csv"

            # Sort findings for determinism (same as JSON)
            sorted_findings = sorted(
                findings, key=lambda f: (f.get("resource_id", ""), f.get("rule", ""))
            )

            write_csv_file(sorted_findings, run_id, csv_path)

            s3_uri = self._upload_to_s3(csv_path, run_id)
            return csv_path, s3_uri

        except Exception as e:
            print(f"Warning: Failed to write CSV file: {e}")
            print("Continuing with JSON artifacts only.")
            return None, None

    def write_report(
        self, run_id: str, report: dict[str, Any]
    ) -> tuple[Path, Optional[str]]:
        """
        Write report.json artifact.

        Args:
            run_id: Run identifier
            report: Report dictionary

        Returns:
            Tuple of (local_path, s3_uri)
        """
        run_dir = self._ensure_run_directory(run_id)
        local_path = self._write_json_file(run_dir, "report.json", report, sort_keys=True)
        s3_uri = self._upload_to_s3(local_path, run_id)
        return local_path, s3_uri

    def write_manifest(
        self, run_id: str, manifest: dict[str, Any]
    ) -> tuple[Path, Optional[str]]:
        """
        Write manifest.json artifact.

        Args:
            run_id: Run identifier
            manifest: Manifest dictionary with file hashes

        Returns:
            Tuple of (local_path, s3_uri)
        """
        run_dir = self._ensure_run_directory(run_id)
        local_path = self._write_json_file(
            run_dir, "manifest.json", manifest, sort_keys=True
        )
        s3_uri = self._upload_to_s3(local_path, run_id)
        return local_path, s3_uri

    def write_signature(
        self, run_id: str, signature: str
    ) -> tuple[Path, Optional[str]]:
        """
        Write manifest.sig artifact.

        Args:
            run_id: Run identifier
            signature: HMAC signature hex string

        Returns:
            Tuple of (local_path, s3_uri)
        """
        run_dir = self._ensure_run_directory(run_id)
        sig_path = run_dir / "manifest.sig"

        with open(sig_path, "w", encoding="utf-8") as f:
            f.write(signature)
            f.write("\n")

        s3_uri = self._upload_to_s3(sig_path, run_id)
        return sig_path, s3_uri

    def write_guardrails_event(
        self,
        run_id: str,
        blocked: bool,
        stage: str,
        reason: str,
        guardrail_id: Optional[str] = None,
        guardrail_version: Optional[str] = None,
    ) -> tuple[Path, Optional[str]]:
        """
        Write guardrails_event.json artifact when guardrails block content.

        Args:
            run_id: Run identifier
            blocked: Whether content was blocked
            stage: Stage where block occurred (planner/explainer)
            reason: Reason for block
            guardrail_id: Guardrail ID if available
            guardrail_version: Guardrail version if available

        Returns:
            Tuple of (local_path, s3_uri)
        """
        run_dir = self._ensure_run_directory(run_id)

        event_data = {
            "run_id": run_id,
            "blocked": blocked,
            "stage": stage,
            "reason": reason,
        }

        if guardrail_id:
            event_data["guardrail_id"] = guardrail_id
        if guardrail_version:
            event_data["guardrail_version"] = guardrail_version

        local_path = self._write_json_file(
            run_dir, "guardrails_event.json", event_data, sort_keys=True
        )
        s3_uri = self._upload_to_s3(local_path, run_id)
        return local_path, s3_uri

    def get_run_directory(self, run_id: str) -> Path:
        """
        Get the path to a run's directory.

        Args:
            run_id: Run identifier

        Returns:
            Path to run directory
        """
        return self.base_path / run_id

    def run_exists(self, run_id: str) -> bool:
        """
        Check if a run directory exists.

        Args:
            run_id: Run identifier

        Returns:
            True if run directory exists
        """
        return self.get_run_directory(run_id).exists()

    def list_artifacts(self, run_id: str) -> list[str]:
        """
        List all artifacts in a run directory.

        Args:
            run_id: Run identifier

        Returns:
            List of artifact filenames
        """
        run_dir = self.get_run_directory(run_id)

        if not run_dir.exists():
            return []

        return sorted([f.name for f in run_dir.iterdir() if f.is_file()])
