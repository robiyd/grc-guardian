"""Simple file-based storage for run metadata."""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

from .config import settings
from .logging_config import logger
from .schemas import RunMetadata


class RunStorage:
    """Simple file-based storage for compliance run metadata."""

    def __init__(self, storage_path: str) -> None:
        """
        Initialize run storage.

        Args:
            storage_path: Base directory for storing run metadata
        """
        self.storage_path = Path(storage_path)
        self._ensure_storage_dir()

    def _ensure_storage_dir(self) -> None:
        """Ensure storage directory exists."""
        try:
            self.storage_path.mkdir(parents=True, exist_ok=True)
            logger.info(f"Storage directory ready: {self.storage_path}")
        except Exception as e:
            logger.error(f"Failed to create storage directory: {e}")
            raise

    def _get_run_file_path(self, run_id: str) -> Path:
        """Get file path for a run."""
        return self.storage_path / f"{run_id}.json"

    def save_run(self, run_metadata: RunMetadata) -> None:
        """
        Save run metadata to storage.

        Args:
            run_metadata: Run metadata to save
        """
        run_file = self._get_run_file_path(run_metadata.run_id)

        try:
            # Convert to dict and handle datetime serialization
            data = run_metadata.model_dump(mode="json")

            with open(run_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)

            logger.info(
                "Run metadata saved",
                extra={"run_id": run_metadata.run_id, "file": str(run_file)},
            )
        except Exception as e:
            logger.error(
                f"Failed to save run metadata: {e}",
                extra={"run_id": run_metadata.run_id},
            )
            raise

    def get_run(self, run_id: str) -> Optional[RunMetadata]:
        """
        Retrieve run metadata from storage.

        Args:
            run_id: Run ID to retrieve

        Returns:
            RunMetadata if found, None otherwise
        """
        run_file = self._get_run_file_path(run_id)

        if not run_file.exists():
            logger.warning(f"Run not found: {run_id}")
            return None

        try:
            with open(run_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Parse datetime strings
            if "created_at" in data and isinstance(data["created_at"], str):
                data["created_at"] = datetime.fromisoformat(
                    data["created_at"].replace("Z", "+00:00")
                )
            if "completed_at" in data and data["completed_at"]:
                data["completed_at"] = datetime.fromisoformat(
                    data["completed_at"].replace("Z", "+00:00")
                )

            run_metadata = RunMetadata(**data)

            logger.info(
                "Run metadata retrieved",
                extra={"run_id": run_id, "file": str(run_file)},
            )

            return run_metadata

        except Exception as e:
            logger.error(f"Failed to retrieve run metadata: {e}", extra={"run_id": run_id})
            return None

    def update_run(self, run_id: str, **updates: any) -> bool:
        """
        Update run metadata.

        Args:
            run_id: Run ID to update
            **updates: Fields to update

        Returns:
            True if successful, False otherwise
        """
        run_metadata = self.get_run(run_id)
        if not run_metadata:
            return False

        try:
            # Update fields
            for key, value in updates.items():
                if hasattr(run_metadata, key):
                    setattr(run_metadata, key, value)

            self.save_run(run_metadata)
            logger.info(f"Run metadata updated: {run_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to update run metadata: {e}", extra={"run_id": run_id})
            return False


# Global storage instance
run_storage = RunStorage(storage_path=settings.storage_path)
