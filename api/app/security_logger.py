"""Security event logging for regression tracking."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .config import settings


class SecurityLogger:
    """Logs security events to JSONL for regression tracking."""

    def __init__(self, log_path: str) -> None:
        """
        Initialize security logger.

        Args:
            log_path: Path to security log file (JSONL format)
        """
        self.log_path = Path(log_path)
        self._ensure_log_directory()

    def _ensure_log_directory(self) -> None:
        """Create log directory if it doesn't exist."""
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def log_event(
        self,
        event_type: str,
        run_id: Optional[str] = None,
        risk_level: str = "low",
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        """
        Log a security event.

        Args:
            event_type: Type of security event (e.g., "prompt_injection_suspected")
            run_id: Optional run ID for correlation
            risk_level: Risk level (low, medium, high)
            details: Additional event details
        """
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "risk_level": risk_level,
        }

        if run_id:
            event["run_id"] = run_id

        if details:
            event["details"] = details

        # Append to JSONL file
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")

    def log_prompt_injection_attempt(
        self,
        run_id: Optional[str],
        matched_pattern: str,
        matched_text: str,
        prompt_preview: str,
    ) -> None:
        """
        Log a prompt injection attempt.

        Args:
            run_id: Run ID for correlation
            matched_pattern: Regex pattern that matched
            matched_text: Text that matched the pattern
            prompt_preview: Preview of the prompt (first 200 chars)
        """
        self.log_event(
            event_type="prompt_injection_suspected",
            run_id=run_id,
            risk_level="medium",
            details={
                "matched_pattern": matched_pattern,
                "matched_text": matched_text,
                "prompt_preview": prompt_preview[:200],
            },
        )

    def log_guardrail_block(
        self,
        run_id: Optional[str],
        intervention_type: str,
        message: str,
    ) -> None:
        """
        Log a Bedrock Guardrails block event.

        Args:
            run_id: Run ID for correlation
            intervention_type: Type of guardrail intervention
            message: Block message
        """
        self.log_event(
            event_type="guardrail_blocked",
            run_id=run_id,
            risk_level="high",
            details={
                "intervention_type": intervention_type,
                "message": message,
            },
        )

    def log_rate_limit_exceeded(
        self,
        client_id: str,
        request_count: int,
    ) -> None:
        """
        Log a rate limit exceeded event.

        Args:
            client_id: Client identifier
            request_count: Number of requests in window
        """
        self.log_event(
            event_type="rate_limit_exceeded",
            run_id=None,
            risk_level="low",
            details={
                "client_id": client_id,
                "request_count": request_count,
            },
        )

    def log_planner_json_repaired(
        self,
        run_id: Optional[str],
        original_error: str,
        repair_successful: bool,
    ) -> None:
        """
        Log a planner JSON repair attempt.

        Args:
            run_id: Run ID for correlation
            original_error: Original validation error
            repair_successful: Whether repair succeeded
        """
        self.log_event(
            event_type="planner_json_repaired",
            run_id=run_id,
            risk_level="medium",
            details={
                "original_error": original_error[:500],  # Truncate
                "repair_successful": repair_successful,
            },
        )

    def log_fallback_invoked(
        self,
        run_id: Optional[str],
        reason: str,
        fallback_type: str = "plan",
    ) -> None:
        """
        Log a fallback invocation.

        Args:
            run_id: Run ID for correlation
            reason: Reason for fallback
            fallback_type: Type of fallback (plan, explainer, etc.)
        """
        self.log_event(
            event_type="fallback_invoked",
            run_id=run_id,
            risk_level="medium",
            details={
                "reason": reason[:500],  # Truncate
                "fallback_type": fallback_type,
            },
        )

    def log_output_guard_stripped(
        self,
        run_id: Optional[str],
        stripped_count: int,
        stripped_types: list[str],
    ) -> None:
        """
        Log output guard stripping hallucinated content.

        Args:
            run_id: Run ID for correlation
            stripped_count: Number of items stripped
            stripped_types: Types of items stripped
        """
        self.log_event(
            event_type="output_guard_stripped",
            run_id=run_id,
            risk_level="high",
            details={
                "stripped_count": stripped_count,
                "stripped_types": stripped_types,
            },
        )


# Global security logger instance
security_logger = SecurityLogger(log_path=settings.security_log_path)
