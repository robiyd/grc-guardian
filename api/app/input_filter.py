"""Input validation and prompt injection detection."""

import re
from typing import Optional

from fastapi import HTTPException, status

from .config import settings
from .logging_config import logger
from .security_logger import security_logger

# Basic prompt injection patterns (denylist)
INJECTION_PATTERNS = [
    r"ignore\s+(previous|all|above|prior)\s+(instructions|directions|commands)",
    r"disregard\s+(previous|all|above|prior)",
    r"forget\s+(everything|all|previous)",
    r"you\s+are\s+now\s+(a|an)\s+",
    r"system\s*:\s*",
    r"<\|.*?\|>",  # Special tokens
    r"###\s*instructions?\s*###",
    r"---\s*instructions?\s*---",
    r"\[SYSTEM\]",
    r"\[INST\]",
    r"<instructions?>",
    r"new\s+role\s*:",
    r"assistant\s+must\s+(now|always)",
    r"override\s+(settings|instructions|rules)",
    r"enable\s+developer\s+mode",
    r"jailbreak",
    r"sudo\s+mode",
]

# Compile patterns for efficiency
COMPILED_PATTERNS = [
    re.compile(pattern, re.IGNORECASE | re.MULTILINE) for pattern in INJECTION_PATTERNS
]


class RiskInfo:
    """Information about input risk assessment."""

    def __init__(
        self,
        has_risk: bool = False,
        risk_type: Optional[str] = None,
        risk_level: str = "none",
        matched_text: Optional[str] = None,
    ) -> None:
        """
        Initialize risk information.

        Args:
            has_risk: Whether risk was detected
            risk_type: Type of risk (e.g., "prompt_injection_suspected")
            risk_level: Risk level (none, low, medium, high)
            matched_text: Text that matched risk patterns
        """
        self.has_risk = has_risk
        self.risk_type = risk_type
        self.risk_level = risk_level
        self.matched_text = matched_text


class InputValidator:
    """Validates and filters input prompts."""

    def __init__(self, max_size_bytes: int, enable_injection_filter: bool) -> None:
        """
        Initialize input validator.

        Args:
            max_size_bytes: Maximum allowed prompt size in bytes
            enable_injection_filter: Whether to enable injection detection
        """
        self.max_size_bytes = max_size_bytes
        self.enable_injection_filter = enable_injection_filter

    def validate_prompt_size(self, prompt: str) -> None:
        """
        Validate prompt size.

        Args:
            prompt: User prompt to validate

        Raises:
            HTTPException: 413 if prompt exceeds size limit
        """
        prompt_bytes = len(prompt.encode("utf-8"))

        if prompt_bytes > self.max_size_bytes:
            logger.warning(
                "Prompt size limit exceeded",
                extra={
                    "prompt_bytes": prompt_bytes,
                    "max_bytes": self.max_size_bytes,
                },
            )
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Prompt too large. Maximum size: {self.max_size_bytes} bytes. "
                f"Received: {prompt_bytes} bytes.",
            )

    def detect_prompt_injection(self, prompt: str) -> Optional[str]:
        """
        Detect potential prompt injection attempts.

        Args:
            prompt: User prompt to check

        Returns:
            Matched pattern if injection detected, None otherwise
        """
        if not self.enable_injection_filter:
            return None

        for pattern in COMPILED_PATTERNS:
            match = pattern.search(prompt)
            if match:
                matched_text = match.group(0)
                logger.warning(
                    "Potential prompt injection detected",
                    extra={
                        "matched_pattern": pattern.pattern,
                        "matched_text": matched_text,
                    },
                )
                return matched_text

        return None

    def validate_with_risk(
        self, prompt: str, run_id: Optional[str] = None
    ) -> RiskInfo:
        """
        Validate prompt and return risk information without blocking.

        This method performs validation but returns risk information
        instead of raising exceptions, allowing downstream components
        (like Bedrock Guardrails) to make final decisions.

        Args:
            prompt: User prompt to validate
            run_id: Optional run ID for security logging

        Returns:
            RiskInfo object with risk assessment

        Raises:
            HTTPException: 413 if prompt exceeds size limit (always block)
        """
        # Always block if size limit exceeded (hard limit)
        self.validate_prompt_size(prompt)

        # Check for injection patterns (soft limit - flag but don't block)
        injection_match = self.detect_prompt_injection(prompt)

        if injection_match:
            # Log security event with run_id
            matched_pattern = None
            for pattern in COMPILED_PATTERNS:
                if pattern.search(prompt):
                    matched_pattern = pattern.pattern
                    break

            security_logger.log_prompt_injection_attempt(
                run_id=run_id,
                matched_pattern=matched_pattern or "unknown",
                matched_text=injection_match,
                prompt_preview=prompt[:200],
            )

            logger.warning(
                "Prompt injection risk detected",
                extra={
                    "run_id": run_id,
                    "matched_text": injection_match,
                    "action": "flagged",
                },
            )

            return RiskInfo(
                has_risk=True,
                risk_type="prompt_injection_suspected",
                risk_level="medium",
                matched_text=injection_match,
            )

        logger.debug(
            "Input validation passed with no risk",
            extra={"prompt_length": len(prompt), "run_id": run_id},
        )

        return RiskInfo(has_risk=False, risk_level="none")

    def validate(self, prompt: str) -> None:
        """
        Validate prompt for size and injection attempts.

        Args:
            prompt: User prompt to validate

        Raises:
            HTTPException: 413 if too large, 400 if injection detected
        """
        # Check size
        self.validate_prompt_size(prompt)

        # Check for injection
        injection_match = self.detect_prompt_injection(prompt)
        if injection_match:
            logger.warning(
                "Blocking potential prompt injection",
                extra={"matched_text": injection_match},
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Potential prompt injection detected. "
                "Please rephrase your request without instructional overrides.",
            )

        logger.debug("Input validation passed", extra={"prompt_length": len(prompt)})


# Global input validator instance
input_validator = InputValidator(
    max_size_bytes=settings.max_prompt_size_bytes,
    enable_injection_filter=settings.enable_prompt_injection_filter,
)
