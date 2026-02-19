"""FastAPI dependency injection functions.

These functions create fresh objects per request, avoiding caching issues.
"""

from typing import Generator

from .config import settings
from .input_filter import InputValidator
from .output_filter import OutputFilter
from .rate_limit import SlidingWindowRateLimiter
from .security_logger import SecurityLogger
from .storage import RunStorage


def get_settings():
    """Get fresh settings instance."""
    from .config import settings
    return settings


def get_input_validator() -> InputValidator:
    """Create fresh input validator per request."""
    return InputValidator(
        max_size_bytes=settings.max_prompt_size_bytes,
        enable_injection_filter=settings.enable_prompt_injection_filter,
    )


def get_output_filter() -> OutputFilter:
    """Create fresh output filter per request."""
    return OutputFilter()


def get_rate_limiter() -> SlidingWindowRateLimiter:
    """Get rate limiter instance."""
    # Note: Rate limiter can be shared across requests since it maintains state
    # For a truly stateless approach, would need Redis or external store
    return SlidingWindowRateLimiter(
        max_requests=settings.rate_limit_requests,
        window_seconds=settings.rate_limit_window_seconds,
    )


def get_security_logger() -> SecurityLogger:
    """Create fresh security logger per request."""
    return SecurityLogger(log_path=settings.security_log_path)


def get_run_storage() -> RunStorage:
    """Create fresh run storage per request."""
    return RunStorage(storage_path=settings.storage_path)


def is_out_of_scope_quick(prompt: str) -> bool:
    """
    Quick pre-validation check for obvious non-compliance questions.

    This avoids unnecessary LLM calls for clearly out-of-scope questions.

    Args:
        prompt: User's question

    Returns:
        True if question is obviously out of scope, False otherwise
    """
    prompt_lower = prompt.lower()

    # Compliance keywords
    compliance_keywords = [
        "s3", "iam", "cloudtrail", "security", "compliance", "audit",
        "encryption", "mfa", "access", "config", "bucket", "policy",
        "rule", "finding", "control", "scan", "check", "evaluate",
        "nist", "soc2", "iso", "pci", "hipaa", "gdpr", "compliant",
        "non-compliant", "violation", "remediate", "posture", "aws",
    ]

    # Check if question has any compliance keywords
    has_compliance_keyword = any(kw in prompt_lower for kw in compliance_keywords)

    # Common non-compliance patterns
    non_compliance_patterns = [
        "weather", "temperature", "forecast", "time", "date",
        "how are you", "hello", "hi ", "hey ", "good morning",
        "what is", "who is", "where is", "when is", "why is",
        "how many ec2", "how many instance", "list ec2", "show ec2",
        "count ec2", "tell me about", "explain",
    ]

    is_likely_non_compliance = any(pattern in prompt_lower for pattern in non_compliance_patterns)

    # Only flag as out-of-scope if:
    # 1. Question is short (< 100 chars)
    # 2. Has non-compliance patterns
    # 3. Has no compliance keywords
    if len(prompt.strip()) < 100:
        return is_likely_non_compliance and not has_compliance_keyword

    return False
