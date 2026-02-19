"""Configuration management for GRC Guardian API."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # API Configuration
    api_title: str = "GRC Guardian API"
    api_version: str = "0.1.0"
    api_description: str = "Autonomous GRC Compliance Guardian API"

    # Security
    guardian_api_key: str = "dev-key-change-in-production"

    # Rate Limiting
    rate_limit_requests: int = 10
    rate_limit_window_seconds: int = 60

    # Input Validation
    max_prompt_size_bytes: int = 8192  # 8KB
    enable_prompt_injection_filter: bool = True

    # Storage
    storage_path: str = "/tmp/grc-guardian/runs"

    # Logging
    log_level: str = "INFO"
    json_logs: bool = True

    # Agent Configuration
    bedrock_region: str = "us-west-2"
    bedrock_model_id: str = "anthropic.claude-3-5-sonnet-20241022-v2:0"

    # Bedrock Guardrails (OWASP LLM01, LLM06 protection)
    bedrock_guardrail_id: str | None = None  # Set to enable guardrails
    bedrock_guardrail_version: str = "1"  # Published version (not DRAFT)

    # Security Logging
    security_log_path: str = "api/app/data/security_regressions.jsonl"

    # Evidence Configuration
    evidence_base_path: str = "api/app/data/runs"  # Local evidence storage
    evidence_s3_bucket: str | None = None  # Optional S3 bucket for evidence
    signing_key: str = "dev-signing-key-change-in-production"  # HMAC signing key
    evidence_version: str = "1.0.0"  # Evidence format version

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


# Global settings instance
settings = Settings()
