"""Evidence signer - HMAC-SHA256 signatures for manifest integrity.

This module provides HMAC-based signing for manifest files.
For MVP, we use HMAC-SHA256 with a secret key.

In production, this could be replaced with:
- AWS KMS for signing
- RSA/ECDSA with private keys
- Hardware Security Modules (HSM)
"""

import hmac
import hashlib
from typing import Any

from .manifest import get_manifest_canonical_json


def sign_manifest(manifest: dict[str, Any], signing_key: str) -> str:
    """
    Sign manifest with HMAC-SHA256.

    Args:
        manifest: Manifest dictionary
        signing_key: Secret signing key

    Returns:
        Hex string of HMAC signature
    """
    # Get canonical JSON representation
    canonical_json = get_manifest_canonical_json(manifest)

    # Compute HMAC-SHA256
    signature = hmac.new(
        signing_key.encode("utf-8"),
        canonical_json.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    return signature


def verify_signature(
    manifest: dict[str, Any], signature: str, signing_key: str
) -> bool:
    """
    Verify HMAC signature of manifest.

    Args:
        manifest: Manifest dictionary
        signature: Hex string of HMAC signature
        signing_key: Secret signing key

    Returns:
        True if signature is valid
    """
    expected_signature = sign_manifest(manifest, signing_key)

    # Use constant-time comparison to prevent timing attacks
    return hmac.compare_digest(signature, expected_signature)


def create_signature_metadata(
    signature: str, signing_key_id: str | None = None
) -> dict[str, Any]:
    """
    Create signature metadata for audit trails.

    Args:
        signature: HMAC signature hex string
        signing_key_id: Optional identifier for the signing key

    Returns:
        Signature metadata dictionary
    """
    metadata = {
        "algorithm": "HMAC-SHA256",
        "signature": signature,
    }

    if signing_key_id:
        metadata["key_id"] = signing_key_id

    return metadata


def sign_and_format(manifest: dict[str, Any], signing_key: str) -> str:
    """
    Sign manifest and return formatted signature string.

    The signature format includes:
    - Algorithm identifier
    - Hex signature

    Args:
        manifest: Manifest dictionary
        signing_key: Secret signing key

    Returns:
        Formatted signature string
    """
    signature = sign_manifest(manifest, signing_key)

    return f"HMAC-SHA256:{signature}"


def parse_signature(signature_string: str) -> tuple[str, str]:
    """
    Parse formatted signature string.

    Args:
        signature_string: Formatted signature (e.g., "HMAC-SHA256:abc123...")

    Returns:
        Tuple of (algorithm, signature_hex)

    Raises:
        ValueError: If signature format is invalid
    """
    if ":" not in signature_string:
        raise ValueError("Invalid signature format: missing algorithm separator")

    parts = signature_string.split(":", 1)
    if len(parts) != 2:
        raise ValueError("Invalid signature format")

    algorithm, signature_hex = parts

    if algorithm != "HMAC-SHA256":
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    return algorithm, signature_hex
