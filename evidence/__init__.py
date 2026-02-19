"""GRC Guardian Evidence - Audit artifact persistence and signing.

This package provides:
- Evidence writer (local + S3)
- SHA256 manifest generation
- HMAC-SHA256 signing
- Verification utilities
"""

from .manifest import generate_manifest, verify_manifest
from .signer import sign_manifest, verify_signature
from .writer import EvidenceWriter

__all__ = [
    "EvidenceWriter",
    "generate_manifest",
    "verify_manifest",
    "sign_manifest",
    "verify_signature",
]

__version__ = "1.0.0"
