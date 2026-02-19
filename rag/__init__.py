"""GRC Guardian RAG - Retrieval-Augmented Generation for control cards.

This package provides:
- Control card library (NIST, SOC 2, ISO 27001)
- Smart keyword retrieval with relevance scoring
- Query validation for RAG security
- Citation generation for compliance reports
"""

from .retrieve import (
    list_all_controls,
    load_all_controls,
    rag_retrieve,
    retrieve_by_id,
)

__all__ = [
    "rag_retrieve",
    "retrieve_by_id",
    "load_all_controls",
    "list_all_controls",
]

__version__ = "1.0.0"
