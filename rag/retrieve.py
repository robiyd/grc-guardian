"""RAG retrieval - keyword-based retrieval of control cards.

This module provides smart keyword retrieval with:
- TF-IDF-like relevance scoring
- Query preprocessing (stop words, lowercasing)
- Metadata extraction from markdown
- Security validations for RAG queries
"""

import re
from collections import Counter
from pathlib import Path
from typing import Any, Optional

# Stop words for query preprocessing
STOP_WORDS = {
    "the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for",
    "of", "with", "by", "from", "is", "are", "was", "were", "be", "been",
    "have", "has", "had", "do", "does", "did", "will", "would", "should",
    "could", "may", "might", "must", "can", "this", "that", "these", "those",
}

# Base path to control cards
CONTROLS_PATH = Path(__file__).parent / "data" / "controls"


class ControlCard:
    """Represents a parsed control card."""

    def __init__(
        self,
        control_id: str,
        framework: str,
        content: str,
        file_path: Path,
        metadata: dict[str, Any],
    ) -> None:
        """
        Initialize control card.

        Args:
            control_id: Control identifier (e.g., AC-2, CC6.1)
            framework: Framework name (NIST 800-53, SOC 2, ISO 27001)
            content: Full markdown content
            file_path: Path to markdown file
            metadata: Extracted metadata from card
        """
        self.control_id = control_id
        self.framework = framework
        self.content = content
        self.file_path = file_path
        self.metadata = metadata

    def get_excerpt(self, max_length: int = 500) -> str:
        """
        Get an excerpt from the control summary.

        Args:
            max_length: Maximum excerpt length

        Returns:
            Excerpt string
        """
        summary = self.metadata.get("summary", "")
        if len(summary) <= max_length:
            return summary

        # Truncate at word boundary
        truncated = summary[:max_length].rsplit(" ", 1)[0]
        return truncated + "..."


def parse_control_card(file_path: Path) -> Optional[ControlCard]:
    """
    Parse a control card markdown file.

    Args:
        file_path: Path to markdown file

    Returns:
        ControlCard object or None if parsing fails
    """
    try:
        content = file_path.read_text(encoding="utf-8")

        metadata = {}

        # Extract control ID
        control_id_match = re.search(r"^## Control ID\s*\n(.+)$", content, re.MULTILINE)
        control_id = control_id_match.group(1).strip() if control_id_match else "Unknown"

        # Extract framework
        framework_match = re.search(r"^## Framework\s*\n(.+)$", content, re.MULTILINE)
        framework = framework_match.group(1).strip() if framework_match else "Unknown"

        # Extract summary
        summary_match = re.search(
            r"^## Control Summary\s*\n(.*?)(?=^##|\Z)",
            content,
            re.MULTILINE | re.DOTALL,
        )
        summary = summary_match.group(1).strip() if summary_match else ""

        # Extract keywords
        keywords_match = re.search(r"^## Keywords\s*\n(.+)$", content, re.MULTILINE)
        keywords = []
        if keywords_match:
            keywords = [k.strip() for k in keywords_match.group(1).split(",")]

        # Extract AWS Config rules
        rules = []
        rules_section = re.search(
            r"^### AWS Config Rules Mapped\s*\n(.*?)(?=^###|^##|\Z)",
            content,
            re.MULTILINE | re.DOTALL,
        )
        if rules_section:
            rule_lines = rules_section.group(1).strip().split("\n")
            for line in rule_lines:
                if line.startswith("- `") and "`" in line[3:]:
                    rule = line.split("`")[1]
                    rules.append(rule)

        metadata = {
            "control_id": control_id,
            "framework": framework,
            "summary": summary,
            "keywords": keywords,
            "aws_config_rules": rules,
        }

        return ControlCard(
            control_id=control_id,
            framework=framework,
            content=content,
            file_path=file_path,
            metadata=metadata,
        )

    except Exception as e:
        print(f"Error parsing {file_path}: {e}")
        return None


def load_all_controls() -> list[ControlCard]:
    """
    Load all control cards from the data directory.

    Returns:
        List of ControlCard objects
    """
    controls = []

    if not CONTROLS_PATH.exists():
        print(f"Warning: Controls directory not found: {CONTROLS_PATH}")
        return controls

    for md_file in CONTROLS_PATH.glob("*.md"):
        card = parse_control_card(md_file)
        if card:
            controls.append(card)

    return controls


def preprocess_query(query: str) -> list[str]:
    """
    Preprocess query for keyword matching.

    Args:
        query: Raw query string

    Returns:
        List of processed query terms
    """
    # Lowercase
    query = query.lower()

    # Remove special characters except hyphens (for control IDs)
    query = re.sub(r"[^\w\s\-]", " ", query)

    # Split into words
    words = query.split()

    # Remove stop words
    words = [w for w in words if w not in STOP_WORDS and len(w) > 2]

    return words


def validate_query(query: str) -> tuple[bool, Optional[str]]:
    """
    Validate RAG query for security issues.

    Checks for:
    - Excessive length
    - Prompt injection patterns
    - Path traversal attempts

    Args:
        query: Query string

    Returns:
        Tuple of (is_valid, error_message)
    """
    # Check length
    if len(query) > 1000:
        return False, "Query too long (max 1000 characters)"

    # Check for path traversal
    if ".." in query or "/" in query or "\\" in query:
        return False, "Query contains suspicious path characters"

    # Check for prompt injection patterns
    injection_patterns = [
        r"ignore\s+previous",
        r"system\s*:",
        r"<\|.*?\|>",
        r"\[INST\]",
    ]

    for pattern in injection_patterns:
        if re.search(pattern, query, re.IGNORECASE):
            return False, "Query contains suspicious injection patterns"

    return True, None


def compute_relevance_score(card: ControlCard, query_terms: list[str]) -> float:
    """
    Compute relevance score for a control card.

    Uses TF-IDF-like scoring with:
    - Exact control ID match (highest weight)
    - Framework name match
    - Keyword matches
    - Content matches

    Args:
        card: ControlCard to score
        query_terms: Preprocessed query terms

    Returns:
        Relevance score (higher is better)
    """
    score = 0.0

    # Exact control ID match (highest weight)
    control_id_lower = card.control_id.lower()
    for term in query_terms:
        if term in control_id_lower:
            score += 10.0

    # Framework name match
    framework_lower = card.framework.lower()
    for term in query_terms:
        if term in framework_lower:
            score += 5.0

    # Keyword matches (high weight)
    keywords_lower = [k.lower() for k in card.metadata.get("keywords", [])]
    for term in query_terms:
        for keyword in keywords_lower:
            if term in keyword or keyword in term:
                score += 3.0

    # Summary content matches
    summary_lower = card.metadata.get("summary", "").lower()
    summary_words = preprocess_query(summary_lower)
    term_freq = Counter(summary_words)

    for term in query_terms:
        if term in term_freq:
            score += term_freq[term] * 0.5

    # AWS Config rule name matches
    rules = card.metadata.get("aws_config_rules", [])
    for term in query_terms:
        for rule in rules:
            if term in rule.lower():
                score += 2.0

    return score


def rag_retrieve(
    query: str,
    top_k: int = 3,
    min_score: float = 0.1,
) -> list[dict[str, Any]]:
    """
    Retrieve relevant control cards using keyword matching.

    Args:
        query: Query string (control ID or natural language)
        top_k: Maximum number of results to return
        min_score: Minimum relevance score threshold

    Returns:
        List of result dictionaries with structure:
        {
            "id": "NIST-800-53:AC-2",
            "framework": "NIST 800-53 Rev 5",
            "excerpt": "Control summary excerpt...",
            "source_path": "rag/data/controls/NIST-800-53-AC-2.md",
            "relevance_score": 15.5,
            "metadata": {...}
        }
    """
    # Validate query
    is_valid, error = validate_query(query)
    if not is_valid:
        print(f"Invalid RAG query: {error}")
        return []

    # Load controls
    controls = load_all_controls()

    if not controls:
        print("Warning: No control cards loaded")
        return []

    # Preprocess query
    query_terms = preprocess_query(query)

    if not query_terms:
        print("Warning: Query produced no searchable terms")
        return []

    # Score all controls
    scored_controls = []
    for card in controls:
        score = compute_relevance_score(card, query_terms)
        if score >= min_score:
            scored_controls.append((score, card))

    # Sort by score (descending)
    scored_controls.sort(reverse=True, key=lambda x: x[0])

    # Take top K
    top_controls = scored_controls[:top_k]

    # Format results
    results = []
    for score, card in top_controls:
        result = {
            "id": f"{card.framework}:{card.control_id}",
            "framework": card.framework,
            "excerpt": card.get_excerpt(500),
            "source_path": str(card.file_path.relative_to(Path.cwd())),
            "relevance_score": round(score, 2),
            "metadata": card.metadata,
        }
        results.append(result)

    return results


def retrieve_by_id(control_id: str) -> Optional[dict[str, Any]]:
    """
    Retrieve a specific control card by ID.

    Args:
        control_id: Control identifier (e.g., "AC-2", "CC6.1", "A.5.15")

    Returns:
        Result dictionary or None if not found
    """
    controls = load_all_controls()

    for card in controls:
        if card.control_id.lower() == control_id.lower():
            return {
                "id": f"{card.framework}:{card.control_id}",
                "framework": card.framework,
                "excerpt": card.get_excerpt(1000),  # Longer excerpt for direct lookup
                "source_path": str(card.file_path.relative_to(Path.cwd())),
                "relevance_score": 100.0,  # Perfect match
                "metadata": card.metadata,
            }

    return None


def list_all_controls() -> list[str]:
    """
    List all available control IDs.

    Returns:
        List of control IDs
    """
    controls = load_all_controls()
    return [f"{card.framework}:{card.control_id}" for card in controls]
