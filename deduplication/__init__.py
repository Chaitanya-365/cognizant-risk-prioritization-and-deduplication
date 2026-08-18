"""
Vulnerability Deduplication Package.
"""

from deduplication.engine import (
    DeduplicationEngine,
    DeduplicationResult,
    DuplicateGroup,
    deduplicate_findings,
)

__all__ = [
    "DeduplicationEngine",
    "DeduplicationResult",
    "DuplicateGroup",
    "deduplicate_findings",
]
