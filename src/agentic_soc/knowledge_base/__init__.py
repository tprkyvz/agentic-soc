"""
knowledge_base/__init__.py – Knowledge Base paketi.
"""

from .schemas import AttackCase, AttackType, Severity
from .storage import save_case, save_cases, query_similar, count_cases
from .retriever import find_similar_cases, format_kb_context
from .embeddings import embed_text, check_embedding_model

__all__ = [
    "AttackCase", "AttackType", "Severity",
    "save_case", "save_cases", "query_similar", "count_cases",
    "find_similar_cases", "format_kb_context",
    "embed_text", "check_embedding_model",
]
