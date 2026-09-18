from __future__ import annotations
from dataclasses import dataclass

@dataclass(frozen=True)
class KnowledgeArticle:
    id: str
    title: str
    summary: str
    content: str
    category: str = "general"
    tags: tuple[str, ...] = ()
