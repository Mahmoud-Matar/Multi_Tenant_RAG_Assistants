"""Typed contracts shared by the RAG pipeline modules."""

from __future__ import annotations

from dataclasses import dataclass

from pydantic import BaseModel, Field


@dataclass(frozen=True)
class SecurityContext:
    user_id: int
    tenant_id: int
    tenant_key: str
    role: str
    access_scopes: tuple[str, ...]


@dataclass(frozen=True)
class RetrievedChunk:
    text: str
    distance: float
    document_id: str
    version_id: str
    chunk_id: str
    filename: str
    access_scope: str


class RAGQueryRequest(BaseModel):
    question: str = Field(min_length=2, max_length=2000)
    top_k: int | None = Field(default=None, ge=1, le=10)


class Citation(BaseModel):
    number: int
    document_id: str
    version_id: str
    chunk_id: str
    filename: str
    excerpt: str


class RAGQueryResponse(BaseModel):
    request_id: str
    answer: str
    citations: list[Citation]
    abstained: bool
    retrieved_chunk_count: int


@dataclass(frozen=True)
class GeneratedAnswer:
    answer: str
