"""Tenant-filtered vector retrieval with PostgreSQL authorization checks."""

from __future__ import annotations

import os
from collections.abc import Callable

from langchain_openai import OpenAIEmbeddings

from multi_tenant_rag_assistants.backend.database import connect
from multi_tenant_rag_assistants.backend.documents import (
    EMBEDDING_MODEL,
    chroma_collection,
)

from .models import RetrievedChunk, SecurityContext


DEFAULT_TOP_K = int(os.getenv("RAG_TOP_K", "5"))
MAX_DISTANCE = float(os.getenv("RAG_MAX_DISTANCE", "0.8"))


def embed_query(text: str) -> list[float]:
    return OpenAIEmbeddings(model=EMBEDDING_MODEL).embed_query(text)


class TenantRetriever:
    def __init__(
        self,
        *,
        collection_factory: Callable | None = None,
        embedding_function: Callable[[str], list[float]] | None = None,
        connection_factory: Callable | None = None,
        max_distance: float = MAX_DISTANCE,
    ) -> None:
        self.collection_factory = collection_factory or chroma_collection
        self.embedding_function = embedding_function or embed_query
        self.connection_factory = connection_factory or connect
        self.max_distance = max_distance

    def retrieve(
        self, context: SecurityContext, question: str, top_k: int | None = None
    ) -> list[RetrievedChunk]:
        limit = top_k or DEFAULT_TOP_K
        with self.connection_factory() as connection:
            authorized_rows = connection.execute(
                """
                SELECT v.id AS version_id, d.id AS document_id,
                       d.original_filename, d.access_scope
                FROM rag_document_versions v
                JOIN rag_documents d ON d.id = v.document_id
                WHERE d.tenant_id = %s AND d.status = 'active'
                  AND v.ingestion_status = 'active'
                  AND d.current_version = v.version_number
                  AND d.access_scope = ANY(%s)
                """,
                (context.tenant_id, list(context.access_scopes)),
            ).fetchall()

        authorized = {row["version_id"]: row for row in authorized_rows}
        if not authorized:
            return []

        # This filter is constructed exclusively from the trusted security context and
        # is sent with the query. There is never an unfiltered cross-tenant search.
        mandatory_filter = {
            "$and": [
                {"tenant_id": {"$eq": context.tenant_key}},
                {"status": {"$eq": "active"}},
                {"access_scope": {"$in": list(context.access_scopes)}},
            ]
        }
        result = self.collection_factory().query(
            query_embeddings=[self.embedding_function(question)],
            n_results=max(limit * 3, limit),
            where=mandatory_filter,
            include=["documents", "metadatas", "distances"],
        )

        chunks: list[RetrievedChunk] = []
        seen: set[str] = set()
        documents = (result.get("documents") or [[]])[0]
        metadatas = (result.get("metadatas") or [[]])[0]
        distances = (result.get("distances") or [[]])[0]
        for text, metadata, distance in zip(documents, metadatas, distances):
            version_id = metadata.get("version_id")
            record = authorized.get(version_id)
            chunk_id = metadata.get("chunk_id")
            if (
                record is None
                or not isinstance(chunk_id, str)
                or chunk_id in seen
                or metadata.get("tenant_id") != context.tenant_key
                or metadata.get("document_id") != record["document_id"]
                or metadata.get("access_scope") != record["access_scope"]
                or float(distance) > self.max_distance
            ):
                continue
            seen.add(chunk_id)
            chunks.append(
                RetrievedChunk(
                    text=text,
                    distance=float(distance),
                    document_id=record["document_id"],
                    version_id=version_id,
                    chunk_id=chunk_id,
                    filename=record["original_filename"],
                    access_scope=record["access_scope"],
                )
            )
            if len(chunks) == limit:
                break
        return chunks
