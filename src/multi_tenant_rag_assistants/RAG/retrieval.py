"""Tenant-filtered vector retrieval with PostgreSQL authorization checks."""

from __future__ import annotations

import os
import re
from collections.abc import Callable

from langchain_openai import OpenAIEmbeddings
from rank_bm25 import BM25Okapi

from multi_tenant_rag_assistants.backend.database import connect
from multi_tenant_rag_assistants.backend.documents import (
    EMBEDDING_MODEL,
    chroma_collection,
)

from .models import RetrievedChunk, SecurityContext


DEFAULT_TOP_K = int(os.getenv("RAG_TOP_K", "5"))
MAX_DISTANCE = float(os.getenv("RAG_MAX_DISTANCE", "0.8"))
TOKEN_PATTERN = re.compile(r"[a-z0-9]+")


def embed_query(text: str, model: str = EMBEDDING_MODEL) -> list[float]:
    return OpenAIEmbeddings(model=model).embed_query(text)


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
        self.embedding_function = embedding_function
        self.connection_factory = connection_factory or connect
        self.max_distance = max_distance

    def retrieve(
        self, context: SecurityContext, question: str, top_k: int | None = None
    ) -> list[RetrievedChunk]:
        thresholds = context.contract["thresholds"]
        limit = min(
            top_k or thresholds.get("top_k", DEFAULT_TOP_K),
            thresholds.get("top_k", DEFAULT_TOP_K),
        )
        max_distance = thresholds.get("max_distance", self.max_distance)
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
                  AND v.contract_id = %s
                  AND v.embedding_model = %s
                  AND d.access_scope = ANY(%s)
                """,
                (
                    context.tenant_id,
                    context.contract_id,
                    context.contract["models"]["embedding_model"],
                    list(context.access_scopes),
                ),
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
                {"contract_id": {"$eq": context.contract_id}},
                {
                    "embedding_model": {
                        "$eq": context.contract["models"]["embedding_model"]
                    }
                },
            ]
        }
        query_embedding = (
            self.embedding_function(question)
            if self.embedding_function
            else embed_query(question, context.contract["models"]["embedding_model"])
        )
        result = self.collection_factory().query(
            query_embeddings=[query_embedding],
            n_results=max(limit * 8, limit),
            where=mandatory_filter,
            include=["documents", "metadatas", "distances"],
        )

        documents = (result.get("documents") or [[]])[0]
        metadatas = (result.get("metadatas") or [[]])[0]
        distances = (result.get("distances") or [[]])[0]
        candidates = []
        for text, metadata, distance in zip(documents, metadatas, distances):
            version_id = metadata.get("version_id")
            record = authorized.get(version_id)
            chunk_id = metadata.get("chunk_id")
            if (
                record is None
                or not isinstance(chunk_id, str)
                or metadata.get("tenant_id") != context.tenant_key
                or metadata.get("document_id") != record["document_id"]
                or metadata.get("access_scope") != record["access_scope"]
                or metadata.get("contract_id") != context.contract_id
                or metadata.get("embedding_model")
                != context.contract["models"]["embedding_model"]
                or float(distance) > max_distance
            ):
                continue
            candidates.append((text, metadata, float(distance), record))

        if not candidates:
            return []

        tokenized_documents = [
            TOKEN_PATTERN.findall(text.casefold()) for text, _, _, _ in candidates
        ]
        query_tokens = TOKEN_PATTERN.findall(question.casefold())
        bm25_scores = (
            BM25Okapi(tokenized_documents).get_scores(query_tokens)
            if query_tokens and any(tokenized_documents)
            else [0.0] * len(candidates)
        )
        query_token_set = set(query_tokens)
        overlap_scores = [
            len(query_token_set.intersection(tokens)) / max(len(query_token_set), 1)
            for tokens in tokenized_documents
        ]
        minimum_bm25 = min(bm25_scores, default=0.0)
        maximum_bm25 = max(bm25_scores, default=0.0)
        bm25_range = maximum_bm25 - minimum_bm25
        ranked = []
        for candidate, bm25_score, overlap_score in zip(
            candidates, bm25_scores, overlap_scores
        ):
            _, _, distance, _ = candidate
            vector_score = max(0.0, 1.0 - (distance / max_distance)) if max_distance else 0.0
            normalized_bm25 = (
                (float(bm25_score) - minimum_bm25) / bm25_range
                if bm25_range > 0
                else 0.0
            )
            # BM25 can collapse to equal or negative scores in very small candidate
            # sets. Token coverage keeps hybrid ranking useful in that case without
            # weakening the mandatory tenant and ACL filters above.
            lexical_score = 0.7 * normalized_bm25 + 0.3 * overlap_score
            ranked.append((0.65 * vector_score + 0.35 * lexical_score, candidate))
        ranked.sort(key=lambda item: (-item[0], item[1][2]))

        chunks: list[RetrievedChunk] = []
        seen: set[str] = set()
        for _, (text, metadata, distance, record) in ranked:
            chunk_id = metadata["chunk_id"]
            if chunk_id in seen:
                continue
            seen.add(chunk_id)
            chunks.append(
                RetrievedChunk(
                    text=text,
                    distance=float(distance),
                    document_id=record["document_id"],
                    version_id=metadata["version_id"],
                    chunk_id=chunk_id,
                    filename=record["original_filename"],
                    access_scope=record["access_scope"],
                )
            )
            if len(chunks) == limit:
                break
        return chunks
