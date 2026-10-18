"""Privacy-conscious RAG query audit events."""

from __future__ import annotations

import hashlib
from uuid import uuid4

from psycopg.types.json import Jsonb

from multi_tenant_rag_assistants.backend.database import connect

from .models import SecurityContext


def write_query_audit(
    *,
    request_id: str,
    context: SecurityContext,
    question: str,
    outcome: str,
    retrieved_count: int,
    cited_count: int,
    latency_ms: int,
    details: dict | None = None,
) -> None:
    with connect() as connection:
        connection.execute(
            """
            INSERT INTO rag_query_audit
                (id, tenant_id, actor_id, query_hash, query_length, outcome,
                 retrieved_chunk_count, cited_chunk_count, latency_ms, details)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                request_id,
                context.tenant_id,
                context.user_id,
                hashlib.sha256(question.encode("utf-8")).hexdigest(),
                len(question),
                outcome,
                retrieved_count,
                cited_count,
                latency_ms,
                Jsonb(details or {}),
            ),
        )


def write_denied_query_audit(*, user: dict, question: str, reason: str) -> None:
    """Record an authorization denial without trusting tenant claims from the caller."""
    claimed_user_id = user.get("id")
    with connect() as connection:
        actor = None
        if isinstance(claimed_user_id, int):
            actor = connection.execute(
                "SELECT id, tenant_id FROM rag_users WHERE id = %s",
                (claimed_user_id,),
            ).fetchone()
        connection.execute(
            """
            INSERT INTO rag_query_audit
                (id, tenant_id, actor_id, query_hash, query_length, outcome, details)
            VALUES (%s, %s, %s, %s, %s, 'denied', %s)
            """,
            (
                f"qry_{uuid4().hex[:20]}",
                actor["tenant_id"] if actor else None,
                actor["id"] if actor else None,
                hashlib.sha256(question.encode("utf-8")).hexdigest(),
                len(question),
                Jsonb({"reason": reason[:160]}),
            ),
        )
