"""Security incident persistence for blocked RAG requests and poisoned evidence."""

from __future__ import annotations

from uuid import uuid4

from psycopg.types.json import Jsonb

from multi_tenant_rag_assistants.backend.database import connect

from .models import RetrievedChunk, SecurityContext
from .threats import ThreatFinding


def write_security_incident(
    *,
    context: SecurityContext,
    request_id: str,
    source: str,
    finding: ThreatFinding,
    chunk: RetrievedChunk | None = None,
) -> str:
    incident_id = f"inc_{uuid4().hex[:20]}"
    with connect() as connection:
        connection.execute(
            """
            INSERT INTO rag_security_incidents
                (id, tenant_id, actor_id, request_id, contract_id, contract_version,
                 source, category, severity, document_id, version_id, chunk_id,
                 evidence_hash, evidence_excerpt, indicators)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                incident_id,
                context.tenant_id,
                context.user_id,
                request_id,
                context.contract_id,
                context.contract_version,
                source,
                finding.category,
                finding.severity,
                chunk.document_id if chunk else None,
                chunk.version_id if chunk else None,
                chunk.chunk_id if chunk else None,
                finding.evidence_hash,
                finding.evidence_excerpt,
                Jsonb(list(finding.indicators)),
            ),
        )
    return incident_id
