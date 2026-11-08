"""Tenant-scoped security incident reporting and response routes."""

from __future__ import annotations

from collections.abc import Callable
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from .database import connect


class IncidentStatusRequest(BaseModel):
    status: Literal["acknowledged", "resolved"]


def _incident_query(where: str) -> str:
    return f"""
        SELECT i.id, i.tenant_id, t.name AS tenant_name, t.slug AS tenant_slug,
               i.actor_id, u.username AS actor_username, u.email AS actor_email,
               i.request_id, i.contract_id, i.contract_version, i.source,
               i.category, i.severity, i.status, i.document_id, i.version_id,
               i.chunk_id, i.evidence_hash, i.evidence_excerpt, i.indicators,
               i.detected_at, i.updated_at, i.acknowledged_at, i.resolved_at,
               i.acknowledged_by, i.resolved_by,
               acknowledger.username AS acknowledged_by_username,
               acknowledger.email AS acknowledged_by_email,
               resolver.username AS resolved_by_username,
               resolver.email AS resolved_by_email
        FROM rag_security_incidents i
        JOIN rag_tenants t ON t.id = i.tenant_id
        LEFT JOIN rag_users u ON u.id = i.actor_id
        LEFT JOIN rag_users acknowledger ON acknowledger.id = i.acknowledged_by
        LEFT JOIN rag_users resolver ON resolver.id = i.resolved_by
        WHERE {where}
        ORDER BY
            CASE i.severity
                WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                WHEN 'medium' THEN 3 ELSE 4
            END,
            i.detected_at DESC
        LIMIT %s
    """


def _set_incident_status(
    *, incident_id: str, status: str, actor_id: int, tenant_id: int | None = None
) -> dict | None:
    tenant_clause = " AND tenant_id = %s" if tenant_id is not None else ""
    parameters: list[object] = [
        status,
        status,
        actor_id,
        status,
        status,
        actor_id,
        status,
        incident_id,
    ]
    if tenant_id is not None:
        parameters.append(tenant_id)
    with connect() as connection:
        return connection.execute(
            f"""
            UPDATE rag_security_incidents
            SET status = %s,
                acknowledged_by = CASE WHEN %s = 'acknowledged'
                    THEN %s ELSE acknowledged_by END,
                acknowledged_at = CASE WHEN %s = 'acknowledged'
                    THEN CURRENT_TIMESTAMP ELSE acknowledged_at END,
                resolved_by = CASE WHEN %s = 'resolved' THEN %s ELSE resolved_by END,
                resolved_at = CASE WHEN %s = 'resolved'
                    THEN CURRENT_TIMESTAMP ELSE resolved_at END,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = %s{tenant_clause} AND status <> 'resolved'
            RETURNING id, tenant_id, status, updated_at, acknowledged_at, resolved_at
            """,
            tuple(parameters),
        ).fetchone()


def create_incident_router(
    require_admin: Callable[..., dict], require_manager: Callable[..., dict]
) -> APIRouter:
    router = APIRouter(tags=["security incidents"])

    @router.get("/api/admin/security/incidents")
    def list_admin_incidents(
        tenant_id: int | None = Query(default=None, gt=0),
        incident_status: Literal["open", "acknowledged", "resolved"] | None = Query(
            default=None, alias="status"
        ),
        limit: int = Query(default=100, ge=1, le=500),
        _: dict = Depends(require_admin),
    ) -> list[dict]:
        clauses = ["TRUE"]
        parameters: list[object] = []
        if tenant_id is not None:
            clauses.append("i.tenant_id = %s")
            parameters.append(tenant_id)
        if incident_status is not None:
            clauses.append("i.status = %s")
            parameters.append(incident_status)
        parameters.append(limit)
        with connect() as connection:
            return connection.execute(
                _incident_query(" AND ".join(clauses)), tuple(parameters)
            ).fetchall()

    @router.patch("/api/admin/security/incidents/{incident_id}")
    def update_admin_incident(
        incident_id: str,
        payload: IncidentStatusRequest,
        administrator: dict = Depends(require_admin),
    ) -> dict:
        row = _set_incident_status(
            incident_id=incident_id,
            status=payload.status,
            actor_id=administrator["id"],
        )
        if row is None:
            raise HTTPException(status_code=404, detail="Open security incident not found.")
        return {"incident": row}

    @router.get("/api/manager/security/incidents")
    def list_manager_incidents(
        incident_status: Literal["open", "acknowledged", "resolved"] | None = Query(
            default=None, alias="status"
        ),
        limit: int = Query(default=100, ge=1, le=500),
        manager: dict = Depends(require_manager),
    ) -> list[dict]:
        clauses = ["i.tenant_id = %s"]
        parameters: list[object] = [manager["tenant_id"]]
        if incident_status is not None:
            clauses.append("i.status = %s")
            parameters.append(incident_status)
        parameters.append(limit)
        with connect() as connection:
            return connection.execute(
                _incident_query(" AND ".join(clauses)), tuple(parameters)
            ).fetchall()

    @router.patch("/api/manager/security/incidents/{incident_id}")
    def update_manager_incident(
        incident_id: str,
        payload: IncidentStatusRequest,
        manager: dict = Depends(require_manager),
    ) -> dict:
        row = _set_incident_status(
            incident_id=incident_id,
            status=payload.status,
            actor_id=manager["id"],
            tenant_id=manager["tenant_id"],
        )
        if row is None:
            raise HTTPException(status_code=404, detail="Open security incident not found.")
        return {"incident": row}

    return router
