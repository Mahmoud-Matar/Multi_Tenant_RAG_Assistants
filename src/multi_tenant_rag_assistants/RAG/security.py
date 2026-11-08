"""Build a trusted tenant context from an already authenticated user."""

from __future__ import annotations

from fastapi import HTTPException

from multi_tenant_rag_assistants.backend.database import connect
from multi_tenant_rag_assistants.backend.documents import tenant_key
from multi_tenant_rag_assistants.backend.contracts import (
    ContractUnavailableError,
    get_active_contract,
)

from .models import SecurityContext


CHAT_ROLES = {"user", "tenant_manager"}


def build_security_context(user: dict) -> SecurityContext:
    """Revalidate tenant membership and authorization in PostgreSQL."""
    user_id = user.get("id")
    tenant_id = user.get("tenant_id")
    role = user.get("role")
    if not isinstance(user_id, int) or not isinstance(tenant_id, int) or tenant_id <= 0:
        raise HTTPException(status_code=403, detail="A trusted tenant context is required.")
    if role not in CHAT_ROLES:
        raise HTTPException(status_code=403, detail="Chat access is not permitted for this role.")

    with connect() as connection:
        membership = connection.execute(
            """
            SELECT u.id AS user_id, u.tenant_id, u.role, t.id, t.slug
            FROM rag_users u
            JOIN rag_tenants t ON t.id = u.tenant_id
            WHERE u.id = %s AND u.tenant_id = %s AND u.role = %s
              AND u.is_active = TRUE AND t.is_active = TRUE
            """,
            (user_id, tenant_id, role),
        ).fetchone()
        if membership is None:
            raise HTTPException(status_code=403, detail="The tenant context is invalid or inactive.")
        try:
            contract_row, contract = get_active_contract(connection, tenant_id)
        except ContractUnavailableError as exc:
            raise HTTPException(
                status_code=503,
                detail="The tenant policy is unavailable or invalid.",
            ) from exc
    role_policy = contract.roles.get(role)
    if role_policy is None or "chat" not in role_policy.capabilities:
        raise HTTPException(status_code=403, detail="Chat is not enabled by the tenant policy.")
    scopes = tuple(role_policy.access_scopes)
    return SecurityContext(
        user_id=user_id,
        tenant_id=tenant_id,
        tenant_key=tenant_key(membership),
        role=role,
        access_scopes=scopes,
        contract_id=contract_row["id"],
        contract_version=contract_row["version"],
        contract_hash=contract_row["contract_hash"],
        contract=contract.model_dump(mode="json"),
    )
