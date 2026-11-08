"""Administrator-only tenant and user management API routes."""

from __future__ import annotations

from collections.abc import Callable
from typing import Literal

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from fastapi import APIRouter, Depends, HTTPException, status
from psycopg import errors
from pydantic import BaseModel, Field, field_validator

from .contracts import (
    ContractUnavailableError,
    TenantDomainContract,
    activate_contract,
    approve_contract,
    contract_payload,
    create_contract_version,
    ensure_default_contract,
    get_active_contract,
    rollback_contract,
    verify_contract_row,
)
from .database import connect


class TenantCreateRequest(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    slug: str = Field(min_length=2, max_length=80, pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
    description: str = Field(default="", max_length=255)

    @field_validator("name", "description", mode="before")
    @classmethod
    def strip_text(cls, value: str) -> str:
        return value.strip()

    @field_validator("slug", mode="before")
    @classmethod
    def normalize_slug(cls, value: str) -> str:
        return value.strip().lower()


class TenantStatusRequest(BaseModel):
    is_active: bool


class UserStatusRequest(BaseModel):
    is_active: bool


class UserRoleRequest(BaseModel):
    role: Literal["user", "tenant_manager", "admin"]
    admin_password: str = Field(min_length=1, max_length=128)


def tenant_admin_payload(row: dict) -> dict:
    return {
        "id": row["id"],
        "name": row["name"],
        "slug": row["slug"],
        "description": row["description"],
        "is_active": row["is_active"],
        "user_count": row.get("user_count", 0),
        "created_at": row["created_at"],
        "contract_state": row.get("contract_state"),
    }


def create_admin_router(require_admin: Callable[..., dict]) -> APIRouter:
    """Build the admin router with the application's session dependency."""
    router = APIRouter(prefix="/api/admin", tags=["administration"])

    @router.get("/tenants")
    def list_tenants(_: dict = Depends(require_admin)) -> list[dict]:
        with connect() as connection:
            rows = connection.execute(
                """
                SELECT t.id, t.name, t.slug, t.description, t.is_active, t.created_at,
                       COUNT(u.id)::INTEGER AS user_count,
                       (SELECT c.state FROM tenant_domain_contracts c
                        WHERE c.tenant_id = t.id
                        ORDER BY c.version DESC LIMIT 1) AS contract_state
                FROM rag_tenants AS t
                LEFT JOIN rag_users AS u ON u.tenant_id = t.id
                GROUP BY t.id
                ORDER BY t.name
                """
            ).fetchall()
        return [tenant_admin_payload(row) for row in rows]

    @router.post("/tenants", status_code=status.HTTP_201_CREATED)
    def create_tenant(
        payload: TenantCreateRequest,
        administrator: dict = Depends(require_admin),
    ) -> dict:
        try:
            with connect() as connection:
                tenant = connection.execute(
                    """
                    INSERT INTO rag_tenants (name, slug, description, is_active)
                    VALUES (%s, %s, %s, FALSE)
                    RETURNING id, name, slug, description, is_active, created_at
                    """,
                    (payload.name, payload.slug, payload.description),
                ).fetchone()
                ensure_default_contract(
                    connection,
                    tenant["id"],
                    tenant["name"],
                    initial_state="draft",
                    actor_id=administrator["id"],
                )
                tenant["contract_state"] = "draft"
        except errors.UniqueViolation as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A tenant with this name or slug already exists.",
            ) from exc
        return {"tenant": tenant_admin_payload(tenant)}

    @router.get("/tenants/{tenant_id}/contracts")
    def list_tenant_contracts(
        tenant_id: int,
        _: dict = Depends(require_admin),
    ) -> list[dict]:
        with connect() as connection:
            tenant = connection.execute(
                "SELECT id FROM rag_tenants WHERE id = %s", (tenant_id,)
            ).fetchone()
            if tenant is None:
                raise HTTPException(status_code=404, detail="Tenant not found.")
            rows = connection.execute(
                "SELECT * FROM tenant_domain_contracts WHERE tenant_id = %s ORDER BY version DESC",
                (tenant_id,),
            ).fetchall()
        payloads = []
        for row in rows:
            payload = contract_payload(row)
            try:
                verify_contract_row(row)
                payload["signature_valid"] = True
            except ContractUnavailableError:
                payload["signature_valid"] = False
            payloads.append(payload)
        return payloads

    @router.post(
        "/tenants/{tenant_id}/contracts", status_code=status.HTTP_201_CREATED
    )
    def create_tenant_contract(
        tenant_id: int,
        payload: TenantDomainContract,
        administrator: dict = Depends(require_admin),
    ) -> dict:
        with connect() as connection:
            tenant = connection.execute(
                "SELECT id FROM rag_tenants WHERE id = %s", (tenant_id,)
            ).fetchone()
            if tenant is None:
                raise HTTPException(status_code=404, detail="Tenant not found.")
            row = create_contract_version(
                connection,
                tenant_id=tenant_id,
                contract=payload,
                actor_id=administrator["id"],
            )
        return {"contract": contract_payload(row)}

    @router.post("/contracts/{contract_id}/approve")
    def approve_tenant_contract(
        contract_id: str,
        administrator: dict = Depends(require_admin),
    ) -> dict:
        with connect() as connection:
            row = approve_contract(connection, contract_id, administrator["id"])
        if row is None:
            raise HTTPException(status_code=409, detail="Only draft contracts can be approved.")
        return {"contract": contract_payload(row)}

    @router.post("/contracts/{contract_id}/activate")
    def activate_tenant_contract(
        contract_id: str,
        administrator: dict = Depends(require_admin),
    ) -> dict:
        try:
            with connect() as connection:
                row = activate_contract(connection, contract_id, administrator["id"])
        except ContractUnavailableError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        if row is None:
            raise HTTPException(status_code=409, detail="Only approved contracts can be activated.")
        return {"contract": contract_payload(row)}

    @router.post("/contracts/{contract_id}/rollback")
    def rollback_tenant_contract(
        contract_id: str,
        administrator: dict = Depends(require_admin),
    ) -> dict:
        try:
            with connect() as connection:
                row = rollback_contract(connection, contract_id, administrator["id"])
        except ContractUnavailableError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        if row is None:
            raise HTTPException(
                status_code=409,
                detail="Only a valid superseded contract can be restored.",
            )
        return {"contract": contract_payload(row)}

    @router.patch("/tenants/{tenant_id}")
    def set_tenant_status(
        tenant_id: int,
        payload: TenantStatusRequest,
        _: dict = Depends(require_admin),
    ) -> dict:
        with connect() as connection:
            if payload.is_active:
                try:
                    get_active_contract(connection, tenant_id)
                except ContractUnavailableError as exc:
                    raise HTTPException(
                        status_code=409,
                        detail="Activate an approved Tenant Domain Contract before activating the tenant.",
                    ) from exc
            tenant = connection.execute(
                """
                UPDATE rag_tenants
                SET is_active = %s
                WHERE id = %s
                RETURNING id, name, slug, description, is_active, created_at
                """,
                (payload.is_active, tenant_id),
            ).fetchone()
            if tenant is not None:
                state_row = connection.execute(
                    "SELECT state FROM tenant_domain_contracts WHERE tenant_id = %s ORDER BY version DESC LIMIT 1",
                    (tenant_id,),
                ).fetchone()
                tenant["contract_state"] = state_row["state"] if state_row else None
                if not payload.is_active:
                    connection.execute(
                        """
                        UPDATE auth_sessions SET revoked_at = CURRENT_TIMESTAMP
                        WHERE tenant_id = %s AND revoked_at IS NULL
                        """,
                        (tenant_id,),
                    )
        if tenant is None:
            raise HTTPException(status_code=404, detail="Tenant not found.")
        return {"tenant": tenant_admin_payload(tenant)}

    @router.get("/tenants/{tenant_id}/users")
    def list_tenant_users(
        tenant_id: int,
        _: dict = Depends(require_admin),
    ) -> dict:
        with connect() as connection:
            tenant = connection.execute(
                "SELECT id, name, slug, is_active FROM rag_tenants WHERE id = %s",
                (tenant_id,),
            ).fetchone()
            if tenant is None:
                raise HTTPException(status_code=404, detail="Tenant not found.")
            users = connection.execute(
                """
                SELECT id, email, username, role, is_active
                FROM rag_users
                WHERE tenant_id = %s
                ORDER BY username, email
                """,
                (tenant_id,),
            ).fetchall()
        return {"tenant": tenant, "users": users}

    @router.get("/admins")
    def list_administrators(_: dict = Depends(require_admin)) -> list[dict]:
        with connect() as connection:
            administrators = connection.execute(
                """
                SELECT u.id, u.username, u.email, u.is_active,
                       t.id AS tenant_id, t.name AS tenant_name
                FROM rag_users AS u
                LEFT JOIN rag_tenants AS t ON t.id = u.tenant_id
                WHERE u.role = 'admin'
                ORDER BY u.username, u.email
                """
            ).fetchall()
        return administrators

    @router.post("/users/{user_id}/approve")
    def approve_pending_user(
        user_id: int,
        _: dict = Depends(require_admin),
    ) -> dict:
        with connect() as connection:
            user = connection.execute(
                """
                UPDATE rag_users
                SET role = 'user', is_active = TRUE, updated_at = CURRENT_TIMESTAMP
                WHERE id = %s AND role = 'pending'
                RETURNING id, email, username, tenant_id, role, is_active
                """,
                (user_id,),
            ).fetchone()
        if user is None:
            raise HTTPException(status_code=404, detail="Pending user not found.")
        return {"user": user}

    @router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
    def decline_pending_user(
        user_id: int,
        _: dict = Depends(require_admin),
    ) -> None:
        with connect() as connection:
            deleted = connection.execute(
                "DELETE FROM rag_users WHERE id = %s AND role = 'pending' RETURNING id",
                (user_id,),
            ).fetchone()
        if deleted is None:
            raise HTTPException(status_code=404, detail="Pending user not found.")

    @router.patch("/users/{user_id}")
    def set_user_status(
        user_id: int,
        payload: UserStatusRequest,
        _: dict = Depends(require_admin),
    ) -> dict:
        with connect() as connection:
            user = connection.execute(
                """
                UPDATE rag_users
                SET is_active = %s, updated_at = CURRENT_TIMESTAMP
                WHERE id = %s AND role <> 'admin'
                RETURNING id, email, username, tenant_id, role, is_active
                """,
                (payload.is_active, user_id),
            ).fetchone()
            if user is not None and not payload.is_active:
                connection.execute(
                    """
                    UPDATE auth_sessions SET revoked_at = CURRENT_TIMESTAMP
                    WHERE user_id = %s AND revoked_at IS NULL
                    """,
                    (user_id,),
                )
        if user is None:
            raise HTTPException(status_code=404, detail="User not found.")
        return {"user": user}

    @router.patch("/users/{user_id}/role")
    def set_user_role(
        user_id: int,
        payload: UserRoleRequest,
        administrator: dict = Depends(require_admin),
    ) -> dict:
        with connect() as connection:
            admin_credentials = connection.execute(
                "SELECT password_hash FROM rag_users WHERE id = %s AND role = 'admin'",
                (administrator["id"],),
            ).fetchone()
            try:
                if admin_credentials is None:
                    raise VerifyMismatchError
                PasswordHasher().verify(
                    admin_credentials["password_hash"], payload.admin_password
                )
            except (VerifyMismatchError, InvalidHashError) as exc:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Administrator password is incorrect.",
                ) from exc

            target = connection.execute(
                "SELECT id, role, tenant_id FROM rag_users WHERE id = %s",
                (user_id,),
            ).fetchone()
            if target is None:
                raise HTTPException(status_code=404, detail="User not found.")
            if target["role"] == "pending":
                raise HTTPException(
                    status_code=409,
                    detail="Approve the pending account before assigning a role.",
                )
            if target["id"] == administrator["id"] and payload.role != "admin":
                raise HTTPException(
                    status_code=400,
                    detail="Administrators cannot remove their own admin role.",
                )
            if payload.role != "admin" and target["tenant_id"] is None:
                raise HTTPException(
                    status_code=400,
                    detail="A tenantless administrator cannot receive a tenant role.",
                )

            user = connection.execute(
                """
                UPDATE rag_users
                SET role = %s, updated_at = CURRENT_TIMESTAMP
                WHERE id = %s
                RETURNING id, email, username, tenant_id, role, is_active
                """,
                (payload.role, user_id),
            ).fetchone()
            connection.execute(
                """
                UPDATE auth_sessions SET revoked_at = CURRENT_TIMESTAMP
                WHERE user_id = %s AND revoked_at IS NULL
                """,
                (user_id,),
            )
        return {"user": user}

    return router
