"""Tenant-manager-only user management API routes."""

from __future__ import annotations

from collections.abc import Callable
from typing import Literal

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from .database import connect


class ManagedUserRoleRequest(BaseModel):
    role: Literal["user", "tenant_manager"]
    manager_password: str = Field(min_length=1, max_length=128)


def create_manager_router(require_manager: Callable[..., dict]) -> APIRouter:
    """Build routes constrained to the signed-in manager's tenant."""
    router = APIRouter(prefix="/api/manager", tags=["tenant management"])

    @router.get("/tenant")
    def tenant_workspace(manager: dict = Depends(require_manager)) -> dict:
        with connect() as connection:
            tenant = connection.execute(
                """
                SELECT id, name, slug, description, is_active
                FROM rag_tenants
                WHERE id = %s
                """,
                (manager["tenant_id"],),
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
                (manager["tenant_id"],),
            ).fetchall()
        return {"tenant": tenant, "users": users}

    @router.patch("/users/{user_id}/role")
    def set_managed_user_role(
        user_id: int,
        payload: ManagedUserRoleRequest,
        manager: dict = Depends(require_manager),
    ) -> dict:
        with connect() as connection:
            credentials = connection.execute(
                """
                SELECT password_hash
                FROM rag_users
                WHERE id = %s AND role = 'tenant_manager'
                """,
                (manager["id"],),
            ).fetchone()
            try:
                if credentials is None:
                    raise VerifyMismatchError
                PasswordHasher().verify(
                    credentials["password_hash"], payload.manager_password
                )
            except (VerifyMismatchError, InvalidHashError) as exc:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Manager password is incorrect.",
                ) from exc

            target = connection.execute(
                """
                SELECT id, role, tenant_id
                FROM rag_users
                WHERE id = %s AND tenant_id = %s
                """,
                (user_id, manager["tenant_id"]),
            ).fetchone()
            if target is None:
                raise HTTPException(status_code=404, detail="User not found in your tenant.")
            if target["role"] in {"pending", "admin"}:
                raise HTTPException(
                    status_code=409,
                    detail="This account's role can only be managed by an administrator.",
                )
            if target["id"] == manager["id"] and payload.role != "tenant_manager":
                raise HTTPException(
                    status_code=400,
                    detail="Tenant managers cannot remove their own manager role.",
                )

            user = connection.execute(
                """
                UPDATE rag_users
                SET role = %s, updated_at = CURRENT_TIMESTAMP
                WHERE id = %s AND tenant_id = %s
                RETURNING id, email, username, tenant_id, role, is_active
                """,
                (payload.role, user_id, manager["tenant_id"]),
            ).fetchone()
        return {"user": user}

    return router
