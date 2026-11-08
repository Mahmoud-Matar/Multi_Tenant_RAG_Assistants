"""Versioned, signed Tenant Domain Contracts and lifecycle operations."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field
from psycopg.types.json import Jsonb


ContractState = Literal["draft", "approved", "active", "superseded", "rolled_back"]
IsolationTier = Literal["pool", "bridge", "silo"]


class KnowledgePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approved_sources: list[str] = Field(default_factory=lambda: ["tenant-managed uploads"])
    allowed_extensions: list[Literal[".pdf", ".docx", ".txt"]] = Field(
        default_factory=lambda: [".pdf", ".docx", ".txt"]
    )
    allowed_access_scopes: list[Literal["employee", "management"]] = Field(
        default_factory=lambda: ["employee", "management"]
    )
    max_document_bytes: int = Field(default=20 * 1024 * 1024, ge=1024, le=200 * 1024 * 1024)


class DomainPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed_topics: list[str] = Field(default_factory=list, max_length=100)
    excluded_topics: list[str] = Field(default_factory=list, max_length=100)
    refusal_message: str = Field(
        default="I couldn't find enough authorized information to answer that question.",
        min_length=10,
        max_length=500,
    )


class RetrievalThresholds(BaseModel):
    model_config = ConfigDict(extra="forbid")

    top_k: int = Field(default=5, ge=1, le=10)
    max_distance: float = Field(default=0.8, ge=0, le=2)
    minimum_citation_support: float = Field(default=0.65, ge=0, le=1)


class RolePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    access_scopes: list[Literal["employee", "management"]]
    capabilities: list[str] = Field(default_factory=list)


class MetricDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")
    label: str = Field(min_length=2, max_length=120)
    definition: str = Field(min_length=5, max_length=500)
    allowed_roles: list[Literal["tenant_manager", "tenant_analyst"]]
    minimum_group_size: int = Field(default=10, ge=1, le=1000)
    allowed_filters: list[str] = Field(default_factory=list)


class ModelPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed_providers: list[str] = Field(default_factory=lambda: ["openai"], min_length=1)
    chat_model: str = Field(default="gpt-4o-mini", min_length=2, max_length=120)
    embedding_model: str = Field(
        default="text-embedding-3-small", min_length=2, max_length=120
    )


class RetentionPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    audit_days: int = Field(default=365, ge=1, le=3650)
    interaction_days: int = Field(default=90, ge=0, le=3650)
    original_document_days: int = Field(default=365, ge=1, le=3650)


class IsolationPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vector_index: IsolationTier = "pool"
    bi_store: IsolationTier = "pool"
    model_endpoint: IsolationTier = "pool"
    audit_log: IsolationTier = "pool"


class TenantDomainContract(BaseModel):
    """Validated policy data used outside the language model's control."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    name: str = Field(min_length=2, max_length=120)
    knowledge: KnowledgePolicy = Field(default_factory=KnowledgePolicy)
    domain: DomainPolicy = Field(default_factory=DomainPolicy)
    thresholds: RetrievalThresholds = Field(default_factory=RetrievalThresholds)
    roles: dict[str, RolePolicy] = Field(
        default_factory=lambda: {
            "user": RolePolicy(access_scopes=["employee"], capabilities=["chat"]),
            "tenant_manager": RolePolicy(
                access_scopes=["employee", "management"],
                capabilities=["chat", "knowledge_management", "tenant_bi"],
            ),
        }
    )
    metrics: list[MetricDefinition] = Field(default_factory=list)
    models: ModelPolicy = Field(default_factory=ModelPolicy)
    retention: RetentionPolicy = Field(default_factory=RetentionPolicy)
    isolation: IsolationPolicy = Field(default_factory=IsolationPolicy)


class ContractUnavailableError(RuntimeError):
    """A tenant has no usable, authentic active contract."""


def default_contract(tenant_name: str) -> TenantDomainContract:
    return TenantDomainContract(name=f"{tenant_name} domain contract")


def _canonical_bytes(contract: TenantDomainContract | dict) -> bytes:
    validated = (
        contract
        if isinstance(contract, TenantDomainContract)
        else TenantDomainContract.model_validate(contract)
    )
    return json.dumps(
        validated.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _signing_key() -> bytes:
    value = os.getenv("TDC_SIGNING_KEY") or os.getenv("AUTH_SECRET_KEY")
    if not value:
        raise RuntimeError("TDC_SIGNING_KEY or AUTH_SECRET_KEY must be configured.")
    return value.encode("utf-8")


def contract_digest(contract: TenantDomainContract | dict) -> tuple[str, str]:
    canonical = _canonical_bytes(contract)
    digest = hashlib.sha256(canonical).hexdigest()
    signature = hmac.new(_signing_key(), canonical, hashlib.sha256).hexdigest()
    return digest, signature


def verify_contract_row(row: dict) -> TenantDomainContract:
    try:
        contract = TenantDomainContract.model_validate(row["contract"])
        digest, signature = contract_digest(contract)
    except Exception as exc:
        raise ContractUnavailableError("The tenant contract is invalid.") from exc
    if not hmac.compare_digest(digest, row["contract_hash"]) or not hmac.compare_digest(
        signature, row["signature"]
    ):
        raise ContractUnavailableError("The tenant contract signature is invalid.")
    return contract


def contract_payload(row: dict, *, include_contract: bool = True) -> dict:
    payload = {
        "id": row["id"],
        "tenant_id": row["tenant_id"],
        "version": row["version"],
        "state": row["state"],
        "contract_hash": row["contract_hash"],
        "created_by": row.get("created_by"),
        "approved_by": row.get("approved_by"),
        "created_at": row["created_at"],
        "approved_at": row.get("approved_at"),
        "activated_at": row.get("activated_at"),
        "based_on_id": row.get("based_on_id"),
    }
    if include_contract:
        payload["contract"] = row["contract"]
    return payload


def create_contract_version(
    connection,
    *,
    tenant_id: int,
    contract: TenantDomainContract | dict,
    actor_id: int | None,
    state: ContractState = "draft",
    based_on_id: str | None = None,
) -> dict:
    validated = (
        contract
        if isinstance(contract, TenantDomainContract)
        else TenantDomainContract.model_validate(contract)
    )
    digest, signature = contract_digest(validated)
    version = connection.execute(
        "SELECT COALESCE(MAX(version), 0) + 1 AS version FROM tenant_domain_contracts WHERE tenant_id = %s",
        (tenant_id,),
    ).fetchone()["version"]
    contract_id = f"tdc_{uuid4().hex[:20]}"
    row = connection.execute(
        """
        INSERT INTO tenant_domain_contracts
            (id, tenant_id, version, state, contract, contract_hash, signature,
             created_by, approved_by, approved_at, activated_at, based_on_id)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s,
                CASE WHEN %s THEN CURRENT_TIMESTAMP ELSE NULL END,
                CASE WHEN %s THEN CURRENT_TIMESTAMP ELSE NULL END, %s)
        RETURNING *
        """,
        (
            contract_id,
            tenant_id,
            version,
            state,
            Jsonb(validated.model_dump(mode="json")),
            digest,
            signature,
            actor_id,
            actor_id if state in {"approved", "active"} else None,
            state in {"approved", "active"},
            state == "active",
            based_on_id,
        ),
    ).fetchone()
    return row


def ensure_default_contract(
    connection,
    tenant_id: int,
    tenant_name: str,
    *,
    initial_state: Literal["draft", "active"] = "active",
    actor_id: int | None = None,
) -> dict:
    existing = connection.execute(
        "SELECT * FROM tenant_domain_contracts WHERE tenant_id = %s ORDER BY version DESC LIMIT 1",
        (tenant_id,),
    ).fetchone()
    if existing:
        return existing
    return create_contract_version(
        connection,
        tenant_id=tenant_id,
        contract=default_contract(tenant_name),
        actor_id=actor_id,
        state=initial_state,
    )


def get_active_contract(connection, tenant_id: int, *, lock: bool = False) -> tuple[dict, TenantDomainContract]:
    suffix = " FOR UPDATE" if lock else ""
    row = connection.execute(
        "SELECT * FROM tenant_domain_contracts WHERE tenant_id = %s AND state = 'active'" + suffix,
        (tenant_id,),
    ).fetchone()
    if row is None:
        raise ContractUnavailableError("The tenant has no active domain contract.")
    return row, verify_contract_row(row)


def approve_contract(connection, contract_id: str, actor_id: int) -> dict | None:
    return connection.execute(
        """
        UPDATE tenant_domain_contracts
        SET state = 'approved', approved_by = %s, approved_at = CURRENT_TIMESTAMP
        WHERE id = %s AND state = 'draft'
        RETURNING *
        """,
        (actor_id, contract_id),
    ).fetchone()


def activate_contract(connection, contract_id: str, actor_id: int) -> dict | None:
    target = connection.execute(
        "SELECT * FROM tenant_domain_contracts WHERE id = %s AND state = 'approved' FOR UPDATE",
        (contract_id,),
    ).fetchone()
    if target is None:
        return None
    verify_contract_row(target)
    connection.execute(
        "UPDATE tenant_domain_contracts SET state = 'superseded' WHERE tenant_id = %s AND state = 'active'",
        (target["tenant_id"],),
    )
    activated = connection.execute(
        """
        UPDATE tenant_domain_contracts
        SET state = 'active', approved_by = COALESCE(approved_by, %s),
            approved_at = COALESCE(approved_at, CURRENT_TIMESTAMP),
            activated_at = CURRENT_TIMESTAMP
        WHERE id = %s
        RETURNING *
        """,
        (actor_id, contract_id),
    ).fetchone()
    connection.execute(
        "UPDATE rag_tenants SET is_active = TRUE WHERE id = %s",
        (target["tenant_id"],),
    )
    return activated


def rollback_contract(connection, target_id: str, actor_id: int) -> dict | None:
    target = connection.execute(
        "SELECT * FROM tenant_domain_contracts WHERE id = %s FOR UPDATE",
        (target_id,),
    ).fetchone()
    if target is None or target["state"] not in {"superseded", "rolled_back"}:
        return None
    contract = verify_contract_row(target)
    connection.execute(
        "UPDATE tenant_domain_contracts SET state = 'rolled_back' WHERE tenant_id = %s AND state = 'active'",
        (target["tenant_id"],),
    )
    return create_contract_version(
        connection,
        tenant_id=target["tenant_id"],
        contract=contract,
        actor_id=actor_id,
        state="active",
        based_on_id=target_id,
    )
