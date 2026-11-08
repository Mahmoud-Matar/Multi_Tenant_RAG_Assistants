"""PostgreSQL connection helpers and idempotent schema initialization."""

from __future__ import annotations

import os
from pathlib import Path

import psycopg
from argon2 import PasswordHasher
from dotenv import load_dotenv
from psycopg.rows import dict_row


PROJECT_ROOT = Path(__file__).resolve().parents[3]
load_dotenv(PROJECT_ROOT / ".env")

DATABASE_URL = os.getenv("DATABASE_URL")


def connect() -> psycopg.Connection:
    """Create a short-lived database connection with dictionary rows."""
    if not DATABASE_URL:
        raise RuntimeError(
            "DATABASE_URL is not configured. Add it to .env."
        )
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS rag_tenants (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name VARCHAR(120) NOT NULL UNIQUE,
    slug VARCHAR(80) NOT NULL UNIQUE,
    description VARCHAR(255) NOT NULL DEFAULT '',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS rag_users (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username VARCHAR(80),
    email VARCHAR(320) UNIQUE,
    password_hash TEXT NOT NULL,
    tenant_id BIGINT,
    role VARCHAR(32) NOT NULL DEFAULT 'user',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    email_verified_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    failed_login_count INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ,
    password_changed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_rag_users_tenant
        FOREIGN KEY (tenant_id) REFERENCES rag_tenants(id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    CONSTRAINT chk_rag_users_email_lowercase CHECK (email IS NULL OR email = LOWER(email)),
    CONSTRAINT chk_rag_users_role CHECK (role IN ('user', 'tenant_manager', 'admin', 'pending')),
    CONSTRAINT chk_rag_users_tenant_assignment CHECK (
        role = 'admin' OR tenant_id IS NOT NULL
    )
);

ALTER TABLE rag_users ADD COLUMN IF NOT EXISTS username VARCHAR(80);
ALTER TABLE rag_users ADD COLUMN IF NOT EXISTS role VARCHAR(32) NOT NULL DEFAULT 'user';
ALTER TABLE rag_users ADD COLUMN IF NOT EXISTS email_verified_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE rag_users ADD COLUMN IF NOT EXISTS failed_login_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE rag_users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ;
ALTER TABLE rag_users ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE rag_users ALTER COLUMN email DROP NOT NULL;
ALTER TABLE rag_users ALTER COLUMN tenant_id DROP NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_rag_users_role'
    ) THEN
        ALTER TABLE rag_users ADD CONSTRAINT chk_rag_users_role
            CHECK (role IN ('user', 'tenant_manager', 'admin', 'pending'));
    END IF;
    ALTER TABLE rag_users DROP CONSTRAINT IF EXISTS chk_rag_users_tenant_assignment;
    ALTER TABLE rag_users ADD CONSTRAINT chk_rag_users_tenant_assignment
        CHECK (role = 'admin' OR tenant_id IS NOT NULL);
END $$;

CREATE INDEX IF NOT EXISTS idx_rag_users_tenant_id ON rag_users (tenant_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_rag_users_username_lower
    ON rag_users (LOWER(username)) WHERE username IS NOT NULL;

CREATE TABLE IF NOT EXISTS auth_sessions (
    id VARCHAR(64) PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES rag_users(id) ON DELETE CASCADE,
    tenant_id BIGINT REFERENCES rag_tenants(id) ON DELETE CASCADE,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMPTZ,
    ip_address VARCHAR(64),
    user_agent VARCHAR(512),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_auth_sessions_user
    ON auth_sessions (user_id, expires_at DESC);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_active
    ON auth_sessions (user_id, revoked_at, expires_at);

CREATE TABLE IF NOT EXISTS auth_action_tokens (
    token_hash CHAR(64) PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES rag_users(id) ON DELETE CASCADE,
    purpose VARCHAR(32) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    requested_ip VARCHAR(64),
    CONSTRAINT chk_auth_action_token_purpose CHECK (
        purpose IN ('email_verification', 'password_reset')
    )
);

CREATE INDEX IF NOT EXISTS idx_auth_action_tokens_user
    ON auth_action_tokens (user_id, purpose, expires_at DESC);

CREATE TABLE IF NOT EXISTS auth_rate_limits (
    action VARCHAR(40) NOT NULL,
    subject_hash CHAR(64) NOT NULL,
    window_started_at TIMESTAMPTZ NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    blocked_until TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (action, subject_hash)
);

CREATE TABLE IF NOT EXISTS tenant_domain_contracts (
    id VARCHAR(40) PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES rag_tenants(id)
        ON UPDATE CASCADE ON DELETE CASCADE,
    version INTEGER NOT NULL,
    state VARCHAR(24) NOT NULL DEFAULT 'draft',
    contract JSONB NOT NULL,
    contract_hash CHAR(64) NOT NULL,
    signature CHAR(64) NOT NULL,
    created_by BIGINT REFERENCES rag_users(id) ON DELETE SET NULL,
    approved_by BIGINT REFERENCES rag_users(id) ON DELETE SET NULL,
    based_on_id VARCHAR(40) REFERENCES tenant_domain_contracts(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    approved_at TIMESTAMPTZ,
    activated_at TIMESTAMPTZ,
    CONSTRAINT uq_tenant_domain_contract_version UNIQUE (tenant_id, version),
    CONSTRAINT chk_tenant_domain_contract_state CHECK (
        state IN ('draft', 'approved', 'active', 'superseded', 'rolled_back')
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_tenant_domain_contract_active
    ON tenant_domain_contracts (tenant_id) WHERE state = 'active';
CREATE INDEX IF NOT EXISTS idx_tenant_domain_contract_history
    ON tenant_domain_contracts (tenant_id, version DESC);

CREATE TABLE IF NOT EXISTS rag_documents (
    id VARCHAR(40) PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES rag_tenants(id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    original_filename VARCHAR(255) NOT NULL,
    storage_key TEXT NOT NULL,
    current_version INTEGER NOT NULL DEFAULT 1,
    status VARCHAR(32) NOT NULL DEFAULT 'quarantined',
    access_scope VARCHAR(32) NOT NULL DEFAULT 'employee',
    uploaded_by BIGINT NOT NULL REFERENCES rag_users(id) ON DELETE RESTRICT,
    contract_id VARCHAR(40) REFERENCES tenant_domain_contracts(id) ON DELETE RESTRICT,
    contract_version INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_rag_documents_status CHECK (
        status IN ('quarantined', 'pending_approval', 'processing', 'active',
                   'failed', 'rejected', 'deleted')
    ),
    CONSTRAINT chk_rag_documents_scope CHECK (
        access_scope IN ('employee', 'management')
    )
);

CREATE TABLE IF NOT EXISTS rag_document_versions (
    id VARCHAR(40) PRIMARY KEY,
    document_id VARCHAR(40) NOT NULL REFERENCES rag_documents(id) ON DELETE CASCADE,
    version_number INTEGER NOT NULL,
    checksum CHAR(64) NOT NULL,
    storage_key TEXT NOT NULL,
    mime_type VARCHAR(100) NOT NULL,
    size_bytes BIGINT NOT NULL,
    approval_status VARCHAR(32) NOT NULL DEFAULT 'pending',
    ingestion_status VARCHAR(32) NOT NULL DEFAULT 'quarantined',
    chunk_count INTEGER NOT NULL DEFAULT 0,
    approved_by BIGINT REFERENCES rag_users(id) ON DELETE RESTRICT,
    approved_at TIMESTAMPTZ,
    contract_id VARCHAR(40) REFERENCES tenant_domain_contracts(id) ON DELETE RESTRICT,
    contract_version INTEGER,
    embedding_model VARCHAR(120),
    chunk_size INTEGER,
    chunk_overlap INTEGER,
    failure_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_rag_document_version UNIQUE (document_id, version_number),
    CONSTRAINT chk_rag_document_approval CHECK (
        approval_status IN ('pending', 'approved', 'rejected')
    ),
    CONSTRAINT chk_rag_document_ingestion CHECK (
        ingestion_status IN ('quarantined', 'queued', 'processing', 'active',
                             'failed', 'rejected', 'superseded', 'revoked')
    )
);

CREATE TABLE IF NOT EXISTS rag_document_audit (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES rag_tenants(id) ON DELETE RESTRICT,
    document_id VARCHAR(40),
    version_id VARCHAR(40),
    actor_id BIGINT REFERENCES rag_users(id) ON DELETE SET NULL,
    action VARCHAR(80) NOT NULL,
    outcome VARCHAR(32) NOT NULL,
    contract_id VARCHAR(40) REFERENCES tenant_domain_contracts(id) ON DELETE RESTRICT,
    contract_version INTEGER,
    details JSONB NOT NULL DEFAULT '{}'::JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS rag_query_audit (
    id VARCHAR(40) PRIMARY KEY,
    tenant_id BIGINT REFERENCES rag_tenants(id) ON DELETE RESTRICT,
    actor_id BIGINT REFERENCES rag_users(id) ON DELETE SET NULL,
    query_hash CHAR(64) NOT NULL,
    query_length INTEGER NOT NULL,
    outcome VARCHAR(32) NOT NULL,
    retrieved_chunk_count INTEGER NOT NULL DEFAULT 0,
    cited_chunk_count INTEGER NOT NULL DEFAULT 0,
    latency_ms INTEGER NOT NULL DEFAULT 0,
    contract_id VARCHAR(40) REFERENCES tenant_domain_contracts(id) ON DELETE RESTRICT,
    contract_version INTEGER,
    details JSONB NOT NULL DEFAULT '{}'::JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_rag_query_audit_outcome CHECK (
        outcome IN ('answered', 'abstained', 'denied', 'failed')
    )
);

CREATE TABLE IF NOT EXISTS rag_security_incidents (
    id VARCHAR(40) PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES rag_tenants(id) ON DELETE RESTRICT,
    actor_id BIGINT REFERENCES rag_users(id) ON DELETE SET NULL,
    request_id VARCHAR(40),
    contract_id VARCHAR(40) REFERENCES tenant_domain_contracts(id) ON DELETE RESTRICT,
    contract_version INTEGER,
    source VARCHAR(32) NOT NULL,
    category VARCHAR(48) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    status VARCHAR(24) NOT NULL DEFAULT 'open',
    document_id VARCHAR(40),
    version_id VARCHAR(40),
    chunk_id VARCHAR(80),
    evidence_hash CHAR(64) NOT NULL,
    evidence_excerpt TEXT NOT NULL DEFAULT '',
    indicators JSONB NOT NULL DEFAULT '[]'::JSONB,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    acknowledged_by BIGINT REFERENCES rag_users(id) ON DELETE SET NULL,
    acknowledged_at TIMESTAMPTZ,
    resolved_by BIGINT REFERENCES rag_users(id) ON DELETE SET NULL,
    resolved_at TIMESTAMPTZ,
    CONSTRAINT chk_rag_security_incident_source CHECK (
        source IN ('user_query', 'retrieved_content', 'document_ingestion')
    ),
    CONSTRAINT chk_rag_security_incident_severity CHECK (
        severity IN ('low', 'medium', 'high', 'critical')
    ),
    CONSTRAINT chk_rag_security_incident_status CHECK (
        status IN ('open', 'acknowledged', 'resolved')
    )
);

CREATE INDEX IF NOT EXISTS idx_rag_documents_tenant
    ON rag_documents (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_rag_document_versions_document
    ON rag_document_versions (document_id, ingestion_status);
CREATE INDEX IF NOT EXISTS idx_rag_document_audit_tenant
    ON rag_document_audit (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_rag_query_audit_tenant
    ON rag_query_audit (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_rag_security_incidents_tenant
    ON rag_security_incidents (tenant_id, status, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_rag_security_incidents_open
    ON rag_security_incidents (status, detected_at DESC)
    WHERE status <> 'resolved';

ALTER TABLE rag_documents
    ADD COLUMN IF NOT EXISTS contract_id VARCHAR(40) REFERENCES tenant_domain_contracts(id) ON DELETE RESTRICT;
ALTER TABLE rag_documents ADD COLUMN IF NOT EXISTS contract_version INTEGER;
ALTER TABLE rag_document_versions
    ADD COLUMN IF NOT EXISTS contract_id VARCHAR(40) REFERENCES tenant_domain_contracts(id) ON DELETE RESTRICT;
ALTER TABLE rag_document_versions ADD COLUMN IF NOT EXISTS contract_version INTEGER;
ALTER TABLE rag_document_versions ADD COLUMN IF NOT EXISTS embedding_model VARCHAR(120);
ALTER TABLE rag_document_versions ADD COLUMN IF NOT EXISTS chunk_size INTEGER;
ALTER TABLE rag_document_versions ADD COLUMN IF NOT EXISTS chunk_overlap INTEGER;
ALTER TABLE rag_document_audit
    ADD COLUMN IF NOT EXISTS contract_id VARCHAR(40) REFERENCES tenant_domain_contracts(id) ON DELETE RESTRICT;
ALTER TABLE rag_document_audit ADD COLUMN IF NOT EXISTS contract_version INTEGER;
ALTER TABLE rag_query_audit
    ADD COLUMN IF NOT EXISTS contract_id VARCHAR(40) REFERENCES tenant_domain_contracts(id) ON DELETE RESTRICT;
ALTER TABLE rag_query_audit ADD COLUMN IF NOT EXISTS contract_version INTEGER;
"""

SEED_TENANTS = (
    ("IT Tenant", "it", "Information Technology"),
    ("HR Tenant", "hr", "Human Resources"),
    ("Operations Tenant", "operations", "Operations"),
    ("R&D Tenant", "research-development", "Research & Development"),
)


def initialize_database() -> None:
    """Create the authentication schema and seed its initial tenants."""
    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute(SCHEMA_SQL)
            cursor.executemany(
                """
                INSERT INTO rag_tenants (name, slug, description)
                VALUES (%s, %s, %s)
                ON CONFLICT (slug) DO UPDATE
                SET name = EXCLUDED.name,
                    description = EXCLUDED.description
                """,
                SEED_TENANTS,
            )
            cursor.execute(
                """
                INSERT INTO rag_users (username, email, password_hash, tenant_id, role)
                VALUES ('admin', NULL, %s, NULL, 'admin')
                ON CONFLICT DO NOTHING
                """,
                (PasswordHasher().hash("admin"),),
            )
            cursor.execute(
                """
                UPDATE rag_users
                SET role = 'admin', tenant_id = NULL
                WHERE LOWER(username) = 'admin'
                """
            )
        from .contracts import ensure_default_contract

        tenants = connection.execute(
            "SELECT id, name, is_active FROM rag_tenants"
        ).fetchall()
        for tenant in tenants:
            ensure_default_contract(
                connection,
                tenant["id"],
                tenant["name"],
                initial_state="active" if tenant["is_active"] else "draft",
            )
        connection.execute(
            """
            UPDATE rag_documents d
            SET contract_id = c.id, contract_version = c.version
            FROM tenant_domain_contracts c
            WHERE c.tenant_id = d.tenant_id AND c.state = 'active'
              AND d.contract_id IS NULL
            """
        )
        connection.execute(
            """
            UPDATE rag_document_versions v
            SET contract_id = d.contract_id, contract_version = d.contract_version
            FROM rag_documents d
            WHERE d.id = v.document_id AND v.contract_id IS NULL
            """
        )
        connection.execute(
            """
            UPDATE rag_document_versions
            SET embedding_model = COALESCE(embedding_model, %s),
                chunk_size = COALESCE(chunk_size, %s),
                chunk_overlap = COALESCE(chunk_overlap, %s)
            WHERE embedding_model IS NULL OR chunk_size IS NULL OR chunk_overlap IS NULL
            """,
            (
                os.getenv("DOCUMENT_EMBEDDING_MODEL", "text-embedding-3-small"),
                int(os.getenv("DOCUMENT_CHUNK_SIZE", "1000")),
                int(os.getenv("DOCUMENT_CHUNK_OVERLAP", "150")),
            ),
        )
