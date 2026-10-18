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
    details JSONB NOT NULL DEFAULT '{}'::JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_rag_query_audit_outcome CHECK (
        outcome IN ('answered', 'abstained', 'denied', 'failed')
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
