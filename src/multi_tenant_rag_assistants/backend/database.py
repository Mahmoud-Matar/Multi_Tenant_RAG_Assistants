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
