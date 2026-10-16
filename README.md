# Multi-Tenant RAG Assistants

A modular multi-tenant retrieval-augmented assistant project with a PostgreSQL-backed authentication API.

## Project modules

- [`src/multi_tenant_rag_assistants/frontend/authentication_frontend/`](src/multi_tenant_rag_assistants/frontend/authentication_frontend/) — authentication interface with sign-in, registration, theme switching, and a database-backed tenant selector
- [`src/multi_tenant_rag_assistants/frontend/chat_frontend/`](src/multi_tenant_rag_assistants/frontend/chat_frontend/) — authenticated chat workspace and message composer
- [`src/multi_tenant_rag_assistants/frontend/admin_frontend/`](src/multi_tenant_rag_assistants/frontend/admin_frontend/) — administrator dashboard for tenant lifecycle and tenant-grouped user management
- [`src/multi_tenant_rag_assistants/frontend/tenant_manager_frontend/`](src/multi_tenant_rag_assistants/frontend/tenant_manager_frontend/) — tenant-manager workspace combining chat, tenant-scoped member roles, and knowledge management
- [`src/multi_tenant_rag_assistants/backend/admin.py`](src/multi_tenant_rag_assistants/backend/admin.py) — administrator-only tenant management, account approval, and user suspension API
- [`src/multi_tenant_rag_assistants/backend/manager.py`](src/multi_tenant_rag_assistants/backend/manager.py) — tenant-scoped manager API for member visibility and role assignment
- [`src/multi_tenant_rag_assistants/backend/auth.py`](src/multi_tenant_rag_assistants/backend/auth.py) — FastAPI endpoints for tenants, registration, and sign-in
- [`src/multi_tenant_rag_assistants/backend/database.py`](src/multi_tenant_rag_assistants/backend/database.py) — idempotent PostgreSQL schema and tenant seeding

## Run locally

1. Configure `DATABASE_URL`, `AUTH_SECRET_KEY`, and `COOKIE_SECURE` in `.env`.
2. Install dependencies with `uv sync`.
3. Run `uv run multi-tenant-rag-assistants`.
4. Open `http://127.0.0.1:8000`.

The API creates `rag_tenants` and `rag_users` if needed and idempotently seeds IT, HR, Operations, and R&D tenants during startup. API documentation is available at `http://127.0.0.1:8000/docs`.
