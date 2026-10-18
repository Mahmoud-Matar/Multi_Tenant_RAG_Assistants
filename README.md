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
- [`src/multi_tenant_rag_assistants/backend/documents.py`](src/multi_tenant_rag_assistants/backend/documents.py) — tenant-authorized quarantine, document registry, approval, versioning, background ingestion, shared Chroma indexing, and retrieval enforcement
- [`src/multi_tenant_rag_assistants/RAG/`](src/multi_tenant_rag_assistants/RAG/) — modular tenant-aware query screening, retrieval, ACL verification, grounded generation, citation validation, and auditing
- [`docs/document-storage-pipeline.md`](docs/document-storage-pipeline.md) — document lifecycle, API, storage, metadata, and security reference
- [`docs/rag-query-pipeline.md`](docs/rag-query-pipeline.md) — runtime RAG security boundary, response contract, and configuration reference

## Prerequisites

- Python 3.12 or newer
- [`uv`](https://docs.astral.sh/uv/) for dependency and environment management
- PostgreSQL running with a database for the application, such as `rag_db`
- An OpenAI API key with access to the configured embedding and chat models

## Run locally

1. Copy `.env.example` to a new file named `.env`.
2. Configure `OPENAI_API_KEY`, `DATABASE_URL`, `AUTH_SECRET_KEY`, and
   `COOKIE_SECURE` in `.env`.
3. Install dependencies with `uv sync`.
4. Run `uv run multi-tenant-rag-assistants`.
5. Open `http://127.0.0.1:8000`.

Only `.env` is loaded by the application. It contains local secrets and is ignored
by Git. `.env.example` is the public template and must contain placeholders rather
than real credentials.

### Environment variables

| Variable | Purpose |
| --- | --- |
| `OPENAI_API_KEY` | Authenticates requests to OpenAI for document embeddings, query embeddings, and grounded answer generation. Create a key in your OpenAI account and never commit it. |
| `DATABASE_URL` | PostgreSQL connection string, including the host, port, database name, user, and password. Example structure: `postgresql://user:password@127.0.0.1:5432/rag_db`. |
| `AUTH_SECRET_KEY` | Private random value used to sign and validate login session tokens. Use a long, unpredictable value that is different from your database password and OpenAI key. Changing it signs out existing sessions. |
| `COOKIE_SECURE` | Controls whether the browser sends the session cookie only over HTTPS. Use `false` for local HTTP development and `true` for an HTTPS deployment. |
| `DOCUMENT_MAX_BYTES` | Maximum accepted upload size in bytes. The default `20971520` is 20 MiB. |
| `DOCUMENT_SCANNER_MODE` | Upload scanning mode. `basic` performs development validation and EICAR detection; production should use `clamav`. |
| `CLAMAV_COMMAND` | Optional ClamAV executable or command name used when the scanner mode is `clamav`. It remains commented out for the default basic mode. |
| `DOCUMENT_CHUNK_SIZE` | Target character length of chunks produced before embedding. |
| `DOCUMENT_CHUNK_OVERLAP` | Number of overlapping characters retained between adjacent chunks to preserve context. |
| `DOCUMENT_EMBEDDING_MODEL` | OpenAI embedding model used for both ingestion and query embeddings. Changing it requires reindexing existing documents. |
| `RAG_CHAT_MODEL` | OpenAI chat model used to generate evidence-constrained answers. Phase 1 uses `gpt-4o-mini`. |
| `RAG_TOP_K` | Default maximum number of authorized chunks supplied as evidence for a question. The API caps requests at 10. |
| `RAG_MAX_DISTANCE` | Maximum accepted Chroma cosine distance. Results with a larger distance are treated as insufficiently relevant. |

The API creates `rag_tenants` and `rag_users` if needed and idempotently seeds IT, HR, Operations, and R&D tenants during startup. API documentation is available at `http://127.0.0.1:8000/docs`.

Document originals are written below `storage/`, embeddings are persisted below
`chroma_data/`, and lifecycle records remain authoritative in PostgreSQL. Both
runtime directories are excluded from Git.

Authenticated users and tenant managers query the knowledge base through
`POST /api/rag/query`. The tenant and allowed access scopes are always derived
from the signed session and revalidated in PostgreSQL; the client cannot select
or override them.
