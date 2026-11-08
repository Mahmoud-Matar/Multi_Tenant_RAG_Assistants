# Atlas Multi-Tenant RAG Assistants Phase 2

A governed multi-tenant retrieval-augmented assistant with signed tenant policy,
tenant-filtered knowledge retrieval, hardened authentication, document governance,
and tenant-scoped security incident response. The current release is Phase 2
(`0.2.0`).

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
- [`docs/security-incident-response.md`](docs/security-incident-response.md) — suspicious-content blocking, incident fields, role visibility, and triage workflow
- [`docs/authentication-security.md`](docs/authentication-security.md) — signing-key rotation, Origin enforcement, lockout, verification/reset, and session revocation

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

Hot reload is disabled by default. Set `APP_RELOAD=true` only for local development.

Only `.env` is loaded by the application. It contains local secrets and is ignored
by Git. `.env.example` is the public template and must contain placeholders rather
than real credentials.

### Environment variables

| Variable | Purpose |
| --- | --- |
| `OPENAI_API_KEY` | Authenticates requests to OpenAI for document embeddings, query embeddings, and grounded answer generation. Create a key in your OpenAI account and never commit it. |
| `DATABASE_URL` | PostgreSQL connection string, including the host, port, database name, user, and password. Example structure: `postgresql://user:password@127.0.0.1:5432/rag_db`. |
| `AUTH_SECRET_KEY` | Private value of at least 32 bytes used to sign login sessions. Changing it without listing the old key in `AUTH_PREVIOUS_KEYS` signs out existing sessions. |
| `AUTH_KEY_ID` | Identifier placed in new JWT headers so multiple signing keys can coexist during rotation. |
| `AUTH_PREVIOUS_KEYS` | Optional JSON object containing old key IDs and secrets while their sessions age out. |
| `AUTH_JWT_ISSUER` / `AUTH_JWT_AUDIENCE` | Values required when issuing and validating every session token. |
| `AUTH_ALLOWED_ORIGINS` | Comma-separated exact browser origins allowed to make state-changing API requests. |
| `AUTH_EMAIL_MODE` | `smtp`, `console` for isolated development, or `disabled`. SMTP is required for a live verification/reset flow. |
| `PUBLIC_BASE_URL` | HTTPS application origin used to construct verification and reset links. |
| `APP_HOST` / `APP_PORT` | Bind address and port for the packaged server command. Defaults to `127.0.0.1:8000`. |
| `APP_RELOAD` | Enables Uvicorn hot reload when `true`. Keep `false` outside local development. |
| `TDC_SIGNING_KEY` | Signs versioned Tenant Domain Contracts. Use a separate long random value in deployment. Local development falls back to `AUTH_SECRET_KEY` for compatibility. |
| `COOKIE_SECURE` | Controls whether the browser sends the session cookie only over HTTPS. Use `false` for local HTTP development and `true` for an HTTPS deployment. |
| `DOCUMENT_MAX_BYTES` | Maximum accepted upload size in bytes. The default `20971520` is 20 MiB. |
| `DOCUMENT_SCANNER_MODE` | Upload scanning mode. `basic` performs development validation and EICAR detection; production should use `clamav`. |
| `CLAMAV_COMMAND` | Optional ClamAV executable or command name used when the scanner mode is `clamav`. It remains commented out for the default basic mode. |
| `DOCUMENT_CHUNK_SIZE` | Target character length of chunks produced before embedding. |
| `DOCUMENT_CHUNK_OVERLAP` | Number of overlapping characters retained between adjacent chunks to preserve context. |
| `DOCUMENT_EMBEDDING_MODEL` | OpenAI embedding model used for both ingestion and query embeddings. Changing it requires reindexing existing documents. |
| `RAG_CHAT_MODEL` | OpenAI chat model used to generate evidence-constrained answers. Phase 2 defaults to `gpt-4o-mini`. |
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

Authentication sessions are server-side revocable and exposed through the
**Account security** page. New registrations require email verification and admin
approval. Login, registration, verification, and reset endpoints are persistently
rate-limited, repeated password failures trigger progressive account lockout, and
unsafe API requests require an explicitly allowed browser Origin.

Platform administrators manage versioned Tenant Domain Contracts from the
**Domain contracts** tab. Contracts validate tenant knowledge policy, domain
boundaries, roles, retrieval thresholds, metric definitions, model routes,
retention, and isolation tiers. Drafts must be approved before activation, and
every active contract is hash-verified and HMAC-signed before use.

New tenants begin in an inactive onboarding state with contract version 1 as a
signed draft. They are hidden from public registration and cannot accept uploads
or chat requests until an administrator approves and activates the contract.
Contract activation activates the tenant atomically; manual tenant activation is
rejected when no valid active contract exists.

The restored RAG path uses the original vector-distance retrieval and citation
validation while preserving tenant and ACL authorization. It screens both questions
and retrieved chunks for prompt injection, tenant escape, exfiltration, poisoning,
and hidden text.
Flagged content never reaches answer generation. Instead, a redacted in-app report
is created for the tenant's managers and platform administrators, who can
acknowledge or resolve it from their dashboards. External email/SIEM delivery is
not part of the current implementation.

## Phase 2 release boundary

Phase 2 includes authenticated user, tenant-manager, and platform-administrator
surfaces; server-side sessions and revocation; signed versioned Tenant Domain
Contracts; approved document ingestion and versioning; tenant and ACL filtered
retrieval; evidence-only answers with citations and abstention; query audit events;
and in-app security incident triage.

The manager BI agent, metric-first analytics, controlled NL-to-SQL, provider-
agnostic model routing, durable ingestion workers, and formal database migrations
remain future phases. Document ingestion currently uses FastAPI background tasks,
so an interrupted API process can lose queued work. PostgreSQL startup DDL remains
the current schema bootstrap. These limits are documented rather than hidden.

Operational probes are available at `GET /api/health/live` and
`GET /api/health/ready`; the compatibility route `GET /api/health` performs the
same readiness check. API responses include `X-Request-ID` and `Cache-Control:
no-store`.

## Verification

Run the complete non-billable test suite:

```powershell
uv run python -m unittest discover -s tests -v
```

The live OpenAI smoke test is opt-in because it consumes API quota:

```powershell
$env:RUN_OPENAI_RAG_TESTS = "1"
uv run python -m unittest tests.test_rag_pipeline.RAGPipelineTests.test_real_openai_embedding_and_grounded_generation -v
```

See [`docs/phase-2-release.md`](docs/phase-2-release.md) for acceptance criteria,
tested boundaries, and known limitations.
