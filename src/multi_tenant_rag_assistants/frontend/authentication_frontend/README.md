# Atlas authentication front end

This is a buildless authentication interface served by the FastAPI backend. The files are split so each piece can be tested or replaced independently:

- `index.html` — semantic page and form markup
- `styles/main.css` — responsive visual system
- `scripts/features/auth-form.js` — tab switching, validation, and API submission
- `scripts/components/tenant-select.js` — accessible tenant dropdown component
- `scripts/config.js` — API base URL configuration

## Run locally

From the repository root, run the combined frontend and API server:

```powershell
uv run multi-tenant-rag-assistants
```

Then open `http://127.0.0.1:8000`.

To run JavaScript syntax checks:

```powershell
cd src/multi_tenant_rag_assistants/frontend/authentication_frontend
npm run check
```

Tenant options are loaded from `GET /api/tenants`. Registration and sign-in submit to the authentication API; passwords are never stored by the browser or returned by the server.
