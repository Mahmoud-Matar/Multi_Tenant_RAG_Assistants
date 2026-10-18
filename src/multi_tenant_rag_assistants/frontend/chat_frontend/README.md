# Atlas chat frontend

This bundle is the authenticated landing page served at `/chat`.

- `index.html` contains the chat workspace structure.
- `styles/main.css` contains the responsive light and dark themes.
- `scripts/app.js` loads the signed-in user, manages the composer, and handles logout.

Message submission calls the authenticated `/api/rag/query` endpoint and renders
grounded answers with expandable source citations.
