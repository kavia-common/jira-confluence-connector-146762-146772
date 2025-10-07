# Integration Backend (FastAPI)

This service exposes the Jira-Confluence Integration API.

Run locally:
- Ensure Python 3.11+ and dependencies installed (pip install -r requirements.txt)
- Start server: `uvicorn src.api.main:app --host 0.0.0.0 --port 3001`

Key endpoints:
- GET /            -> Health JSON
- GET /health      -> Health JSON
- GET /routes      -> List routes
- GET /docs        -> Swagger UI
- GET /auth/jira   -> Returns { url } for Atlassian authorize

CORS:
Configured via environment. Defaults allow http://localhost:3000 for frontend development.

Verify:
- Curl: `curl -i http://localhost:3001/health`
- Browser: open http://localhost:3001/docs
