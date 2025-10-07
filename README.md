# Integration Backend (FastAPI)

This service exposes the Jira-Confluence Integration API.

Run locally:
- Ensure Python 3.11+ and dependencies installed (pip install -r requirements.txt)
- Start server: `uvicorn src.api.main:app --host 0.0.0.0 --port 3001`

Key endpoints:
- GET /                  -> Health JSON
- GET /health            -> Health JSON
- GET /routes            -> List routes
- GET /docs              -> Swagger UI
- GET /auth/jira         -> Returns { url } for Atlassian authorize
- GET /auth/status       -> Lightweight connection status (JSON)

CORS:
- Configured via environment with credentials enabled (cookies used for OAuth).
- Set BACKEND_CORS_ORIGINS to a comma-separated list of exact origins that are allowed to call the backend.
  Example:
    BACKEND_CORS_ORIGINS=https://vscode-internal-18211-beta.beta01.cloud.kavia.ai:4000,http://localhost:3000
- Do NOT use '*' when credentials are in use (allow_credentials=True).
- If BACKEND_CORS_ORIGINS is unset, the backend defaults to ["http://localhost:3000"] for development.
- If NEXT_PUBLIC_FRONTEND_BASE_URL or FRONTEND_BASE_URL are present, their exact values are also included automatically.
- The backend also ensures the preview frontend origin is included when applicable for cloud previews.

Verify:
- Curl: `curl -i http://localhost:3001/health`
- Browser: open http://localhost:3001/docs

CORS Verification (with credentials):
- After setting BACKEND_CORS_ORIGINS appropriately, a request from your frontend origin should receive:
  Access-Control-Allow-Origin: <your-frontend-origin>
  Access-Control-Allow-Credentials: true
- Example preflight:
  curl -i -X OPTIONS \
    -H "Origin: https://vscode-internal-18211-beta.beta01.cloud.kavia.ai:4000" \
    -H "Access-Control-Request-Method: GET" \
    http://localhost:3001/auth/status
