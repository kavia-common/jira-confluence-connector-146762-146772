# Integration Backend (FastAPI)

This service handles OAuth 2.0 (3LO) with Atlassian for Jira and Confluence, persistence, and connector endpoints.

Canonical Atlassian OAuth Redirect URI (STRICT)
- The backend now uses a single env-driven canonical redirect URI for Jira, controlled by:
  - JIRA_REDIRECT_URI (required; if not set, a deployment default is used)
- The exact value must be registered in the Atlassian Developer Console under Redirect URLs.
- Default used when env is missing (for this deployment):
  https://vscode-internal-36721-beta.beta01.cloud.kavia.ai:3001/auth/jira/callback
- No legacy/front-end/alias fallbacks are used anymore.

Note: The acceptance criteria requires the Jira OAuth flow to use:
https://vscode-internal-36721-beta.beta01.cloud.kavia.ai:3001/auth/jira/callback

Environment variables (see .env.example)
- JIRA_REDIRECT_URI=
- JIRA_OAUTH_CLIENT_ID=
- JIRA_OAUTH_CLIENT_SECRET=
- CONFLUENCE_OAUTH_CLIENT_ID=
- CONFLUENCE_OAUTH_CLIENT_SECRET=
- APP_FRONTEND_URL=http://localhost:3000
- BACKEND_CORS_ORIGINS=http://localhost:3000
- INTEGRATION_DB_URL=sqlite:///./integration.db
- DEV_MODE=true

Notes:
- The frontend does not send redirect_uri. It calls the backend login endpoints and the backend sets redirect_uri.
- Backend initiates login with the exact redirect_uri resolved from environment (or the strict default).
- You can verify which redirect URI is active via:
  GET /health/redirect-uri
- You can verify the full authorize URL (with encoded redirect_uri) via:
  GET /health/authorize-url

Alias callback routes
- The backend exposes both non-/api and /api-prefixed alias routes for compatibility:
  - /auth/jira/login and /auth/jira/callback
  - /api/auth/jira/login and /api/auth/jira/callback
  - /auth/confluence/login and /auth/confluence/callback
  - /api/auth/confluence/login and /api/auth/confluence/callback
  - Generic alias: /api/oauth/atlassian/callback (delegates to Jira handler)
    (Note: For the Jira authorize URL, we still use JIRA_REDIRECT_URI only.)

Important
- Whatever redirect path you pick, JIRA_REDIRECT_URI must match it exactly in the Atlassian app.
- The backend no longer derives redirect_uri from other envs or uses legacy fallbacks.
