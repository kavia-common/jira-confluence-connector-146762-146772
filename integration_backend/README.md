# Integration Backend (FastAPI)

This service handles OAuth 2.0 (3LO) with Atlassian for Jira and Confluence, persistence, and connector endpoints.

Canonical Atlassian OAuth Redirect URI
- The backend uses a single env-driven canonical redirect URI for Atlassian, controlled by:
  - ATLASSIAN_OAUTH_REDIRECT_URI (preferred)
  - Fallbacks: ATLASSIAN_REDIRECT_URI, JIRA_OAUTH_REDIRECT_URI, CONFLUENCE_OAUTH_REDIRECT_URI
- The exact value must be registered in the Atlassian Developer Console under Redirect URLs.
- Example (canonical for this environment; register this exact URL in Atlassian Developer Console):
  https://vscode-internal-21156-beta.beta01.cloud.kavia.ai:3001/api/oauth/atlassian/callback
  Alternatively you can use:
  https://<backend-domain>/auth/jira/callback
  https://<backend-domain>/api/auth/jira/callback
  Ensure whatever you choose matches exactly in the Atlassian app settings.

Environment variables (see .env.example)
- ATLASSIAN_OAUTH_REDIRECT_URI=
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
- Backend initiates login with the exact redirect_uri resolved from environment.
- You can verify which redirect URI is active via:
  GET /health/redirect-uri

Alias callback routes
- The backend exposes both non-/api and /api-prefixed alias routes for compatibility:
  - /auth/jira/login and /auth/jira/callback
  - /api/auth/jira/login and /api/auth/jira/callback
  - /auth/confluence/login and /auth/confluence/callback
  - /api/auth/confluence/login and /api/auth/confluence/callback
  - Generic alias: /api/oauth/atlassian/callback (delegates to Jira handler)

Important
- Whatever redirect path you pick, ATLASSIAN_OAUTH_REDIRECT_URI must match it exactly.
- If you change to /api/oauth/atlassian/callback, update Atlassian app Redirect URL to the same absolute URL.

