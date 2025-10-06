# OAuth Start Flow (Backend)

Aligned Atlassian OAuth endpoints with return_url handling.

Required environment variables:
- ATLASSIAN_CLIENT_ID
- ATLASSIAN_REDIRECT_URI
- ATLASSIAN_CLIENT_SECRET (optional with PKCE)
- ATLASSIAN_SCOPES (optional; space-separated)
- BACKEND_CORS_ORIGINS (comma-separated origins; include your frontend origin)

Jira legacy OAuth vars (used by /auth/jira and /auth/jira/login):
- JIRA_OAUTH_CLIENT_ID
- JIRA_OAUTH_CLIENT_SECRET
- JIRA_OAUTH_REDIRECT_URI

If these are missing, GET /api/oauth/atlassian/login will respond with 500 and a JSON error.

New/Aligned Routing:
- GET /api/oauth/atlassian/login
  Query: return_url (required absolute URL), scope (optional)
  Behavior: generate state + PKCE, persist state->return_url, set httpOnly sid cookie, redirect (307) to Atlassian authorize
- GET /api/oauth/atlassian/callback
  Query: code, state
  Behavior: validate state and session, exchange code for tokens, persist tokens (in-memory session), redirect 307 to saved return_url with:
    - success: ?result=success
    - error: ?result=error&message=<url-encoded message>

Compatibility/Diagnostics:
- GET /api/oauth/start -> 307 to /api/oauth/atlassian/login (preserves redirect/return_url into redirect state embedding)
- GET /routes -> lists registered routes for diagnostics
- GET /api/config -> shows effective backendBaseUrl, frontendBaseUrl, redirectUri and presence flags

Frontend Integration:
- Use your Connect page (e.g., /connect) as return_url:
  window.location.href = `${BACKEND_URL}/api/oauth/atlassian/login?return_url=${encodeURIComponent(window.location.origin + '/connect')}`
- After auth, the backend redirects to:
  /connect?result=success
  or /connect?result=error&message=...

Host and frontend settings:
- In cloud preview, your backend is hosted at a non-localhost domain (e.g., https://...:3001).
- Do not call localhost:3001 from the frontend preview. Instead set NEXT_PUBLIC_BACKEND_URL to the preview domain and use it for all API calls.
- Example:
  NEXT_PUBLIC_BACKEND_URL=https://vscode-internal-XXXXX-beta.beta01.cloud.kavia.ai:3001

Dotenv:
- The application attempts to load .env automatically on startup.
- See integration_backend/.env.example for variables.

Examples:
- Start login directly with return_url to /connect:
  GET ${NEXT_PUBLIC_BACKEND_URL}/api/oauth/atlassian/login?return_url=${encodeURIComponent(`${window.location.origin}/connect`)}
- Start via shim preserving UI redirect (alternate path):
  GET ${NEXT_PUBLIC_BACKEND_URL}/api/oauth/start?redirect=${encodeURIComponent(`${window.location.origin}/connect`)}
