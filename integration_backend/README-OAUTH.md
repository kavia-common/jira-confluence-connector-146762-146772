# OAuth Start Flow (Backend)

Required environment variables:
- ATLASSIAN_CLIENT_ID
- ATLASSIAN_REDIRECT_URI

Jira legacy OAuth vars (used by /auth/jira and /auth/jira/login):
- JIRA_OAUTH_CLIENT_ID
- JIRA_OAUTH_CLIENT_SECRET
- JIRA_OAUTH_REDIRECT_URI
  Set JIRA_OAUTH_REDIRECT_URI to:
  https://vscode-internal-21712-beta.beta01.cloud.kavia.ai:4000/oauth/jira

If these are missing, GET /api/oauth/atlassian/login will respond with 500 and a JSON error.

Routing:
- GET /api/oauth/start -> 307 to /api/oauth/atlassian/login (preserves ?redirect=... or ?return_url=... into ?redirect=...)
- GET /api/oauth/atlassian/login -> 302 to Atlassian authorize URL
- GET /routes -> lists registered routes for diagnostics
- GET /api/config -> shows effective backendBaseUrl, frontendBaseUrl, redirectUri and presence flags

Host and frontend settings:
- In cloud preview, your backend is hosted at a non-localhost domain (e.g., https://vscode-internal-XXXXX-beta.beta01.cloud.kavia.ai:3001).
- Do not call localhost:3001 from the frontend preview. Instead set NEXT_PUBLIC_BACKEND_URL to the preview domain and use it for all API calls.
- Example:
  NEXT_PUBLIC_BACKEND_URL=https://vscode-internal-XXXXX-beta.beta01.cloud.kavia.ai:3001

Dotenv:
- The application attempts to load .env automatically on startup.

Examples:
- Start login directly:
  GET ${NEXT_PUBLIC_BACKEND_URL}/api/oauth/atlassian/login
- Start via shim preserving UI redirect:
  GET ${NEXT_PUBLIC_BACKEND_URL}/api/oauth/start?redirect=${encodeURIComponent(`${window.location.origin}/connected`)}
