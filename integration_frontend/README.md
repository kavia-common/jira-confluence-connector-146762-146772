# Integration Frontend

This minimal Next.js frontend includes a simple connect flow for Atlassian/Jira OAuth.

Environment variables:
- NEXT_PUBLIC_BACKEND_URL: Absolute URL to the running backend (e.g., https://vscode-internal-XXXXX-beta.beta01.cloud.kavia.ai:3001)

Pages:
- /connect: Preferred return page for the OAuth flow. Start login using:
  GET {NEXT_PUBLIC_BACKEND_URL}/api/oauth/atlassian/login?return_url=${encodeURIComponent(window.location.origin + '/connect')}
  The backend will redirect back to /connect with ?result=success or ?result=error&message=...
- /oauth/callback: Legacy route used by older flows that return provider/status/user_id/state.

Notes:
- Ensure CORS settings on the backend include your frontend origin (config via BACKEND_CORS_ORIGINS).
- For full PKCE flow, you can also start at GET {NEXT_PUBLIC_BACKEND_URL}/api/oauth/atlassian/login.
