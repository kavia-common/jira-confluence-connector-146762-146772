# Integration Frontend

This minimal Next.js frontend includes a simple connect flow for Atlassian/Jira OAuth.

Environment variables:
- NEXT_PUBLIC_BACKEND_URL: Absolute URL to the running backend (e.g., https://vscode-internal-XXXXX-beta.beta01.cloud.kavia.ai:3001)
  Required for cloud previews where frontend and backend are on different hosts. The frontend will prefer this value.

Pages:
- /connect: Preferred return page for the OAuth flow. Start login using:
  GET {NEXT_PUBLIC_BACKEND_URL}/api/oauth/atlassian/login?return_url=${encodeURIComponent(window.location.origin + '/connect')}
  The backend will redirect back to /connect with ?result=success or ?result=error&message=...
  Note: return_url must be an absolute URL. State entries are valid for 10 minutes; late callbacks will show a clear error with a link back to /connect.
- /oauth/callback: Legacy route used by older flows that return provider/status/user_id/state.

Notes:
- Ensure CORS settings on the backend include your frontend origin (config via BACKEND_CORS_ORIGINS).
- For full PKCE flow, you can also start at GET {NEXT_PUBLIC_BACKEND_URL}/api/oauth/atlassian/login.
