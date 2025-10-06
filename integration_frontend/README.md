# Integration Frontend

This minimal Next.js frontend includes a simple connect flow for Atlassian/Jira OAuth.

Environment variables:
- NEXT_PUBLIC_BACKEND_URL: Absolute URL to the running backend (e.g., https://vscode-internal-XXXXX-beta.beta01.cloud.kavia.ai:3001)

Pages:
- /connect: Renders a button to start the Jira OAuth flow using GET {NEXT_PUBLIC_BACKEND_URL}/auth/jira which returns JSON { url }.
- /oauth/callback: Displays the result after the backend redirects back to the frontend with query params (?provider=&status=&user_id=&state=).

Notes:
- Ensure CORS settings on the backend include your frontend origin (config via BACKEND_CORS_ORIGINS).
- For full PKCE flow, you can also start at GET {NEXT_PUBLIC_BACKEND_URL}/api/oauth/atlassian/login.
