Ports Convention

- Backend (integration_backend - FastAPI): 3001
  - OAuth callback endpoints must use host:3001.
  - CORS allowlist should include http://localhost:3000 (and any environment-specific :3000 host).
- Frontend (integration_frontend - Next.js): 3000
  - API calls must target backend http://localhost:3001 (or environment-specific :3001 host).
  - NEXT_PUBLIC_BACKEND_BASE_URL should reference :3001.

Deployment callback requirement:
- ATLASSIAN_REDIRECT_URI=https://vscode-internal-29161-beta.beta01.cloud.kavia.ai:3001/api/oauth/callback/jira

Validation checklist:
- No references to backend on :4000.
- Backend configs/messages reference :3001 where a backend URL is needed.
- Frontend specific configs reference :3000 where a frontend URL is needed.
