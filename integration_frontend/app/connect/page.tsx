'use client';

import React from 'react';
import { getJiraAuthorizeUrl } from '../../lib/oauth';

export default function ConnectPage() {
  /** Connect page: provides a button to start Jira OAuth via backend and handles errors gracefully. */
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  const startJiraConnect = async () => {
    setError(null);
    setLoading(true);
    try {
      const state = Math.random().toString(36).slice(2); // simple demo state
      const url = await getJiraAuthorizeUrl({ state });
      window.location.href = url;
    } catch (e: any) {
      setError(e?.message || 'Failed to start Jira OAuth.');
      setLoading(false);
    }
  };

  return (
    <div style={{ maxWidth: 640, margin: '40px auto', padding: 24, background: '#fff', borderRadius: 12, boxShadow: '0 2px 8px rgba(0,0,0,0.06)' }}>
      <h1 style={{ fontSize: 24, marginBottom: 12 }}>Connect Jira</h1>
      <p style={{ color: '#374151', marginBottom: 16 }}>
        Click the button below to connect your Atlassian account via OAuth. You will be redirected to Atlassian to authorize.
      </p>
      {error && (
        <div style={{ background: '#FEF2F2', color: '#991B1B', padding: 12, borderRadius: 8, marginBottom: 12 }}>
          {error}
        </div>
      )}
      <button
        onClick={startJiraConnect}
        disabled={loading}
        style={{
          background: loading ? '#93C5FD' : '#2563EB',
          color: '#fff',
          padding: '10px 16px',
          borderRadius: 8,
          border: 'none',
          cursor: loading ? 'not-allowed' : 'pointer',
          transition: 'background 0.2s ease',
        }}
      >
        {loading ? 'Redirecting…' : 'Connect Jira'}
      </button>
      <div style={{ marginTop: 12, fontSize: 12, color: '#6B7280' }}>
        Ensure NEXT_PUBLIC_BACKEND_URL is set to your backend preview URL to avoid CORS/404 errors.
      </div>
    </div>
  );
}
