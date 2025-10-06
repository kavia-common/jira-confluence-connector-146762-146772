'use client';

import React, { useEffect, useMemo, useState } from 'react';

function useQuery() {
  const [params, setParams] = useState<URLSearchParams>(new URLSearchParams());
  useEffect(() => {
    setParams(new URLSearchParams(window.location.search));
  }, []);
  return params;
}

export default function OAuthCallbackPage() {
  /** Displays result of OAuth redirect from backend and provides next steps. */
  const q = useQuery();
  const provider = q.get('provider');
  const status = q.get('status');
  const userId = q.get('user_id');
  const state = q.get('state');

  const isSuccess = status === 'success';
  const message = useMemo(() => {
    if (!provider || !status) return 'Missing parameters from OAuth callback.';
    if (isSuccess) return `Successfully connected ${provider}.`;
    return `OAuth flow for ${provider} returned status: ${status}`;
  }, [provider, status, isSuccess]);

  return (
    <div style={{ maxWidth: 640, margin: '40px auto', padding: 24, background: '#fff', borderRadius: 12, boxShadow: '0 2px 8px rgba(0,0,0,0.06)' }}>
      <h1 style={{ fontSize: 24, marginBottom: 12 }}>OAuth Callback</h1>
      <div
        style={{
          background: isSuccess ? '#ECFDF5' : '#FEF2F2',
          color: isSuccess ? '#065F46' : '#991B1B',
          padding: 12,
          borderRadius: 8,
          marginBottom: 12,
        }}
      >
        {message}
      </div>
      <div style={{ fontSize: 14, color: '#374151', marginBottom: 16 }}>
        <div><strong>Provider:</strong> {provider || '-'}</div>
        <div><strong>Status:</strong> {status || '-'}</div>
        <div><strong>User ID:</strong> {userId || '-'}</div>
        <div><strong>State:</strong> {state || '-'}</div>
      </div>
      <a
        href="/connect"
        style={{
          color: '#2563EB',
          textDecoration: 'none',
          padding: '8px 0',
          display: 'inline-block',
        }}
      >
        Back to Connect
      </a>
    </div>
  );
}
