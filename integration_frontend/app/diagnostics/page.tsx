'use client';

import React, { useEffect, useState } from 'react';

type BackendConfig = {
  backendBaseUrl: string;
  frontendBaseUrl: string;
  redirectUri: string;
  hasClientId: boolean;
  hasRedirectUri: boolean;
  hasScopes: boolean;
  hasRedis: boolean;
  stateTtlSeconds: number;
};

export default function DiagnosticsPage() {
  const [health, setHealth] = useState<string>('Checking…');
  const [config, setConfig] = useState<BackendConfig | null>(null);
  const [error, setError] = useState<string | null>(null);
  const backend = process.env.NEXT_PUBLIC_BACKEND_URL;

  useEffect(() => {
    const run = async () => {
      setError(null);
      try {
        const hResp = await fetch(`${backend}/health`, { credentials: 'omit' });
        if (hResp.ok) {
          const h = await hResp.json();
          setHealth(`OK: ${h?.message || 'running'}`);
        } else {
          // fall back to root check
          const rResp = await fetch(`${backend}/`, { credentials: 'omit' });
          if (rResp.ok) {
            const r = await rResp.json();
            setHealth(`OK (/): ${r?.message || 'running'}`);
          } else {
            setHealth(`Failed (${hResp.status})`);
          }
        }

        const cResp = await fetch(`${backend}/api/config`, { credentials: 'omit' });
        if (cResp.ok) {
          const cfg = await cResp.json();
          setConfig(cfg);
        } else {
          setError(`Failed to fetch /api/config (${cResp.status})`);
        }
      } catch (e: any) {
        setError(e?.message || 'Network error contacting backend');
      }
    };
    if (backend) run();
    else setError('NEXT_PUBLIC_BACKEND_URL is not set');
  }, [backend]);

  return (
    <div style={{ maxWidth: 760, margin: '40px auto', padding: 24, background: '#fff', borderRadius: 12, boxShadow: '0 2px 8px rgba(0,0,0,0.06)' }}>
      <h1 style={{ fontSize: 24, marginBottom: 12 }}>Diagnostics</h1>
      <div style={{ marginBottom: 12, color: '#374151' }}>
        Backend URL: <code>{backend || '(not set)'}</code>
      </div>
      {error && (
        <div style={{ background: '#FEF2F2', color: '#991B1B', padding: 12, borderRadius: 8, marginBottom: 12 }}>
          {error}
        </div>
      )}
      <div style={{ background: '#ECFDF5', color: '#065F46', padding: 12, borderRadius: 8, marginBottom: 12 }}>
        Health: {health}
      </div>
      <h2 style={{ fontSize: 18, marginTop: 16, marginBottom: 8 }}>Backend Config</h2>
      {config ? (
        <pre style={{ background: '#F3F4F6', padding: 12, borderRadius: 8, overflow: 'auto' }}>
          {JSON.stringify(config, null, 2)}
        </pre>
      ) : (
        <div style={{ color: '#6B7280' }}>Loading /api/config…</div>
      )}
      <div style={{ marginTop: 16, fontSize: 12, color: '#6B7280' }}>
        Note: Ensure BACKEND_CORS_ORIGINS includes this frontend origin. For previews, set NEXT_PUBLIC_BACKEND_URL to the backend preview domain.
      </div>
    </div>
  );
}
