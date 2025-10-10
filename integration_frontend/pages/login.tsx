import { useEffect, useState } from "react";

type LoginResult = {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
};

export default function LoginPage() {
  const [csrf, setCsrf] = useState<string>("");
  const [email, setEmail] = useState<string>("");
  const [password, setPassword] = useState<string>("");
  const [error, setError] = useState<string>("");
  const [loading, setLoading] = useState<boolean>(false);

  const backendBase =
    process.env.NEXT_PUBLIC_BACKEND_BASE_URL || "";

  useEffect(() => {
    async function fetchCsrf() {
      try {
        const res = await fetch(`${backendBase}/auth/csrf`, {
          credentials: "include",
        });
        const data = await res.json();
        if (data?.token) {
          setCsrf(data.token);
        } else if (data?.status === "success" && data?.token) {
          setCsrf(data.token);
        }
      } catch (e) {
        setError("Failed to fetch CSRF token");
      }
    }
    fetchCsrf();
  }, [backendBase]);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const res = await fetch(`${backendBase}/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": csrf,
        },
        credentials: "include",
        body: JSON.stringify({ email, password }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        setError(err?.message || err?.detail || "Login failed");
      } else {
        const data: LoginResult = await res.json();
        // Store tokens (for demo; production should use httpOnly cookies)
        localStorage.setItem("access_token", data.access_token);
        localStorage.setItem("refresh_token", data.refresh_token);
        window.location.href = "/";
      }
    } catch (e: any) {
      setError(e?.message || "Network error");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={{ minHeight: "100vh", display: "grid", placeItems: "center", background: "#f9fafb" }}>
      <form
        onSubmit={onSubmit}
        style={{
          background: "#ffffff",
          padding: "2rem",
          width: "100%",
          maxWidth: 420,
          borderRadius: 12,
          boxShadow: "0 10px 25px rgba(0,0,0,0.08)",
        }}
      >
        <h1 style={{ margin: 0, marginBottom: 8, fontSize: 24, color: "#111827" }}>Sign in</h1>
        <p style={{ marginTop: 0, color: "#6b7280" }}>Use your account credentials</p>

        <label style={{ display: "block", fontSize: 14, color: "#374151", marginTop: 16 }}>Email</label>
        <input
          type="email"
          required
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="you@example.com"
          style={{
            width: "100%",
            padding: "10px 12px",
            borderRadius: 8,
            border: "1px solid #e5e7eb",
            outline: "none",
            marginTop: 4,
          }}
        />

        <label style={{ display: "block", fontSize: 14, color: "#374151", marginTop: 16 }}>Password</label>
        <input
          type="password"
          required
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="********"
          style={{
            width: "100%",
            padding: "10px 12px",
            borderRadius: 8,
            border: "1px solid #e5e7eb",
            outline: "none",
            marginTop: 4,
          }}
        />

        {error ? (
          <div style={{ color: "#EF4444", marginTop: 12, fontSize: 14 }}>{error}</div>
        ) : null}

        <button
          type="submit"
          disabled={loading || !csrf}
          style={{
            width: "100%",
            marginTop: 20,
            background: "#2563EB",
            color: "white",
            border: "none",
            borderRadius: 8,
            padding: "10px 12px",
            cursor: "pointer",
            opacity: loading || !csrf ? 0.7 : 1,
          }}
        >
          {loading ? "Signing in..." : "Sign in"}
        </button>
      </form>
    </div>
  );
}
