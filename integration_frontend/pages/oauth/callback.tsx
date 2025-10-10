import { useEffect } from "react";
import { useRouter } from "next/router";

export default function OAuthCallback() {
  const router = useRouter();
  useEffect(() => {
    const q = router.query || {};
    const oauth = (q.oauth as string) || (q.provider as string) || "atlassian";
    const status = (q.status as string) || "success";
    const state = (q.state as string) || "";
    // Route to login with state reference so login page can resolve CSRF
    const params = new URLSearchParams({ oauth, status, state });
    window.location.replace(`/login?${params.toString()}`);
  }, [router]);
  return null;
}
