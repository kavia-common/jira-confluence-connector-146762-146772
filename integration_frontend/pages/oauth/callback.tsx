import { useEffect } from "react";
import { useRouter } from "next/router";

export default function OAuthCallback() {
  const router = useRouter();
  useEffect(() => {
    const q = router.query || {};
    const state = (q.state as string) || "";
    // Do not fetch or render any JSON. Immediately navigate to /login with state param.
    const params = new URLSearchParams();
    if (state) params.set("state", state);
    router.replace(`/login${params.toString() ? `?${params.toString()}` : ""}`);
  }, [router]);
  return null;
}
