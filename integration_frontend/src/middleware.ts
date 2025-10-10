/**
 * Next.js middleware to redirect unauthenticated users from protected routes to /login.
 * Note: For a simple demo, protect the root path '/'.
 */
import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';

export async function middleware(req: NextRequest) {
  const url = req.nextUrl.clone();
  if (url.pathname === '/') {
    // Call backend session; since middleware cannot fetch with credentials cross-origin,
    // rely on cookie presence heuristic: if no access cookie, redirect.
    const accessCookie = req.cookies.get('access_token');
    if (!accessCookie) {
      url.pathname = '/login';
      return NextResponse.redirect(url);
    }
  }
  return NextResponse.next();
}

export const config = {
  matcher: ['/'],
};
