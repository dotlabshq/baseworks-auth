/**
 * Token hashing utilities — no libsodium dependency, Web Crypto only.
 * Runtime-agnostic: Workers, Node 20+, browser.
 */

/** HMAC-SHA-256 hash with optional pepper. Use for API key storage at rest. */
export async function hashToken(token: string, pepper?: string): Promise<string> {
  const input = pepper ? `${pepper}:${token}` : token;
  const buf   = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('');
}

export function looksLikeJwt(token: string): boolean {
  return token.split('.').length === 3;
}

export function stripBearer(header: string | null | undefined): string | null {
  if (!header?.startsWith('Bearer ')) return null;
  const token = header.slice(7).trim();
  return token || null;
}
