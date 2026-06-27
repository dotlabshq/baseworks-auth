// Edge/server session: Pomerium JWT assertion headers + OIDC cookie fallback.
// Requires: next/headers (peer dep: next).

import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { getSessionFromCookies, type OidcSession } from "./session";
import { buildPublicUrl, normalizeUrlLike } from "./url-helpers";

export type EdgeAuthProvider = "anonymous" | "cookie" | "pomerium";

export type EdgeSession = OidcSession & {
  groups?: string[];
  provider: EdgeAuthProvider;
  rawClaims?: Record<string, unknown>;
  role?: string;
  username?: string;
};

function firstHeader(headerStore: Headers, names: string[]) {
  for (const name of names) {
    const value = headerStore.get(name);
    if (value) return value;
  }
  return undefined;
}

function decodeBase64Url(value: string) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(normalized.length + ((4 - (normalized.length % 4)) % 4), "=");
  return Buffer.from(padded, "base64").toString("utf8");
}

function parseJwtPayload(token: string): Record<string, unknown> | null {
  try {
    const [, payload] = token.split(".");
    if (!payload) return null;
    return JSON.parse(decodeBase64Url(payload)) as Record<string, unknown>;
  } catch {
    return null;
  }
}

function stringClaim(claims: Record<string, unknown>, keys: string[]) {
  for (const key of keys) {
    const value = claims[key];
    if (typeof value === "string" && value.trim()) return value;
    if (Array.isArray(value)) {
      const first = value.find((item) => typeof item === "string" && item.trim());
      if (first) return first as string;
    }
  }
  return undefined;
}

function parseHeaderClaim(value: string | undefined) {
  if (!value) return undefined;
  try {
    const parsed = JSON.parse(value) as unknown;
    if (typeof parsed === "string" && parsed.trim()) return parsed;
    if (Array.isArray(parsed)) {
      const first = parsed.find((item) => typeof item === "string" && item.trim());
      if (first) return first as string;
    }
  } catch {
    // Pomerium may forward plain header values depending on configuration.
  }
  return value.trim() || undefined;
}

function stringHeaderClaim(headerStore: Headers, names: string[]) {
  for (const name of names) {
    const value = parseHeaderClaim(headerStore.get(name) ?? undefined);
    if (value) return value;
  }
  return undefined;
}

function stringArrayClaim(claims: Record<string, unknown>, keys: string[]) {
  for (const key of keys) {
    const value = claims[key];
    if (typeof value === "string" && value.trim()) return [value];
    if (Array.isArray(value)) {
      const strings = value.filter((item): item is string => typeof item === "string" && item.trim().length > 0);
      if (strings.length) return strings;
    }
  }
  return undefined;
}

function stringArrayHeaderClaim(headerStore: Headers, names: string[]) {
  for (const name of names) {
    const raw = headerStore.get(name);
    if (!raw) continue;
    try {
      const parsed = JSON.parse(raw) as unknown;
      if (typeof parsed === "string" && parsed.trim()) return [parsed];
      if (Array.isArray(parsed)) {
        const strings = parsed.filter((item): item is string => typeof item === "string" && item.trim().length > 0);
        if (strings.length) return strings;
      }
    } catch {
      const values = raw.split(",").map((v) => v.trim()).filter(Boolean);
      if (values.length) return values;
    }
  }
  return undefined;
}

function parsePomeriumSession(headerStore: Headers): EdgeSession | null {
  const assertion = firstHeader(headerStore, ["x-pomerium-jwt-assertion", "x-pomerium-jwt"]);
  const claims = assertion ? parseJwtPayload(assertion) : {};

  const email =
    stringHeaderClaim(headerStore, ["x-pomerium-claim-email", "x-forwarded-email"]) ??
    stringClaim(claims ?? {}, ["email"]);
  const subject =
    stringHeaderClaim(headerStore, ["x-pomerium-claim-sub", "x-pomerium-claim-user", "x-user-id"]) ??
    stringClaim(claims ?? {}, ["sub", "user", "id"]);
  const name =
    stringHeaderClaim(headerStore, ["x-pomerium-claim-name", "x-forwarded-user"]) ??
    stringClaim(claims ?? {}, ["name", "preferred_username"]);
  const pictureUrl =
    stringHeaderClaim(headerStore, ["x-pomerium-claim-picture"]) ??
    stringClaim(claims ?? {}, ["picture"]);
  const username =
    stringHeaderClaim(headerStore, ["x-pomerium-claim-username", "x-pomerium-claim-preferred-username"]) ??
    stringClaim(claims ?? {}, ["username", "preferred_username", "user"]);
  const groups =
    stringArrayHeaderClaim(headerStore, ["x-pomerium-claim-groups", "x-pomerium-claim-roles"]) ??
    stringArrayClaim(claims ?? {}, ["groups", "roles"]);
  const role =
    stringHeaderClaim(headerStore, ["x-pomerium-claim-role"]) ??
    stringClaim(claims ?? {}, ["role"]);

  if (!email && !subject && !name) return null;

  return {
    email,
    expiresAt: Number.MAX_SAFE_INTEGER,
    groups,
    isAuthenticated: true,
    name,
    pictureUrl,
    provider: "pomerium",
    rawClaims: claims ?? undefined,
    role,
    subject: subject ?? email,
    username,
  };
}

export async function getEdgeSession(): Promise<EdgeSession> {
  const headerStore = await headers();
  const pomerium = parsePomeriumSession(headerStore);
  if (pomerium) return pomerium;

  const cookieSession = await getSessionFromCookies();
  if (cookieSession.isAuthenticated) {
    return { ...cookieSession, provider: "cookie" };
  }

  return { expiresAt: 0, isAuthenticated: false, provider: "anonymous" };
}

export function getPomeriumAuthenticateUrl(redirectTo: string, origin?: string) {
  const appUrl = origin ?? process.env.APP_PUBLIC_URL ?? process.env.NEXT_PUBLIC_SITE_URL;
  if (!appUrl) return null;
  const url = new URL(
    process.env.POMERIUM_LOGIN_PATH ?? "/auth/edge/login",
    `${normalizeUrlLike(appUrl)}/`,
  );
  url.searchParams.set("pomerium_redirect_uri", buildPublicUrl(redirectTo, origin));
  return url.toString();
}

export function handleEdgeLogin(request: Request) {
  const url = new URL(request.url);
  const redirectTo = url.searchParams.get("pomerium_redirect_uri") ?? "/";
  redirect(redirectTo);
}

export function getPomeriumSignOutUrl(redirectTo: string, origin?: string) {
  const authUrl =
    process.env.POMERIUM_AUTHENTICATE_URL ?? process.env.POMERIUM_AUTH_URL ?? origin;
  if (!authUrl) return null;
  const url = new URL("/.pomerium/sign_out", `${normalizeUrlLike(authUrl)}/`);
  url.searchParams.set("pomerium_redirect_uri", buildPublicUrl(redirectTo, origin));
  return url.toString();
}
