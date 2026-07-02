// Next.js OIDC session management — PKCE flow, cookie helpers, logout.
// Requires: next, next/headers, next/server (peer deps).

import { cookies } from "next/headers";
import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";
import { base64urlEncode, base64urlDecodeString } from "@baseworks/core";
import { getAuthPublicUrl, normalizeUrlLike } from "./url-helpers";
import { generatePkce } from "./pkce.js";

type DiscoveryDocument = {
  authorization_endpoint: string;
  end_session_endpoint?: string;
  issuer: string;
  jwks_uri: string;
  token_endpoint: string;
};

type JwtPayload = {
  aud?: string | string[];
  email?: string;
  exp?: number;
  iss?: string;
  name?: string;
  nonce?: string;
  picture?: string;
  sub?: string;
};

type TokenResponse = {
  access_token?: string;
  error?: string;
  error_description?: string;
  expires_in?: number;
  id_token?: string;
  refresh_token?: string;
  token_type?: string;
};

type OidcTransaction = {
  codeVerifier: string;
  nonce: string;
  returnTo: string;
};

export type OidcSession = {
  audience?: string | string[];
  email?: string;
  expiresAt: number;
  isAuthenticated: boolean;
  issuer?: string;
  name?: string;
  pictureUrl?: string;
  subject?: string;
  tokenIdentifier?: string;
};

export const oidcCookies = {
  codeVerifier: "oidc_code_verifier",
  state: "oidc_state",
  nonce: "oidc_nonce",
  returnTo: "oidc_return_to",
  idToken: "oidc_id_token",
  accessToken: "oidc_access_token",
  refreshToken: "oidc_refresh_token",
  expiresAt: "oidc_expires_at",
  session: "oidc_session",
} as const;

function getIssuer() {
  return (process.env.OIDC_ISSUER ?? "https://nesskey.com").replace(/\/+$/, "");
}

function getClientId() {
  const clientId = process.env.OIDC_CLIENT_ID;
  if (!clientId) throw new Error("OIDC_CLIENT_ID is required.");
  return clientId;
}

function getOptionalClientSecret() {
  return process.env.OIDC_CLIENT_SECRET;
}

function getCookieDomain() {
  const domain = process.env.OIDC_COOKIE_DOMAIN?.trim();
  return domain || undefined;
}

function getScope() {
  return process.env.OIDC_SCOPE ?? "openid profile email offline_access";
}

function getPublicAuthBasePath() {
  return normalizeUrlLike(process.env.OIDC_PUBLIC_BASE_PATH ?? getAuthPublicUrl() ?? "/auth");
}

function getRedirectUriOverride() {
  return process.env.OIDC_REDIRECT_URI ?? null;
}

function getDefaultSignedOutRedirect() {
  return process.env.OIDC_DEFAULT_REDIRECT ?? "/";
}

function getPublicSiteUrlFromEnv(request?: NextRequest) {
  const explicit =
    process.env.APP_PUBLIC_URL ??
    process.env.NEXT_PUBLIC_SITE_URL ??
    process.env.OIDC_PUBLIC_SITE_URL;
  if (explicit) return normalizeUrlLike(explicit);
  if (request) return normalizeUrlLike(request.nextUrl.origin);
  return null;
}

function resolvePublicRedirect(target: string, request: NextRequest) {
  if (/^https?:\/\//.test(target)) return new URL(target);
  const publicSiteUrl = getPublicSiteUrlFromEnv(request);
  if (publicSiteUrl) return new URL(target, publicSiteUrl);
  return new URL(target, request.url);
}

function randomString() {
  return base64urlEncode(crypto.getRandomValues(new Uint8Array(32)));
}

async function discoverOidc() {
  const issuer = getIssuer();
  const response = await fetch(`${issuer}/.well-known/openid-configuration`);
  if (!response.ok) throw new Error(`Failed to load OIDC discovery document from ${issuer}.`);
  return (await response.json()) as DiscoveryDocument;
}

function parseJwtPayload(token: string): JwtPayload {
  const part = token.split(".")[1] ?? "";
  return JSON.parse(base64urlDecodeString(part)) as JwtPayload;
}

function encodeSessionCookie(session: OidcSession) {
  return base64urlEncode(new TextEncoder().encode(JSON.stringify(session)));
}

function parseSessionCookie(value: string): OidcSession | null {
  try {
    const session = JSON.parse(base64urlDecodeString(value)) as OidcSession;
    return session.isAuthenticated ? session : null;
  } catch {
    return null;
  }
}

function encodeTransactionCookie(transaction: OidcTransaction) {
  return base64urlEncode(new TextEncoder().encode(JSON.stringify(transaction)));
}

function parseTransactionCookie(value: string): OidcTransaction | null {
  try {
    const transaction = JSON.parse(base64urlDecodeString(value)) as OidcTransaction;
    if (!transaction.codeVerifier || !transaction.returnTo) return null;
    return transaction;
  } catch {
    return null;
  }
}

function getTransactionCookieName(state: string) {
  return `oidc_tx_${state}`;
}

function getCookieOptions(request: NextRequest) {
  return {
    domain: getCookieDomain(),
    httpOnly: true,
    path: "/",
    sameSite: "lax" as const,
    secure: request.nextUrl.protocol === "https:",
  };
}

function expireCookie(response: NextResponse, request: NextRequest, name: string) {
  response.cookies.set(name, "", { ...getCookieOptions(request), expires: new Date(0) });
}

function setTransactionCookie(
  response: NextResponse,
  request: NextRequest,
  state: string,
  transaction: OidcTransaction,
) {
  response.cookies.set(
    getTransactionCookieName(state),
    encodeTransactionCookie(transaction),
    { ...getCookieOptions(request), expires: new Date(Date.now() + 10 * 60 * 1_000) },
  );
}

function getRedirectUri(request: NextRequest) {
  const override = getRedirectUriOverride();
  if (override) return override;
  return new URL(
    `${getPublicAuthBasePath()}/oidc/callback`,
    getPublicSiteUrlFromEnv(request) ?? request.nextUrl.origin,
  ).toString();
}

function appendClientAuthentication(
  headers: Headers,
  params: URLSearchParams,
  clientId: string,
  clientSecret?: string,
) {
  if (clientSecret) {
    const basic = btoa(`${clientId}:${clientSecret}`);
    headers.set("authorization", `Basic ${basic}`);
    return;
  }
  params.set("client_id", clientId);
}

async function exchangeAuthorizationCode(args: {
  clientId: string;
  clientSecret?: string;
  code: string;
  codeVerifier: string;
  redirectUri: string;
  tokenEndpoint: string;
}) {
  const params = new URLSearchParams({
    code: args.code,
    code_verifier: args.codeVerifier,
    grant_type: "authorization_code",
    redirect_uri: args.redirectUri,
  });
  const reqHeaders = new Headers({ "content-type": "application/x-www-form-urlencoded" });
  appendClientAuthentication(reqHeaders, params, args.clientId, args.clientSecret);
  const response = await fetch(args.tokenEndpoint, {
    body: params.toString(),
    headers: reqHeaders,
    method: "POST",
  });
  const json = (await response.json()) as TokenResponse;
  if (!response.ok || !json.id_token) {
    throw new Error(json.error_description ?? "OIDC code exchange failed.");
  }
  return json;
}

async function refreshIdToken(args: {
  clientId: string;
  clientSecret?: string;
  refreshToken: string;
  tokenEndpoint: string;
}) {
  const params = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: args.refreshToken,
  });
  const reqHeaders = new Headers({ "content-type": "application/x-www-form-urlencoded" });
  appendClientAuthentication(reqHeaders, params, args.clientId, args.clientSecret);
  const response = await fetch(args.tokenEndpoint, {
    body: params.toString(),
    headers: reqHeaders,
    method: "POST",
  });
  const json = (await response.json()) as TokenResponse;
  if (!response.ok || !json.id_token) {
    throw new Error(json.error_description ?? "OIDC token refresh failed.");
  }
  return json;
}

function sessionFromPayload(payload: JwtPayload): OidcSession {
  return {
    audience: payload.aud,
    email: payload.email,
    expiresAt: payload.exp ?? 0,
    isAuthenticated: true,
    issuer: payload.iss,
    name: payload.name,
    pictureUrl: payload.picture,
    subject: payload.sub,
    tokenIdentifier:
      payload.sub && payload.iss ? `${payload.sub}|${payload.iss}` : undefined,
  };
}

function applyTokenCookies(response: NextResponse, request: NextRequest, tokens: TokenResponse) {
  const options = getCookieOptions(request);
  const payload = parseJwtPayload(tokens.id_token!);
  const expiresAt =
    payload.exp ??
    (tokens.expires_in ? Math.floor(Date.now() / 1_000) + tokens.expires_in : undefined);
  if (!expiresAt) throw new Error("The OIDC ID token did not include an expiry.");

  response.cookies.set(oidcCookies.idToken, tokens.id_token!, {
    ...options,
    expires: new Date(expiresAt * 1_000),
  });
  response.cookies.set(oidcCookies.expiresAt, String(expiresAt), {
    ...options,
    expires: new Date(expiresAt * 1_000),
  });
  response.cookies.set(
    oidcCookies.session,
    encodeSessionCookie(sessionFromPayload({ ...payload, exp: expiresAt })),
    { ...options, expires: new Date(expiresAt * 1_000) },
  );
  if (tokens.access_token) {
    response.cookies.set(oidcCookies.accessToken, tokens.access_token, {
      ...options,
      expires: new Date(expiresAt * 1_000),
    });
  }
  if (tokens.refresh_token) {
    response.cookies.set(oidcCookies.refreshToken, tokens.refresh_token, options);
  }
}

function clearTransientCookies(response: NextResponse, request: NextRequest) {
  expireCookie(response, request, oidcCookies.codeVerifier);
  expireCookie(response, request, oidcCookies.state);
  expireCookie(response, request, oidcCookies.nonce);
}

export async function buildAuthorizationRedirect(request: NextRequest) {
  const discovery = await discoverOidc();
  const clientId = getClientId();
  const { challenge, verifier } = await generatePkce();
  const nonce = randomString();
  const state = randomString();
  const redirectUri = getRedirectUri(request);
  const returnTo =
    request.nextUrl.searchParams.get("redirectTo") ?? getDefaultSignedOutRedirect();

  const url = new URL(discovery.authorization_endpoint);
  url.searchParams.set("client_id", clientId);
  url.searchParams.set("code_challenge", challenge);
  url.searchParams.set("code_challenge_method", "S256");
  url.searchParams.set("nonce", nonce);
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", getScope());
  url.searchParams.set("state", state);

  const response = NextResponse.redirect(url);
  const options = getCookieOptions(request);
  setTransactionCookie(response, request, state, { codeVerifier: verifier, nonce, returnTo });
  response.cookies.set(oidcCookies.codeVerifier, verifier, options);
  response.cookies.set(oidcCookies.state, state, options);
  response.cookies.set(oidcCookies.nonce, nonce, options);
  response.cookies.set(oidcCookies.returnTo, returnTo, options);
  return response;
}

export async function handleAuthorizationCallback(request: NextRequest) {
  const cookieStore = await cookies();
  const code = request.nextUrl.searchParams.get("code");
  const state = request.nextUrl.searchParams.get("state");
  const transaction = state
    ? parseTransactionCookie(cookieStore.get(getTransactionCookieName(state))?.value ?? "")
    : null;
  const savedState = cookieStore.get(oidcCookies.state)?.value;
  const codeVerifier =
    transaction?.codeVerifier ?? cookieStore.get(oidcCookies.codeVerifier)?.value;
  const savedNonce = transaction?.nonce ?? cookieStore.get(oidcCookies.nonce)?.value;
  const returnTo =
    transaction?.returnTo ??
    cookieStore.get(oidcCookies.returnTo)?.value ??
    getDefaultSignedOutRedirect();

  if (
    !code ||
    !state ||
    !codeVerifier ||
    (!transaction && (!savedState || state !== savedState))
  ) {
    return NextResponse.redirect(
      resolvePublicRedirect(`${getPublicAuthBasePath()}?error=oidc_state`, request),
    );
  }

  try {
    const discovery = await discoverOidc();
    const tokens = await exchangeAuthorizationCode({
      clientId: getClientId(),
      clientSecret: getOptionalClientSecret(),
      code,
      codeVerifier,
      redirectUri: getRedirectUri(request),
      tokenEndpoint: discovery.token_endpoint,
    });
    const payload = parseJwtPayload(tokens.id_token!);
    if (savedNonce && payload.nonce && payload.nonce !== savedNonce) {
      throw new Error("OIDC nonce mismatch.");
    }
    const response = NextResponse.redirect(resolvePublicRedirect(returnTo, request));
    applyTokenCookies(response, request, tokens);
    clearTransientCookies(response, request);
    expireCookie(response, request, oidcCookies.returnTo);
    expireCookie(response, request, getTransactionCookieName(state));
    return response;
  } catch {
    return NextResponse.redirect(
      resolvePublicRedirect(`${getPublicAuthBasePath()}?error=oidc_callback`, request),
    );
  }
}

export async function getSessionFromCookies(): Promise<OidcSession> {
  const cookieStore = await cookies();
  const idToken = cookieStore.get(oidcCookies.idToken)?.value;
  if (idToken) {
    try {
      return sessionFromPayload(parseJwtPayload(idToken));
    } catch {
      // fall through to compact session cookie
    }
  }
  const sessionCookie = cookieStore.get(oidcCookies.session)?.value;
  const session = sessionCookie ? parseSessionCookie(sessionCookie) : null;
  return session ?? { expiresAt: 0, isAuthenticated: false };
}

export async function getServerIdToken() {
  const cookieStore = await cookies();
  return cookieStore.get(oidcCookies.idToken)?.value ?? null;
}

export async function hasServerOidcSession() {
  const cookieStore = await cookies();
  return Boolean(
    cookieStore.get(oidcCookies.session)?.value ??
      cookieStore.get(oidcCookies.idToken)?.value ??
      cookieStore.get(oidcCookies.accessToken)?.value,
  );
}

export async function getServerAccessToken() {
  const cookieStore = await cookies();
  const accessToken = cookieStore.get(oidcCookies.accessToken)?.value;
  if (accessToken) return accessToken;

  const refreshToken = cookieStore.get(oidcCookies.refreshToken)?.value;
  if (!refreshToken) return null;

  try {
    const discovery = await discoverOidc();
    const tokens = await refreshIdToken({
      clientId: getClientId(),
      clientSecret: getOptionalClientSecret(),
      refreshToken,
      tokenEndpoint: discovery.token_endpoint,
    });
    return tokens.access_token ?? null;
  } catch {
    return null;
  }
}

export async function buildSessionResponse(_request?: NextRequest) {
  const cookieStore = await cookies();
  const idToken = cookieStore.get(oidcCookies.idToken)?.value;
  const expiresAt = Number(cookieStore.get(oidcCookies.expiresAt)?.value ?? "0");
  const now = Math.floor(Date.now() / 1_000);

  if (!idToken || expiresAt <= now) {
    return NextResponse.json({ expiresAt: 0, isAuthenticated: false } satisfies OidcSession, {
      status: 401,
    });
  }
  return NextResponse.json(sessionFromPayload({ ...parseJwtPayload(idToken), exp: expiresAt }));
}

export async function buildTokenResponse(request: NextRequest) {
  const cookieStore = await cookies();
  const idToken = cookieStore.get(oidcCookies.idToken)?.value;
  const expiresAt = Number(cookieStore.get(oidcCookies.expiresAt)?.value ?? "0");
  const now = Math.floor(Date.now() / 1_000);

  if (!idToken || expiresAt <= now) {
    const response = NextResponse.json({ token: null }, { status: 401 });
    expireCookie(response, request, oidcCookies.idToken);
    expireCookie(response, request, oidcCookies.refreshToken);
    expireCookie(response, request, oidcCookies.expiresAt);
    return response;
  }
  return NextResponse.json({ token: idToken });
}

export async function buildLogoutResponse(request: NextRequest) {
  const redirectTo =
    request.nextUrl.searchParams.get("redirectTo") ?? getDefaultSignedOutRedirect();
  const postLogoutUrl = resolvePublicRedirect(redirectTo, request).toString();

  const cookieStore = await cookies();
  const idToken = cookieStore.get(oidcCookies.idToken)?.value;

  const clearResponse = NextResponse.redirect(postLogoutUrl);
  Object.values(oidcCookies).forEach((name) => expireCookie(clearResponse, request, name));

  try {
    const discovery = await discoverOidc();
    if (discovery.end_session_endpoint) {
      const endSessionUrl = new URL(discovery.end_session_endpoint);
      endSessionUrl.searchParams.set("post_logout_redirect_uri", postLogoutUrl);
      if (idToken) endSessionUrl.searchParams.set("id_token_hint", idToken);
      return NextResponse.redirect(endSessionUrl.toString(), {
        headers: clearResponse.headers,
      });
    }
  } catch {
    // Discovery failed — local-only logout.
  }

  return clearResponse;
}
