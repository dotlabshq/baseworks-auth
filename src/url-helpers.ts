export function normalizeUrlLike(value: string) {
  if (value === "/") return "";
  return value.replace(/\/+$/, "");
}

function joinPublicUrl(base: string, path = "") {
  const normalizedBase = normalizeUrlLike(base);
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  if (!normalizedBase) return normalizedPath;
  if (/^https?:\/\//.test(normalizedBase)) {
    return new URL(normalizedPath, `${normalizedBase}/`).toString();
  }
  return `${normalizedBase}${normalizedPath}`;
}

export function getAuthPublicUrl() {
  return normalizeUrlLike(process.env.NEXT_PUBLIC_AUTH_URL ?? "/auth");
}

export function getAccountPublicUrl() {
  return normalizeUrlLike(process.env.NEXT_PUBLIC_ACCOUNT_URL ?? "/account");
}

export function getAppBasePath(defaultPath = "") {
  return normalizeUrlLike(
    process.env.NEXT_PUBLIC_APP_BASE_PATH ?? process.env.APP_BASE_PATH ?? defaultPath,
  );
}

export function getPublicSiteUrl() {
  return normalizeUrlLike(process.env.APP_PUBLIC_URL ?? process.env.NEXT_PUBLIC_SITE_URL ?? "");
}

export function buildPublicUrl(pathOrUrl: string, fallbackOrigin?: string) {
  if (/^https?:\/\//.test(pathOrUrl)) return pathOrUrl;
  const origin = getPublicSiteUrl() || fallbackOrigin;
  if (!origin) return pathOrUrl;
  return new URL(pathOrUrl, `${normalizeUrlLike(origin)}/`).toString();
}

function buildAuthUrl(path: string, redirectTo: string, origin?: string) {
  const target = joinPublicUrl(getAuthPublicUrl(), path);
  const targetIsAbsolute = /^https?:\/\//.test(target);
  const fallbackOrigin = "http://localhost";
  const url = new URL(target, origin ?? fallbackOrigin);
  url.searchParams.set("redirectTo", redirectTo);
  const href = url.toString();
  if (origin || targetIsAbsolute) return href;
  return href.replace(fallbackOrigin, "");
}

export function buildAuthLoginUrl(redirectTo: string, origin?: string) {
  return buildAuthUrl("/login", redirectTo, origin);
}

export function buildAuthLogoutUrl(redirectTo: string, origin?: string) {
  return buildAuthUrl(
    "/logout",
    process.env.NEXT_PUBLIC_SIGN_OUT_REDIRECT_URL ?? redirectTo,
    origin,
  );
}

export function buildAccountProfileUrl() {
  return joinPublicUrl(getAccountPublicUrl(), "/profile");
}
