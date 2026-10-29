/**
 * Thin fetch wrapper. The access token lives in memory only; the refresh token
 * is kept in sessionStorage (cleared when the tab closes) so a reload does not
 * force a new login, while nothing persists on a shared workstation.
 */

const BASE = "/api/v1";
const REFRESH_KEY = "ciip.refresh";

let accessToken: string | null = null;
let onAuthLost: () => void = () => {};

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

export function setAuthLostHandler(handler: () => void) {
  onAuthLost = handler;
}

export function setTokens(access: string | null, refresh?: string | null) {
  accessToken = access;
  try {
    if (refresh) sessionStorage.setItem(REFRESH_KEY, refresh);
    if (refresh === null) sessionStorage.removeItem(REFRESH_KEY);
  } catch {
    /* storage unavailable: stay memory-only */
  }
}

/** Remove and return the stored refresh token (used on logout, before the server call). */
export function takeRefreshToken(): string | null {
  const token = getRefreshToken();
  try {
    sessionStorage.removeItem(REFRESH_KEY);
  } catch {
    /* ignore */
  }
  return token;
}

export function getRefreshToken(): string | null {
  try {
    return sessionStorage.getItem(REFRESH_KEY);
  } catch {
    return null;
  }
}

function errorMessage(body: unknown, fallback: string): string {
  if (body && typeof body === "object" && "detail" in body) {
    const detail = (body as { detail: unknown }).detail;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) {
      return detail.map((d) => (d && typeof d === "object" && "msg" in d ? String(d.msg) : String(d))).join(" ; ");
    }
  }
  return fallback;
}

let refreshing: Promise<boolean> | null = null;

export async function tryRefresh(): Promise<boolean> {
  const refresh = getRefreshToken();
  if (!refresh) return false;
  refreshing ??= (async () => {
    try {
      const resp = await fetch(`${BASE}/auth/refresh`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refresh_token: refresh }),
      });
      if (!resp.ok) {
        setTokens(null, null);
        return false;
      }
      const data = await resp.json();
      setTokens(data.access_token, data.refresh_token);
      return true;
    } finally {
      refreshing = null;
    }
  })();
  return refreshing;
}

type Options = { method?: string; body?: unknown; raw?: boolean; headers?: Record<string, string> };

export async function api<T = unknown>(path: string, opts: Options = {}, retry = true): Promise<T> {
  const headers: Record<string, string> = { ...(opts.headers ?? {}) };
  if (opts.body !== undefined) headers["Content-Type"] = "application/json";
  if (accessToken) headers.Authorization = `Bearer ${accessToken}`;
  const resp = await fetch(`${BASE}${path}`, {
    method: opts.method ?? (opts.body !== undefined ? "POST" : "GET"),
    headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });
  if (resp.status === 401 && retry && accessToken !== null) {
    if (await tryRefresh()) return api<T>(path, opts, false);
    onAuthLost();
  }
  if (!resp.ok) {
    let body: unknown = null;
    try {
      body = await resp.json();
    } catch {
      /* not JSON */
    }
    throw new ApiError(resp.status, errorMessage(body, `Erreur ${resp.status}`));
  }
  if (resp.status === 204) return undefined as T;
  if (opts.raw) return (await resp.text()) as T;
  return (await resp.json()) as T;
}

export function qs(params: Record<string, string | number | boolean | undefined | null | string[]>): string {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === "") continue;
    if (Array.isArray(v)) v.forEach((x) => sp.append(k, x));
    else sp.set(k, String(v));
  }
  const s = sp.toString();
  return s ? `?${s}` : "";
}

/** Download an authenticated endpoint as a file. */
export async function download(path: string, filename: string) {
  const text = await api<string>(path, { raw: true });
  const url = URL.createObjectURL(new Blob([text]));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
