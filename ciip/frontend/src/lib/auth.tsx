import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import type { Me } from "../types";
import { api, getRefreshToken, setAuthLostHandler, setTokens, takeRefreshToken, tryRefresh } from "./api";

interface AuthState {
  me: Me | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  can: (perm: string) => boolean;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<Me | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setAuthLostHandler(() => {
      setTokens(null, null);
      setMe(null);
    });
    (async () => {
      if (getRefreshToken() && (await tryRefresh())) {
        try {
          setMe(await api<Me>("/auth/me"));
        } catch {
          setMe(null);
        }
      }
      setLoading(false);
    })();
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    const tokens = await api<{ access_token: string; refresh_token: string }>("/auth/login", {
      body: { email, password },
    });
    setTokens(tokens.access_token, tokens.refresh_token);
    setMe(await api<Me>("/auth/me"));
  }, []);

  const logout = useCallback(async () => {
    try {
      // Drop the local copy first so a reload during the call cannot reuse it.
      await api("/auth/logout", { body: { refresh_token: takeRefreshToken() } });
    } finally {
      setTokens(null, null);
      setMe(null);
    }
  }, []);

  const can = useCallback((perm: string) => !!me?.permissions.includes(perm), [me]);

  return <AuthContext.Provider value={{ me, loading, login, logout, can }}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth outside AuthProvider");
  return ctx;
}
