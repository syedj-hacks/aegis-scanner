import React, { createContext, useContext, useState } from "react";

import { api } from "./api";

type Role = "user" | "admin";

interface AuthState {
  email: string | null;
  role: Role | null;
  isAuthenticated: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthState | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [email, setEmail] = useState<string | null>(localStorage.getItem("aegis_email"));
  const [role, setRole] = useState<Role | null>(localStorage.getItem("aegis_role") as Role | null);

  const persist = (token: string, r: Role, e: string) => {
    localStorage.setItem("aegis_token", token);
    localStorage.setItem("aegis_role", r);
    localStorage.setItem("aegis_email", e);
    setRole(r);
    setEmail(e);
  };

  const login = async (loginEmail: string, password: string) => {
    const res = await api.post("/auth/login", { email: loginEmail, password });
    persist(res.data.access_token, res.data.role, res.data.email);
  };

  const register = async (regEmail: string, password: string) => {
    const res = await api.post("/auth/register", { email: regEmail, password });
    persist(res.data.access_token, res.data.role, res.data.email);
  };

  const logout = () => {
    localStorage.removeItem("aegis_token");
    localStorage.removeItem("aegis_role");
    localStorage.removeItem("aegis_email");
    setRole(null);
    setEmail(null);
  };

  return (
    <AuthContext.Provider
      value={{ email, role, isAuthenticated: !!role, login, register, logout }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
