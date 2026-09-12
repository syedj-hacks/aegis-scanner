import axios from "axios";

/**
 * Where the API lives, decided at runtime so ONE build works everywhere:
 *  - VITE_API_BASE baked in at build time always wins;
 *  - on the hosted GitHub Pages site, talk to a backend on this machine;
 *  - under `npm run dev` (Vite on :5173), the backend is on :8000 of the same host;
 *  - otherwise the backend is serving this bundle itself, so use the same origin
 *    (this is how the launcher runs it, including from other devices on the LAN).
 */
function resolveApiBase(): string {
  const baked = import.meta.env.VITE_API_BASE;
  if (baked) return baked.replace(/\/$/, "");
  const { protocol, hostname, origin } = window.location;
  if (hostname.endsWith("github.io")) return "http://localhost:8000";
  if (import.meta.env.DEV) return `${protocol}//${hostname}:8000`;
  return origin;
}

export const API_BASE = resolveApiBase();

export const api = axios.create({ baseURL: API_BASE });

api.interceptors.request.use((config) => {
  const token = localStorage.getItem("aegis_token");
  if (token) {
    config.headers = config.headers || {};
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (res) => res,
  (err) => {
    const onAuthPage = /#\/(login|register)/.test(window.location.hash);
    if (err?.response?.status === 401 && !onAuthPage) {
      localStorage.removeItem("aegis_token");
      localStorage.removeItem("aegis_role");
      localStorage.removeItem("aegis_email");
      window.location.hash = "#/login";
    }
    return Promise.reject(err);
  }
);

/** Human-readable message for a failed request. */
export function errorMessage(err: any, fallback: string): string {
  if (err?.response) {
    const detail = err.response.data?.detail;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail) && detail[0]?.msg) return String(detail[0].msg).replace(/^Value error, /, "");
    return fallback;
  }
  // No response at all: the server is down or unreachable.
  return "Can't reach the Aegis Shield server. Check that it is running and try again.";
}
