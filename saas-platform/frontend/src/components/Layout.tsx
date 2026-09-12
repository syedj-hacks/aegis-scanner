import { NavLink, Outlet } from "react-router-dom";

import { useAuth } from "../lib/auth";

export default function Layout() {
  const { email, role, logout } = useAuth();

  const linkClass = ({ isActive }: { isActive: boolean }) =>
    `px-3 py-2 rounded-md text-sm font-medium ${
      isActive ? "bg-cyan-600 text-white" : "text-slate-300 hover:bg-slate-800"
    }`;

  return (
    <div className="min-h-screen flex flex-col">
      <header className="border-b border-slate-800 bg-slate-900">
        <div className="max-w-6xl mx-auto flex items-center justify-between px-4 py-3">
          <div className="flex items-center gap-2">
            <span className="text-cyan-400 font-bold text-lg">🛡 Aegis Shield</span>
          </div>
          <nav className="flex items-center gap-1">
            <NavLink to="/dashboard" className={linkClass}>Dashboard</NavLink>
            <NavLink to="/profiles" className={linkClass}>Scan</NavLink>
            <NavLink to="/billing" className={linkClass}>Billing</NavLink>
            {role === "admin" && <NavLink to="/admin" className={linkClass}>Admin</NavLink>}
          </nav>
          <div className="flex items-center gap-3 text-sm">
            <span className="text-slate-400">{email}</span>
            <button
              onClick={logout}
              className="px-3 py-1.5 rounded-md bg-slate-800 hover:bg-slate-700 text-slate-200"
            >
              Log out
            </button>
          </div>
        </div>
      </header>
      <main className="flex-1 max-w-6xl w-full mx-auto px-4 py-6">
        <Outlet />
      </main>
    </div>
  );
}
