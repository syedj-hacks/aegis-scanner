import { NavLink, Outlet, useNavigate } from "react-router-dom";

import { useAuth } from "../lib/auth";
import Brand from "./Brand";
import Footer from "./Footer";

export default function Layout() {
  const { email, role, logout } = useAuth();
  const navigate = useNavigate();

  const linkClass = ({ isActive }: { isActive: boolean }) =>
    `-mb-px border-b-2 py-5 text-[0.85rem] transition-colors ${
      isActive ? "border-brand text-on-dark" : "border-transparent text-dim-dark hover:text-on-dark"
    }`;

  const signOut = () => {
    logout();
    navigate("/login");
  };

  return (
    <div className="flex min-h-screen flex-col">
      <header className="sticky top-0 z-20 border-b border-dark-line bg-dark/[0.92] text-on-dark backdrop-blur-[6px]">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-x-8 px-5 sm:px-8">
          <div className="py-4">
            <Brand to="/dashboard" />
          </div>
          <nav className="order-3 flex w-full gap-7 overflow-x-auto sm:order-none sm:w-auto">
            <NavLink to="/dashboard" className={linkClass}>Dashboard</NavLink>
            <NavLink to="/profiles" className={linkClass}>New scan</NavLink>
            <NavLink to="/billing" className={linkClass}>Billing</NavLink>
            {role === "admin" && <NavLink to="/admin" className={linkClass}>Admin</NavLink>}
          </nav>
          <div className="flex items-center gap-4 py-3">
            <span className="hidden max-w-[22ch] truncate font-mono text-xs text-dim-dark md:inline">{email}</span>
            <button onClick={signOut} className="btn-outline-dark btn-sm">
              Sign out
            </button>
          </div>
        </div>
      </header>
      <main className="flex-1 bg-light">
        <Outlet />
      </main>
      <Footer />
    </div>
  );
}
