import { FormEvent, useState } from "react";
import { Link, useNavigate } from "react-router-dom";

import { useAuth } from "../lib/auth";

export default function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      await login(email, password);
      navigate("/dashboard");
    } catch (err: any) {
      setError(err?.response?.data?.detail || "Login failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-950">
      <form onSubmit={onSubmit} className="w-full max-w-sm bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
        <h1 className="text-xl font-bold text-cyan-400">🛡 Aegis Shield</h1>
        <p className="text-sm text-slate-400">Sign in to run and manage scans.</p>
        {error && <p className="text-sm text-red-400">{error}</p>}
        <input
          type="email" required placeholder="Email" value={email}
          onChange={(e) => setEmail(e.target.value)}
          className="w-full rounded-md bg-slate-800 border border-slate-700 px-3 py-2 text-sm"
        />
        <input
          type="password" required placeholder="Password" value={password}
          onChange={(e) => setPassword(e.target.value)}
          className="w-full rounded-md bg-slate-800 border border-slate-700 px-3 py-2 text-sm"
        />
        <button disabled={loading} className="w-full rounded-md bg-cyan-600 hover:bg-cyan-500 py-2 text-sm font-medium disabled:opacity-50">
          {loading ? "Signing in..." : "Sign in"}
        </button>
        <p className="text-sm text-slate-400">
          No account? <Link to="/register" className="text-cyan-400">Register</Link>
        </p>
        <div className="text-xs text-slate-500 border-t border-slate-800 pt-3">
          Demo accounts (seeded via seed_demo_users.py):
          <br />free@demo.aegis / DemoFree123!
          <br />pro@demo.aegis / DemoPro123!
          <br />enterprise@demo.aegis / DemoEnterprise123!
        </div>
      </form>
    </div>
  );
}
