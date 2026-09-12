import { FormEvent, useState } from "react";
import { Link, useNavigate } from "react-router-dom";

import { useAuth } from "../lib/auth";

export default function Register() {
  const { register } = useAuth();
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
      await register(email, password);
      navigate("/dashboard");
    } catch (err: any) {
      setError(err?.response?.data?.detail || "Registration failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-950">
      <form onSubmit={onSubmit} className="w-full max-w-sm bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
        <h1 className="text-xl font-bold text-cyan-400">Create your account</h1>
        <p className="text-sm text-slate-400">
          New accounts start on the Free tier. There is no public path to create an admin account.
        </p>
        {error && <p className="text-sm text-red-400">{error}</p>}
        <input
          type="email" required placeholder="Email" value={email}
          onChange={(e) => setEmail(e.target.value)}
          className="w-full rounded-md bg-slate-800 border border-slate-700 px-3 py-2 text-sm"
        />
        <input
          type="password" required minLength={8} placeholder="Password (min 8 chars)" value={password}
          onChange={(e) => setPassword(e.target.value)}
          className="w-full rounded-md bg-slate-800 border border-slate-700 px-3 py-2 text-sm"
        />
        <button disabled={loading} className="w-full rounded-md bg-cyan-600 hover:bg-cyan-500 py-2 text-sm font-medium disabled:opacity-50">
          {loading ? "Creating..." : "Create account"}
        </button>
        <p className="text-sm text-slate-400">
          Already registered? <Link to="/login" className="text-cyan-400">Sign in</Link>
        </p>
      </form>
    </div>
  );
}
