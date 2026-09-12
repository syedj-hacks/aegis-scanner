import { FormEvent, useState } from "react";
import { Link, useNavigate } from "react-router-dom";

import AuthShell, { FormError } from "../components/AuthShell";
import PasswordInput from "../components/PasswordInput";
import { errorMessage } from "../lib/api";
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
    } catch (err) {
      setError(errorMessage(err, "Sign in failed"));
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthShell
      eyebrow="Sign in"
      title="Welcome back."
      aside={
        <Link to="/register" className="text-sm text-dim-dark transition-colors hover:text-brand">
          Create account
        </Link>
      }
    >
      <form onSubmit={onSubmit} className="space-y-5">
        <FormError message={error} />
        <div>
          <label htmlFor="login-email" className="field-label-dark">Work email</label>
          <input
            id="login-email"
            type="email"
            required
            autoComplete="email"
            placeholder="you@company.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="input-dark"
          />
        </div>
        <PasswordInput
          dark
          label="Password"
          required
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        <button disabled={loading} className="btn-primary w-full">
          {loading ? "Signing in…" : "Sign in"}
        </button>
        <p className="border-t border-dark-line pt-5 text-sm text-dim-dark">
          New to Aegis Shield?{" "}
          <Link to="/register" className="font-semibold text-on-dark hover:text-brand">
            Create an account
          </Link>
        </p>
      </form>
    </AuthShell>
  );
}
