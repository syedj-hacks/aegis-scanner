import { FormEvent, useState } from "react";
import { Link, useNavigate } from "react-router-dom";

import AuthShell, { FormError } from "../components/AuthShell";
import PasswordInput from "../components/PasswordInput";
import { errorMessage } from "../lib/api";
import { useAuth } from "../lib/auth";

export default function Register() {
  const { register } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    if (password !== confirm) {
      setError("Passwords don't match.");
      return;
    }
    setLoading(true);
    try {
      await register(email, password);
      navigate("/dashboard");
    } catch (err) {
      setError(errorMessage(err, "Could not create your account"));
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthShell
      eyebrow="Create account"
      title="Start scanning in minutes."
      aside={
        <Link to="/login" className="text-sm text-dim-dark transition-colors hover:text-brand">
          Sign in
        </Link>
      }
    >
      <form onSubmit={onSubmit} className="space-y-5">
        <FormError message={error} />
        <div>
          <label htmlFor="reg-email" className="field-label-dark">Work email</label>
          <input
            id="reg-email"
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
          minLength={8}
          autoComplete="new-password"
          placeholder="At least 8 characters"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        <PasswordInput
          dark
          label="Confirm password"
          required
          minLength={8}
          autoComplete="new-password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
        />
        <button disabled={loading} className="btn-primary w-full">
          {loading ? "Creating account…" : "Create account"}
        </button>
        <p className="font-mono text-[0.7rem] leading-relaxed text-dim-dark">
          Every account starts on the Free plan. Upgrade any time from Billing.
        </p>
        <p className="border-t border-dark-line pt-5 text-sm text-dim-dark">
          Already have an account?{" "}
          <Link to="/login" className="font-semibold text-on-dark hover:text-brand">
            Sign in
          </Link>
        </p>
      </form>
    </AuthShell>
  );
}
