import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

import { api } from "../lib/api";

interface ProfileInfo {
  name: string;
  description: string;
  locked: boolean;
  requires_authorization: boolean;
}

export default function Profiles() {
  const navigate = useNavigate();
  const [profiles, setProfiles] = useState<ProfileInfo[]>([]);
  const [target, setTarget] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const [authHeader, setAuthHeader] = useState("");
  const [authCookie, setAuthCookie] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    api.get("/scans/profiles").then((res) => setProfiles(res.data));
  }, []);

  const selectedInfo = profiles.find((p) => p.name === selected);

  const submit = async () => {
    if (!target || !selected) return;
    setError(null);
    setSubmitting(true);
    try {
      const res = await api.post("/scans/submit", {
        target,
        profile: selected,
        auth_header: authHeader || null,
        auth_cookie: authCookie || null,
        authorized_intrusive: authorized,
      });
      navigate(`/scans/${res.data.id}`);
    } catch (err: any) {
      setError(err?.response?.data?.detail || "Could not submit scan");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">New Scan</h1>

      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3">
        <label className="block text-sm text-slate-400">Target (hostname or IP — no CIDR ranges)</label>
        <input
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="example.com or 10.0.0.5"
          className="w-full rounded-md bg-slate-800 border border-slate-700 px-3 py-2 text-sm font-mono"
        />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {profiles.map((p) => (
          <button
            key={p.name}
            onClick={() => !p.locked && setSelected(p.name)}
            disabled={p.locked}
            className={`text-left rounded-xl border p-4 transition ${
              selected === p.name
                ? "border-cyan-500 bg-cyan-950/40"
                : "border-slate-800 bg-slate-900"
            } ${p.locked ? "opacity-60 cursor-not-allowed" : "hover:border-slate-600"}`}
          >
            <div className="flex items-center justify-between">
              <span className="font-semibold capitalize">{p.name}</span>
              {p.locked && <span title="Upgrade to unlock">🔒</span>}
            </div>
            <p className="text-sm text-slate-400 mt-1">{p.description}</p>
            {p.locked && (
              <p className="text-xs text-amber-400 mt-2">
                Upgrade to {p.name === "recon" || p.name === "deepscan" ? "Enterprise" : "Pro"} to unlock
              </p>
            )}
            {p.requires_authorization && !p.locked && (
              <p className="text-xs text-amber-400 mt-2">
                ⚠ Can trigger intrusive tools (wpscan/sqlmap/hydra/enum4linux) — requires authorization
              </p>
            )}
          </button>
        ))}
      </div>

      {selectedInfo && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3">
          <h2 className="font-semibold">Options for {selectedInfo.name}</h2>
          <div>
            <label className="block text-sm text-slate-400">Auth header (Pro/Enterprise only)</label>
            <input
              value={authHeader}
              onChange={(e) => setAuthHeader(e.target.value)}
              placeholder="Authorization: Bearer ..."
              className="w-full rounded-md bg-slate-800 border border-slate-700 px-3 py-2 text-sm font-mono"
            />
          </div>
          <div>
            <label className="block text-sm text-slate-400">Auth cookie (Pro/Enterprise only)</label>
            <input
              value={authCookie}
              onChange={(e) => setAuthCookie(e.target.value)}
              placeholder="session=..."
              className="w-full rounded-md bg-slate-800 border border-slate-700 px-3 py-2 text-sm font-mono"
            />
          </div>

          {selectedInfo.requires_authorization && (
            <label className="flex items-start gap-2 text-sm bg-red-950/40 border border-red-800 rounded-md p-3">
              <input
                type="checkbox"
                checked={authorized}
                onChange={(e) => setAuthorized(e.target.checked)}
                className="mt-1"
              />
              <span>
                I own this target, or I am explicitly authorized to security-test it, including
                intrusive tools this profile may run (wpscan, sqlmap, hydra, enum4linux). This
                confirmation is logged with a timestamp and my IP address.
              </span>
            </label>
          )}

          {error && <p className="text-sm text-red-400">{error}</p>}

          <button
            onClick={submit}
            disabled={submitting || !target || (selectedInfo.requires_authorization && !authorized)}
            className="w-full rounded-md bg-cyan-600 hover:bg-cyan-500 py-2 text-sm font-medium disabled:opacity-50"
          >
            {submitting ? "Submitting..." : "Start Scan"}
          </button>
        </div>
      )}
    </div>
  );
}
