import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";

import PageHeader from "../components/PageHeader";
import { api, errorMessage } from "../lib/api";

interface ProfileInfo {
  name: string;
  description: string;
  locked: boolean;
  requires_authorization: boolean;
}

const REQUIRED_PLAN: Record<string, string> = {
  webaudit: "Pro",
  stealthscan: "Pro",
  deepscan: "Enterprise",
  recon: "Enterprise",
};

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
    } catch (err) {
      setError(errorMessage(err, "Could not start the scan"));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <>
      <PageHeader
        eyebrow="New scan"
        title="Choose a target and profile"
        description="Scans run the real toolchain against the host you enter. Only scan systems you own or are authorized to test."
      />

      <div className="mx-auto max-w-6xl space-y-8 px-5 py-10 sm:px-8">
        <div className="panel p-5 sm:p-6">
          <label htmlFor="target" className="field-label">Target — hostname or IP address (no CIDR ranges)</label>
          <input
            id="target"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="app.example.com or 10.0.0.5"
            className="input font-mono"
          />
        </div>

        <div>
          <div className="eyebrow-light mb-4">Scan profile</div>
          <div className="grid grid-cols-1 gap-px border border-light-line bg-light-line md:grid-cols-2 lg:grid-cols-3">
            {profiles.map((p, i) => {
              const isSelected = selected === p.name;
              return (
                <button
                  key={p.name}
                  onClick={() => !p.locked && setSelected(p.name)}
                  disabled={p.locked}
                  aria-pressed={isSelected}
                  className={`relative flex flex-col bg-light px-6 py-6 text-left transition-colors ${
                    p.locked ? "cursor-not-allowed" : "hover:bg-light-alt"
                  } ${isSelected ? "outline outline-2 -outline-offset-2 outline-brand" : ""}`}
                >
                  <div className="mb-4 flex items-center justify-between">
                    <span className={`num-badge ${p.locked ? "border-light-line text-dim" : ""}`}>
                      {String(i + 1).padStart(2, "0")}
                    </span>
                    {p.locked ? (
                      <span className="tag">{REQUIRED_PLAN[p.name] ?? "Upgrade"} plan</span>
                    ) : isSelected ? (
                      <span className="tag border-brand text-brand">selected</span>
                    ) : null}
                  </div>
                  <span className={`font-display text-[1.02rem] font-bold ${p.locked ? "text-dim" : ""}`}>{p.name}</span>
                  <p className="mt-1.5 text-[0.85rem] text-dim">{p.description}</p>
                  {p.requires_authorization && !p.locked && (
                    <p className="mt-3 font-mono text-[0.7rem] text-brand-dim">
                      Can run intrusive tools — authorization required
                    </p>
                  )}
                </button>
              );
            })}
          </div>
          {profiles.some((p) => p.locked) && (
            <p className="mt-3 text-sm text-dim">
              Locked profiles are available on higher plans. <Link to="/billing" className="text-action">Compare plans</Link>
            </p>
          )}
        </div>

        {selectedInfo && (
          <div className="panel">
            <div className="panel-head">
              <h2 className="panel-title">
                Options · <span className="font-mono text-[0.95rem] font-medium">{selectedInfo.name}</span>
              </h2>
            </div>
            <div className="grid grid-cols-1 gap-5 p-5 sm:p-6 md:grid-cols-2">
              <div>
                <label htmlFor="auth-header" className="field-label">Auth header · Pro and Enterprise</label>
                <input
                  id="auth-header"
                  value={authHeader}
                  onChange={(e) => setAuthHeader(e.target.value)}
                  placeholder="Authorization: Bearer …"
                  className="input font-mono"
                />
              </div>
              <div>
                <label htmlFor="auth-cookie" className="field-label">Auth cookie · Pro and Enterprise</label>
                <input
                  id="auth-cookie"
                  value={authCookie}
                  onChange={(e) => setAuthCookie(e.target.value)}
                  placeholder="session=…"
                  className="input font-mono"
                />
              </div>

              {selectedInfo.requires_authorization && (
                <label className="flex items-start gap-3 border-l-2 border-brand bg-light-alt p-4 text-sm md:col-span-2">
                  <input
                    type="checkbox"
                    checked={authorized}
                    onChange={(e) => setAuthorized(e.target.checked)}
                    className="mt-1 accent-[#E85D2C]"
                  />
                  <span>
                    I own this target, or I am explicitly authorized to security-test it, including the intrusive
                    tools this profile may run (wpscan, sqlmap, hydra, enum4linux). This confirmation is recorded with
                    a timestamp and my IP address.
                  </span>
                </label>
              )}

              {error && (
                <p role="alert" className="border-l-2 border-brand bg-brand/5 px-3 py-2 text-sm md:col-span-2">{error}</p>
              )}

              <div className="md:col-span-2">
                <button
                  onClick={submit}
                  disabled={submitting || !target || (selectedInfo.requires_authorization && !authorized)}
                  className="btn-primary w-full sm:w-auto"
                >
                  {submitting ? "Starting…" : "Start scan"}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </>
  );
}
