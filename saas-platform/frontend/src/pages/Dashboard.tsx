import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import { JobStatus } from "../components/Labels";
import PageHeader from "../components/PageHeader";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import { planLabel } from "../lib/plans";

interface ScanJob {
  id: number;
  target: string;
  profile: string;
  status: "queued" | "running" | "done" | "failed";
  created_at: string;
  error: string | null;
}

interface Subscription {
  tier: "free" | "pro" | "enterprise";
  scans_used_this_period: number;
  scans_limit: number | null;
  status: string;
  pending_tier: string | null;
}

export default function Dashboard() {
  const { email } = useAuth();
  const [jobs, setJobs] = useState<ScanJob[] | null>(null);
  const [sub, setSub] = useState<Subscription | null>(null);

  const load = async () => {
    const [jobsRes, subRes] = await Promise.all([api.get("/scans/jobs"), api.get("/billing/subscription")]);
    setJobs(jobsRes.data);
    setSub(subRes.data);
  };

  useEffect(() => {
    load().catch(() => setJobs([]));
    const interval = setInterval(() => load().catch(() => undefined), 5000); // job status updates
    return () => clearInterval(interval);
  }, []);

  const active = jobs?.filter((j) => j.status === "queued" || j.status === "running").length ?? 0;
  const done = jobs?.filter((j) => j.status === "done").length ?? 0;

  const stats: [string, string][] = [
    [sub ? planLabel(sub.tier) : "—", sub?.pending_tier ? `Plan · ${planLabel(sub.pending_tier)} requested` : "Current plan"],
    [
      sub ? `${sub.scans_used_this_period}${sub.scans_limit !== null ? ` / ${sub.scans_limit}` : ""}` : "—",
      sub?.scans_limit === null ? "Scans this period · unlimited" : "Scans used this period",
    ],
    [String(active), "In progress"],
    [String(done), "Completed scans"],
  ];

  return (
    <>
      <PageHeader
        eyebrow="Dashboard"
        title="Scan activity"
        description={email ? <>Signed in as <span className="font-mono text-on-dark">{email}</span></> : undefined}
        actions={<Link to="/profiles" className="btn-primary">New scan</Link>}
      />

      <div className="border-b border-light-line">
        <div className="mx-auto grid max-w-6xl grid-cols-2 lg:grid-cols-4">
          {stats.map(([num, label], i) => (
            <div
              key={label}
              className={`px-5 py-7 sm:px-8 ${i % 2 === 1 ? "border-l border-light-line" : ""} ${
                i >= 2 ? "border-t border-light-line lg:border-t-0" : ""
              } ${i === 2 ? "lg:border-l" : ""}`}
            >
              <div className="font-display text-[1.9rem] font-extrabold leading-none">{num}</div>
              <div className="mt-2 text-[0.8rem] text-dim">{label}</div>
            </div>
          ))}
        </div>
      </div>

      <div className="mx-auto max-w-6xl px-5 py-10 sm:px-8">
        <div className="panel">
          <div className="panel-head">
            <h2 className="panel-title">Recent scans</h2>
            <span className="font-mono text-[0.7rem] text-dim">Refreshes every 5s</span>
          </div>
          <div className="overflow-x-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Target</th>
                  <th>Profile</th>
                  <th>Status</th>
                  <th>Submitted</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {jobs === null && (
                  <tr><td colSpan={5} className="py-10 text-center text-dim">Loading…</td></tr>
                )}
                {jobs?.length === 0 && (
                  <tr>
                    <td colSpan={5} className="py-12 text-center">
                      <p className="font-display font-bold">No scans yet</p>
                      <p className="mt-1 text-sm text-dim">Run a quickscan against a host you own to get started.</p>
                      <Link to="/profiles" className="btn-outline btn-sm mt-4">New scan</Link>
                    </td>
                  </tr>
                )}
                {jobs?.map((j) => (
                  <tr key={j.id}>
                    <td className="font-mono text-[0.82rem]">{j.target}</td>
                    <td className="font-mono text-[0.82rem] text-dim">{j.profile}</td>
                    <td>
                      <JobStatus status={j.status} />
                      {j.status === "failed" && j.error && (
                        <div className="mt-1 max-w-xs text-xs text-dim">{j.error}</div>
                      )}
                    </td>
                    <td className="whitespace-nowrap text-dim">{new Date(j.created_at).toLocaleString()}</td>
                    <td className="text-right">
                      <Link to={`/scans/${j.id}`} className="text-action">View</Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </>
  );
}
