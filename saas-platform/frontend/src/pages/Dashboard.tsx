import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import { api } from "../lib/api";

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
}

const statusColor: Record<string, string> = {
  queued: "bg-slate-700 text-slate-200",
  running: "bg-amber-600 text-white",
  done: "bg-emerald-600 text-white",
  failed: "bg-red-600 text-white",
};

export default function Dashboard() {
  const [jobs, setJobs] = useState<ScanJob[]>([]);
  const [sub, setSub] = useState<Subscription | null>(null);

  const load = async () => {
    const [jobsRes, subRes] = await Promise.all([
      api.get("/scans/jobs"),
      api.get("/billing/subscription"),
    ]);
    setJobs(jobsRes.data);
    setSub(subRes.data);
  };

  useEffect(() => {
    load();
    const interval = setInterval(load, 5000); // poll for job status updates
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Dashboard</h1>
        <Link to="/profiles" className="rounded-md bg-cyan-600 hover:bg-cyan-500 px-4 py-2 text-sm font-medium">
          + New Scan
        </Link>
      </div>

      {sub && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex items-center justify-between">
          <div>
            <p className="text-sm text-slate-400">Current plan</p>
            <p className="text-lg font-semibold capitalize">{sub.tier}</p>
          </div>
          <div className="text-right">
            <p className="text-sm text-slate-400">Scans used this period</p>
            <p className="text-lg font-semibold">
              {sub.scans_used_this_period}
              {sub.scans_limit !== null ? ` / ${sub.scans_limit}` : " / Unlimited"}
            </p>
          </div>
        </div>
      )}

      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-slate-800 text-slate-300 text-left">
            <tr>
              <th className="px-4 py-2">Target</th>
              <th className="px-4 py-2">Profile</th>
              <th className="px-4 py-2">Status</th>
              <th className="px-4 py-2">Submitted</th>
              <th className="px-4 py-2"></th>
            </tr>
          </thead>
          <tbody>
            {jobs.length === 0 && (
              <tr>
                <td colSpan={5} className="px-4 py-6 text-center text-slate-500">
                  No scans yet. Start one from "New Scan".
                </td>
              </tr>
            )}
            {jobs.map((j) => (
              <tr key={j.id} className="border-t border-slate-800">
                <td className="px-4 py-2 font-mono">{j.target}</td>
                <td className="px-4 py-2">{j.profile}</td>
                <td className="px-4 py-2">
                  <span className={`px-2 py-0.5 rounded text-xs font-medium ${statusColor[j.status]}`}>
                    {j.status}
                  </span>
                  {j.status === "failed" && j.error && (
                    <span className="ml-2 text-xs text-red-400">{j.error}</span>
                  )}
                </td>
                <td className="px-4 py-2 text-slate-400">{new Date(j.created_at).toLocaleString()}</td>
                <td className="px-4 py-2 text-right">
                  <Link to={`/scans/${j.id}`} className="text-cyan-400 hover:underline">
                    View
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
