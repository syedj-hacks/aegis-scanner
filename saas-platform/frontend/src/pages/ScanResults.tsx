import { useEffect, useMemo, useState } from "react";
import { useParams } from "react-router-dom";

import { api, API_BASE } from "../lib/api";

interface Finding {
  id: number;
  port: number | null;
  service: string | null;
  severity: string | null;
  description: string | null;
  finding_type: string | null;
  cve_id: string | null;
  remediation: string | null;
}

interface ScanJob {
  id: number;
  target: string;
  profile: string;
  status: "queued" | "running" | "done" | "failed";
  aegis_scan_id: number | null;
  error: string | null;
}

interface HistoryJob extends ScanJob {
  created_at: string;
}

const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const severityColor: Record<string, string> = {
  CRITICAL: "bg-red-700 text-white",
  HIGH: "bg-orange-600 text-white",
  MEDIUM: "bg-amber-600 text-white",
  LOW: "bg-slate-600 text-white",
};

export default function ScanResults() {
  const { jobId } = useParams();
  const [job, setJob] = useState<ScanJob | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [history, setHistory] = useState<HistoryJob[]>([]);
  const [reportFormats, setReportFormats] = useState<string[]>(["html"]);
  const [diffAllowed, setDiffAllowed] = useState(false);
  const [compareTargetId, setCompareTargetId] = useState<number | "">("");
  const [diffResult, setDiffResult] = useState<any | null>(null);
  const [sortSeverity, setSortSeverity] = useState(true);
  const [filterSeverity, setFilterSeverity] = useState<string>("ALL");

  const loadJob = async () => {
    const res = await api.get(`/scans/jobs/${jobId}`);
    setJob(res.data);
    if (res.data.status === "done") {
      const f = await api.get(`/scans/jobs/${jobId}/findings`);
      setFindings(f.data);
      const h = await api.get(`/scans/history`, { params: { target: res.data.target } });
      setHistory(h.data.filter((j: HistoryJob) => j.id !== res.data.id && j.aegis_scan_id));
    }
  };

  useEffect(() => {
    api.get("/billing/subscription").then((res) => {
      const tier = res.data.tier;
      setReportFormats(tier === "free" ? ["html"] : tier === "pro" ? ["html", "pdf"] : ["html", "pdf", "json"]);
      setDiffAllowed(tier !== "free");
    });
  }, []);

  useEffect(() => {
    loadJob();
    const interval = setInterval(() => {
      if (job?.status !== "done" && job?.status !== "failed") loadJob();
    }, 4000);
    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [jobId, job?.status]);

  const visibleFindings = useMemo(() => {
    let list = [...findings];
    if (filterSeverity !== "ALL") list = list.filter((f) => f.severity === filterSeverity);
    if (sortSeverity) {
      list.sort(
        (a, b) =>
          SEVERITY_ORDER.indexOf(a.severity || "LOW") - SEVERITY_ORDER.indexOf(b.severity || "LOW")
      );
    }
    return list;
  }, [findings, filterSeverity, sortSeverity]);

  const runDiff = async () => {
    if (!job?.aegis_scan_id || !compareTargetId) return;
    const other = history.find((h) => h.id === compareTargetId);
    if (!other?.aegis_scan_id) return;
    const [a, b] = [job.aegis_scan_id, other.aegis_scan_id].sort((x, y) => x - y);
    const res = await api.post("/scans/diff", { scan_id_a: a, scan_id_b: b });
    setDiffResult(res.data);
  };

  if (!job) return <p>Loading...</p>;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold font-mono">{job.target}</h1>
        <p className="text-slate-400 text-sm">{job.profile} — status: {job.status}</p>
        {job.error && <p className="text-red-400 text-sm mt-1">{job.error}</p>}
      </div>

      {job.status === "done" && (
        <>
          <div className="flex items-center gap-2 flex-wrap">
            {reportFormats.map((fmt) => (
              <a
                key={fmt}
                href={`${API_BASE}/scans/jobs/${job.id}/report?fmt=${fmt}`}
                target="_blank"
                rel="noreferrer"
                className="rounded-md bg-slate-800 hover:bg-slate-700 px-3 py-1.5 text-xs uppercase font-medium"
              >
                Download {fmt}
              </a>
            ))}
            {!reportFormats.includes("pdf") && (
              <span className="text-xs text-slate-500">PDF export requires Pro or Enterprise</span>
            )}
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
            <div className="flex items-center justify-between px-4 py-2 border-b border-slate-800">
              <h2 className="font-semibold">Findings ({findings.length})</h2>
              <div className="flex items-center gap-2 text-sm">
                <select
                  value={filterSeverity}
                  onChange={(e) => setFilterSeverity(e.target.value)}
                  className="bg-slate-800 border border-slate-700 rounded-md px-2 py-1"
                >
                  <option value="ALL">All severities</option>
                  {SEVERITY_ORDER.map((s) => (
                    <option key={s} value={s}>{s}</option>
                  ))}
                </select>
                <button
                  onClick={() => setSortSeverity((v) => !v)}
                  className="bg-slate-800 hover:bg-slate-700 rounded-md px-2 py-1"
                >
                  Sort by severity: {sortSeverity ? "on" : "off"}
                </button>
              </div>
            </div>
            <table className="w-full text-sm">
              <thead className="bg-slate-800 text-slate-300 text-left">
                <tr>
                  <th className="px-4 py-2">Severity</th>
                  <th className="px-4 py-2">Port</th>
                  <th className="px-4 py-2">Type</th>
                  <th className="px-4 py-2">Description</th>
                  <th className="px-4 py-2">CVE</th>
                </tr>
              </thead>
              <tbody>
                {visibleFindings.map((f) => (
                  <tr key={f.id} className="border-t border-slate-800 align-top">
                    <td className="px-4 py-2">
                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${severityColor[f.severity || "LOW"]}`}>
                        {f.severity || "LOW"}
                      </span>
                    </td>
                    <td className="px-4 py-2 font-mono">{f.port ?? "-"}</td>
                    <td className="px-4 py-2">{f.finding_type}</td>
                    <td className="px-4 py-2 max-w-xl">{f.description}</td>
                    <td className="px-4 py-2 font-mono">{f.cve_id || "-"}</td>
                  </tr>
                ))}
                {visibleFindings.length === 0 && (
                  <tr><td colSpan={5} className="px-4 py-6 text-center text-slate-500">No findings match this filter.</td></tr>
                )}
              </tbody>
            </table>
          </div>

          {diffAllowed && history.length > 0 && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3">
              <h2 className="font-semibold">Compare with a previous scan</h2>
              <div className="flex items-center gap-2">
                <select
                  value={compareTargetId}
                  onChange={(e) => setCompareTargetId(Number(e.target.value))}
                  className="bg-slate-800 border border-slate-700 rounded-md px-2 py-1 text-sm"
                >
                  <option value="">Select a scan...</option>
                  {history.map((h) => (
                    <option key={h.id} value={h.id}>
                      #{h.id} — {h.profile} — {new Date(h.created_at).toLocaleString()}
                    </option>
                  ))}
                </select>
                <button
                  onClick={runDiff}
                  disabled={!compareTargetId}
                  className="rounded-md bg-cyan-600 hover:bg-cyan-500 px-3 py-1.5 text-sm font-medium disabled:opacity-50"
                >
                  Compare
                </button>
              </div>

              {diffResult && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-3">
                  <DiffColumn title="New" color="text-red-400" items={diffResult.new} />
                  <DiffColumn title="Fixed (confirmed)" color="text-emerald-400" items={diffResult.fixed} />
                  <DiffColumn
                    title="Unverified (no re-check ran)"
                    color="text-amber-400"
                    items={diffResult.unverified}
                    note="These findings disappeared, but the tool that would have re-confirmed them didn't run this time — absence proves nothing here."
                  />
                  <DiffColumn title="Severity changed" color="text-cyan-400" items={diffResult.changed} />
                </div>
              )}
            </div>
          )}
          {!diffAllowed && (
            <p className="text-sm text-slate-500">Scan comparison requires Pro or Enterprise.</p>
          )}
        </>
      )}
    </div>
  );
}

function DiffColumn({ title, color, items, note }: { title: string; color: string; items: any[]; note?: string }) {
  return (
    <div className="bg-slate-800/50 rounded-lg p-3">
      <h3 className={`font-semibold text-sm ${color}`}>{title} ({items?.length ?? 0})</h3>
      {note && <p className="text-xs text-slate-500 mt-1">{note}</p>}
      <ul className="mt-2 space-y-1 max-h-48 overflow-y-auto">
        {(items || []).map((f: any, i: number) => (
          <li key={i} className="text-xs text-slate-300 border-t border-slate-700 pt-1">
            {f.description || f.finding_type}
          </li>
        ))}
        {(!items || items.length === 0) && <li className="text-xs text-slate-500">None</li>}
      </ul>
    </div>
  );
}
