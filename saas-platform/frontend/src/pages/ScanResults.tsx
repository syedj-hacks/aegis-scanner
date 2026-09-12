import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";

import { JobStatus, Severity } from "../components/Labels";
import PageHeader from "../components/PageHeader";
import { api, errorMessage } from "../lib/api";

interface Finding {
  id: number;
  port: number | null;
  service: string | null;
  product?: string | null;
  version?: string | null;
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

const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

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
  const [downloadError, setDownloadError] = useState<string | null>(null);

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

  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const f of findings) {
      const s = (f.severity || "INFO").toUpperCase();
      c[s] = (c[s] || 0) + 1;
    }
    return c;
  }, [findings]);

  const visibleFindings = useMemo(() => {
    let list = [...findings];
    if (filterSeverity !== "ALL") list = list.filter((f) => (f.severity || "INFO").toUpperCase() === filterSeverity);
    if (sortSeverity) {
      const rank = (s: string | null) => {
        const i = SEVERITY_ORDER.indexOf((s || "INFO").toUpperCase());
        return i === -1 ? SEVERITY_ORDER.length : i;
      };
      list.sort((a, b) => rank(a.severity) - rank(b.severity));
    }
    return list;
  }, [findings, filterSeverity, sortSeverity]);

  // Reports need the bearer token, which a plain <a href> can't send — fetch
  // the file with the API client and hand the browser a blob instead.
  const download = async (fmt: string) => {
    if (!job) return;
    setDownloadError(null);
    try {
      const res = await api.get(`/scans/jobs/${job.id}/report`, { params: { fmt }, responseType: "blob" });
      const blob = fmt === "json" ? new Blob([await res.data.text()], { type: "application/json" }) : res.data;
      // Always saved as a file, never opened in a tab: a blob: URL inherits this
      // app's origin, and report HTML embeds text taken from the scanned target.
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${job.target}_${job.profile}.${fmt}`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 60_000);
    } catch (err: any) {
      let message = errorMessage(err, "Download failed");
      const data = err?.response?.data;
      if (data instanceof Blob) {
        try {
          message = JSON.parse(await data.text()).detail || message;
        } catch {
          /* keep generic message */
        }
      }
      setDownloadError(message);
    }
  };

  const runDiff = async () => {
    if (!job?.aegis_scan_id || !compareTargetId) return;
    const other = history.find((h) => h.id === compareTargetId);
    if (!other?.aegis_scan_id) return;
    const [a, b] = [job.aegis_scan_id, other.aegis_scan_id].sort((x, y) => x - y);
    const res = await api.post("/scans/diff", { scan_id_a: a, scan_id_b: b });
    setDiffResult(res.data);
  };

  if (!job) {
    return <div className="mx-auto max-w-6xl px-5 py-16 text-dim sm:px-8">Loading scan…</div>;
  }

  return (
    <>
      <PageHeader
        eyebrow={`Scan #${job.id} · ${job.profile}`}
        title={<span className="font-mono text-[0.85em] font-semibold tracking-normal">{job.target}</span>}
        description={
          job.status === "done"
            ? `${findings.length} finding${findings.length === 1 ? "" : "s"} recorded.`
            : job.status === "failed"
              ? job.error || "The scan did not complete."
              : "The scan is in progress. This page updates automatically."
        }
        actions={
          <div className="flex items-center gap-3">
            <span className="[&_.tag]:border-dark-line [&_.tag]:text-on-dark">
              <JobStatus status={job.status} />
            </span>
            <Link to="/dashboard" className="btn-outline-dark btn-sm">All scans</Link>
          </div>
        }
      />

      {job.status === "done" && (
        <>
          <div className="border-b border-light-line">
            <div className="mx-auto grid max-w-6xl grid-cols-2 sm:grid-cols-4">
              {SEVERITY_ORDER.slice(0, 4).map((s, i) => (
                <div key={s} className={`px-5 py-6 sm:px-8 ${i > 0 ? "border-l border-light-line" : ""} ${i === 2 ? "border-l-0 sm:border-l" : ""} ${i >= 2 ? "border-t border-light-line sm:border-t-0" : ""}`}>
                  <div className={`font-display text-[1.9rem] font-extrabold leading-none ${s === "CRITICAL" && counts[s] ? "text-brand" : ""}`}>
                    {counts[s] || 0}
                  </div>
                  <div className="mt-2 font-mono text-[0.7rem] uppercase tracking-[0.08em] text-dim">{s.toLowerCase()}</div>
                </div>
              ))}
            </div>
          </div>

          <div className="mx-auto max-w-6xl space-y-8 px-5 py-10 sm:px-8">
            <div className="flex flex-wrap items-center gap-3">
              <span className="eyebrow-light mr-2">Export</span>
              {reportFormats.map((fmt) => (
                <button key={fmt} onClick={() => download(fmt)} className="btn-outline btn-sm font-mono uppercase">
                  {fmt}
                </button>
              ))}
              {!reportFormats.includes("pdf") && (
                <span className="text-sm text-dim">
                  PDF and JSON exports are on <Link to="/billing" className="text-action">Pro and Enterprise</Link>
                </span>
              )}
              {downloadError && <span role="alert" className="text-sm text-brand-dim">{downloadError}</span>}
            </div>

            <div className="panel">
              <div className="panel-head">
                <h2 className="panel-title">Findings</h2>
                <div className="flex items-center gap-2 text-sm">
                  <label htmlFor="sev-filter" className="sr-only">Filter by severity</label>
                  <select
                    id="sev-filter"
                    value={filterSeverity}
                    onChange={(e) => setFilterSeverity(e.target.value)}
                    className="input w-auto py-1.5"
                  >
                    <option value="ALL">All severities</option>
                    {SEVERITY_ORDER.map((s) => (
                      <option key={s} value={s}>{s.charAt(0) + s.slice(1).toLowerCase()}</option>
                    ))}
                  </select>
                  <button onClick={() => setSortSeverity((v) => !v)} className="btn-outline btn-sm" aria-pressed={sortSeverity}>
                    {sortSeverity ? "Sorted by severity" : "Original order"}
                  </button>
                </div>
              </div>
              <div className="overflow-x-auto">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Severity</th>
                      <th>Port</th>
                      <th>Type</th>
                      <th>Description</th>
                      <th>CVE</th>
                    </tr>
                  </thead>
                  <tbody>
                    {visibleFindings.map((f) => (
                      <tr key={f.id}>
                        <td><Severity level={f.severity} /></td>
                        <td className="font-mono text-[0.82rem]">{f.port ?? "—"}</td>
                        <td className="whitespace-nowrap text-dim">{f.finding_type?.replace(/_/g, " ")}</td>
                        <td className="min-w-[18rem] max-w-xl">
                          {f.description ||
                            // Service-inventory records carry no description, only what's listening.
                            [[f.product, f.version].filter(Boolean).join(" "), f.service].filter(Boolean).join(" · ") ||
                            "—"}
                          {f.remediation && <div className="mt-1.5 text-[0.82rem] text-dim">Fix: {f.remediation}</div>}
                        </td>
                        <td className="whitespace-nowrap font-mono text-[0.82rem]">{f.cve_id || "—"}</td>
                      </tr>
                    ))}
                    {visibleFindings.length === 0 && (
                      <tr><td colSpan={5} className="py-10 text-center text-dim">No findings match this filter.</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            {diffAllowed && history.length > 0 && (
              <div className="panel">
                <div className="panel-head">
                  <h2 className="panel-title">Compare with a previous scan</h2>
                  <div className="flex items-center gap-2">
                    <label htmlFor="compare" className="sr-only">Previous scan</label>
                    <select
                      id="compare"
                      value={compareTargetId}
                      onChange={(e) => setCompareTargetId(e.target.value ? Number(e.target.value) : "")}
                      className="input w-auto py-1.5 text-sm"
                    >
                      <option value="">Select a scan…</option>
                      {history.map((h) => (
                        <option key={h.id} value={h.id}>
                          #{h.id} · {h.profile} · {new Date(h.created_at).toLocaleString()}
                        </option>
                      ))}
                    </select>
                    <button onClick={runDiff} disabled={!compareTargetId} className="btn-primary btn-sm">
                      Compare
                    </button>
                  </div>
                </div>

                {diffResult && (
                  <div className="grid grid-cols-1 gap-px bg-light-line md:grid-cols-2">
                    <DiffColumn title="New" emphasis items={diffResult.new} />
                    <DiffColumn title="Fixed · confirmed" items={diffResult.fixed} />
                    <DiffColumn
                      title="Unverified"
                      items={diffResult.unverified}
                      note="These findings disappeared, but the tool that would have re-confirmed them didn't run this time — their absence proves nothing."
                    />
                    <DiffColumn title="Severity changed" items={diffResult.changed} />
                  </div>
                )}
              </div>
            )}
            {!diffAllowed && (
              <p className="text-sm text-dim">
                Scan comparison is available on <Link to="/billing" className="text-action">Pro and Enterprise</Link>.
              </p>
            )}
          </div>
        </>
      )}
    </>
  );
}

function DiffColumn({ title, items, note, emphasis }: { title: string; items: any[]; note?: string; emphasis?: boolean }) {
  return (
    <div className="bg-light p-5">
      <h3 className={`font-mono text-[0.72rem] uppercase tracking-[0.08em] ${emphasis ? "text-brand" : "text-ink"}`}>
        {title} · {items?.length ?? 0}
      </h3>
      {note && <p className="mt-1.5 text-xs text-dim">{note}</p>}
      <ul className="mt-3 max-h-48 overflow-y-auto">
        {(items || []).map((f: any, i: number) => (
          <li key={i} className="border-t border-light-line py-1.5 text-[0.82rem]">
            {f.description || f.finding_type}
          </li>
        ))}
        {(!items || items.length === 0) && <li className="text-[0.82rem] text-dim">None</li>}
      </ul>
    </div>
  );
}
