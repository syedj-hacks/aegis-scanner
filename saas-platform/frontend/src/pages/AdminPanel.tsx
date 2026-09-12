import { useEffect, useState } from "react";

import PageHeader from "../components/PageHeader";
import { api, errorMessage } from "../lib/api";
import { planLabel } from "../lib/plans";

interface DashboardStats {
  total_users: number;
  users_per_tier: Record<string, number>;
  scans_this_month: number;
  total_findings: number;
  output_dir_bytes: number;
}

interface AdminUser {
  id: number;
  email: string;
  role: string;
  is_active: boolean;
  tier: string;
  scans_used_this_period: number;
  last_login_at: string | null;
  created_at: string;
}

interface AdminReport {
  job_id: number;
  user_id: number;
  target: string;
  profile: string;
  created_at: string;
  size_bytes: number;
}

interface AuditEntry {
  id: number;
  admin_id: number;
  action: string;
  target_user_id: number | null;
  timestamp: string;
  detail: string | null;
}

interface UpgradeRequest {
  id: number;
  user_id: number;
  email: string;
  current_tier: string;
  requested_tier: string;
  amount: number;
  created_at: string;
}

type Tab = "overview" | "requests" | "users" | "reports" | "audit";

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`;
  return `${(n / 1024 ** 3).toFixed(2)} GB`;
}

export default function AdminPanel() {
  const [tab, setTab] = useState<Tab>("overview");
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [reports, setReports] = useState<AdminReport[]>([]);
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [requests, setRequests] = useState<UpgradeRequest[]>([]);
  const [error, setError] = useState<string | null>(null);

  const loadAll = async () => {
    const [s, u, r, a, q] = await Promise.all([
      api.get("/admin/dashboard"),
      api.get("/admin/users"),
      api.get("/admin/reports"),
      api.get("/admin/audit-log"),
      api.get("/admin/upgrade-requests"),
    ]);
    setStats(s.data);
    setUsers(u.data);
    setReports(r.data);
    setAudit(a.data);
    setRequests(q.data);
  };

  useEffect(() => {
    loadAll();
  }, []);

  const act = async (fn: () => Promise<unknown>) => {
    setError(null);
    try {
      await fn();
      await loadAll();
    } catch (err) {
      setError(errorMessage(err, "Action failed"));
    }
  };

  const setTier = (userId: number, tier: string) => act(() => api.post(`/admin/users/${userId}/tier`, { tier }));

  const resetPassword = (userId: number) => {
    const pw = prompt("New password (at least 8 characters):");
    if (!pw) return;
    act(() => api.post(`/admin/users/${userId}/reset-password`, { new_password: pw }));
  };

  const toggleSuspend = (userId: number) => act(() => api.post(`/admin/users/${userId}/suspend`));

  const deleteUser = (userId: number) => {
    if (!confirm("Permanently delete this user and all their scans?")) return;
    act(() => api.delete(`/admin/users/${userId}`));
  };

  const deleteReport = (jobId: number) => {
    if (!confirm("Delete this report from disk and the database?")) return;
    act(() => api.delete(`/admin/reports/${jobId}`));
  };

  const decide = (id: number, decision: "approve" | "reject") =>
    act(() => api.post(`/admin/upgrade-requests/${id}/${decision}`));

  const tabs: [Tab, string][] = [
    ["overview", "Overview"],
    ["requests", `Upgrade requests${requests.length ? ` · ${requests.length}` : ""}`],
    ["users", "Users"],
    ["reports", "Reports"],
    ["audit", "Audit log"],
  ];

  return (
    <>
      <PageHeader eyebrow="Administration" title="Workspace control" description="Users, plan approvals, stored reports and the audit trail." />

      <div className="border-b border-light-line bg-light">
        <div role="tablist" className="mx-auto flex max-w-6xl overflow-x-auto px-5 sm:px-8">
          {tabs.map(([key, label]) => (
            <button
              key={key}
              role="tab"
              aria-selected={tab === key}
              onClick={() => setTab(key)}
              className={`-mb-px whitespace-nowrap border-b-2 px-1 py-4 text-sm transition-colors [&:not(:first-child)]:ml-7 ${
                tab === key ? "border-brand font-semibold text-ink" : "border-transparent text-dim hover:text-ink"
              }`}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      <div className="mx-auto max-w-6xl space-y-6 px-5 py-10 sm:px-8">
        {error && <p role="alert" className="border-l-2 border-brand bg-brand/5 px-4 py-3 text-sm">{error}</p>}

        {tab === "overview" && stats && (
          <div className="grid grid-cols-2 gap-px border border-light-line bg-light-line lg:grid-cols-4">
            <StatCell label="Total users" value={stats.total_users} />
            <StatCell label="Scans in the last 30 days" value={stats.scans_this_month} />
            <StatCell label="Findings stored" value={stats.total_findings} />
            <StatCell label="Report storage" value={formatBytes(stats.output_dir_bytes)} />
            {Object.entries(stats.users_per_tier).map(([tier, count]) => (
              <StatCell key={tier} label={`${planLabel(tier)} accounts`} value={count} />
            ))}
            <StatCell label="Pending upgrade requests" value={requests.length} highlight={requests.length > 0} />
          </div>
        )}

        {tab === "requests" && (
          <div className="panel overflow-x-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Requested</th>
                  <th>Account</th>
                  <th>Change</th>
                  <th>Invoice</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {requests.map((r) => (
                  <tr key={r.id}>
                    <td className="whitespace-nowrap text-dim">{new Date(r.created_at).toLocaleString()}</td>
                    <td>{r.email}</td>
                    <td className="whitespace-nowrap">
                      {planLabel(r.current_tier)} <span className="text-dim">→</span>{" "}
                      <span className="font-semibold">{planLabel(r.requested_tier)}</span>
                    </td>
                    <td className="font-mono text-[0.82rem]">${(r.amount / 100).toFixed(2)} / mo</td>
                    <td className="whitespace-nowrap text-right">
                      <button onClick={() => decide(r.id, "reject")} className="btn-outline btn-sm mr-2">Decline</button>
                      <button onClick={() => decide(r.id, "approve")} className="btn-primary btn-sm">Approve</button>
                    </td>
                  </tr>
                ))}
                {requests.length === 0 && (
                  <tr><td colSpan={5} className="py-10 text-center text-dim">No pending requests.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        )}

        {tab === "users" && (
          <div className="panel overflow-x-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Email</th>
                  <th>Role</th>
                  <th>Plan</th>
                  <th>Scans used</th>
                  <th>Last sign-in</th>
                  <th>Status</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.id}>
                    <td>{u.email}</td>
                    <td className="font-mono text-[0.82rem] text-dim">{u.role}</td>
                    <td>
                      {u.role === "admin" ? (
                        planLabel(u.tier)
                      ) : (
                        <select value={u.tier} onChange={(e) => setTier(u.id, e.target.value)} className="input w-auto py-1 text-sm">
                          <option value="free">Free</option>
                          <option value="pro">Pro</option>
                          <option value="enterprise">Enterprise</option>
                        </select>
                      )}
                    </td>
                    <td className="font-mono text-[0.82rem]">{u.scans_used_this_period}</td>
                    <td className="whitespace-nowrap text-dim">
                      {u.last_login_at ? new Date(u.last_login_at).toLocaleString() : "Never"}
                    </td>
                    <td>
                      {u.is_active ? <span className="tag border-ink text-ink">active</span> : <span className="tag border-brand-dim text-brand-dim">suspended</span>}
                    </td>
                    <td className="whitespace-nowrap text-right">
                      {u.role !== "admin" && (
                        <div className="flex justify-end gap-4">
                          <button onClick={() => resetPassword(u.id)} className="text-action">Reset password</button>
                          <button onClick={() => toggleSuspend(u.id)} className="text-action">
                            {u.is_active ? "Suspend" : "Reinstate"}
                          </button>
                          <button onClick={() => deleteUser(u.id)} className="text-action text-brand-dim">Delete</button>
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {tab === "reports" && (
          <div className="panel">
            <div className="overflow-x-auto">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Target</th>
                    <th>Profile</th>
                    <th>User ID</th>
                    <th>Created</th>
                    <th>Size</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {reports.map((r) => (
                    <tr key={r.job_id}>
                      <td className="font-mono text-[0.82rem]">{r.target}</td>
                      <td className="font-mono text-[0.82rem] text-dim">{r.profile}</td>
                      <td className="font-mono text-[0.82rem]">{r.user_id}</td>
                      <td className="whitespace-nowrap text-dim">{new Date(r.created_at).toLocaleString()}</td>
                      <td className="font-mono text-[0.82rem]">{formatBytes(r.size_bytes)}</td>
                      <td className="text-right">
                        <button onClick={() => deleteReport(r.job_id)} className="text-action text-brand-dim">Delete</button>
                      </td>
                    </tr>
                  ))}
                  {reports.length === 0 && (
                    <tr><td colSpan={6} className="py-10 text-center text-dim">No stored reports.</td></tr>
                  )}
                </tbody>
              </table>
            </div>
            <p className="border-t border-light-line px-5 py-3 text-xs text-dim">
              The engine keeps the five most recent reports per target and profile; older ones are pruned automatically.
            </p>
          </div>
        )}

        {tab === "audit" && (
          <div className="panel overflow-x-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Admin</th>
                  <th>Action</th>
                  <th>Target user</th>
                  <th>Detail</th>
                </tr>
              </thead>
              <tbody>
                {audit.map((a) => (
                  <tr key={a.id}>
                    <td className="whitespace-nowrap text-dim">{new Date(a.timestamp).toLocaleString()}</td>
                    <td className="font-mono text-[0.82rem]">{a.admin_id}</td>
                    <td className="font-mono text-[0.82rem]">{a.action}</td>
                    <td className="font-mono text-[0.82rem]">{a.target_user_id ?? "—"}</td>
                    <td className="text-dim">{a.detail ?? "—"}</td>
                  </tr>
                ))}
                {audit.length === 0 && (
                  <tr><td colSpan={5} className="py-10 text-center text-dim">No administrative actions recorded.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  );
}

function StatCell({ label, value, highlight }: { label: string; value: string | number; highlight?: boolean }) {
  return (
    <div className="bg-light px-6 py-6">
      <div className={`font-display text-[1.9rem] font-extrabold leading-none ${highlight ? "text-brand" : ""}`}>{value}</div>
      <div className="mt-2 text-[0.8rem] text-dim">{label}</div>
    </div>
  );
}
