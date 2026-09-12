import { useEffect, useState } from "react";

import { api } from "../lib/api";

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

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`;
  return `${(n / 1024 ** 3).toFixed(2)} GB`;
}

export default function AdminPanel() {
  const [tab, setTab] = useState<"dashboard" | "users" | "reports" | "audit">("dashboard");
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [reports, setReports] = useState<AdminReport[]>([]);
  const [audit, setAudit] = useState<AuditEntry[]>([]);

  const loadAll = async () => {
    const [s, u, r, a] = await Promise.all([
      api.get("/admin/dashboard"),
      api.get("/admin/users"),
      api.get("/admin/reports"),
      api.get("/admin/audit-log"),
    ]);
    setStats(s.data);
    setUsers(u.data);
    setReports(r.data);
    setAudit(a.data);
  };

  useEffect(() => {
    loadAll();
  }, []);

  const setTier = async (userId: number, tier: string) => {
    await api.post(`/admin/users/${userId}/tier`, { tier });
    loadAll();
  };

  const resetPassword = async (userId: number) => {
    const pw = prompt("New password (min 8 chars):");
    if (!pw) return;
    await api.post(`/admin/users/${userId}/reset-password`, { new_password: pw });
    alert("Password reset.");
  };

  const toggleSuspend = async (userId: number) => {
    await api.post(`/admin/users/${userId}/suspend`);
    loadAll();
  };

  const deleteUser = async (userId: number) => {
    if (!confirm("Permanently delete this user and all their scans?")) return;
    await api.delete(`/admin/users/${userId}`);
    loadAll();
  };

  const deleteReport = async (jobId: number) => {
    if (!confirm("Delete this report from disk and the database?")) return;
    await api.delete(`/admin/reports/${jobId}`);
    loadAll();
  };

  const tabClass = (t: string) =>
    `px-3 py-2 rounded-md text-sm font-medium ${tab === t ? "bg-cyan-600 text-white" : "text-slate-300 hover:bg-slate-800"}`;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Admin Panel</h1>
      <div className="flex gap-1">
        <button className={tabClass("dashboard")} onClick={() => setTab("dashboard")}>Dashboard</button>
        <button className={tabClass("users")} onClick={() => setTab("users")}>Users</button>
        <button className={tabClass("reports")} onClick={() => setTab("reports")}>Reports</button>
        <button className={tabClass("audit")} onClick={() => setTab("audit")}>Audit Log</button>
      </div>

      {tab === "dashboard" && stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <StatCard label="Total users" value={stats.total_users} />
          <StatCard label="Scans this month" value={stats.scans_this_month} />
          <StatCard label="Total findings stored" value={stats.total_findings} />
          <StatCard label="Report storage" value={formatBytes(stats.output_dir_bytes)} />
          {Object.entries(stats.users_per_tier).map(([tier, count]) => (
            <StatCard key={tier} label={`${tier} users`} value={count} />
          ))}
        </div>
      )}

      {tab === "users" && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-slate-800 text-slate-300 text-left">
              <tr>
                <th className="px-4 py-2">Email</th>
                <th className="px-4 py-2">Role</th>
                <th className="px-4 py-2">Tier</th>
                <th className="px-4 py-2">Scans used</th>
                <th className="px-4 py-2">Last login</th>
                <th className="px-4 py-2">Active</th>
                <th className="px-4 py-2">Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id} className="border-t border-slate-800">
                  <td className="px-4 py-2">{u.email}</td>
                  <td className="px-4 py-2">{u.role}</td>
                  <td className="px-4 py-2">
                    {u.role === "admin" ? (
                      <span className="capitalize">{u.tier}</span>
                    ) : (
                      <select
                        value={u.tier}
                        onChange={(e) => setTier(u.id, e.target.value)}
                        className="bg-slate-800 border border-slate-700 rounded-md px-2 py-1"
                      >
                        <option value="free">free</option>
                        <option value="pro">pro</option>
                        <option value="enterprise">enterprise</option>
                      </select>
                    )}
                  </td>
                  <td className="px-4 py-2">{u.scans_used_this_period}</td>
                  <td className="px-4 py-2 text-slate-400">
                    {u.last_login_at ? new Date(u.last_login_at).toLocaleString() : "never"}
                  </td>
                  <td className="px-4 py-2">{u.is_active ? "yes" : "suspended"}</td>
                  <td className="px-4 py-2 space-x-2">
                    {u.role !== "admin" && (
                      <>
                        <button onClick={() => resetPassword(u.id)} className="text-cyan-400 hover:underline">Reset PW</button>
                        <button onClick={() => toggleSuspend(u.id)} className="text-amber-400 hover:underline">
                          {u.is_active ? "Suspend" : "Unsuspend"}
                        </button>
                        <button onClick={() => deleteUser(u.id)} className="text-red-400 hover:underline">Delete</button>
                      </>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {tab === "reports" && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-slate-800 text-slate-300 text-left">
              <tr>
                <th className="px-4 py-2">Target</th>
                <th className="px-4 py-2">Profile</th>
                <th className="px-4 py-2">User ID</th>
                <th className="px-4 py-2">Created</th>
                <th className="px-4 py-2">Size</th>
                <th className="px-4 py-2"></th>
              </tr>
            </thead>
            <tbody>
              {reports.map((r) => (
                <tr key={r.job_id} className="border-t border-slate-800">
                  <td className="px-4 py-2 font-mono">{r.target}</td>
                  <td className="px-4 py-2">{r.profile}</td>
                  <td className="px-4 py-2">{r.user_id}</td>
                  <td className="px-4 py-2 text-slate-400">{new Date(r.created_at).toLocaleString()}</td>
                  <td className="px-4 py-2">{formatBytes(r.size_bytes)}</td>
                  <td className="px-4 py-2">
                    <button onClick={() => deleteReport(r.job_id)} className="text-red-400 hover:underline">Delete</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="text-xs text-slate-500 px-4 py-2">
            Aegis auto-prunes older reports beyond 5 per profile+target — this list reflects what's
            currently on disk.
          </p>
        </div>
      )}

      {tab === "audit" && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-slate-800 text-slate-300 text-left">
              <tr>
                <th className="px-4 py-2">Time</th>
                <th className="px-4 py-2">Admin ID</th>
                <th className="px-4 py-2">Action</th>
                <th className="px-4 py-2">Target user</th>
                <th className="px-4 py-2">Detail</th>
              </tr>
            </thead>
            <tbody>
              {audit.map((a) => (
                <tr key={a.id} className="border-t border-slate-800">
                  <td className="px-4 py-2 text-slate-400">{new Date(a.timestamp).toLocaleString()}</td>
                  <td className="px-4 py-2">{a.admin_id}</td>
                  <td className="px-4 py-2">{a.action}</td>
                  <td className="px-4 py-2">{a.target_user_id ?? "-"}</td>
                  <td className="px-4 py-2 text-slate-400">{a.detail ?? "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function StatCard({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
      <p className="text-sm text-slate-400">{label}</p>
      <p className="text-2xl font-bold">{value}</p>
    </div>
  );
}
