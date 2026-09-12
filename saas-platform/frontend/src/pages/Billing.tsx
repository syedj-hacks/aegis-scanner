import { useEffect, useState } from "react";

import { api } from "../lib/api";

interface Subscription {
  tier: "free" | "pro" | "enterprise";
  status: string;
  scans_used_this_period: number;
  scans_limit: number | null;
  renews_at: string | null;
  started_at: string;
}

interface Payment {
  id: number;
  amount: number;
  tier: string;
  simulated_method: string;
  status: string;
  created_at: string;
  note: string | null;
}

const TIERS: { tier: "free" | "pro" | "enterprise"; label: string; price: string; features: string[] }[] = [
  { tier: "free", label: "Free", price: "$0", features: ["10 scans/month", "quickscan, compliance", "HTML reports"] },
  { tier: "pro", label: "Pro", price: "$19.99/mo", features: ["Unlimited scans", "+ webaudit, stealthscan", "HTML + PDF", "Diff (2 scans)", "Live view"] },
  { tier: "enterprise", label: "Enterprise", price: "$49.99/mo", features: ["Unlimited scans", "+ deepscan, recon", "HTML + PDF + JSON", "Unlimited diff", "2 parallel scans", "Full config"] },
];

export default function Billing() {
  const [sub, setSub] = useState<Subscription | null>(null);
  const [payments, setPayments] = useState<Payment[]>([]);
  const [busy, setBusy] = useState(false);

  const load = async () => {
    const [subRes, payRes] = await Promise.all([api.get("/billing/subscription"), api.get("/billing/payments")]);
    setSub(subRes.data);
    setPayments(payRes.data);
  };

  useEffect(() => {
    load();
  }, []);

  const upgrade = async (tier: string) => {
    setBusy(true);
    try {
      await api.post("/billing/simulate-upgrade", { tier });
      await load();
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Billing</h1>
      <p className="text-sm text-amber-400 bg-amber-950/40 border border-amber-800 rounded-md p-3">
        Demo mode — no real payment is processed. "Simulate Upgrade" writes a mock ledger entry and
        changes your tier immediately.
      </p>

      {sub && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <p className="text-sm text-slate-400">Current plan</p>
          <p className="text-lg font-semibold capitalize">{sub.tier} ({sub.status})</p>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {TIERS.map((t) => (
          <div key={t.tier} className={`rounded-xl border p-4 space-y-3 ${sub?.tier === t.tier ? "border-cyan-500 bg-cyan-950/30" : "border-slate-800 bg-slate-900"}`}>
            <h2 className="font-semibold text-lg">{t.label}</h2>
            <p className="text-2xl font-bold">{t.price}</p>
            <ul className="text-sm text-slate-400 space-y-1">
              {t.features.map((f) => <li key={f}>• {f}</li>)}
            </ul>
            <button
              disabled={busy || sub?.tier === t.tier}
              onClick={() => upgrade(t.tier)}
              className="w-full rounded-md bg-cyan-600 hover:bg-cyan-500 py-2 text-sm font-medium disabled:opacity-50"
            >
              {sub?.tier === t.tier ? "Current plan" : "Simulate Upgrade"}
            </button>
          </div>
        ))}
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        <h2 className="font-semibold px-4 py-2 border-b border-slate-800">Payment history (mock ledger)</h2>
        <table className="w-full text-sm">
          <thead className="bg-slate-800 text-slate-300 text-left">
            <tr>
              <th className="px-4 py-2">Date</th>
              <th className="px-4 py-2">Tier</th>
              <th className="px-4 py-2">Amount</th>
              <th className="px-4 py-2">Method</th>
              <th className="px-4 py-2">Status</th>
              <th className="px-4 py-2">Note</th>
            </tr>
          </thead>
          <tbody>
            {payments.map((p) => (
              <tr key={p.id} className="border-t border-slate-800">
                <td className="px-4 py-2">{new Date(p.created_at).toLocaleString()}</td>
                <td className="px-4 py-2 capitalize">{p.tier}</td>
                <td className="px-4 py-2">${(p.amount / 100).toFixed(2)}</td>
                <td className="px-4 py-2">{p.simulated_method}</td>
                <td className="px-4 py-2">{p.status}</td>
                <td className="px-4 py-2 text-slate-400">{p.note || "-"}</td>
              </tr>
            ))}
            {payments.length === 0 && (
              <tr><td colSpan={6} className="px-4 py-6 text-center text-slate-500">No payments yet.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
