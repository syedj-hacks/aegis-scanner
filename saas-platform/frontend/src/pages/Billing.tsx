import { useEffect, useState } from "react";

import PageHeader from "../components/PageHeader";
import { api, errorMessage } from "../lib/api";
import { PLANS, TIER_RANK, Tier, planLabel } from "../lib/plans";

interface Subscription {
  tier: Tier;
  status: string;
  scans_used_this_period: number;
  scans_limit: number | null;
  renews_at: string | null;
  started_at: string;
  period_start_date: string;
  pending_tier: Tier | null;
}

interface Payment {
  id: number;
  amount: number;
  tier: string;
  simulated_method: string;
  status: "paid" | "pending" | "failed";
  created_at: string;
  note: string | null;
}

const METHOD_LABEL: Record<string, string> = {
  invoice: "Invoice",
  manual: "Manual",
  "plan change": "Plan change",
  "manual/demo": "Invoice",
  "admin/demo": "Manual",
};

function statusLabel(p: Payment): { text: string; className: string } {
  if (p.status === "paid") return { text: "Paid", className: "tag border-ink text-ink" };
  if (p.status === "pending") return { text: "Pending review", className: "tag border-brand text-brand" };
  return { text: p.note?.startsWith("Cancelled") ? "Cancelled" : "Declined", className: "tag" };
}

export default function Billing() {
  const [sub, setSub] = useState<Subscription | null>(null);
  const [payments, setPayments] = useState<Payment[]>([]);
  const [busy, setBusy] = useState<Tier | "cancel" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const load = async () => {
    const [subRes, payRes] = await Promise.all([api.get("/billing/subscription"), api.get("/billing/payments")]);
    setSub(subRes.data);
    setPayments(payRes.data);
  };

  useEffect(() => {
    load();
  }, []);

  const changePlan = async (tier: Tier) => {
    if (!sub) return;
    const isDowngrade = TIER_RANK[tier] < TIER_RANK[sub.tier];
    if (isDowngrade && !confirm(`Switch to the ${planLabel(tier)} plan? Features above that plan stop immediately.`)) return;
    setBusy(tier);
    setError(null);
    setNotice(null);
    try {
      await api.post("/billing/change-plan", { tier });
      setNotice(
        isDowngrade
          ? `You're now on the ${planLabel(tier)} plan.`
          : `Upgrade to ${planLabel(tier)} requested. Your plan activates as soon as the invoice is approved.`
      );
      await load();
    } catch (err) {
      setError(errorMessage(err, "Could not change your plan"));
    } finally {
      setBusy(null);
    }
  };

  const cancelRequest = async () => {
    setBusy("cancel");
    setError(null);
    setNotice(null);
    try {
      await api.delete("/billing/upgrade-request");
      await load();
    } catch (err) {
      setError(errorMessage(err, "Could not cancel the request"));
    } finally {
      setBusy(null);
    }
  };

  const periodEnds = sub ? new Date(new Date(sub.period_start_date).getTime() + 30 * 86_400_000) : null;

  return (
    <>
      <PageHeader
        eyebrow="Billing"
        title="Plan and invoices"
        description="Manage your subscription. Upgrades are invoiced and activate once approved; downgrades take effect immediately."
      />

      {sub && (
        <div className="border-b border-light-line">
          <div className="mx-auto grid max-w-6xl grid-cols-1 sm:grid-cols-3">
            {[
              [planLabel(sub.tier), sub.status === "active" ? "Current plan · active" : `Current plan · ${sub.status}`],
              [
                `${sub.scans_used_this_period}${sub.scans_limit !== null ? ` / ${sub.scans_limit}` : ""}`,
                sub.scans_limit === null ? "Scans this period · unlimited" : "Scans used this period",
              ],
              [periodEnds ? periodEnds.toLocaleDateString(undefined, { day: "numeric", month: "short" }) : "—", "Usage resets on"],
            ].map(([num, label], i) => (
              <div key={label} className={`px-5 py-7 sm:px-8 ${i > 0 ? "border-t border-light-line sm:border-l sm:border-t-0" : ""}`}>
                <div className="font-display text-[1.9rem] font-extrabold leading-none">{num}</div>
                <div className="mt-2 text-[0.8rem] text-dim">{label}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="mx-auto max-w-6xl space-y-10 px-5 py-10 sm:px-8">
        {sub?.pending_tier && (
          <div className="flex flex-wrap items-center justify-between gap-4 border border-light-line border-l-2 border-l-brand bg-light-alt px-5 py-4">
            <div>
              <div className="font-display font-bold">Upgrade to {planLabel(sub.pending_tier)} is pending review</div>
              <div className="text-sm text-dim">You keep full access to your current plan until it's approved.</div>
            </div>
            <button onClick={cancelRequest} disabled={busy !== null} className="btn-outline btn-sm">
              {busy === "cancel" ? "Cancelling…" : "Cancel request"}
            </button>
          </div>
        )}
        {notice && !sub?.pending_tier && (
          <p role="status" className="border-l-2 border-ink bg-light-alt px-4 py-3 text-sm">{notice}</p>
        )}
        {error && <p role="alert" className="border-l-2 border-brand bg-brand/5 px-4 py-3 text-sm">{error}</p>}

        <div className="grid grid-cols-1 gap-px border border-light-line bg-light-line md:grid-cols-3">
          {PLANS.map((p) => {
            const current = sub?.tier === p.tier;
            const pending = sub?.pending_tier === p.tier;
            const isUpgrade = sub ? TIER_RANK[p.tier] > TIER_RANK[sub.tier] : false;
            return (
              <div key={p.tier} className={`relative flex flex-col bg-light px-7 py-8 ${current ? "outline outline-2 -outline-offset-2 outline-ink" : ""}`}>
                <div className="flex items-center justify-between">
                  <span className="font-mono text-[0.72rem] uppercase tracking-[0.1em] text-dim">{p.label}</span>
                  {current && <span className="tag border-ink text-ink">current</span>}
                  {pending && <span className="tag border-brand text-brand">requested</span>}
                </div>
                <div className="mt-3 flex items-baseline gap-2">
                  <span className="font-display text-[2.3rem] font-extrabold leading-none">{p.price}</span>
                  <span className="text-sm text-dim">{p.cadence}</span>
                </div>
                <p className="mt-3 text-[0.9rem] text-dim">{p.summary}</p>
                <ul className="mt-6 flex-1 space-y-2 border-t border-light-line pt-5 text-[0.88rem]">
                  {p.features.map((f) => (
                    <li key={f} className="flex gap-3">
                      <span className="font-mono text-brand" aria-hidden>—</span>
                      {f}
                    </li>
                  ))}
                </ul>
                <button
                  disabled={!sub || busy !== null || current || pending}
                  onClick={() => changePlan(p.tier)}
                  className={`mt-7 w-full ${isUpgrade && !pending ? "btn-primary" : "btn-outline"}`}
                >
                  {current
                    ? "Current plan"
                    : pending
                      ? "Awaiting approval"
                      : busy === p.tier
                        ? "Submitting…"
                        : isUpgrade
                          ? `Upgrade to ${p.label}`
                          : `Switch to ${p.label}`}
                </button>
              </div>
            );
          })}
        </div>

        <div className="panel">
          <div className="panel-head">
            <h2 className="panel-title">Invoices and plan changes</h2>
          </div>
          <div className="overflow-x-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Date</th>
                  <th>Plan</th>
                  <th>Amount</th>
                  <th>Method</th>
                  <th>Status</th>
                  <th>Note</th>
                </tr>
              </thead>
              <tbody>
                {payments.map((p) => {
                  const st = statusLabel(p);
                  return (
                    <tr key={p.id}>
                      <td className="whitespace-nowrap text-dim">{new Date(p.created_at).toLocaleDateString()}</td>
                      <td>{planLabel(p.tier)}</td>
                      <td className="font-mono text-[0.82rem]">${(p.amount / 100).toFixed(2)}</td>
                      <td className="text-dim">{METHOD_LABEL[p.simulated_method] ?? p.simulated_method}</td>
                      <td><span className={st.className}>{st.text}</span></td>
                      <td className="text-dim">{p.note && !/simulat|demo/i.test(p.note) ? p.note : "—"}</td>
                    </tr>
                  );
                })}
                {payments.length === 0 && (
                  <tr><td colSpan={6} className="py-10 text-center text-dim">No invoices yet.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </>
  );
}
