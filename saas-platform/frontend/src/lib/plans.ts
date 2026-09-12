export type Tier = "free" | "pro" | "enterprise";

export interface Plan {
  tier: Tier;
  label: string;
  price: string;
  cadence: string;
  summary: string;
  features: string[];
}

// Mirrors backend/app/tiers.py, which is the enforcing source of truth.
export const PLANS: Plan[] = [
  {
    tier: "free",
    label: "Free",
    price: "$0",
    cadence: "forever",
    summary: "For a first look at a single host.",
    features: ["10 scans per month", "quickscan and compliance profiles", "HTML reports"],
  },
  {
    tier: "pro",
    label: "Pro",
    price: "$19.99",
    cadence: "per month",
    summary: "For teams auditing their web applications.",
    features: [
      "Unlimited scans",
      "Adds webaudit and stealthscan",
      "HTML and PDF reports",
      "Scan comparison",
      "Authenticated scanning",
    ],
  },
  {
    tier: "enterprise",
    label: "Enterprise",
    price: "$49.99",
    cadence: "per month",
    summary: "Full-depth assessments and recon.",
    features: [
      "Everything in Pro",
      "Adds deepscan and recon",
      "HTML, PDF and JSON exports",
      "2 scans in parallel",
    ],
  },
];

export const TIER_RANK: Record<Tier, number> = { free: 0, pro: 1, enterprise: 2 };

export function planLabel(tier: string | null | undefined): string {
  return PLANS.find((p) => p.tier === tier)?.label ?? String(tier ?? "");
}
