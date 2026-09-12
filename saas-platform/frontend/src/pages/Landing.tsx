import { useState } from "react";
import { Link } from "react-router-dom";

import Brand from "../components/Brand";
import Footer from "../components/Footer";
import { useAuth } from "../lib/auth";
import { PLANS } from "../lib/plans";

const TABS = ["Findings", "Services", "Evidence", "Compare", "Report"] as const;
type Tab = (typeof TABS)[number];

// Illustrative scan output for the hero panel — the same shape the product's
// scan results page shows. Lines tagged "brand" draw the eye; "dim" recede.
type Line = { t: string; k?: "dim" | "brand" };
const PANES: Record<Tab, { left: [string, Line[]]; right: [string, Line[]]; status: string }> = {
  Findings: {
    left: ["Scan · deepscan", [
      { t: "target   shop.example.com" },
      { t: "profile  deepscan · authorized", k: "dim" },
      { t: "22/tcp   ssh     OpenSSH 8.2p1", k: "dim" },
      { t: "443/tcp  https   nginx 1.18.0", k: "dim" },
      { t: "3306/tcp mysql   MySQL 5.7.33", k: "brand" },
    ]],
    right: ["Finding · AEG-0142", [
      { t: "SQL injection — /products?id=", k: "brand" },
      { t: "Severity: Critical · CVSS 9.8", k: "dim" },
      { t: "Confirmed by sqlmap (boolean blind)", k: "dim" },
      { t: "Mapped: PCI-DSS 6.2.4 · OWASP A03", k: "dim" },
      { t: "Fix: parameterize the product lookup" },
    ]],
    status: "14 tools ran · 0 failed",
  },
  Services: {
    left: ["Discovery · nmap -sV", [
      { t: "PORT     STATE  SERVICE  VERSION" },
      { t: "22/tcp   open   ssh      OpenSSH 8.2p1", k: "dim" },
      { t: "80/tcp   open   http     nginx 1.18.0", k: "dim" },
      { t: "443/tcp  open   https    nginx 1.18.0", k: "dim" },
      { t: "3306/tcp open   mysql    MySQL 5.7.33", k: "brand" },
    ]],
    right: ["Exposure", [
      { t: "Database port reachable from internet", k: "brand" },
      { t: "Severity: High", k: "dim" },
      { t: "4 services fingerprinted", k: "dim" },
      { t: "Fix: restrict 3306 to the app subnet" },
    ]],
    status: "Service detection finished in 41s",
  },
  Evidence: {
    left: ["Request", [
      { t: "GET /products?id=12' AND '1'='1 HTTP/1.1" },
      { t: "Host: shop.example.com", k: "dim" },
      { t: "User-Agent: aegis-shield", k: "dim" },
      { t: "Accept: text/html", k: "dim" },
    ]],
    right: ["Response diff", [
      { t: "true  condition → 200 · 18,402 bytes", k: "dim" },
      { t: "false condition → 200 ·  2,117 bytes", k: "dim" },
      { t: "Content differs on injected boolean", k: "brand" },
      { t: "Reproduced 3 of 3 attempts" },
    ]],
    status: "Evidence captured by sqlmap",
  },
  Compare: {
    left: ["Previous · 02 Sep", [
      { t: "critical  1", k: "brand" },
      { t: "high      3" },
      { t: "medium    7", k: "dim" },
      { t: "low      12", k: "dim" },
    ]],
    right: ["Latest · 09 Sep", [
      { t: "new         1  SQL injection", k: "brand" },
      { t: "fixed       2  confirmed by re-check" },
      { t: "unverified  1  tool did not re-run", k: "dim" },
      { t: "unchanged  19", k: "dim" },
    ]],
    status: "Fixed vs. unverified kept separate",
  },
  Report: {
    left: ["Export", [
      { t: "shop.example.com_deepscan.html" },
      { t: "shop.example.com_deepscan.pdf" },
      { t: "shop.example.com_deepscan.json", k: "dim" },
    ]],
    right: ["Executive summary", [
      { t: "Risk score 8.4 / 10", k: "brand" },
      { t: "23 findings across 4 services", k: "dim" },
      { t: "PCI-DSS · ISO 27001 · NIST 800-53", k: "dim" },
      { t: "Remediation steps for every finding" },
    ]],
    status: "Report ready to share",
  },
};

const STEPS = [
  ["01", "Discover", "Service and version detection maps every open port before a web tool is pointed at it."],
  ["02", "Assess", "Web, TLS and service checks run in parallel — nikto, nuclei, ZAP, sslyze and more."],
  ["03", "Score", "Each finding gets a CVSS-based severity, known-CVE matching and compliance mapping."],
  ["04", "Report & compare", "Export HTML, PDF or JSON, then diff scans to prove what was actually fixed."],
];

const STATS = [
  ["6", "Scan profiles, from quick sweep to full assessment"],
  ["15+", "Integrated open-source security tools"],
  ["3", "Compliance frameworks mapped per finding"],
  ["3", "Export formats: HTML, PDF, JSON"],
];

function PaneLines({ lines }: { lines: Line[] }) {
  return (
    <>
      {lines.map((l, i) => (
        <div
          key={i}
          className={`mb-[5px] whitespace-pre ${
            l.k === "brand" ? "text-brand" : l.k === "dim" ? "text-dim-dark" : "text-on-dark"
          }`}
        >
          {l.t}
        </div>
      ))}
    </>
  );
}

export default function Landing() {
  const { isAuthenticated } = useAuth();
  const [tab, setTab] = useState<Tab>("Findings");
  const pane = PANES[tab];

  // Hash routing owns the URL fragment, so in-page links scroll explicitly.
  const scrollTo = (id: string) => document.getElementById(id)?.scrollIntoView({ behavior: "smooth" });

  const primaryCta = isAuthenticated ? (
    <Link to="/dashboard" className="btn-primary px-7 py-3.5">Open dashboard</Link>
  ) : (
    <Link to="/register" className="btn-primary px-7 py-3.5">Start free</Link>
  );

  return (
    <div className="min-h-screen">
      <header className="sticky top-0 z-20 border-b border-dark-line bg-dark/[0.92] text-on-dark backdrop-blur-[6px]">
        <div className="mx-auto flex max-w-[1280px] items-center justify-between px-5 py-5 sm:px-11">
          <Brand />
          <nav className="hidden gap-8 text-[0.85rem] md:flex">
            <button onClick={() => scrollTo("how")} className="text-dim-dark transition-colors hover:text-on-dark">How it works</button>
            <button onClick={() => scrollTo("plans")} className="text-dim-dark transition-colors hover:text-on-dark">Plans</button>
            {!isAuthenticated && (
              <Link to="/login" className="text-dim-dark transition-colors hover:text-on-dark">Sign in</Link>
            )}
          </nav>
          {isAuthenticated ? (
            <Link to="/dashboard" className="btn-primary btn-sm px-4 py-2">Dashboard</Link>
          ) : (
            <Link to="/register" className="btn-primary btn-sm px-4 py-2">Create account</Link>
          )}
        </div>
      </header>
      <div className="hero-atmosphere text-on-dark">

        <section className="mx-auto max-w-[1280px] px-5 pt-16 text-center sm:px-11 sm:pt-20">
          <div className="eyebrow mb-6">Automated vulnerability assessment</div>
          <h1 className="mx-auto mb-6 max-w-[15ch] text-[clamp(2.6rem,6vw,5rem)] font-extrabold leading-[0.98] tracking-[-0.025em]">
            Find the exposure before <span className="text-brand">attackers</span> do.
          </h1>
          <p className="mx-auto mb-9 max-w-[52ch] text-[1.08rem] text-dim-dark">
            Aegis Shield runs real security tooling against the hosts you own and turns the output into
            scored, de-duplicated findings with remediation you can act on.
          </p>
          <div className="mb-10 flex flex-wrap justify-center gap-4">
            {primaryCta}
            <button onClick={() => scrollTo("how")} className="btn-outline-dark px-7 py-3.5">
              See how it works
            </button>
          </div>
          <div className="mb-14 flex flex-wrap justify-center gap-x-10 gap-y-2 font-mono text-[0.78rem] text-dim-dark">
            <span>nmap · nuclei · ZAP · sqlmap</span>
            <span>CVSS severity scoring</span>
            <span>PCI-DSS · ISO 27001 · NIST mapping</span>
          </div>

          <div className="mx-auto max-w-[1080px] overflow-hidden rounded-md border border-dark-line bg-dark-surface text-left">
            <div role="tablist" className="flex overflow-x-auto border-b border-dark-line font-mono text-[0.72rem]">
              {TABS.map((t) => (
                <button
                  key={t}
                  role="tab"
                  aria-selected={tab === t}
                  onClick={() => setTab(t)}
                  className={`whitespace-nowrap border-r border-dark-line px-[18px] py-[13px] transition-colors ${
                    tab === t ? "bg-brand/[0.06] text-brand" : "text-dim-dark hover:text-on-dark"
                  }`}
                >
                  {t}
                </button>
              ))}
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2">
              {[pane.left, pane.right].map(([label, lines], i) => (
                <div
                  key={label}
                  className={`overflow-x-auto px-[22px] py-5 font-mono text-[0.8rem] ${
                    i === 0 ? "border-b border-dark-line md:border-b-0 md:border-r" : ""
                  }`}
                >
                  <div className="mb-3 text-[0.68rem] uppercase tracking-[0.06em] text-dim-dark">{label}</div>
                  <PaneLines lines={lines} />
                </div>
              ))}
            </div>
            <div className="flex flex-wrap justify-between gap-2 border-t border-dark-line px-[22px] py-2.5 font-mono text-[0.7rem] text-dim-dark">
              <span>{pane.status}</span>
              <span>Report generated 14:02:11</span>
            </div>
          </div>
          <div className="h-[70px]" />
        </section>
      </div>

      <div className="bg-light">
        <div className="mx-auto grid max-w-[1280px] grid-cols-2 border-y border-light-line lg:grid-cols-4">
          {STATS.map(([num, label], i) => (
            <div
              key={label}
              className={`px-5 py-8 sm:px-11 ${i % 2 === 1 ? "border-l border-light-line" : ""} ${
                i >= 2 ? "border-t border-light-line lg:border-t-0" : ""
              } ${i === 2 ? "lg:border-l" : ""}`}
            >
              <div className="font-display text-[2.3rem] font-extrabold leading-none text-ink">{num}</div>
              <div className="mt-2 text-[0.82rem] text-dim">{label}</div>
            </div>
          ))}
        </div>

        <section id="how" className="mx-auto max-w-[1280px] scroll-mt-20 px-5 py-20 sm:px-11">
          <div className="mb-12 text-center">
            <div className="eyebrow-light mb-3.5">How a scan runs</div>
            <h2 className="mx-auto max-w-[22ch] text-[2.1rem] font-extrabold leading-tight tracking-[-0.01em]">
              Every assessment, run the same disciplined way
            </h2>
          </div>
          <div className="grid grid-cols-1 gap-px border border-light-line bg-light-line sm:grid-cols-2 lg:grid-cols-4">
            {STEPS.map(([n, title, body]) => (
              <div key={n} className="bg-light px-6 py-8">
                <div className="num-badge mb-5">{n}</div>
                <h3 className="mb-2 text-[1.02rem] font-bold">{title}</h3>
                <p className="text-[0.86rem] text-dim">{body}</p>
              </div>
            ))}
          </div>
        </section>

        <section id="plans" className="mx-auto max-w-[1280px] scroll-mt-20 px-5 pb-20 sm:px-11">
          <div className="mb-12 text-center">
            <div className="eyebrow-light mb-3.5">Plans</div>
            <h2 className="mx-auto max-w-[22ch] text-[2.1rem] font-extrabold leading-tight tracking-[-0.01em]">
              Start free. Go deeper when you need to.
            </h2>
          </div>
          <div className="grid grid-cols-1 gap-px border border-light-line bg-light-line md:grid-cols-3">
            {PLANS.map((p) => (
              <div key={p.tier} className="flex flex-col bg-light px-7 py-8">
                <div className="font-mono text-[0.72rem] uppercase tracking-[0.1em] text-dim">{p.label}</div>
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
                <Link to={isAuthenticated ? "/billing" : "/register"} className="btn-outline mt-7 w-full">
                  {p.tier === "free" ? "Start free" : `Choose ${p.label}`}
                </Link>
              </div>
            ))}
          </div>
        </section>
      </div>

      <div className="bg-dark px-5 py-20 text-center text-on-dark sm:px-11">
        <h2 className="mx-auto mb-5 max-w-[20ch] text-[clamp(1.8rem,3.6vw,2.6rem)] font-extrabold leading-tight">
          See what your attack surface actually looks like.
        </h2>
        <p className="mx-auto mb-8 max-w-[46ch] text-dim-dark">
          Create an account, point a quickscan at a host you own, and get a scored report in minutes.
        </p>
        {primaryCta}
      </div>

      <Footer />
    </div>
  );
}
