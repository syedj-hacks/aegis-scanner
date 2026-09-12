# Aegis Scanner
Kali Linux vulnerability assessment framework — 

> ## Aegis Shield — the web platform
> This repository also contains **Aegis Shield**, a subscription-based web app built on this engine.
> **Start it with one click:** double-click `Start Aegis Shield.bat` on Windows, or run
> `./start-aegis-shield.sh` on Linux. Python 3.10+ is the only requirement.
> Full documentation: **[saas-platform/README.md](saas-platform/README.md)**

## Run Locally (Docker — no setup)

This runs the whole Aegis Shield web app, including every scanning tool, in one
container. Nothing to install but Docker.

1. Install **[Docker Desktop](https://www.docker.com/products/docker-desktop/)** and start it.
2. Clone this repo and open its folder.
3. Run it:
   - **Windows:** double-click **`run.bat`**
   - **Linux / macOS:** run **`./run.sh`**
4. When it prints the URL, open **http://localhost:8000** in your browser and sign in
   with the admin e-mail and password shown in the `.env` file (created on first run).

The first build takes a few minutes (it downloads the security tools); later starts are quick.
Stop it with `docker compose down`. For a live/hosted deploy, see **[DEPLOY.md](DEPLOY.md)**.

## Setup
```bash
git clone https://github.com/syedj-hacks/aegis-scanner.git
cd aegis-scanner
chmod +x install.sh
./install.sh
source venv/bin/activate
```

## Usage
```bash
python3 aegis.py <target> [--profile PROFILE] [-v]
```

Run it with no arguments for a guided menu:

```
1. Vulnerability scan   pick a profile and scan a host
2. Recon mapper         map what a domain or company name exposes (passive)
3. Scan diff            compare two finished scans
```

Any argument at all skips the menu, so every existing command line behaves
exactly as before.

### Profiles

| Profile | Description |
|---|---|
| `quickscan` (default) | Fast overview — DNS, top-port nmap scan, service detection, quick whatweb + high-severity nuclei check. |
| `stealthscan` | Quiet -T2 scan of common ports — minimal footprint. One whatweb fingerprint; deliberately no nuclei. |
| `webaudit` | Web-focused audit — headers, Nikto, gobuster/dirb, whatweb, sslyze + CVE enrichment on web ports. |
| `deepscan` | Full assessment — recon, all ports, web audit, CVE/severity/remediation, TXT+PDF reports. |
| `compliance` | TLS cipher + HTTP header nmap scripts, sslyze and whatweb on TLS ports for a compliance-oriented baseline. |
| `recon` | Passive attack-surface map — certificate transparency, subdomains, OSINT, public cloud buckets, breach check. Sends nothing to the target. |

Example:
```bash
python3 aegis.py 192.168.56.101 --profile deepscan
```

### Recon mapper

The only mode that accepts a **company name** as well as a domain, because
it never contacts the target — everything it reads is public (crt.sh
certificate logs, DNS aggregators, cloud storage namespaces, Have I Been
Pwned).

```bash
python3 aegis.py example.com --recon      # domain mode: full pipeline
python3 aegis.py --recon "Acme Corp"      # company mode: OSINT + buckets only
```

With a bare company name there is no domain to resolve, so DNS, certificate
transparency and subdomain enumeration are reported as *not applicable*
rather than run and failed.

The breach check needs an API key (HIBP has required one since 2019). Set
`AEGIS_HIBP_API_KEY` in `.env` to enable it. **Without a key the check
reports itself as NOT RUN — it does not report accounts as clean**, because
a false all-clear is the one output someone would act on by doing nothing.

### Scan diff

```bash
python3 aegis.py --diff 41 57             # compare two finished scans
python3 aegis.py --diff 41 57 --diff-verbose
```

Every scan also prints a one-line delta against the previous scan of the
same target automatically.

Findings are classified `new` / `fixed` / `escalated` / `unchanged` — and
`unverified`, which is the one that matters: if the tool that would have
found a finding did not run in the later scan, its absence proves nothing
and it is **not** counted as fixed.

### Live dashboard

```bash
python3 aegis.py scanme.nmap.org --live   # or answer the prompt
```

Opens a browser view that fills in as the scan runs — current tool, progress,
and findings appearing newest-first. It is served from `127.0.0.1` on a
random port (a `file://` page cannot poll for data; browsers block it), and
it stops when the command exits.

Every scan writes a self-contained `report.html` alongside the TXT and PDF —
sortable and filterable, no external resources, safe to email or open offline.

Run from the repo root (paths for `output/`, `database/aegis.db`, and `.env`
are all resolved relative to it). Each scan is recorded in
`database/aegis.db`; reports are written to `output/<target>/`.

`aegis.py --help` lists all flags, and `aegis.py --version` prints the
current version.

## Plugin engine (concurrent, YAML-driven)

Alongside the built-in profiles there is a plugin-driven scan engine that
runs independent checks concurrently and enriches every finding with live
CVSS/EPSS scoring. It is opt-in — the profiles above are unchanged and
remain the default.

```bash
python3 aegis.py <target> --engine --scan-profile full   # concurrent full scan
python3 aegis.py <target> --engine --scan-profile quick --threads 8
python3 aegis.py --list-plugins                           # what checks exist
```

- **Plugins** live in [`plugins/`](plugins/) and are auto-discovered — every
  existing detection tool has one, and a new check is a new file, no core
  edit. See [`docs/PLUGIN_GUIDE.md`](docs/PLUGIN_GUIDE.md).
- **Signatures** ([`signatures/*.yaml`](signatures/)) are declarative,
  Nuclei-style HTTP checks — add one with no Python at all.
- **YAML scan profiles** ([`profiles_yaml/`](profiles_yaml/):
  quick/full/stealth/recon) choose which plugins run and set a per-target
  safety throttle (`--threads` bounds concurrency; the profile's
  `max_requests_per_second` paces launches so a fragile target is not
  overwhelmed).
- **Enrichment**: each finding gets a live CVSS vector/score (NVD, cached),
  an EPSS exploit-probability (FIRST.org), a combined risk score, and a
  **Confirmed vs Potential** confidence label. `--criticality` weights the
  target in the environment Risk Score.
- **Outputs**: every scan now also writes machine-readable `report.*.json`
  (scripting) and `report.*.sarif` (CI/CD, e.g. GitHub code scanning)
  beside the TXT/PDF/HTML.

## Comparison to Industry Tools

Aegis is a lightweight open-source scanner, not a commercial platform. This
is an honest account of where it is comparable to a tool like Nessus and
where it is not.

**Comparable in kind:**

- **CVSS + EPSS risk scoring.** Findings carry a live CVSS vector/score and
  an EPSS exploit-probability, combined into a single risk score and rolled
  up into an environment Risk Score weighted by configurable asset
  criticality — the same severity-plus-likelihood model commercial scanners
  use to prioritise.
- **Plugin architecture.** Detection is a set of discoverable plugins plus a
  declarative signature format, so coverage grows without touching the core
  — the same extensibility model as Nessus plugins / Nuclei templates.
- **Confirmed vs Potential.** Findings the scanner actually exercised are
  distinguished from version/banner inferences, with lightweight active
  validation — the false-positive discipline a professional report needs.
- **CI/CD & scripting integration.** Native SARIF output drops into GitHub
  code scanning and other pipelines; JSON output chains into other tools.
- **Safety throttling.** A per-target request-rate governor bounds scan
  pressure, the way a commercial scanner's safe-checks/pacing does.
- **Executive + technical reporting.** The PDF separates an executive
  summary (risk posture, top risks in plain language) from per-finding
  technical detail.

**Still a gap (what Aegis does *not* do):**

- **No continuous or scheduled scanning.** Aegis runs on demand; there is no
  built-in scheduler, monitoring, or trend-over-time engine.
- **No agent-based scanning.** It scans over the network only — there are no
  host agents for authenticated local inspection at scale.
- **No compliance templates.** There is a control-mapping compliance profile,
  but no packaged PCI-DSS / HIPAA / CIS-benchmark audit templates.
- **Smaller detection corpus.** It orchestrates a fixed set of best-in-class
  open-source tools plus its own signatures; it does not carry the tens of
  thousands of vendor-maintained checks a commercial feed does.
- **No centralised multi-user platform.** No web console, RBAC, asset
  inventory, or ticketing integrations — it is a CLI tool with local report
  output.

### Known detection gaps (from the Phase 6 lab smoke test)

The plugin engine was smoke-tested live against the BlackBox lab (see
[`smoke_test/PHASE6_RESULTS.md`](smoke_test/PHASE6_RESULTS.md)). It completed
without crashing, generated PDF/JSON/SARIF, enriched findings with
CVSS+EPSS, and knocked no service offline. The honest gaps it surfaced:

- **No sqlmap / XSS / nmap-NSE plugin yet.** The legacy `deepscan` confirms a
  SQL injection on DVWA and runs NSE scripts; the engine does not yet, so
  its full profile trades active *injection confirmation* for speed and
  enrichment. Use `--profile deepscan` (legacy) when injection confirmation
  matters, or contribute those plugins (see `docs/PLUGIN_GUIDE.md`).
- **App-level vulns need authentication** (DVWA XSS/command-injection,
  Juice/WebGoat challenges) — supply `--auth-cookie` and the injection
  plugins above.
- **Version-matched CVEs are labelled `Potential`, not confirmed** — by
  design. On the Samba host the engine matched 16 CVEs (incl. CVE-2015-0240,
  CVSS 10.0, EPSS 0.88) from the banner and flagged every one Potential
  rather than asserting exploitability it did not test.

## Documentation
All project documentation lives in [`important documentations/`](important%20documentations/):

| File | What it covers |
|---|---|
| `TUTORIAL.md` | Start here — install, first scan, reading a report. |
| `COMMANDS.txt` | Every command, flag, and maintenance/one-off tool invocation. |
| `OVERVIEW_CONTEXT.md` | Repo map, module-by-module API surface, data flow. |
| `BACKEND_STRUCTURE.md` | Internals: every wrapper's contract, the shared conventions, known gaps. |
| `WRITEUP.md` | Design decisions and honesty notes — why things work the way they do. |
| `aegis_scanner_status_and_capabilities.txt` | Plain-language status: what is verified live, what isn't, demo guidance. |

`smoke_test/` holds the per-pass live verification write-ups, and
`test-targets/` is a local, isolated docker lab of intentionally vulnerable
services used to exercise the conditional tools (wpscan/sqlmap/hydra/enum4linux).
