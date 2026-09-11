# Contributing to Aegis Scanner

Thanks for wanting to help. Aegis is a lightweight, open-source Python
vulnerability-assessment framework for Kali, and it stays useful only if
new work holds to a few principles the codebase has learned the hard way.

## Ground rules (the non-negotiables)

These come from real bugs this project has shipped and fixed. They are why
the code looks the way it does.

1. **A tool that fails must be *counted* as failed by the same code path
   that *reports* it.** Never split "record the failure" and "count the
   failure" into two functions — they drift, and a scan then reports a tool
   as having run when it silently produced nothing. See the skip-flag
   convention in `modules/profiles/_common.py`.

2. **Never raise out of a scan.** Every tool wrapper and every plugin's
   `run()` returns a structured result on failure instead of throwing.
   `run_tool()` / `safe_call()` / `ScannerPlugin.execute()` enforce this.
   One broken check must not cost the whole scan.

3. **"Cannot verify" is not "does not apply."** A blank field, an
   unmatched CVE, an un-run tool — each is reported as what it actually is.
   A false all-clear is the one output a user acts on by doing nothing, so
   it is the one we never emit by accident (see the HIBP breach check).

4. **Confirmed vs Potential is load-bearing.** A finding the scanner
   *observed* (a payload reflected, an injection that returned data) is
   Confirmed; a version/banner inference is Potential. Don't mark something
   Confirmed that was not actually exercised.

5. **Detection logic has one home.** The plugin layer (`plugins/`) reuses
   the wrappers in `modules/` and their mappers rather than reimplementing
   them. A second copy is a second place for behaviour to drift.

## Development setup

```bash
git clone https://github.com/syedj-hacks/aegis-scanner.git
cd aegis-scanner
./install.sh
source venv/bin/activate
```

Or use the container, which needs no local tool install:

```bash
docker build -t aegis-scanner .
docker run --rm -v "$PWD/output:/app/output" aegis-scanner --list-plugins
```

## Before you open a PR

Run the two gates CI runs:

```bash
ruff check .                     # lint
for t in tests/t_phase1_plugins.py tests/t_phase2_engine.py \
         tests/t_phase3_enrichment.py tests/t_phase4_reporting.py \
         tests/t_cvss.py tests/t_diff.py tests/t_phase8.py \
         tests/t_phase9.py tests/t_phase10.py; do python "$t"; done
```

Every test file exits non-zero on a failed assertion. Add assertions for
new behaviour — the suites are plain `check(name, condition)` harnesses, no
framework to learn.

## Adding a new check

You have two options, in increasing order of power:

- **A signature** (`signatures/*.yaml`) — a declarative HTTP check, no
  Python. Best for "request this path, match this response." See
  [docs/PLUGIN_GUIDE.md](docs/PLUGIN_GUIDE.md#signatures).
- **A plugin** (`plugins/*.py`) — a full `ScannerPlugin` when you need
  logic a signature can't express. See
  [docs/PLUGIN_GUIDE.md](docs/PLUGIN_GUIDE.md#plugins).

Neither requires editing any core file — both are auto-discovered.

## Style

`ruff` (configured in `pyproject.toml`) is the arbiter. The house style
favours explanatory comments that say *why*, not *what* — match the density
of the module you are editing. Reference code as `path:line`.

## Scope and safety

Aegis is for **authorised** assessment: your own systems, an engagement you
have permission for, a lab like the bundled `test-targets/`. Contributions
that add mass-targeting, DoS, or detection-evasion-for-attack features are
out of scope. Dual-use is fine; offense-only is not.
