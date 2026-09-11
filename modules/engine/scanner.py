"""
modules/engine/scanner.py
The plugin-driven, concurrent scan engine (Phase 2).

WHAT IT DOES
------------
Given a YAML profile and a target, it:

  1. Runs the DISCOVERY plugins (dns, port_scan, service_detect,
     banner_grab) sequentially — they produce the context (open ports,
     per-port services/versions) every other plugin consumes, so there is
     nothing to parallelise until they finish.
  2. Derives the run context from that: which ports are web ports, whether
     each is HTTPS, whether a WordPress install / SMB service / login
     service / injectable candidate is present — the same signals the
     legacy deepscan computes to gate its conditional tools.
  3. Runs the remaining applicable plugins CONCURRENTLY, one plugin task
     per (plugin, port), through a ThreadPoolExecutor bounded by --threads
     and a per-target RateLimiter (the safety governor).
  4. Collects every plugin's findings and outcome with full isolation: a
     plugin that raises, times out, or is missing its tool becomes a
     failed/skipped PluginResult and the rest of the scan continues.

RELATIONSHIP TO THE LEGACY PROFILES
-----------------------------------
This does NOT replace modules/profiles/*.py — those remain the default and
are untouched. The engine reuses the exact same detection code (via the
plugins, which wrap the same wrapper modules and mappers) and the exact
same database/reporting/attribution pipeline (insert_findings_bulk,
persist_tool_run, finalise_reports). A scan run through the engine produces
rows indistinguishable in shape from a legacy scan, so every downstream
consumer works unchanged.

ISOLATION IS THE CONTRACT
-------------------------
"one crashing plugin doesn't kill the whole scan" (the Phase 2 requirement)
is enforced at two levels: plugins/base.execute() converts any exception
into a failed PluginResult, and the engine's future handling here converts
even an executor-level failure into one. Neither a broken plugin nor a
broken target can take the scan down.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from plugins import loader
from plugins.base import PluginResult
from modules.engine.ratelimit import RateLimiter

from modules.utils.display import (
    print_phase, print_info, print_success, print_warning, print_error,
)
from modules.utils.logger import log_scan_start, log_scan_end, get_logger
from modules.profiles._common import (
    is_web_port, is_https_port, web_param_candidates,
    count_and_report_tool_failures, persist_tool_run, finalise_reports,
)
from database.db import insert_scan, insert_findings_bulk
from modules.reporting.dashboard_live import update_live_data
from modules.enrichment.pipeline import enrich_findings
from modules.enrichment.risk import environment_risk_score

try:
    from modules.utils.config import MAX_THREADS
except ImportError:
    MAX_THREADS = 10


# Which plugins are "discovery" — run first, sequentially, to build context.
# Identified by name rather than by a flag on the plugin so this stays a
# property of the engine's staging, not of the plugin contract.
_DISCOVERY_PLUGINS = ("dns", "port_scan", "service_detect", "banner_grab")


class ScanEngine:
    """
    Orchestrates one plugin-driven scan of one target.

    Stateless between runs except for construction params (profile, thread
    budget). scan() may be called for several targets, but the engine is
    cheap to build per target and the multi-target driver does exactly that
    so each target gets its own RateLimiter (one throttled host must not
    slow another).
    """

    def __init__(self, profile: dict, threads: int = None,
                 non_interactive: bool = False, auth=None,
                 criticality: str = "medium", active_validation: bool = True):
        self.profile = profile or {}
        self.threads = max(1, min(int(threads or MAX_THREADS), MAX_THREADS))
        self.non_interactive = non_interactive
        self.auth = auth
        # Asset criticality weights this target's findings in the
        # environment risk roll-up (Phase 4). A stealth/passive profile
        # turns off active validation (no live probing of the target).
        self.criticality = criticality or "medium"
        self.active_validation = active_validation
        self.limiter = RateLimiter.from_profile(self.profile.get("safety"))

    # --- plugin selection ------------------------------------------------

    def _selected(self):
        """Every plugin this profile selects, discovery ones included."""
        return loader.select(
            names=self.profile.get("plugins"),
            target_types=self.profile.get("target_types") or None,
            exclude=self.profile.get("exclude"),
        )

    def _base_config(self, target):
        """The config dict every plugin receives, before per-port keys."""
        cfg = {
            "profile": self.profile.get("nmap_profile") or "deepscan",
            "nmap_profile": self.profile.get("nmap_profile"),
            "nuclei_severity": self.profile.get("nuclei_severity"),
            "gobuster_wordlist": self.profile.get("gobuster_wordlist"),
            "auth": self.auth,
            "target": target,
        }
        return cfg

    # --- one plugin invocation, throttled & isolated --------------------

    def _run_plugin(self, plugin, target, config) -> PluginResult:
        """
        Acquire the safety governor, run the plugin, release. Passive
        plugins bypass the governor (nothing is being sent to the target to
        throttle). Any escape is caught and turned into a failed result —
        the executor must never see an exception.
        """
        passive = getattr(plugin, "passive", False)
        try:
            if not passive:
                self.limiter.acquire()
            try:
                return plugin.execute(target, config)
            finally:
                if not passive:
                    self.limiter.release()
        except Exception as exc:  # noqa: BLE001 — belt and braces over execute()
            return PluginResult(
                plugin=plugin.name, outcome="failed",
                error=f"engine-level failure: {type(exc).__name__}: {exc}",
                target=target, port=config.get("port"),
            )

    def _run_stage(self, tasks, target, label) -> list:
        """
        Run a list of (plugin, config) tasks concurrently, return their
        PluginResults. Results come back as they complete; the caller does
        not depend on order.
        """
        if not tasks:
            return []
        results = []
        workers = max(1, min(self.threads, len(tasks)))
        with ThreadPoolExecutor(max_workers=workers,
                                thread_name_prefix=f"aegis-{label}") as pool:
            futures = {
                pool.submit(self._run_plugin, plugin, target, cfg): plugin.name
                for plugin, cfg in tasks
            }
            for future in as_completed(futures):
                # _run_plugin never raises, but as_completed can surface a
                # cancellation; guard so one oddity cannot lose the stage.
                try:
                    results.append(future.result())
                except Exception as exc:  # noqa: BLE001
                    results.append(PluginResult(
                        plugin=futures[future], outcome="failed",
                        error=f"future failed: {exc}", target=target))
        return results

    # --- context derivation (parity with deepscan's gating) -------------

    def _derive_web_context(self, open_ports):
        """[(port, use_https)] for every open web port."""
        web = []
        for entry in open_ports or []:
            if is_web_port(entry):
                web.append((entry["port"], is_https_port(entry)))
        return web

    def _derive_conditional_context(self, base_ctx, open_ports, services,
                                    web_results):
        """
        Compute wordpress/injectable/login/SMB signals from the web-stage
        results, mirroring deepscan's gating so the service/conditional
        plugins fire on exactly the same evidence.
        """
        ctx = dict(base_ctx)
        ctx["open_ports"] = open_ports
        ctx["services"] = services

        # WordPress: a gobuster path fingerprint OR a whatweb CMS match.
        wp_port, wp_https = None, False
        gobuster_raw = [r.raw for r in web_results if r.plugin == "gobuster"]
        whatweb_raw = [r.raw for r in web_results if r.plugin == "whatweb"]
        for g in gobuster_raw:
            if g.get("wordpress_fingerprinted"):
                wp_port = g.get("port")
                wp_https = is_https_port({"port": wp_port})
                break
        if wp_port is None:
            for w in whatweb_raw:
                if str(w.get("cms_detected") or "").strip().lower() == "wordpress":
                    wp_port = w.get("port")
                    wp_https = is_https_port({"port": wp_port})
                    break
        ctx["wordpress_fingerprinted"] = wp_port is not None
        ctx["wordpress_port"] = wp_port
        ctx["wordpress_https"] = wp_https

        # Injectable candidates for a future sqlmap plugin, from discovered
        # script endpoints — same helper deepscan uses.
        dirb_raw = [r.raw for r in web_results if r.plugin == "dirb"]
        ctx["injectable_candidates"] = web_param_candidates(gobuster_raw, dirb_raw)
        return ctx

    # --- the scan --------------------------------------------------------

    def scan(self, target: str) -> dict:
        """
        Run the full staged scan against one target.

        Returns a result dict:
            {scan_id, target, findings (list[Finding]), plugin_results,
             tool_results (legacy shape), stats, report_paths, elapsed,
             throttle_wait}

        Never raises — the whole point of the engine is that a scan
        completes with whatever it got, recording failures rather than
        propagating them.
        """
        started = time.time()
        profile_name = self.profile.get("name") or "engine"
        log_scan_start(target, profile_name)
        print_phase(f"ENGINE SCAN [{profile_name}] — {target}")

        selected = self._selected()
        selected_names = {p.name for p in selected}
        by_name = {p.name: p for p in selected}
        scan_id = insert_scan(target, profile_name)

        base_cfg = self._base_config(target)
        all_results = []
        all_findings = []

        def _absorb(results):
            batch = []
            for r in results:
                all_results.append(r)
                for f in r.findings:
                    all_findings.append(f)
                    batch.append(f)
            if not batch:
                return
            # Phase 3 enrichment BEFORE persist, so confidence/EPSS/risk are
            # written to the row rather than bolted on afterwards. EPSS is
            # batched+cached, so enriching per stage costs at most one API
            # call per stage and usually zero (cache hits). Active
            # validation re-reads a live banner only for version-matched web
            # findings; the profile can turn it off.
            for f in batch:
                setattr(f, "criticality", self.criticality)
            enrich_findings(batch, target, active_validation=self.active_validation)
            insert_findings_bulk(scan_id, [f.to_db_dict() for f in batch])

        # --- Stage 1: discovery, sequential --------------------------
        ctx = dict(base_cfg)
        open_ports, services = [], []
        for name in _DISCOVERY_PLUGINS:
            plugin = by_name.get(name)
            if plugin is None:
                continue
            result = self._run_plugin(plugin, target, ctx)
            _absorb([result])
            raw = result.raw or {}
            if name == "port_scan":
                open_ports = raw.get("open_ports") or []
                ctx["open_ports"] = open_ports
            elif name == "service_detect":
                services = raw.get("services") or []
                ctx["services"] = services
            update_live_data(target, [f.to_db_dict() for f in all_findings],
                             current_tool=name, progress_pct=15)

        # --- Stage 2: web plugins, concurrent per web port -----------
        web_ports = self._derive_web_context(open_ports)
        web_plugins = [p for p in selected
                       if "web" in p.target_types and p.name not in _DISCOVERY_PLUGINS]
        web_tasks = []
        for port, use_https in web_ports:
            port_cfg = dict(ctx)
            port_cfg.update(port=port, use_https=use_https)
            for plugin in web_plugins:
                # wpscan gates on a WordPress signal we don't have yet in
                # this stage; it is deferred to stage 3 with the other
                # conditional plugins. Everything else runs now.
                if plugin.name == "wpscan":
                    continue
                web_tasks.append((plugin, dict(port_cfg)))

        if web_tasks:
            print_info(f"[engine] web stage: {len(web_tasks)} plugin task(s) "
                       f"across {len(web_ports)} port(s), up to {self.threads} at once")
        web_results = self._run_stage(web_tasks, target, "web")
        _absorb(web_results)
        update_live_data(target, [f.to_db_dict() for f in all_findings],
                         current_tool="web plugins", progress_pct=60)

        # --- Stage 3: conditional service/web plugins ----------------
        cond_ctx = self._derive_conditional_context(ctx, open_ports, services, web_results)
        cond_tasks = []

        # wpscan, now that WordPress detection has run.
        if "wpscan" in selected_names and cond_ctx.get("wordpress_fingerprinted"):
            wp_cfg = dict(cond_ctx)
            wp_cfg.update(port=cond_ctx["wordpress_port"],
                          use_https=cond_ctx["wordpress_https"],
                          wordpress_fingerprinted=True)
            cond_tasks.append((by_name["wpscan"], wp_cfg))

        # Service-context plugins (enum4linux, hydra); applicable() gates
        # each on the open ports / services in cond_ctx.
        for plugin in selected:
            if "service" in plugin.target_types:
                cond_tasks.append((plugin, dict(cond_ctx)))

        cond_results = self._run_stage(cond_tasks, target, "conditional")
        _absorb(cond_results)

        # --- Stage 4: passive plugins (if a domain/emails apply) -----
        passive_plugins = [p for p in selected if "passive" in p.target_types]
        passive_tasks = [(p, dict(cond_ctx)) for p in passive_plugins]
        passive_results = self._run_stage(passive_tasks, target, "passive")
        _absorb(passive_results)

        update_live_data(target, [f.to_db_dict() for f in all_findings],
                         current_tool="finalising", progress_pct=95)

        # --- outcome accounting (legacy pipeline) --------------------
        tool_results = [r.to_tool_result() for r in all_results]
        stats = {
            "tools_run": len(tool_results),
            "tools_failed": count_and_report_tool_failures(target, tool_results),
            "tools_skipped": sum(1 for r in tool_results if r.get("skipped")),
        }
        persist_tool_run(scan_id, tool_results)

        # Environment Risk Score for the whole scan (Phase 4), from every
        # finding's combined risk weighted by this asset's criticality.
        env_risk = environment_risk_score(
            [f.to_db_dict() for f in all_findings], self.criticality)
        stats["environment_risk"] = env_risk["score"]
        stats["risk_band"] = env_risk["band"]
        log_scan_end(target, stats)

        txt_path, pdf_path, html_path = finalise_reports(
            target, profile_name, scan_id, non_interactive=self.non_interactive)

        elapsed = time.time() - started
        print_success(
            f"[engine] scan {scan_id} complete — {len(all_findings)} finding(s), "
            f"{stats['tools_run']} plugin(s) "
            f"({stats['tools_failed']} failed, {stats['tools_skipped']} skipped) "
            f"in {elapsed:.1f}s; {self.limiter.total_wait:.1f}s spent throttled")

        return {
            "scan_id": scan_id, "target": target,
            "findings": all_findings, "plugin_results": all_results,
            "tool_results": tool_results, "stats": stats,
            "report_paths": [p for p in (txt_path, pdf_path, html_path) if p],
            "elapsed": elapsed, "throttle_wait": self.limiter.total_wait,
            "environment_risk": env_risk,
        }


def run_engine_scan(target: str, profile: dict, threads: int = None,
                    non_interactive: bool = False, auth=None,
                    criticality: str = "medium",
                    active_validation: bool = None) -> tuple:
    """
    Convenience wrapper returning the (scan_id, txt, pdf, html, stats) tuple
    that aegis.py's dispatch and multi_target._normalise already understand
    — so an engine scan slots into the existing CLI plumbing with no special
    handling.

    active_validation defaults to OFF for a passive-only profile (there is
    no target being probed to validate against) and ON otherwise.
    """
    if active_validation is None:
        types = set(profile.get("target_types") or [])
        active_validation = types != {"passive"}
    engine = ScanEngine(profile, threads=threads,
                        non_interactive=non_interactive, auth=auth,
                        criticality=criticality,
                        active_validation=active_validation)
    result = engine.scan(target)
    paths = result["report_paths"]
    txt = paths[0] if len(paths) > 0 else None
    pdf = paths[1] if len(paths) > 1 else None
    html = paths[2] if len(paths) > 2 else None
    return result["scan_id"], txt, pdf, html, result["stats"]
