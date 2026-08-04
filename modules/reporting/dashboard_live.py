"""
modules/reporting/dashboard_live.py
Live scan dashboard — findings appear in a browser as the scan produces them.

Why this serves over localhost instead of just opening a file
--------------------------------------------------------------
The obvious design is: write live_dashboard.html and live_data.json next to
each other in output/<target>/, open the HTML with xdg-open, and have the
page fetch() the JSON every couple of seconds.

That design does not work, and it fails silently, which is worse. A page
opened as file:///... has a null origin, and every modern browser refuses
fetch()/XHR against file:// URLs under the same-origin policy. The dashboard
would load, render its empty shell, and sit at "waiting for data…" forever
while the scan ran perfectly well beside it — with the real reason visible
only in the browser's developer console. Verified rather than assumed: this
is CORS behaviour on file:// in Chrome and Firefox alike.

So the dashboard is served instead, by a tiny HTTP server on 127.0.0.1 and
an ephemeral port, from the target's own output directory. That makes the
page a real http:// origin, fetch() works as intended, and the URL is the
thing handed to the browser.

Scope of that server, deliberately:
  - bound to 127.0.0.1 explicitly, never 0.0.0.0 — it is not reachable from
    the network, which matters because a scan's output directory contains
    findings about a third party
  - serves exactly one directory, the target's own output/<target>/
  - a daemon thread, so it cannot keep the process alive after a scan
  - port 0, so the OS picks a free port and two concurrent scans of
    different targets never collide

If the server cannot start for any reason, init_live_dashboard() reports it
and returns None. The scan then runs exactly as it always has — the live
view is an optional extra, and nothing about a scan's real output depends
on it.

Atomicity
---------
live_data.json is rewritten in full on every update, via a temporary file
and os.replace(). os.replace is atomic on POSIX, so the polling browser
either reads the whole previous document or the whole new one, never a
half-written one — a partial read is a JSON parse error, which the page
would show as a broken dashboard on a scan that is fine.

update_live_data() is called from the profile orchestrators, which run web
tools concurrently (see _common.run_web_tools), so the shared state is
guarded by a lock.
"""

import json
import os
import threading
from datetime import datetime
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

from modules.utils.config import output_dir
from modules.utils.display import print_info, print_warning
from modules.reporting.report_html import THEME

try:
    from modules.utils.config import LIVE_DASHBOARD_POLL_MS
except ImportError:
    # config.py is gitignored, so a per-user copy predating this key is a
    # real possibility — same fallback pattern _common.py uses.
    LIVE_DASHBOARD_POLL_MS = 2000

DATA_FILENAME = "live_data.json"
PAGE_FILENAME = "live_dashboard.html"

_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

# Per-target live state, and the lock that guards it. Keyed by target so a
# --targets run with several concurrent scans keeps them separate.
_state_lock = threading.Lock()
_state = {}
_servers = {}


def _empty_state(target: str) -> dict:
    return {
        "target": target,
        "status": "starting",
        "current_tool": "",
        "progress_pct": 0,
        "started": datetime.now().isoformat(timespec="seconds"),
        "updated": datetime.now().isoformat(timespec="seconds"),
        "counts": {name: 0 for name in _SEVERITY_ORDER},
        "total": 0,
        "findings": [],
        "report_url": None,
    }


def _write_atomic(path: str, text: str) -> bool:
    """Write `text` to `path` via a temp file + os.replace. False on failure."""
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        return True
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return False


def _serve(directory: str):
    """
    Start a localhost-only static server for `directory`.

    Returns (url_base, server) or (None, None). Never raises: a port that
    cannot be bound, a directory that vanished, a sandbox that forbids
    listening — all of them mean "no live view", not "no scan".
    """
    class _QuietHandler(SimpleHTTPRequestHandler):
        # The default handler logs every request to stderr, which would
        # interleave a line every two seconds into the middle of the scan's
        # Rich progress bars for the entire run.
        def log_message(self, *args):
            pass

        def end_headers(self):
            # The whole point is that the page sees fresh data; a cached
            # live_data.json is the one thing that would defeat it.
            # SimpleHTTPRequestHandler does not itself override end_headers,
            # so this reaches BaseHTTPRequestHandler's — no recursion.
            self.send_header("Cache-Control", "no-store, must-revalidate")
            SimpleHTTPRequestHandler.end_headers(self)

    try:
        handler = partial(_QuietHandler, directory=directory)
        # Port 0 => the OS assigns a free one. 127.0.0.1, never 0.0.0.0.
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    except OSError as exc:
        print_warning(f"[Dashboard] could not start the local server: {exc}")
        return None, None

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    return f"http://{host}:{port}", server


def init_live_dashboard(target: str) -> str:
    """
    Write the dashboard page, seed live_data.json, and start the local
    server. Returns the dashboard URL, or None if it could not be started.
    """
    try:
        directory = output_dir(target)
    except OSError as exc:
        print_warning(f"[Dashboard] could not create the output directory: {exc}")
        return None

    with _state_lock:
        _state[target] = _empty_state(target)
        payload = json.dumps(_state[target], default=str, indent=1)

    page = _PAGE_TEMPLATE.format(
        target=target.replace("<", "&lt;").replace(">", "&gt;"),
        poll_ms=int(LIVE_DASHBOARD_POLL_MS),
        data_file=DATA_FILENAME,
        **{f"c_{k}": v for k, v in THEME.items()},
    )

    ok_page = _write_atomic(os.path.join(directory, PAGE_FILENAME), page)
    ok_data = _write_atomic(os.path.join(directory, DATA_FILENAME), payload)
    if not (ok_page and ok_data):
        print_warning(f"[Dashboard] could not write the dashboard files into {directory}")
        return None

    url_base, server = _serve(directory)
    if not url_base:
        return None

    with _state_lock:
        _servers[target] = server

    return f"{url_base}/{PAGE_FILENAME}"


def update_live_data(target: str, new_findings: list = None,
                     status: str = "running", current_tool: str = "",
                     progress_pct: int = None) -> None:
    """
    Append findings and refresh the live JSON. Called after each tool.

    Never raises, and does nothing at all for a target whose dashboard was
    never started — so a profile can call this unconditionally and the
    no-dashboard case costs one dict lookup.
    """
    with _state_lock:
        state = _state.get(target)
        if state is None:
            return

        for finding in new_findings or []:
            if not isinstance(finding, dict):
                continue
            severity = str(finding.get("severity") or "LOW").upper()
            if severity not in state["counts"]:
                severity = "LOW"
            state["counts"][severity] += 1
            state["total"] += 1
            # Newest first: the feed is read from the top while a scan runs.
            state["findings"].insert(0, {
                "severity": severity,
                "port": finding.get("port"),
                "service": finding.get("service") or "",
                "type": finding.get("finding_type") or finding.get("type") or "",
                "cve": finding.get("cve_id") or "",
                "description": " ".join(str(finding.get("description") or "").split()),
                "at": datetime.now().strftime("%H:%M:%S"),
            })

        state["status"] = status
        if current_tool:
            state["current_tool"] = current_tool
        if progress_pct is not None:
            state["progress_pct"] = max(0, min(100, int(progress_pct)))
        state["updated"] = datetime.now().isoformat(timespec="seconds")
        payload = json.dumps(state, default=str, indent=1)

    try:
        _write_atomic(os.path.join(output_dir(target), DATA_FILENAME), payload)
    except OSError:
        pass


def finalize_live_dashboard(target: str, summary: dict = None,
                            report_url: str = "report.html") -> None:
    """
    Mark the scan complete so the page stops polling and shows the banner.

    The final severity counts come from `summary` (build_summary()'s output)
    when one is given, replacing the counts accumulated during the run.
    Those two can legitimately differ — the live counts are what the
    profile handed to update_live_data(), while the summary is what actually
    landed in the database after deduplication — and the database is the
    authority. A dashboard that ends showing a number the report contradicts
    is worse than one that corrects itself at the end.
    """
    with _state_lock:
        state = _state.get(target)
        if state is None:
            return

        if summary:
            by_severity = summary.get("by_severity") or {}
            if by_severity:
                state["counts"] = {
                    name: int(by_severity.get(name, 0) or 0)
                    for name in _SEVERITY_ORDER
                }
                state["total"] = sum(state["counts"].values())

        state["status"] = "complete"
        state["progress_pct"] = 100
        state["current_tool"] = ""
        state["report_url"] = report_url
        state["updated"] = datetime.now().isoformat(timespec="seconds")
        payload = json.dumps(state, default=str, indent=1)

    try:
        _write_atomic(os.path.join(output_dir(target), DATA_FILENAME), payload)
    except OSError:
        pass

    print_info(
        f"[Dashboard] scan complete — the live dashboard for {target} will show "
        "the final result and stop polling."
    )


def dashboard_is_running(target: str) -> bool:
    """True if a live dashboard server is up for `target`."""
    with _state_lock:
        return target in _servers


def shutdown_live_dashboard(target: str) -> None:
    """
    Stop the local server for one target.

    Note what the process lifetime actually does here, because it is not
    what you would hope: the server runs on a DAEMON thread, so it dies the
    instant aegis.py's main thread exits. The dashboard is therefore live
    for exactly as long as the scan is, and the "Scan complete — open the
    full report" banner is unreachable a moment later (verified: curl to
    the port immediately after a run returns a connection refusal).

    That is why aegis.py holds the process open at the end of an
    interactive run with a dashboard, rather than exiting straight into a
    dead port. This function exists for tests and for a caller that wants
    the port back before then.
    """
    with _state_lock:
        server = _servers.pop(target, None)
        _state.pop(target, None)
    if server is not None:
        try:
            server.shutdown()
            server.server_close()
        except Exception:
            pass


# --- The page ------------------------------------------------------------
# Same palette and shape as report_html.py's static report, so the live view
# and the final report are visibly one artefact. Braces are doubled for
# str.format, as they are there.
_PAGE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Aegis — live scan: {target}</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; padding: 0 0 50px; background: {c_bg}; color: {c_text};
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
  header {{ background: linear-gradient(135deg, {c_panel} 0%, {c_panel_alt} 100%);
            border-bottom: 3px solid {c_accent}; padding: 22px 30px; }}
  header h1 {{ margin: 0; font-size: 20px; letter-spacing: .5px; }}
  header h1 .accent {{ color: {c_accent}; }}
  header .target {{ font-family: monospace; font-size: 26px; font-weight: 700;
                    margin-top: 4px; }}
  main {{ max-width: 1080px; margin: 0 auto; padding: 24px 20px; }}
  .card {{ background: {c_panel}; border: 1px solid {c_border}; border-radius: 10px;
           padding: 20px; margin-bottom: 20px; }}
  .card h2 {{ margin: 0 0 14px; font-size: 13px; text-transform: uppercase;
              letter-spacing: 1.3px; color: {c_muted}; font-weight: 600; }}

  .status {{ display: flex; align-items: center; gap: 12px; font-size: 15px; }}
  .dot {{ width: 11px; height: 11px; border-radius: 50%; background: {c_medium};
          animation: pulse 1.4s ease-in-out infinite; flex: 0 0 auto; }}
  .dot.done {{ background: {c_low}; animation: none; }}
  .dot.stale {{ background: {c_muted}; animation: none; }}
  @keyframes pulse {{ 0%,100% {{ opacity: 1; }} 50% {{ opacity: .25; }} }}
  .tool {{ font-family: monospace; color: {c_accent}; }}

  .bar {{ height: 9px; background: {c_bg}; border-radius: 5px; overflow: hidden;
          margin-top: 14px; border: 1px solid {c_border}; }}
  .bar > div {{ height: 100%; width: 0; background: {c_accent};
                transition: width .45s ease; }}

  .banner {{ display: none; background: {c_low}; color: #10241c; border-radius: 8px;
             padding: 15px 18px; font-weight: 600; margin-bottom: 20px; }}
  .banner a {{ color: #10241c; font-weight: 700; }}
  .banner.show {{ display: block; }}

  .tiles {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 11px; }}
  .tile {{ background: {c_panel_alt}; border-left: 4px solid {c_border};
           border-radius: 8px; padding: 14px 10px; text-align: center; }}
  .tile-n {{ font-size: 29px; font-weight: 700; font-family: monospace; line-height: 1; }}
  .tile-l {{ font-size: 10px; letter-spacing: 1.1px; color: {c_muted}; margin-top: 5px; }}
  .tile.CRITICAL {{ border-left-color: {c_critical}; }}
  .tile.CRITICAL .tile-n {{ color: {c_critical}; }}
  .tile.HIGH {{ border-left-color: {c_high}; }}
  .tile.HIGH .tile-n {{ color: {c_high}; }}
  .tile.MEDIUM {{ border-left-color: {c_medium}; }}
  .tile.MEDIUM .tile-n {{ color: {c_medium}; }}
  .tile.LOW {{ border-left-color: {c_low}; }}
  .tile.LOW .tile-n {{ color: {c_low}; }}

  .feed {{ list-style: none; margin: 0; padding: 0; max-height: 460px;
           overflow-y: auto; }}
  .feed li {{ padding: 9px 4px; border-bottom: 1px solid {c_border};
              font-size: 13px; display: flex; gap: 11px; align-items: baseline; }}
  .feed li:first-child {{ animation: flash .9s ease; }}
  @keyframes flash {{ from {{ background: rgba(233,69,96,.16); }} to {{ background: none; }} }}
  .sev {{ flex: 0 0 auto; min-width: 70px; text-align: center; padding: 2px 7px;
          border-radius: 4px; font-size: 10px; font-weight: 700; font-family: monospace;
          letter-spacing: .6px; }}
  .sev.CRITICAL {{ background: {c_critical}; color: #fff; }}
  .sev.HIGH {{ background: {c_high}; color: #1a1a2e; }}
  .sev.MEDIUM {{ background: {c_medium}; color: #1a1a2e; }}
  .sev.LOW {{ background: {c_low}; color: #1a1a2e; }}
  .at {{ flex: 0 0 auto; color: {c_muted}; font-family: monospace; font-size: 11px; }}
  .where {{ flex: 0 0 auto; color: {c_muted}; font-family: monospace; font-size: 11px; }}
  .what {{ flex: 1 1 auto; }}
  .waiting {{ color: {c_muted}; text-align: center; padding: 30px; font-size: 13px; }}
  footer {{ text-align: center; color: {c_muted}; font-size: 11px; padding: 20px; }}
</style>
</head>
<body>
<header>
  <h1><span class="accent">AEGIS</span> SCANNER — live</h1>
  <div class="target">{target}</div>
</header>

<main>
  <div id="banner" class="banner">
    Scan complete. <a id="reportLink" href="report.html">Open the full report &rarr;</a>
  </div>

  <section class="card">
    <h2>Progress</h2>
    <div class="status">
      <span id="dot" class="dot"></span>
      <span id="statusText">Waiting for the scan to start&hellip;</span>
    </div>
    <div class="bar"><div id="barFill"></div></div>
  </section>

  <section class="card">
    <h2>Findings so far</h2>
    <div class="tiles" id="tiles"></div>
  </section>

  <section class="card">
    <h2>Live feed <span style="text-transform:none;letter-spacing:0">(newest first)</span></h2>
    <ul class="feed" id="feed"></ul>
    <div id="waiting" class="waiting">Waiting for data&hellip;</div>
  </section>
</main>

<footer>Aegis Scanner — polling every {poll_ms} ms</footer>

<script>
(function () {{
  "use strict";
  var SEVS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
  var POLL = {poll_ms};
  var timer = null, rendered = 0;

  var tilesEl = document.getElementById("tiles");
  var feedEl = document.getElementById("feed");
  var waitEl = document.getElementById("waiting");
  var dotEl = document.getElementById("dot");
  var statusEl = document.getElementById("statusText");
  var barEl = document.getElementById("barFill");
  var bannerEl = document.getElementById("banner");
  var linkEl = document.getElementById("reportLink");

  SEVS.forEach(function (s) {{
    var d = document.createElement("div");
    d.className = "tile " + s;
    var n = document.createElement("div");
    n.className = "tile-n"; n.id = "n" + s; n.textContent = "0";
    var l = document.createElement("div");
    l.className = "tile-l"; l.textContent = s;
    d.appendChild(n); d.appendChild(l);
    tilesEl.appendChild(d);
  }});

  function text(parent, cls, value) {{
    var el = document.createElement("span");
    el.className = cls;
    el.textContent = value;
    parent.appendChild(el);
    return el;
  }}

  function render(data) {{
    SEVS.forEach(function (s) {{
      document.getElementById("n" + s).textContent =
        (data.counts && data.counts[s]) || 0;
    }});

    var pct = data.progress_pct || 0;
    barEl.style.width = pct + "%";

    if (data.status === "complete") {{
      dotEl.className = "dot done";
      statusEl.textContent = "Scan complete — " + (data.total || 0) + " finding(s).";
      bannerEl.className = "banner show";
      if (data.report_url) linkEl.setAttribute("href", data.report_url);
      if (timer) {{ clearInterval(timer); timer = null; }}
    }} else if (data.status === "starting") {{
      dotEl.className = "dot";
      statusEl.textContent = "Starting\\u2026";
    }} else {{
      dotEl.className = "dot";
      statusEl.textContent = "Running";
      if (data.current_tool) {{
        statusEl.textContent = "Running ";
        var t = document.createElement("span");
        t.className = "tool";
        t.textContent = data.current_tool;
        statusEl.appendChild(t);
        statusEl.appendChild(document.createTextNode("  \\u2014  " + pct + "%"));
      }}
    }}

    var findings = data.findings || [];
    if (findings.length !== rendered) {{
      // Rebuilt rather than diffed: the list arrives newest-first already
      // and is bounded by what one scan produces, so a full rebuild is
      // cheap and cannot drift out of sync with the source.
      feedEl.textContent = "";
      findings.forEach(function (f) {{
        var li = document.createElement("li");
        text(li, "sev " + (f.severity || "LOW"), f.severity || "LOW");
        text(li, "at", f.at || "");
        text(li, "where", (f.port ? ":" + f.port : "") + (f.cve ? " " + f.cve : ""));
        text(li, "what", f.description || f.type || "(no description)");
        feedEl.appendChild(li);
      }});
      rendered = findings.length;
    }}
    waitEl.style.display = findings.length ? "none" : "block";
  }}

  function poll() {{
    // Cache-busted: a conditional request served from cache would freeze
    // the dashboard on a scan that is still producing findings.
    fetch("{data_file}?t=" + Date.now(), {{ cache: "no-store" }})
      .then(function (r) {{
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      }})
      .then(render)
      .catch(function () {{
        // A failed poll mid-scan is almost always the file being replaced
        // at that instant. Say so honestly and keep polling rather than
        // showing an error that resolves itself in two seconds.
        dotEl.className = "dot stale";
        statusEl.textContent = "Waiting for data\\u2026";
      }});
  }}

  poll();
  timer = setInterval(poll, POLL);
}})();
</script>
</body>
</html>
"""
