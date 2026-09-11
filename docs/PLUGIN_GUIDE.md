# Plugin & Signature Authoring Guide

Aegis has two ways to add a check, both **auto-discovered** — you never edit
a core file to register one. Pick the lightest that can express your check.

| You want to…                                         | Use a…      |
|------------------------------------------------------|-------------|
| Request a path and match the response                | Signature   |
| Run any logic, call a tool, correlate several things | Plugin      |

---

## Signatures

A signature is a YAML (or JSON) file in `signatures/`. Drop it in; the
loader turns it into a plugin named `sig:<id>` and the engine runs it
against every web port. No Python.

### Minimal example

```yaml
id: exposed-git-config          # unique; becomes the plugin name sig:exposed-git-config
info:
  name: Exposed .git/config
  severity: medium              # info | low | medium | high | critical
  description: The repository config is publicly served.
  remediation: Deny access to /.git at the web server.
  reference:
    - https://owasp.org/www-community/attacks/Source_code_disclosure
  cve: [CVE-2021-XXXXX]         # optional
  cvss: 5.3                     # optional
requests:
  - method: GET                 # GET (default) or POST
    path: "/.git/config"        # appended to the target's web base URL
    matchers_condition: and     # and (default) | or  — combines the matchers
    matchers:
      - type: status
        status: [200]
      - type: word
        part: body              # body (default) | header
        words: ["[core]", "repositoryformatversion"]
        condition: and          # and | or (default or)
```

### Matcher types

| type     | matches when…                                                        |
|----------|----------------------------------------------------------------------|
| `status` | the response code is in `status: [...]`                              |
| `word`   | `words` are found in `part` (body/header); `condition` and/or        |
| `regex`  | any pattern in `regex: [...]` matches `part`                         |
| `header` | header `header:` is present (and contains any `words`, if given)     |

- Multiple `requests` are tried in order; the signature **fires on the
  first request that matches**. Use this for a check whose target hides
  under several common paths.
- A signature that fires produces a **Confirmed** finding — a matcher
  matching is an observed response characteristic, not a version guess.

### What signatures deliberately can't do

No response chaining, no extractors feeding later requests, no templating
that reaches the shell or filesystem. A signature is *data*, evaluated by
`plugins/signature.py`; it is never executed. If your check needs more,
write a plugin.

### Test it

```bash
python3 -c "from plugins.loader import get; \
  print(get('sig:exposed-git-config').execute('TARGET', {'port': 80}).findings)"
```

---

## Plugins

A plugin is a `ScannerPlugin` subclass in a new file under `plugins/`. The
loader discovers every concrete subclass automatically.

### The contract

```python
from plugins.base import ScannerPlugin, Finding, CONFIRMED, POTENTIAL

class MyCheckPlugin(ScannerPlugin):
    name = "mycheck"                       # unique, lowercase, filesystem-safe
    description = "One line, shown by --list-plugins."
    target_types = ("web",)                # host | web | service | passive
    severity_baseline = "MEDIUM"           # severity when the tool doesn't say
    requires = ("some-binary",)            # external tools; checked before run
    order = 50                             # lower runs earlier (discovery is 0-3)

    def run(self, target, config):
        """Do the work. MUST NOT raise — return a dict, put failures in
        {'error': ...}. `config` carries port/use_https/profile/auth and,
        for host plugins, open_ports/services."""
        return {"port": config.get("port"), "error": None, "hits": [...]}

    def parse_output(self, raw):
        """Map the raw dict to Finding objects."""
        return [Finding(
            title="...", finding_type="mycheck_finding", plugin=self.name,
            severity="HIGH", port=raw.get("port"),
            evidence="what was observed",
            remediation="what to do",
            confidence=CONFIRMED,          # you observed it; else POTENTIAL
        )]
```

That is the whole interface. `execute()` (in the base class) wraps `run()`
+ `parse_output()` with timing, availability checks, and isolation — you
do not write any of that.

### The rules that matter (see CONTRIBUTING.md)

- **`run()` never raises.** If you shell out, use the existing wrappers in
  `modules/` (which already honour this) rather than calling `subprocess`
  yourself. `execute()` will catch an escape and mark the plugin failed,
  but that is a backstop, not a licence.
- **Reuse, don't reimplement.** If a wrapper for your tool exists in
  `modules/`, call it and map its output via `plugins/_mappers.py`. Look at
  `plugins/web.py` — every plugin there is a thin wrapper around an
  existing, live-verified module.
- **Confidence is honest.** `CONFIRMED` only if you exercised the
  vulnerability. A version match is `POTENTIAL`.
- **`applicable(config)`** gates a plugin to the contexts it fits (e.g.
  wpscan only where WordPress was fingerprinted). A plugin that isn't
  applicable is recorded as *skipped with a reason*, not silently absent.

### `config` keys you can read

| key                     | when set                                    |
|-------------------------|---------------------------------------------|
| `port`, `use_https`     | web/service plugins, per port               |
| `open_ports`, `services`| host/service plugins, after discovery       |
| `profile`               | active nmap/rate-limit profile name         |
| `auth`                  | authenticated-scan credential, if any       |
| `nuclei_severity`, `gobuster_wordlist` | from the YAML profile        |
| `wordpress_fingerprinted`, `injectable_candidates` | conditional gates|

### Register it in a profile

Nothing to register — it's discovered. To have it run, list its `name` in a
YAML profile's `plugins:` (`profiles_yaml/*.yaml`), or use `plugins: all`.
Confirm it loaded:

```bash
python3 aegis.py --list-plugins
```

### Enrichment is automatic

You do not compute EPSS, risk scores, or run active validation — the engine
does that for every finding after `parse_output()`. Emit the CVE ids
(`cve_ids=[...]`) and CVSS (`cvss_score=...`) you know; the pipeline attaches
the rest.
