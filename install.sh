#!/usr/bin/env bash
#
# install.sh
# Installer for Aegis Scanner (Cyber404 Academy 2026) on Kali Linux.
#
# 1. apt-installs every external tool a modules/ wrapper shells out to via
#    error_handler.run_tool(), plus the Python venv/pip and WeasyPrint's
#    native rendering libraries.
# 2. Creates a venv and installs requirements.txt into it.
# 3. Runs setup.py for API-key / directory bootstrap.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$REPO_ROOT/venv"

# External CLI tools invoked via run_tool(), grepped from modules/:
#   bind9-dnsutils -> nslookup   modules/recon/dns.py
#   nmap                          modules/scanning/port_scanner.py, service_detect.py
#   nikto                         modules/web/nikto_wrap.py
#   gobuster                      modules/web/gobuster_wrap.py
#   subfinder, amass              modules/recon/subdomain.py
#   theharvester                  modules/recon/osint.py
#   dirb                          modules/web/dirb_wrap.py (also provides
#                                 /usr/share/wordlists/dirb/common.txt, gobuster_wrap.py's
#                                 default wordlist)
#   whatweb                       modules/web/whatweb_wrap.py
#   nuclei                        modules/web/nuclei_wrap.py
#   zaproxy                       modules/web/zap_wrap.py — apt's zaproxy package ships the
#                                 ZAP daemon/GUI; if zap-baseline.py isn't on PATH after
#                                 install, grab it from the ZAP install itself
#                                 (see https://www.zaproxy.org/docs/docker/baseline-scan/)
#   sslyze                        modules/web/sslyze_wrap.py
#   testssl.sh                    modules/web/testssl_wrap.py — complements sslyze rather than
#                                 replacing it: sslyze inventories accepted protocols/ciphers,
#                                 testssl.sh tests for named TLS vulnerabilities (Heartbleed,
#                                 ROBOT, renegotiation, ...) that sslyze does not check at all.
#                                 In apt on Debian/Kali as "testssl.sh"; a git-clone fallback
#                                 below covers distros where it is not packaged.
#   wpscan                        modules/web/wpscan_wrap.py
#   sqlmap                        modules/web/sqlmap_wrap.py
#   hydra                         modules/scanning/hydra_wrap.py
#   enum4linux                    modules/scanning/enum4linux_wrap.py
SCAN_TOOLS=(
    bind9-dnsutils nmap nikto gobuster subfinder amass theharvester dirb
    whatweb nuclei zaproxy sslyze testssl.sh wpscan sqlmap hydra enum4linux
)

# Python environment + WeasyPrint's native Pango/Cairo/GDK-Pixbuf bindings
# (report_pdf.py imports weasyprint lazily specifically because these can
# be missing).
ENV_DEPS=(python3-venv python3-pip libpango-1.0-0 libpangocairo-1.0-0 libcairo2 libgdk-pixbuf-2.0-0)

echo "=== Aegis Scanner install ==="

if [[ "$(id -u)" -eq 0 ]]; then
    SUDO=""
else
    SUDO="sudo"
fi

echo "[*] Updating apt package lists"
$SUDO apt update

echo "[*] Installing scan tools: ${SCAN_TOOLS[*]}"
if $SUDO apt install -y "${SCAN_TOOLS[@]}"; then
    echo "[+] Scan tools installed"
else
    echo "[-] Some scan tools failed to install — check apt output above."
    echo "    aegis.py still runs; a profile using a missing tool logs a warning and skips it."
fi

# apt's nuclei package is missing/stale on some Kali mirrors — fall back to
# the official Go install so modules/web/nuclei_wrap.py always has a real
# binary to call.
if ! command -v nuclei >/dev/null 2>&1 && ! command -v "$HOME/go/bin/nuclei" >/dev/null 2>&1; then
    if command -v go >/dev/null 2>&1; then
        echo "[*] apt's nuclei package is unavailable here — installing via 'go install' instead"
        GOBIN="$HOME/go/bin" go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
            && echo "[+] nuclei installed to $HOME/go/bin/nuclei — add \$HOME/go/bin to PATH" \
            || echo "[-] 'go install' for nuclei failed — nuclei_wrap.py will log 'binary not found' until this is resolved"
    else
        echo "[-] nuclei is missing and no Go toolchain is present to install it — install Go or nuclei manually"
    fi
fi

# testssl.sh is packaged in Debian/Kali apt (verified: 3.2.2+dfsg-1), so the
# SCAN_TOOLS entry above normally covers it. It is a single self-contained
# bash script, though, and is NOT packaged everywhere — so where apt has no
# package, clone it instead of leaving compliance scans without their
# vulnerability-check half. modules/web/testssl_wrap.py probes
# /opt/testssl.sh/testssl.sh explicitly, which is where this puts it.
if ! command -v testssl.sh >/dev/null 2>&1 && ! command -v testssl >/dev/null 2>&1 \
   && [[ ! -x /opt/testssl.sh/testssl.sh ]]; then
    if command -v git >/dev/null 2>&1; then
        echo "[*] testssl.sh is not available from apt here — installing via git clone to /opt/testssl.sh"
        if $SUDO git clone --depth 1 --branch 3.2 https://github.com/testssl/testssl.sh.git /opt/testssl.sh; then
            $SUDO chmod +x /opt/testssl.sh/testssl.sh
            echo "[+] testssl.sh installed to /opt/testssl.sh/testssl.sh"
        else
            echo "[-] git clone of testssl.sh failed — the compliance profile will log it as unavailable and continue"
        fi
    else
        echo "[-] testssl.sh is missing and git is not installed to fetch it — install one or the other manually"
    fi
fi

# modules/web/zap_wrap.py drives OWASP ZAP directly (daemon + REST API via
# the zapv2 client from requirements.txt) rather than shelling out to
# zap-baseline.py, which apt's zaproxy package does not ship. All that's
# needed beyond the Python dependency is zap.sh from the zaproxy package
# itself and a JRE — both already covered by SCAN_TOOLS/apt above.
if ! command -v java >/dev/null 2>&1; then
    echo "[-] No JRE found on PATH — OWASP ZAP (modules/web/zap_wrap.py) needs one to run its daemon"
fi
if [[ ! -f /usr/share/zaproxy/zap.sh ]] && ! command -v zap.sh >/dev/null 2>&1; then
    echo "[-] zap.sh not found under /usr/share/zaproxy/ or on PATH — modules/web/zap_wrap.py will report ZAP as unavailable"
fi

# --- One-time ZAP passive-scan-rules bootstrap ----------------------------
# A fresh apt install of zaproxy ships zap.sh + the "Passive scanner
# rules" add-on FILE (pscanrules — the real ~60-rule vulnerability-
# detection set: missing headers, CSP, cookie flags, info disclosure,
# etc.) but does NOT pre-register that add-on as "installed" in a ZAP
# profile — it just sits on disk unused until something triggers ZAP's
# own local-plugin bootstrap. zap_wrap.py's daemon config deliberately
# avoids ANY online update-checking on every normal scan run (to keep
# scans fast and avoid a half-downloaded add-on if a scan is interrupted
# mid-download), which means that bootstrap NEVER happens on its own
# during ordinary use — a target's ZAP baseline scan then returns 0
# findings forever, on every target, with no error. This was diagnosed
# and fixed live during this project's own development; doing the
# bootstrap once here, on a genuinely fresh ~/.ZAP (before anyone has ever
# run a scan), avoids ever hitting that gap in the first place.
#
# IMPORTANT — do not "fix" ZAP by rerunning zap.sh -addonupdate or
# -addoninstall <id> against this profile later, even if a scan looks
# like it's returning too few ZAP findings. That specific action sequence
# is the leading suspect for how this add-on got silently uninstalled
# during this project's own debugging: an add-on update reconciliation
# uninstalled the old pscanrules version while updating unrelated
# add-ons, then failed to reinstall the replacement because the
# marketplace catalog lookup for that specific id was failing — leaving
# it permanently gone with no error logged against it specifically. If
# ZAP baseline scans start returning 0 findings after previously working,
# the fix is: back up and delete ~/.ZAP, then re-run the bootstrap block
# below (or re-run this installer) rather than touching the marketplace.
if [[ -f /usr/share/zaproxy/zap.sh ]] || command -v zap.sh >/dev/null 2>&1; then
    ZAP_SH="/usr/share/zaproxy/zap.sh"
    command -v zap.sh >/dev/null 2>&1 && ZAP_SH="$(command -v zap.sh)"

    if [[ -d "$HOME/.ZAP" ]]; then
        echo "[*] ~/.ZAP already exists — leaving it alone (assumed already bootstrapped)"
    else
        echo "[*] Bootstrapping OWASP ZAP's local profile (installs the passive-scan ruleset add-on, one time only) — this downloads real add-on files and can take a minute or two"
        ZAP_BOOT_LOG="$(mktemp)"
        "$ZAP_SH" -daemon -host 127.0.0.1 -port 8091 \
            -config api.disablekey=true \
            -config autoupdate.checkOnStart=false \
            -config autoupdate.installScannerRules=false \
            -config autoupdate.installAddonUpdates=false \
            -config autoupdate.reportAlphaAddons=false \
            -config autoupdate.reportBetaAddons=false \
            > "$ZAP_BOOT_LOG" 2>&1 &
        ZAP_BOOT_PID=$!

        ZAP_READY=""
        for _ in $(seq 1 60); do
            if grep -q "ZAP is now listening" "$ZAP_BOOT_LOG" 2>/dev/null; then
                ZAP_READY="1"
                break
            fi
            sleep 2
        done

        if [[ -n "$ZAP_READY" ]]; then
            # The API port being open doesn't mean the add-on download
            # finished — give it real time to pull the bundled add-ons
            # over the network before asking it to shut down.
            sleep 30
            curl -s "http://127.0.0.1:8091/JSON/core/action/shutdown/" >/dev/null 2>&1 || true
            sleep 5
            echo "[+] ZAP profile bootstrapped and shut down cleanly (state persisted to ~/.ZAP)"
        else
            echo "[-] ZAP did not become ready within the bootstrap window — passive-scan findings may come back empty until this is retried. See BACKEND_STRUCTURE.md / this block's comments for manual recovery."
        fi

        kill "$ZAP_BOOT_PID" >/dev/null 2>&1 || true
        rm -f "$ZAP_BOOT_LOG"
    fi
fi

echo "[*] Installing Python/WeasyPrint system dependencies: ${ENV_DEPS[*]}"
if $SUDO apt install -y "${ENV_DEPS[@]}"; then
    echo "[+] System dependencies installed"
else
    echo "[-] Some system dependencies failed to install — venv creation or PDF reports may fail."
fi

echo "[*] Setting up Python virtual environment at $VENV_DIR"
if [[ ! -d "$VENV_DIR" ]]; then
    python3 -m venv "$VENV_DIR"
    echo "[+] venv created"
else
    echo "[+] venv already exists"
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

echo "[*] Installing Python dependencies from requirements.txt"
pip install --upgrade pip >/dev/null
if pip install -r "$REPO_ROOT/requirements.txt"; then
    echo "[+] Python dependencies installed"
else
    echo "[-] pip install failed — see output above."
    exit 1
fi

echo "[*] Running post-install setup (API key, directories)"
python3 "$REPO_ROOT/setup.py"

echo ""
echo "=== Install complete ==="
echo "Activate the venv before running Aegis Scanner:"
echo "  source venv/bin/activate"
echo "  python3 aegis.py <target> --profile quickscan"
