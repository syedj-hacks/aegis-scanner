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
#   dirb                          provides /usr/share/wordlists/dirb/common.txt (gobuster_wrap.py default wordlist)
SCAN_TOOLS=(bind9-dnsutils nmap nikto gobuster subfinder amass theharvester dirb)

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
