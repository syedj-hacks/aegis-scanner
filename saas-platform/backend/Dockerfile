# Aegis Shield backend — built on the same Kali base as the root Aegis
# Dockerfile so the scanning tools it shells out to (nmap, nikto, gobuster,
# whatweb, nuclei, sslyze, sqlmap, hydra, wpscan, enum4linux) are on PATH.
#
# Build context MUST be the repository root (not this directory), since the
# backend imports the Aegis engine as a library from ../.. :
#   docker build -f saas-platform/backend/Dockerfile -t aegis-shield-backend .

FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv \
        nmap nikto gobuster dirb whatweb nuclei sslyze testssl.sh \
        sqlmap hydra dnsutils wpscan enum4linux \
        wordlists \
        libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 \
        libcairo2 libffi-dev \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# Tool set above = exactly what the engine shells out to for the quick/stealth/
# webaudit/deepscan/compliance profiles. Two that the earlier image omitted and
# which silently broke scans are now included:
#   - dirb + testssl.sh      : webaudit/deepscan invoke both directly.
#   - wordlists              : provides /usr/share/wordlists/dirb/common.txt,
#                              the DEFAULT wordlist for BOTH gobuster and dirb —
#                              without it content-discovery finds nothing.
# NOT bundled, to keep the image lean (each is optional and heavy):
#   - ZAP (zap.sh)           : deepscan's ZAP step reports a graceful tool
#                              failure without it; run the docker/zap container
#                              and set ZAP_HOST to enable it (see docker-compose).
#   - recon-profile OSINT     : theHarvester, amass, subfinder, cloud_enum. Add
#                              `theharvester amass` to the apt line above if you
#                              need the passive `recon` profile in the container.

WORKDIR /app

# Aegis engine dependencies first (cache layer), then the SaaS backend's own.
COPY requirements.txt ./requirements.txt
RUN pip3 install --break-system-packages -r requirements.txt

COPY saas-platform/backend/requirements.txt ./saas-platform/backend/requirements.txt
RUN pip3 install --break-system-packages -r saas-platform/backend/requirements.txt

# Full repo, so aegis_bridge.py can import the engine as a library.
COPY . .

WORKDIR /app/saas-platform/backend

RUN chmod +x entrypoint.sh
ENTRYPOINT ["./entrypoint.sh"]
