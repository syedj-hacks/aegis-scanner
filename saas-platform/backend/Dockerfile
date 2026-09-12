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
        nmap nikto gobuster whatweb nuclei sslyze \
        sqlmap hydra dnsutils wpscan enum4linux \
        libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 \
        libcairo2 libffi-dev \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

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
