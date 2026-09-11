# Dockerfile — run Aegis Scanner with no local setup: `docker run`.
#
# WHY THIS IMAGE EXISTS
# ---------------------
# Aegis shells out to a specific set of Kali security tools (nmap, nikto,
# gobuster, whatweb, nuclei, sslyze, sqlmap, hydra, enum4linux, ...). Getting
# all of them installed and on PATH is the single biggest setup hurdle, and
# it is exactly what a container removes: this image is built on the Kali
# rolling base so those tools are an apt-get away, pins the Python deps, and
# leaves a ready-to-run scanner as its entrypoint.
#
# BUILD
#   docker build -t aegis-scanner .
#
# RUN (reports land in ./output on the host via the volume mount)
#   docker run --rm -v "$PWD/output:/app/output" aegis-scanner <target> [flags]
#   docker run --rm -v "$PWD/output:/app/output" aegis-scanner --list-plugins
#   docker run --rm -v "$PWD/output:/app/output" aegis-scanner scanme.nmap.org --engine --scan-profile quick
#
# The database and .env can be mounted too, to persist scan history / supply
# API keys:
#   docker run --rm \
#     -v "$PWD/output:/app/output" \
#     -v "$PWD/database:/app/database" \
#     -v "$PWD/.env:/app/.env:ro" \
#     aegis-scanner <target>
#
# NETWORKING
#   To scan a service running on the Docker host, use --network host (Linux)
#   or host.docker.internal (Docker Desktop). A container on the default
#   bridge cannot reach the host's 127.0.0.1.

FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# System + security tooling. kali-rolling carries these in its default repos.
# weasyprint needs the pango/cairo/gdk-pixbuf native libraries for PDF
# rendering — installed here so the PDF report works out of the box rather
# than failing at typeset time with an opaque native-library error.
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv \
        nmap nikto gobuster whatweb nuclei sslyze \
        sqlmap hydra dnsutils \
        libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 \
        libcairo2 libffi-dev \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Dependencies first, so a code change does not bust the pip layer cache.
COPY requirements.txt .
RUN pip3 install --break-system-packages -r requirements.txt

# Then the application.
COPY . .

# A non-root user for the scan itself. nmap's raw-socket scan types (-sS)
# need CAP_NET_RAW; Aegis's profiles use connect-scan-compatible flags, so
# running unprivileged is fine for the default profiles. If you need a SYN
# scan, add --cap-add=NET_RAW to `docker run`.
RUN useradd --create-home --shell /usr/sbin/nologin aegis \
    && mkdir -p /app/output /app/database \
    && chown -R aegis:aegis /app/output /app/database
USER aegis

# aegis.py is the entrypoint; flags/target are passed as `docker run` args.
ENTRYPOINT ["python3", "aegis.py"]
CMD ["--help"]
