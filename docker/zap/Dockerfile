# docker/zap/Dockerfile
# OWASP ZAP daemon for Aegis Scanner, with a DISPOSABLE ~/.ZAP profile.
#
# Why this image exists
# ---------------------
# WRITEUP.md §3.1 documents a failure that cost real debugging time: ZAP's
# "Passive scanner rules" add-on (pscanrules — the ~60-rule set that IS the
# baseline scan's entire detection capability) silently uninstalled itself
# and stayed gone. Every subsequent scan then returned zero findings, on
# every target, with no error anywhere: a scan that looked clean and was
# simply blind. The same class of failure occurs when a daemon is killed
# mid-add-on-download and leaves a half-written zip on disk, after which
# every start fails with "zip END header not found".
#
# Both have the same root cause: ~/.ZAP is persistent, mutable state that
# a scan can corrupt, and nothing ever resets it. The local-zap.sh path
# inherits whatever state the last run left behind, forever.
#
# A container fixes that structurally rather than by remembering to clean
# up. The profile below is baked at BUILD time and lives inside the
# container's writable layer, so:
#
#     docker compose restart zap
#
# discards whatever the last run did to it and comes back with the exact
# profile this Dockerfile built — the guaranteed-fresh-profile fix, for
# free, as a documented one-liner instead of a debugging session. There is
# deliberately NO volume mounted over /home/zap/.ZAP: persisting it would
# reintroduce the entire problem this image exists to remove.
FROM ghcr.io/zaproxy/zaproxy:stable

# Match zap_wrap.py's local-spawn configuration exactly, so a scan behaves
# the same whether it targets this container or a local daemon. Online
# add-on update checks are disabled for the same reason they are disabled
# there: they are slow, network-dependent, and a daemon killed mid-download
# leaves a corrupted add-on that breaks every later start.
#
# Baking these at build time rather than passing them per-run means a
# `docker compose restart` cannot come back with different settings than
# the ones that were tested.
ENV ZAP_PORT=8090

USER zap
WORKDIR /zap

# Pre-register the add-ons ZAP ships, ONCE, at build time.
#
# This is the containerised form of install.sh's one-time bootstrap, and it
# is here for the same reason: a fresh ZAP install has the pscanrules
# add-on FILE on disk but does not register it as installed, and with
# online update checks off, nothing ever triggers that registration during
# ordinary use. The result is a daemon that starts cleanly and finds
# nothing. Doing it here means the built image is already past that state,
# and every restart returns to a profile where it has already happened.
RUN /zap/zap.sh -cmd -addoninstall pscanrules -addoninstall spiderAjax \
      -config autoupdate.checkOnStart=false \
      -config autoupdate.installAddonUpdates=false \
    || echo "[warn] add-on bootstrap returned non-zero; the base image may already include them"

EXPOSE 8090

# -host 0.0.0.0 so the daemon is reachable from outside the container;
# api.addrs.addr.* allows the API to be called from the Docker bridge
# network, which ZAP otherwise refuses as an untrusted address.
#
# api.disablekey=true matches zap_wrap.py's local daemon. That is safe
# ONLY because docker-compose.yml binds this port to 127.0.0.1 — see the
# warning there before changing the binding.
CMD ["zap.sh", "-daemon", \
     "-host", "0.0.0.0", "-port", "8090", \
     "-config", "api.disablekey=true", \
     "-config", "api.addrs.addr.name=.*", \
     "-config", "api.addrs.addr.regex=true", \
     "-config", "autoupdate.checkOnStart=false", \
     "-config", "autoupdate.installScannerRules=false", \
     "-config", "autoupdate.installAddonUpdates=false", \
     "-config", "autoupdate.reportAlphaAddons=false", \
     "-config", "autoupdate.reportBetaAddons=false"]
