#!/bin/bash
# ssh-extra/disable-persource-penalties.sh
#
# linuxserver custom-cont-init.d hook. Runs after this image's own sshd
# config generation but its own sshd may already have started (init order
# in this image runs custom-cont-init.d late) — so this both edits the
# config AND restarts the sshd service so the change actually takes
# effect this boot, not just on a hypothetical future restart.
#
# Why: OpenSSH's PerSourcePenalties (default-on in the OpenSSH version
# this image ships) resets rapid repeated connection attempts from one
# source. That's a real, desirable anti-brute-force control on a genuine
# server — and exactly what defeats the purpose of this throwaway,
# deliberately-weak local test fixture for Aegis's hydra wrapper. Local,
# isolated, authorized test target only — never do this on a real server.

CONF=/config/sshd/sshd_config

if ! grep -q "^PerSourcePenalties no" "$CONF" 2>/dev/null; then
    {
        echo ""
        echo "# Added by test-targets/ssh-extra — deliberately weakened for Aegis hydra testing"
        echo "PerSourcePenalties no"
        echo "MaxStartups 100:30:1000"
        echo "MaxAuthTries 100"
    } >> "$CONF"
fi

# Restart the already-running sshd service so the edit takes effect now.
if [ -d /run/service/svc-openssh-server ]; then
    s6-svc -r /run/service/svc-openssh-server
fi
