#!/usr/bin/env sh
# Linux/macOS one-click start for Aegis Shield. See launch_aegis_shield.py.
cd "$(dirname "$0")" || exit 1

if command -v python3 >/dev/null 2>&1; then
    python3 launch_aegis_shield.py "$@"
else
    echo "Python 3.10 or newer is required. Install it with your package manager, e.g.:"
    echo "  sudo apt install python3 python3-venv"
fi
status=$?

# Keep the window open after an error, or when started from a file manager
# (no terminal attached), so the message can be read.
if [ "$status" -ne 0 ] || [ ! -t 1 ]; then
    printf "\nPress Enter to close..."
    read -r _
fi
exit $status
