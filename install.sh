#!/usr/bin/env bash
# Run directly on the target Linux host, including through ssh -t from any OS.
set -euo pipefail
[ "$(uname -s)" = Linux ] || { echo 'Run this bootstrap on a Linux VPS via ssh -t.' >&2; exit 1; }
# curl | bash uses stdin for code; prompts must read the controlling terminal.
command -v python3 >/dev/null || { echo 'Install Python 3.9-3.12 first (sudo apt-get install python3), then repeat.' >&2; exit 1; }
command -v curl >/dev/null || { echo 'Install curl and ca-certificates first.' >&2; exit 1; }
setup_dir=$(mktemp -d /tmp/serverdeck-bootstrap.XXXXXXXX)
chmod 700 "$setup_dir"
trap 'rm -rf -- "$setup_dir"' EXIT
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/Atlantik56/ServerDeck/main/install.py -o "$setup_dir/install.py"
python3 "$setup_dir/install.py" --mode local "$@" </dev/tty
