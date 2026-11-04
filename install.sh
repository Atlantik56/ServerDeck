#!/usr/bin/env bash
# Compatibility URL. The maintained entry point is scripts/install.sh.
set -euo pipefail
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/Atlantik56/ServerDeck/main/scripts/install.sh | bash -s -- "$@"
