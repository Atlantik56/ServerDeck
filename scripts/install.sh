#!/usr/bin/env bash
# Shared minimal bootstrap; the confirmed Linux installer always upgrades the OS.
set -euo pipefail
[ "$(uname -s)" = Linux ] || { echo 'Run this bootstrap on a Linux VPS via ssh -t.' >&2; exit 1; }
bootstrap_only=false
dry_run=false
wizard_args=(--mode local)
for argument in "$@"; do
    case "$argument" in
        --bootstrap-only) bootstrap_only=true ;;
        --dry-run) dry_run=true; wizard_args+=("$argument") ;;
        *) wizard_args+=("$argument") ;;
    esac
done
# Read release values as data; do not execute /etc/os-release as shell code.
distro=''
version=''
while IFS='=' read -r field value; do
    value="${value#\"}"; value="${value%\"}"
    value="${value#\'}"; value="${value%\'}"
    case "$field" in ID) distro="$value" ;; VERSION_ID) version="$value" ;; esac
done < /etc/os-release
case "$distro:$version" in
    ubuntu:24.04|debian:12) ;;
    *) echo 'Supported VPS systems: Ubuntu 24.04 and Debian 12.' >&2; exit 1 ;;
esac
command -v apt-get >/dev/null || { echo 'APT is required.' >&2; exit 1; }
# Bootstrap must not modify a running panel or another existing web server.
for path in /opt/server-deck /opt/server-deck-web /etc/server-deck /var/lib/serverdeck /usr/local/lib/server-deck /etc/caddy; do
    [ ! -e "$path" ] && [ ! -L "$path" ] || { echo "Existing installation/configuration: $path. Use a clean dedicated host." >&2; exit 1; }
done
missing=()
command -v python3 >/dev/null || missing+=(python3)
command -v curl >/dev/null || missing+=(curl)
command -v tar >/dev/null || missing+=(tar)
[ -s /etc/ssl/certs/ca-certificates.crt ] || missing+=(ca-certificates)
if [ "${#missing[@]}" -gt 0 ]; then
    if "$dry_run"; then
        echo "Dry run: missing bootstrap dependencies: ${missing[*]}. No packages were changed." >&2
        exit 1
    fi
    elevate=(env)
    if [ "$(id -u)" -ne 0 ]; then
        command -v sudo >/dev/null || { echo 'Root or sudo access is required to install missing dependencies.' >&2; exit 1; }
        sudo -v </dev/tty
        elevate=(sudo -n -- env)
    fi
    echo "Installing missing bootstrap dependencies: ${missing[*]}"
    "${elevate[@]}" DEBIAN_FRONTEND=noninteractive NEEDRESTART_SUSPEND=1 NEEDRESTART_MODE=l apt-get -o APT::Update::Error-Mode=any update </dev/null
    "${elevate[@]}" DEBIAN_FRONTEND=noninteractive NEEDRESTART_SUSPEND=1 NEEDRESTART_MODE=l apt-get install -y --no-upgrade --no-remove --no-install-recommends -o Dpkg::Options::=--force-confold "${missing[@]}" </dev/null
    if [ ! -s /etc/ssl/certs/ca-certificates.crt ] && command -v update-ca-certificates >/dev/null; then
        "${elevate[@]}" update-ca-certificates </dev/null
    fi
fi
for binary in python3 curl tar; do
    command -v "$binary" >/dev/null || { echo "Required component is still missing: $binary" >&2; exit 1; }
done
[ -s /etc/ssl/certs/ca-certificates.crt ] || { echo 'The CA certificate bundle is missing; HTTPS verification remains enabled.' >&2; exit 1; }
# This is used by the Python SSH launcher before transferring the source tarball.
"$bootstrap_only" && exit 0
setup_dir=$(mktemp -d /tmp/serverdeck-bootstrap.XXXXXXXX)
chmod 700 "$setup_dir"
trap 'rm -rf -- "$setup_dir"' EXIT
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/Atlantik56/ServerDeck/main/installer/install.py -o "$setup_dir/install.py"
# curl | bash uses stdin for code; only the wizard reads the controlling terminal.
python3 "$setup_dir/install.py" "${wizard_args[@]}" </dev/tty
