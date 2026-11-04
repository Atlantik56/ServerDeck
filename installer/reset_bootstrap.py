#!/usr/bin/env python3
"""Deliberate root recovery: issue a new one-hour first-run code if no account exists."""
import hashlib
import argparse
import fcntl
import socket
import stat
import importlib.util
import json
import os
import pathlib
import pwd
import secrets
import tempfile
import time


def main():
    if os.geteuid() != 0:
        raise SystemExit('Run through sudo on the controller VPS.')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recover-incomplete-setup', action='store_true')
    args = parser.parse_args()
    state = pathlib.Path('/var/lib/server-deck-auth')
    lock = state / 'bootstrap.lock'
    owner = pwd.getpwnam('caddy')
    fd = os.open(str(lock), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid not in (0, owner.pw_uid):
        os.close(fd)
        raise SystemExit('Bootstrap lock requires administrator review.')
    with os.fdopen(fd, 'a') as handle:
        os.fchmod(handle.fileno(), 0o600)
        os.fchown(handle.fileno(), owner.pw_uid, owner.pw_gid)
        fcntl.flock(handle, fcntl.LOCK_EX)
        recover(args, state)


def recover(args, state):
    spec = importlib.util.spec_from_file_location('deck_fixed_helper', '/usr/local/lib/server-deck/account_helper.py')
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    accounts = helper.configured_accounts()
    if str(accounts) not in ('/etc/caddy/server-deck-accounts', '/etc/caddy/server-deck-accounts.d/accounts') or accounts.is_symlink():
        raise SystemExit('Account path requires administrator review.')
    if accounts.read_text().strip():
        raise SystemExit('An account already exists. Bootstrap remains closed; use reset_account.py for deliberate password recovery.')
    used = state / 'bootstrap-used'
    if used.exists():
        if not args.recover_incomplete_setup:
            raise SystemExit('Setup was already claimed. Refusing to reopen; review incomplete setup manually or use --recover-incomplete-setup with explicit host confirmation.')
        if input('Recover incomplete setup: type this hostname (' + socket.gethostname() + '): ').strip() != socket.gethostname():
            raise SystemExit('Cancelled.')
    if input('Issue a new first-run code? Type RESET: ').strip() != 'RESET':
        raise SystemExit('Cancelled.')
    owner = pwd.getpwnam('caddy')
    code = secrets.token_urlsafe(32)
    payload = dict(version=1, tokenHash=hashlib.sha256(code.encode()).hexdigest(), expiresAt=int(time.time()) + 3600, consumed=False)
    fd, name = tempfile.mkstemp(prefix='.bootstrap-', dir=str(state))
    try:
        os.fchmod(fd, 0o600)
        os.fchown(fd, owner.pw_uid, owner.pw_gid)
        with os.fdopen(fd, 'w') as output:
            json.dump(payload, output)
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, state / 'bootstrap.json')
        if used.exists():
            used.unlink()
    finally:
        if os.path.exists(name):
            os.unlink(name)
    print('One-time setup code (valid for one hour): ' + code)
    print('Open /login/ on the controller HTTPS address. Existing servers and SSH policies were not changed.')


if __name__ == '__main__':
    main()
