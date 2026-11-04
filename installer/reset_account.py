#!/usr/bin/env python3
"""Deliberate root password recovery for an existing web account; never used by install."""
import getpass
import fcntl
import importlib.util
import os
import pathlib
import re
import subprocess


def main():
    if os.geteuid() != 0:
        raise SystemExit('Run through sudo on the controller VPS.')
    spec = importlib.util.spec_from_file_location('deck_fixed_helper', '/usr/local/lib/server-deck/account_helper.py')
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    path = helper.configured_accounts()
    if str(path) not in ('/etc/caddy/server-deck-accounts', '/etc/caddy/server-deck-accounts.d/accounts') or path.is_symlink():
        raise SystemExit('Account path requires administrator review.')
    old = path.read_text()
    user = input('Existing panel username: ').strip()
    helper.account_hash(old, user)  # Refuse creation or changing another store.
    new = getpass.getpass('New password (12–72 bytes): ')
    confirm = getpass.getpass('Confirm new password: ')
    if len(new) < 12 or len(new.encode()) > 72 or new != confirm or any(c in new for c in '\x00\r\n'):
        raise SystemExit('Password policy or confirmation failed.')
    if input('Replace this web account password? Type RESET: ').strip() != 'RESET':
        raise SystemExit('Cancelled.')
    hashed = helper.hash_password(new)
    with helper.LOCK.open('a') as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        path = helper.configured_accounts()
        old = path.read_text()
        helper.account_hash(old, user)
        stat = path.stat()
        updated = helper.replace_hash(old, user, hashed)
        helper.atomic(path, updated, stat.st_uid, stat.st_gid)
    print('Web account password changed; existing session checks revoke old password sessions. VPN services and SSH passwords were not changed.')


if __name__ == '__main__':
    main()
