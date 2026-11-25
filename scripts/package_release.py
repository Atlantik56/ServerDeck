#!/usr/bin/env python3
"""Build the public runtime release asset from one committed Git tree."""
import argparse
import hashlib
import pathlib
import subprocess
import sys


REPOSITORY = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY / 'backend'))

from panel_release import MAX_FILE, REVISION, ReleaseError, pack_bundle, selected_path, version_key


def git(repository, *args):
    return subprocess.check_output(['git', '-C', str(repository), *args], stdin=subprocess.DEVNULL)


def committed_runtime(repository, revision):
    commit = git(repository, 'rev-parse', '--verify', '--end-of-options', revision + '^{commit}').decode('ascii').strip()
    if not REVISION.fullmatch(commit):
        raise ReleaseError('Git не вернул полный идентификатор коммита.')
    entries = git(repository, 'ls-tree', '-lrz', '--full-tree', commit, '--', 'VERSION', 'backend', 'frontend')
    files = {}
    version = None
    for entry in entries.split(b'\x00'):
        if not entry:
            continue
        metadata, _, filename = entry.partition(b'\t')
        path = filename.decode('utf-8')
        if path != 'VERSION' and not selected_path(path):
            continue
        mode, kind, oid, size = metadata.decode('ascii').split()
        if kind != 'blob' or mode not in ('100644', '100755') or int(size) > MAX_FILE:
            raise ReleaseError('В коммите обнаружен неподдерживаемый файл пакета.')
        contents = git(repository, 'cat-file', 'blob', oid)
        if path == 'VERSION':
            version = contents.decode('ascii').strip()
            version_key(version)
        else:
            files[path] = contents
    if version is None:
        raise ReleaseError('В коммите отсутствует VERSION.')
    return version, commit, files


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--revision', required=True, help='Committed Git tag, ref or SHA')
    parser.add_argument('--output', type=pathlib.Path, required=True, help='New archive path')
    args = parser.parse_args(argv)
    try:
        version, revision, files = committed_runtime(REPOSITORY, args.revision)
        bundle = pack_bundle(version, revision, files)
        with args.output.open('xb') as output:
            output.write(bundle)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f'{error}\n')
    print(f'Server Deck {version} ({revision})')
    print(f'{len(files)} files, {len(bundle)} bytes, SHA-256 {hashlib.sha256(bundle).hexdigest()}')


if __name__ == '__main__':
    main()
