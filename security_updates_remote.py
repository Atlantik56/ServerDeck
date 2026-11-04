"""Fixed read-only Ubuntu kernel-package facts for the CVE release watcher.

This adapter accepts no request, invokes no shell and never changes packages,
services or boot state. Package evidence identifies the source build; it is not
a byte-for-byte attestation of the running kernel or a Livepatch assessment.
"""
import json
import os
import pathlib
import re
import subprocess
import time


MAX_OUTPUT = 1024 * 1024
MAX_PACKAGES = 1024
PACKAGE = re.compile(r'[a-z0-9][a-z0-9+.\-]{0,199}(?::[a-z0-9][a-z0-9\-]{0,39})?')
SOURCE = re.compile(r'[a-z0-9][a-z0-9+.\-]{0,199}')
VERSION = re.compile(r'[0-9][A-Za-z0-9.+:~\-]{0,199}')
KERNEL = re.compile(r'[A-Za-z0-9][A-Za-z0-9._+~\-]{0,119}')
CODENAME = re.compile(r'[a-z][a-z0-9\-]{0,39}')
BOOT_ID = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
PACKAGE_FORMAT = '${binary:Package}\t${Version}\t${source:Package}\t${source:Version}\t${db:Status-Status}\n'


def read_small(path, limit=16384):
    with pathlib.Path(path).open('r', encoding='utf-8', errors='strict') as handle:
        value = handle.read(limit + 1)
    if len(value) > limit:
        raise ValueError('oversize')
    return value


def command(args, timeout=10):
    """Only callers below supply fixed argv; no stderr is returned to the UI."""
    result = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True,
                            text=True, timeout=timeout,
                            env=dict(os.environ, LC_ALL='C'))
    if not isinstance(result.stdout, str) or len(result.stdout) > MAX_OUTPUT:
        raise ValueError('invalid output')
    return result.returncode, result.stdout


def parse_packages(output):
    if not isinstance(output, str) or len(output) > MAX_OUTPUT:
        raise ValueError('invalid packages')
    rows = []
    seen = set()
    for line in output.splitlines():
        fields = line.split('\t')
        if len(fields) != 5:
            raise ValueError('invalid package row')
        package, version, source, source_version, status = fields
        if status != 'installed':
            continue
        if (not PACKAGE.fullmatch(package) or not VERSION.fullmatch(version) or
                not SOURCE.fullmatch(source) or not VERSION.fullmatch(source_version)):
            raise ValueError('invalid package facts')
        base = package.split(':', 1)[0]
        if not base.startswith(('linux-image-', 'linux-modules-')):
            raise ValueError('unexpected package')
        if package in seen:
            raise ValueError('duplicate package')
        seen.add(package)
        rows.append({'package': package, 'version': version,
                     'source': source, 'sourceVersion': source_version})
        if len(rows) > MAX_PACKAGES:
            raise ValueError('too many packages')
    return rows


def base_name(row):
    return row['package'].split(':', 1)[0]


def os_release():
    values = {}
    for line in read_small('/etc/os-release').splitlines():
        key, separator, value = line.partition('=')
        if separator and key in ('ID', 'VERSION_CODENAME'):
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                value = value[1:-1]
            values[key] = value
    identifier = values.get('ID', '')
    codename = values.get('VERSION_CODENAME', '')
    if not SOURCE.fullmatch(identifier) or not CODENAME.fullmatch(codename):
        raise ValueError('invalid operating system')
    return {'id': identifier, 'codename': codename}


def boot_id():
    value = read_small('/proc/sys/kernel/random/boot_id', 80).strip()
    if not BOOT_ID.fullmatch(value):
        raise ValueError('invalid boot identity')
    return value


def version_signature():
    try:
        value = read_small('/proc/version_signature', 512).strip()
    except (OSError, ValueError):
        return ''
    return value if len(value) <= 500 and all(32 <= ord(char) <= 126 for char in value) else ''


def installed_kernels(packages):
    """Keep complete image+module pairs, without guessing signed source names."""
    by_name = {}
    for row in packages:
        by_name.setdefault(base_name(row), []).append(row)
    results = []
    for name, modules in sorted(by_name.items()):
        if not name.startswith('linux-modules-') or name.startswith('linux-modules-extra-'):
            continue
        release = name[len('linux-modules-'):]
        if not KERNEL.fullmatch(release) or len(modules) != 1:
            continue
        images = by_name.get('linux-image-' + release, []) + by_name.get('linux-image-unsigned-' + release, [])
        if len(images) != 1:
            continue
        module, image = modules[0], images[0]
        results.append({'kernel': release, 'sourcePackage': module['source'],
                        'sourceVersion': module['sourceVersion'],
                        'imagePackage': image['package'], 'imageVersion': image['version'],
                        'modulesPackage': module['package']})
    return results


def collect():
    result = {'ok': False, 'checkedAt': time.time(), 'os': {}, 'kernel': '',
              'bootId': None, 'sourcePackage': None, 'installedVersion': None,
              'runningImage': None, 'runningModules': None, 'installedKernels': [],
              'rebootRequired': False, 'versionSignature': ''}
    try:
        result['os'] = os_release()
        release = os.uname().release
        if not isinstance(release, str) or not KERNEL.fullmatch(release):
            raise ValueError('invalid kernel identity')
        result['kernel'] = release
        result['versionSignature'] = version_signature()
        before = boot_id()
        result['bootId'] = before
        if result['os']['id'] != 'ubuntu':
            result.update(unsupported=True, error='Поддерживается сопоставление пакетов ядра Ubuntu.')
            return result
        code, output = command(['dpkg-query', '-W', '-f=' + PACKAGE_FORMAT,
                                'linux-image*', 'linux-modules*'])
        if code != 0:
            raise ValueError('package query incomplete')
        packages = parse_packages(output)
        modules = [row for row in packages if base_name(row) == 'linux-modules-' + release]
        images = [row for row in packages if base_name(row) in
                  ('linux-image-' + release, 'linux-image-unsigned-' + release)]
        if len(modules) != 1 or len(images) != 1:
            raise ValueError('unowned or ambiguous running kernel')
        module, image = modules[0], images[0]
        # Signed images commonly have source linux-signed; the exact matching
        # modules package, rather than a string rewrite, identifies linux/HWE/etc.
        if not module['source'].startswith('linux'):
            raise ValueError('unexpected kernel source')
        result.update(sourcePackage=module['source'], installedVersion=module['sourceVersion'],
                      runningImage=image, runningModules=module,
                      installedKernels=[row for row in installed_kernels(packages)
                                        if pathlib.Path('/boot/vmlinuz-' + row['kernel']).is_file()],
                      rebootRequired=pathlib.Path('/var/run/reboot-required').is_file())
        if boot_id() != before or os.uname().release != release:
            raise ValueError('kernel changed during measurement')
        result.update(ok=True, error='')
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        result['error'] = 'Не удалось подтвердить исходный пакет запущенного ядра Ubuntu.'
    return result


def main():
    print(json.dumps(collect(), ensure_ascii=False, separators=(',', ':')))


if __name__ == '__main__':
    main()
