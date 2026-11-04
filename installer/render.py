"""Pure configuration rendering for the public, fresh-host installer."""
import re
import ipaddress

DOMAIN = re.compile(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}')
SECRET = re.compile(r'[A-Za-z0-9_-]{32,128}')


def validate(domain, gateway='', auth_gateway=''):
    if not DOMAIN.fullmatch(domain):
        raise ValueError('Invalid domain')
    if gateway and not SECRET.fullmatch(gateway):
        raise ValueError('Invalid gateway')
    if auth_gateway and not SECRET.fullmatch(auth_gateway):
        raise ValueError('Invalid auth gateway')


def bootstrap_caddy(domain):
    validate(domain)
    return '''http://DOMAIN {
    @challenge path /.well-known/acme-challenge/*
    handle @challenge {
        root * /var/lib/server-deck-acme
        file_server
    }
    handle {
        respond 404
    }
}
'''.replace('DOMAIN', domain)


def caddy_config(domain, gateway, auth_gateway, public_paths, port=443, ip_mode=False):
    if ip_mode:
        address = ipaddress.ip_address(domain)
        if address.version != 4 or not address.is_global:
            raise ValueError('Public IPv4 required')
        if type(port) is not int or not 1024 <= port <= 65535:
            raise ValueError('Invalid HTTPS port')
        validate('deck.example.org', gateway, auth_gateway)
    else:
        validate(domain, gateway, auth_gateway)
        if port != 443:
            raise ValueError('Domain mode uses HTTPS port 443')
    if not gateway or not auth_gateway:
        raise ValueError('Missing private gateway secrets')
    if not public_paths or any(not re.fullmatch(r'/[A-Za-z0-9_./-]+', p) or '..' in p for p in public_paths):
        raise ValueError('Invalid public asset path')
    content = '''{
    on_demand_tls {
        ask http://127.0.0.1:8766/tls-ask
    }
}
http://DOMAIN {
    @challenge path /.well-known/acme-challenge/*
    handle @challenge {
        root * /var/lib/server-deck-acme
        file_server
    }
    handle {
        redir https://DOMAIN{uri} 308
    }
}
https://DOMAIN {
    tls /etc/caddy/server-deck-tls/fullchain.pem /etc/caddy/server-deck-tls/privkey.pem
    encode gzip
    header Strict-Transport-Security "max-age=31536000"
    header -Server
    @deckPublic path PUBLIC_PATHS
    handle @deckPublic {
        root * /opt/server-deck-web
        header {
            Cache-Control "no-store"
            X-Content-Type-Options nosniff
            Referrer-Policy no-referrer
            X-Frame-Options DENY
            Content-Security-Policy "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; worker-src 'self'; manifest-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        }
        @deckManifest path /manifest.webmanifest
        header @deckManifest Content-Type application/manifest+json
        @deckWorker path /pwa-sw.js
        header @deckWorker Service-Worker-Allowed /
        file_server
    }
    @deckAuth path /auth/login /auth/logout /auth/session /auth/setup
    handle @deckAuth {
        reverse_proxy 127.0.0.1:8768 {
            header_up X-Deck-Auth AUTH_SECRET
            header_up X-Deck-Client-IP {remote_host}
            header_up -Authorization
        }
    }
    handle {
        route {
            request_header -X-Deck-User
            request_header -X_Deck_User
            forward_auth 127.0.0.1:8768 {
                uri /check
                copy_headers X-Deck-User
                header_up X-Deck-Auth AUTH_SECRET
                header_up X-Deck-Client-IP {remote_host}
                header_up -Authorization
            }
            reverse_proxy 127.0.0.1:8765 {
                header_up X-Deck-Gateway BACKEND_SECRET
                header_up -X-Deck-Auth
                header_up -Authorization
                header_up -Cookie
                header_up -X-Deck-Bridge-Port
            }
        }
    }
}
https:// {
    tls {
        on_demand
    }
    header Strict-Transport-Security "max-age=31536000"
    header -Server
    route {
        request_header -X-Deck-Bridge-Port
        request_header -X_Deck_Bridge_Port
        forward_auth 127.0.0.1:8766 {
            uri /bridge?host={host}
            copy_headers X-Deck-Bridge-Port
            header_up -Authorization
            header_up -Cookie
            header_up -X-Deck-Gateway
        }
        reverse_proxy 127.0.0.1:{http.request.header.X-Deck-Bridge-Port} {
            header_up Host 127.0.0.1:{http.request.header.X-Deck-Bridge-Port}
            header_up X-Deck-Gateway BACKEND_SECRET
            header_up -Authorization
            header_up -X-Deck-Bridge-Port
        }
    }
}
'''.replace('DOMAIN', domain).replace('PUBLIC_PATHS', ' '.join(sorted(set(public_paths)))).replace('AUTH_SECRET', auth_gateway).replace('BACKEND_SECRET', gateway)
    if ip_mode:
        start = content.index('https://' + domain + ' {')
        finish = content.index('\nhttps:// {', start)
        content = content[start:finish].replace('https://' + domain + ' {', 'https://' + domain + ':' + str(port) + ' {', 1)
        content = content.replace('    header Strict-Transport-Security "max-age=31536000"\n', '')
        content = '{\n    auto_https disable_redirects\n}\n' + content
    return content


APP_UNIT = '''[Unit]
Description=Server Deck private control plane
Wants=network-online.target
After=network-online.target
[Service]
Type=simple
User=serverdeck
Group=serverdeck
Environment=HOME=/var/lib/serverdeck
Environment=PYTHONDONTWRITEBYTECODE=1
Environment=PYTHONUNBUFFERED=1
EnvironmentFile=/etc/server-deck/server.env
WorkingDirectory=/opt/server-deck
ExecStart=/usr/bin/python3 -u /opt/server-deck/server.py --port 8765
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
ReadWritePaths=/opt/server-deck /var/lib/serverdeck
[Install]
WantedBy=multi-user.target
'''

AUTH_UNIT = '''[Unit]
Description=Server Deck web sign-in
After=network.target
[Service]
Type=simple
User=caddy
Group=caddy
Environment=PYTHONDONTWRITEBYTECODE=1
EnvironmentFile=/etc/server-deck/auth.env
ExecStart=/usr/bin/python3 -I /usr/local/lib/server-deck/web_auth.py
Restart=on-failure
RestartSec=3
UMask=0077
StateDirectory=server-deck-auth
StateDirectoryMode=0700
ReadWritePaths=/etc/caddy/server-deck-accounts.d /var/lib/server-deck-auth
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
[Install]
WantedBy=multi-user.target
'''

RENEW_SERVICE = '''[Unit]
Description=Renew Server Deck TLS certificate with Certbot
[Service]
Type=oneshot
ExecStart=/usr/bin/certbot renew --quiet
'''

RENEW_TIMER = '''[Unit]
Description=Daily Certbot renewal check for Server Deck
[Timer]
OnCalendar=*-*-* 03,15:00:00
RandomizedDelaySec=3600
Persistent=true
[Install]
WantedBy=timers.target
'''


def renew_hook(domain):
    validate(domain)
    return """#!/usr/bin/env python3
import fcntl, grp, json, os, pathlib, re, subprocess, sys
metadata_path = pathlib.Path('/etc/server-deck/deployment.json')
root = pathlib.Path('/etc/caddy/server-deck-tls')

def selected_lineage():
    metadata = json.loads(metadata_path.read_text())
    if metadata.get('mode') != 'domain':
        return None, metadata
    name = metadata.get('certificateName', 'server-deck')
    if not isinstance(name, str) or not re.fullmatch(r'server-deck(?:-domain-[a-f0-9]{8})?', name):
        raise ValueError('Invalid managed certificate name')
    lineage = pathlib.Path('/etc/letsencrypt/live') / name
    return (lineage if os.environ.get('RENEWED_LINEAGE') == str(lineage) else None), metadata

def run(argv):
    return subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True).stdout

def stage(path, data, gid):
    if path.exists() or path.is_symlink():
        raise ValueError('Stale TLS preparation file requires review')
    fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o640)
    with os.fdopen(fd, 'wb') as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    os.chown(path, 0, gid)

# Ignore issuance for a not-yet-selected domain BEFORE the mutation lock: the
# explicit domain switch itself holds that lock while Certbot obtains a cert.
lineage, _ = selected_lineage()
if lineage is None:
    raise SystemExit(0)
mutation = pathlib.Path('/var/lib/server-deck')
mutation.mkdir(mode=0o700, exist_ok=True)
with (mutation / 'mutation.lock').open('a') as lock:
    fcntl.flock(lock, fcntl.LOCK_EX)
    lineage, metadata = selected_lineage()
    if lineage is None:
        raise SystemExit(0)
    gid = grp.getgrnam('caddy').gr_gid
    names = ('fullchain.pem', 'privkey.pem')
    old = {name: (root / name).read_bytes() for name in names}
    prepared = {name: root / (name + '.renew-new') for name in names}
    changed = False
    created = []
    try:
        for name in names:
            stage(prepared[name], (lineage / name).read_bytes(), gid)
            created.append(prepared[name])
        cert = str(prepared['fullchain.pem'])
        key = str(prepared['privkey.pem'])
        run(['/usr/bin/openssl', 'x509', '-in', cert, '-noout', '-checkend', '86400'])
        run(['/usr/bin/openssl', 'x509', '-in', cert, '-noout', '-checkhost', metadata['host']])
        certificate_key = run(['/usr/bin/openssl', 'x509', '-in', cert, '-pubkey', '-noout']).strip()
        private_public_key = run(['/usr/bin/openssl', 'pkey', '-in', key, '-pubout']).strip()
        if certificate_key != private_public_key:
            raise ValueError('Certificate and private key do not match')
        changed = True
        for name in names:
            os.replace(prepared[name], root / name)
        run(['/usr/bin/caddy', 'validate', '--config', '/etc/caddy/Caddyfile', '--adapter', 'caddyfile'])
        run(['/usr/bin/systemctl', 'reload', 'caddy.service'])
    except Exception:
        if changed:
            for name in names:
                restore = root / (name + '.renew-restore')
                stage(restore, old[name], gid)
                os.replace(restore, root / name)
            try:
                run(['/usr/bin/caddy', 'validate', '--config', '/etc/caddy/Caddyfile', '--adapter', 'caddyfile'])
                run(['/usr/bin/systemctl', 'reload', 'caddy.service'])
            except Exception:
                raise SystemExit('TLS renewal failed and restore reload needs administrator review')
        raise SystemExit('TLS renewal was not applied; previous certificate preserved')
    finally:
        for path in created:
            if path.is_file() and not path.is_symlink():
                path.unlink()
"""


# Public files only; runtime handlers remain behind session authentication.
PUBLIC_PATHS = ['/install', '/install/', '/install/index.html', '/login', '/login/', '/login/index.html', '/manifest.webmanifest', '/pwa-sw.js', '/pwa/icon-192.png', '/pwa/icon-512.png', '/pwa/icon-maskable-512.png', '/pwa/icon.svg', '/pwa/install.css', '/pwa/install.js', '/pwa/login.css', '/pwa/login.js']
