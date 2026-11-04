"""HTTPS deployment behind the authenticated, loopback-only Caddy gateway."""
import ipaddress, os, re, secrets, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs

ORIGIN = os.environ.get('DECK_PUBLIC_ORIGIN', '').rstrip('/')
GATEWAY = os.environ.get('DECK_GATEWAY_TOKEN', '')
if ORIGIN:
    parsed = urlsplit(ORIGIN)
    if parsed.scheme != 'https' or not re.fullmatch(r'[a-z0-9.-]+(?::[0-9]{1,5})?', parsed.netloc) or not parsed.hostname or parsed.path or parsed.query or parsed.fragment or parsed.username or parsed.password or (parsed.port is not None and not 1 <= parsed.port <= 65535):
        raise ValueError('DECK_PUBLIC_ORIGIN must be a plain HTTPS origin')
    if len(GATEWAY) < 32:
        raise ValueError('Missing private gateway credential')
HOST = urlsplit(ORIGIN).hostname if ORIGIN else ''

def gateway_ok(headers):
    return not ORIGIN or secrets.compare_digest(headers.get('X-Deck-Gateway', ''), GATEWAY)

def origins(port):
    return (ORIGIN,) if ORIGIN else ('http://127.0.0.1:'+str(port), 'http://localhost:'+str(port))

def hosts(port):
    return (urlsplit(ORIGIN).netloc,) if ORIGIN else ('127.0.0.1:'+str(port), 'localhost:'+str(port))

def bridge_supported():
    if not ORIGIN:return True
    try:ipaddress.ip_address(HOST);return False
    except ValueError:return urlsplit(ORIGIN).port in (None,443)

def bridge_host(sid, panel):
    if not bridge_supported():
        raise ValueError('Для встроенных панелей добавьте домен в настройках Server Deck. Прямые ссылки и управление сервисами доступны по IP.')
    if not re.fullmatch(r'[a-z0-9-]+', sid) or panel not in ('lucx', 'mtproxyl'):
        raise ValueError('Invalid panel identity')
    return sid+'-'+panel+'.'+HOST

def policy():
    frames = ('https://*.'+HOST if bridge_supported() else '') if ORIGIN else 'http://127.0.0.1:*'
    return "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-src 'self' "+frames+"; form-action 'self' "+frames+"; frame-ancestors 'none'"

def allowed_domain(domain, servers):
    return bool(ORIGIN) and (domain == HOST or bridge_supported() and any(domain == bridge_host(s['id'], p) for s in servers for p in ('lucx', 'mtproxyl')))

def start_router(servers, manager):
    """Caddy-only certificate permission and already-open bridge routing. Never opens a panel."""
    if not ORIGIN:
        return
    class Router(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self):
            parsed=urlsplit(self.path);query=parse_qs(parsed.query)
            status=403;port=None
            if parsed.path == '/tls-ask':
                domain=query.get('domain', [''])[0]
                status=200 if allowed_domain(domain, servers()) else 403
            elif parsed.path == '/bridge':
                domain=query.get('host', [''])[0]
                m=manager()
                if m and allowed_domain(domain, servers()):
                    with m.lock:
                        b=next((b for b in m.bridges.values() if urlsplit(b.origin).hostname == domain and not b.closed), None)
                    if b: status=200;port=b.httpd.server_port
                    else: status=404
            self.send_response(status)
            if port:self.send_header('X-Deck-Bridge-Port', str(port))
            self.send_header('Content-Length','0');self.send_header('Cache-Control','no-store');self.end_headers()
    httpd=ThreadingHTTPServer(('127.0.0.1',8766),Router)
    threading.Thread(target=httpd.serve_forever,name='private-https-router',daemon=True).start()
    return httpd
