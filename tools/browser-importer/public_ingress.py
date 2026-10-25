"""Pure, opt-in standalone public ingress renderers; no activation hooks.

Return configuration text only: no file reads/writes, DNS, processes or listeners.
The caller owns certificate provisioning, private runtime-directory creation and
syntax/live validation. In particular backend_ca must contain public CA material
only; rendering validates its path, never opens or inspects its contents.
These configs do not include or alter the existing private package frontend.
"""
import ipaddress
import re

from package_service import nginx_path, parse_origin


def _port(port):
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('Invalid ingress port.')
    if port in (8443, 8080, 8081, 12321):
        raise ValueError('Reserved service port.')


def _address(value):
    if not isinstance(value, str) or str(ipaddress.IPv4Address(value)) != value:
        raise ValueError('A canonical IPv4 address is required.')


def _origin(value):
    if not isinstance(value, str):
        raise ValueError('An explicit public origin is required.')
    match = re.fullmatch(r'https://[a-z0-9.-]+(?::([1-9][0-9]{0,4}))?', value)
    if not match or match[1] == '443':
        raise ValueError('Invalid public origin.')
    port = int(match[1]) if match[1] else 443
    _port(port)
    return parse_origin(value, port), port


def _tls_name(value):
    if not isinstance(value, str) or not re.fullmatch(r'[a-z0-9.-]+', value):
        raise ValueError('Invalid TLS name.')
    return parse_origin('https://' + value, 443).host


def render_backend(*, public_origin, tls_name, bind, port, ship_port, certificate,
                   key, runtime_dir):
    """Dedicated TLS endpoint to the fixed normal ship loopback HTTP listener."""
    origin, edge_port = _origin(public_origin)
    _port(port)
    _address(bind)
    tls_name = _tls_name(tls_name)
    if port == edge_port or type(ship_port) is not int or ship_port != 8081:
        raise ValueError('Dedicated backend and fixed ship port required.')
    authority = origin.authority
    return _render(public_origin=public_origin, tls_name=tls_name, bind=bind, port=port,
                   certificate=certificate, key=key, runtime_dir=runtime_dir,
                   upstream=f'http://127.0.0.1:{ship_port}', extra='', authority=authority)


def _render(*, public_origin, tls_name, bind, port, certificate, key, runtime_dir,
            upstream, extra, authority):
    cert, private_key = map(nginx_path, (certificate, key))
    nginx_path(runtime_dir)
    runtime_dir = str(runtime_dir)
    origin, public_port = _origin(public_origin)
    # Nginx selects a vhost again from HTTP Host after the TLS SNI selection.
    # Both names must select this one ship-only vhost; the explicit SNI and Host
    # guards below still require their distinct, exact configured values.
    server_names = tls_name if tls_name == origin.host else tls_name + ' ' + origin.host
    # Canonical origins contain no regex metacharacters except DNS dots.
    origin_pattern = public_origin.replace('.', '[.]')
    return f'''daemon off;
worker_processes 1;
pid {nginx_path(runtime_dir + '/nginx.pid')};
error_log /dev/null crit;
events {{ worker_connections 128; }}
http {{
    access_log off;
    server_tokens off;
    client_body_temp_path {nginx_path(runtime_dir + '/body')};
    proxy_temp_path {nginx_path(runtime_dir + '/proxy')};
    fastcgi_temp_path {nginx_path(runtime_dir + '/fastcgi')};
    uwsgi_temp_path {nginx_path(runtime_dir + '/uwsgi')};
    scgi_temp_path {nginx_path(runtime_dir + '/scgi')};
    client_header_timeout 15s;
    client_body_timeout 30s;
    send_timeout 30s;
    keepalive_timeout 30s;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_tickets off;
    map $http_upgrade $connection_upgrade {{
        default upgrade;
        "" close;
    }}
    map $http_origin $public_origin_state {{
        default denied;
        "" absent;
        ~^{origin_pattern}$ exact;
    }}
    map "$public_origin_state:$request_method" $public_origin_allowed {{
        default 0;
        ~^exact: 1;
        ~^absent:GET$ 1;
        ~^absent:HEAD$ 1;
    }}
    server {{
        listen {bind}:{port} ssl default_server;
        server_name _;
        ssl_reject_handshake on;
        return 421;
    }}
    server {{
        listen {bind}:{port} ssl;
        server_name {server_names};
        ssl_certificate {cert};
        ssl_certificate_key {private_key};
        if ($ssl_server_name != "{tls_name}") {{ return 421; }}
        if ($http_host != "{authority}") {{ return 421; }}
        if ($host != "{origin.host}") {{ return 421; }}
        if ($public_origin_allowed = 0) {{ return 403; }}
        client_max_body_size 2m;
        location / {{
            proxy_pass {upstream};
            {extra}
            proxy_cookie_domain ~.* {origin.host};
            proxy_cookie_flags ~^urbauth- secure;
            proxy_http_version 1.1;
            proxy_request_buffering off;
            proxy_buffering off;
            proxy_max_temp_file_size 0;
            proxy_connect_timeout 5s;
            proxy_read_timeout 3600s;
            proxy_send_timeout 60s;
            proxy_next_upstream off;
            proxy_set_header Host "{authority}";
            proxy_set_header Origin $http_origin;
            proxy_set_header Forwarded 'proto=https;host="{authority}"';
            proxy_set_header X-Forwarded-For $remote_addr;
            proxy_set_header X-Forwarded-Host "{authority}";
            proxy_set_header X-Forwarded-Proto https;
            proxy_set_header X-Forwarded-Port {public_port};
            proxy_set_header X-Forwarded-Server "";
            proxy_set_header X-Forwarded-Prefix "";
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection $connection_upgrade;
        }}
    }}
}}
'''


def render_edge(*, public_origin, bind, port, backend_address, backend_port,
                backend_tls_name, certificate, key, backend_ca, runtime_dir):
    """Public TLS endpoint to one fixed IPv4 backend with verified TLS/SNI."""
    origin, edge_port = _origin(public_origin)
    _port(port)
    _port(backend_port)
    _address(bind)
    _address(backend_address)
    backend_tls_name = _tls_name(backend_tls_name)
    if port != edge_port or backend_port == port:
        raise ValueError('Distinct backend and matching public listener required.')
    authority, host = origin.authority, origin.host
    extra = f'''proxy_ssl_verify on;
            proxy_ssl_verify_depth 1;
            proxy_ssl_server_name on;
            proxy_ssl_name {backend_tls_name};
            proxy_ssl_trusted_certificate {nginx_path(backend_ca)};
            proxy_ssl_protocols TLSv1.2 TLSv1.3;'''
    return _render(public_origin=public_origin, tls_name=host, bind=bind, port=port,
                   certificate=certificate, key=key, runtime_dir=runtime_dir,
                   upstream=f'https://{backend_address}:{backend_port}',
                   extra=extra, authority=authority)
