#!/usr/bin/env python3
"""
ssl-alias-proxy — TLS reverse proxy for domain aliases.

Listens on SSL_ALIAS_PROXY_PORT (default 8444), terminates TLS using
per-domain alias certificates, and forwards to the app's primary HTTPS
port (localhost:SSL_HTTPS_PORT) via a new TLS connection.

Uses SNI callback to select the correct certificate for each alias domain.
The app continues to serve its primary domain on SSL_HTTPS_PORT with its
own certificate — zero app-side changes required.

Started by ssl-setup after alias certificates are acquired.

Environment variables:
    SSL_ALIAS_PROXY_PORT  — listen port (default: 8444)
    SSL_HTTPS_PORT        — app's primary HTTPS port to forward to (default: 443)
    SSL_DOMAIN            — primary domain (excluded from alias proxy)
    SSL_DOMAIN_ALIASES    — comma-separated alias domains
"""

import os
import ssl
import socket
import sys
import threading
import time
import signal

LISTEN_PORT = int(os.environ.get("SSL_ALIAS_PROXY_PORT", "8444"))
UPSTREAM_PORT = int(os.environ.get("SSL_HTTPS_PORT", "443"))
PRIMARY_DOMAIN = os.environ.get("SSL_DOMAIN", "")
ALIASES_RAW = os.environ.get("SSL_DOMAIN_ALIASES", "")
CERT_BASE = "/etc/letsencrypt/live"
BUFFER_SIZE = 65536
MAX_CONNECTIONS = 200
SHUTDOWN = False


def log(msg):
    print(f"[ssl-alias-proxy] {msg}", flush=True)


def warn(msg):
    print(f"[ssl-alias-proxy] WARNING: {msg}", file=sys.stderr, flush=True)


def parse_aliases():
    """Parse SSL_DOMAIN_ALIASES into a list of domain strings."""
    if not ALIASES_RAW:
        return []
    aliases = []
    for a in ALIASES_RAW.split(","):
        a = a.strip()
        if a and a != PRIMARY_DOMAIN and a not in aliases:
            aliases.append(a)
    return aliases


def build_ssl_context(aliases):
    """Build an SSL context with SNI callback for alias cert selection."""
    # Default context with the first alias cert
    if not aliases:
        return None

    first = aliases[0]
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(
        certfile=f"{CERT_BASE}/{first}/fullchain.pem",
        keyfile=f"{CERT_BASE}/{first}/privkey.pem",
    )

    # Pre-build per-alias contexts for SNI callback
    alias_contexts = {}
    for alias in aliases:
        try:
            actx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            actx.minimum_version = ssl.TLSVersion.TLSv1_2
            actx.load_cert_chain(
                certfile=f"{CERT_BASE}/{alias}/fullchain.pem",
                keyfile=f"{CERT_BASE}/{alias}/privkey.pem",
            )
            alias_contexts[alias] = actx
            log(f"Loaded cert for alias: {alias}")
        except Exception as e:
            warn(f"Failed to load cert for {alias}: {e}")

    def sni_callback(sslsock, server_name, _ctx):
        if server_name in alias_contexts:
            sslsock.context = alias_contexts[server_name]
        else:
            # Reject unknown domains instead of serving wrong cert
            warn(f"Rejecting unknown SNI: {server_name}")
            return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME

    ctx.sni_callback = sni_callback
    return ctx


def forward_data(src, dst, label):
    """Forward data from src socket to dst socket."""
    try:
        src.settimeout(300)  # 5 min timeout to detect dead peers
        while not SHUTDOWN:
            try:
                data = src.recv(BUFFER_SIZE)
            except socket.timeout:
                if SHUTDOWN:
                    break
                continue  # keepalive — retry recv
            if not data:
                break
            dst.sendall(data)
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def handle_client(client_ssl, client_addr, semaphore=None):
    """Handle one alias TLS connection: terminate and forward to app."""
    upstream_ssl = None
    upstream_sock = None
    try:
        # Connect to the app's primary HTTPS port with TLS
        upstream_sock = socket.create_connection(
            ("127.0.0.1", UPSTREAM_PORT), timeout=5
        )
        upstream_ctx = ssl.create_default_context()
        upstream_ctx.check_hostname = False
        upstream_ctx.verify_mode = ssl.CERT_NONE  # local loopback, app's self-managed cert
        try:
            upstream_ssl = upstream_ctx.wrap_socket(upstream_sock)
        except Exception:
            upstream_sock.close()
            upstream_sock = None
            raise

        # Bidirectional forwarding
        t1 = threading.Thread(
            target=forward_data,
            args=(client_ssl, upstream_ssl, "client→app"),
            daemon=True,
        )
        t2 = threading.Thread(
            target=forward_data,
            args=(upstream_ssl, client_ssl, "app→client"),
            daemon=True,
        )
        t1.start()
        t2.start()
        t1.join()
        t2.join()

    except Exception as e:
        if not SHUTDOWN:
            warn(f"Connection from {client_addr}: {e}")
    finally:
        try:
            client_ssl.close()
        except OSError:
            pass
        if upstream_ssl:
            try:
                upstream_ssl.close()
            except OSError:
                pass
        if semaphore:
            semaphore.release()


def reload_certs(server_ctx, aliases):
    """Reload certificates (called after renewal)."""
    log("Reloading alias certificates...")
    alias_contexts = {}
    for alias in aliases:
        try:
            actx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            actx.minimum_version = ssl.TLSVersion.TLSv1_2
            actx.load_cert_chain(
                certfile=f"{CERT_BASE}/{alias}/fullchain.pem",
                keyfile=f"{CERT_BASE}/{alias}/privkey.pem",
            )
            alias_contexts[alias] = actx
            log(f"Reloaded cert for alias: {alias}")
        except Exception as e:
            warn(f"Failed to reload cert for {alias}: {e}")

    def sni_callback(sslsock, server_name, _ctx):
        if server_name in alias_contexts:
            sslsock.context = alias_contexts[server_name]
        else:
            warn(f"Rejecting unknown SNI after reload: {server_name}")
            return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME

    server_ctx.sni_callback = sni_callback


def main():
    global SHUTDOWN

    aliases = parse_aliases()
    if not aliases:
        log("No aliases configured — alias proxy not needed")
        # Sleep forever so supervisord doesn't restart
        while True:
            time.sleep(86400)

    log(f"Starting TLS alias proxy on port {LISTEN_PORT}")
    log(f"Forwarding to app at localhost:{UPSTREAM_PORT}")
    log(f"Aliases: {', '.join(aliases)}")

    ctx = build_ssl_context(aliases)
    if ctx is None:
        log("No valid alias contexts — exiting")
        sys.exit(1)

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.settimeout(5.0)  # accept timeout for shutdown check
    server_sock.bind(("0.0.0.0", LISTEN_PORT))
    server_sock.listen(128)

    log(f"Listening on 0.0.0.0:{LISTEN_PORT} (max {MAX_CONNECTIONS} connections)")
    conn_semaphore = threading.Semaphore(MAX_CONNECTIONS)

    # Write PID for lifecycle management
    with open("/tmp/.ssl-alias-proxy.pid", "w") as f:
        f.write(str(os.getpid()))

    def handle_signal(signum, frame):
        global SHUTDOWN
        SHUTDOWN = True
        log("Shutting down...")

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    # Cert reload check (every 60s, watches /tmp/.ssl-renewal-restart mtime)
    last_reload_check = time.time()
    last_reload_mtime = 0

    while not SHUTDOWN:
        try:
            client_sock, client_addr = server_sock.accept()
        except socket.timeout:
            # Check for cert reload (only if marker file mtime changed)
            now = time.time()
            if now - last_reload_check > 60:
                last_reload_check = now
                try:
                    mtime = os.path.getmtime("/tmp/.ssl-renewal-restart")
                    if mtime > last_reload_mtime:
                        last_reload_mtime = mtime
                        reload_certs(ctx, aliases)
                except FileNotFoundError:
                    pass
            continue
        except OSError:
            if SHUTDOWN:
                break
            raise

        if not conn_semaphore.acquire(timeout=1):
            warn("Max connections reached, rejecting")
            client_sock.close()
            continue

        try:
            client_ssl = ctx.wrap_socket(client_sock, server_side=True)
        except ssl.SSLError:
            client_sock.close()
            conn_semaphore.release()
            continue
        except OSError:
            client_sock.close()
            conn_semaphore.release()
            continue

        t = threading.Thread(
            target=handle_client, args=(client_ssl, client_addr, conn_semaphore),
            daemon=True,
        )
        t.start()

    server_sock.close()
    log("Alias proxy stopped")


if __name__ == "__main__":
    main()
