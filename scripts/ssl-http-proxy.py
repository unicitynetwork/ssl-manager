#!/usr/bin/env python3
"""
ssl-http-proxy: HTTP reverse proxy for ssl-manager.

Listens on port 80 and routes requests:
  /.well-known/acme-challenge/*  -> serve files from webroot directory
  /_ssl/health                   -> JSON certificate status
  /_ssl/nonce/*                  -> nonce store (GET/POST/DELETE)
  /*                             -> reverse proxy to upstream app

Configuration via CLI args and environment variables.
"""

import argparse
import http.client
import http.server
import json
import os
import socket
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------

# Thread-safe nonce store
_nonce_lock = threading.Lock()
_nonces: dict[str, float] = {}  # nonce -> creation timestamp

# Configuration (set in main, read by handler)
_config: dict = {}

# Limits
MAX_PROXY_BODY = int(os.environ.get("PROXY_MAX_BODY_SIZE", 10 * 1024 * 1024))
MAX_ACME_BODY = 1024
CONNECT_TIMEOUT = 5
READ_TIMEOUT = 30

# Reserved ports that APP_HTTP_PORT must not use
RESERVED_PORTS = {80, 8404}


# ---------------------------------------------------------------------------
# Certificate inspection
# ---------------------------------------------------------------------------

def _get_cert_info(cert_dir: str) -> dict:
    """Read certificate expiry from fullchain.pem in cert_dir."""
    info = {
        "domain": os.environ.get("SSL_DOMAIN", ""),
        "cert_expires": None,
        "days_remaining": None,
    }

    if not cert_dir:
        return info

    cert_file = os.path.join(cert_dir, "fullchain.pem")
    if not os.path.isfile(cert_file):
        return info

    try:
        result = subprocess.run(
            ["openssl", "x509", "-enddate", "-noout", "-in", cert_file],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            # Output: notAfter=Jun 28 12:00:00 2026 GMT
            date_str = result.stdout.strip().split("=", 1)[1]
            # Parse the date
            expiry = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
            expiry = expiry.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            delta = expiry - now
            info["cert_expires"] = expiry.strftime("%Y-%m-%dT%H:%M:%SZ")
            info["days_remaining"] = max(0, delta.days)
    except Exception:
        pass

    return info


def _check_upstream_reachable(host: str, port: int) -> bool:
    """Check if upstream is reachable with a quick TCP connect."""
    if port == 0:
        return False
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except (OSError, socket.timeout):
        return False


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------

class ProxyHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler implementing reverse proxy and ssl-manager paths."""

    # Suppress default request logging (too noisy for health checks)
    def log_message(self, format, *args):
        pass

    def _parse_upstream(self) -> tuple[str, int]:
        """Parse upstream host:port from config."""
        upstream = _config.get("upstream", "127.0.0.1:0")
        parts = upstream.rsplit(":", 1)
        host = parts[0]
        port = int(parts[1]) if len(parts) > 1 else 0
        return host, port

    def _send_json(self, code: int, data: dict):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, code: int, text: str):
        body = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_error_json(self, code: int, message: str):
        self._send_json(code, {"error": message})

    # -- ACME challenge handling --

    def _serve_acme_challenge(self):
        """Serve ACME challenge files from the webroot."""
        webroot = _config.get("webroot", "/var/www/acme-challenge")
        # self.path is e.g. /.well-known/acme-challenge/TOKEN
        # Resolve against webroot, prevent directory traversal
        rel_path = self.path.lstrip("/")
        file_path = Path(webroot) / rel_path

        # Prevent directory traversal
        try:
            file_path = file_path.resolve()
            webroot_resolved = Path(webroot).resolve()
            if not str(file_path).startswith(str(webroot_resolved) + os.sep):
                self._send_text(403, "Forbidden")
                return
        except (ValueError, OSError):
            self._send_text(403, "Forbidden")
            return

        if file_path.is_file():
            try:
                content = file_path.read_bytes()
                if len(content) > MAX_ACME_BODY:
                    self._send_text(413, "ACME challenge file too large")
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
            except OSError:
                self._send_text(500, "Error reading challenge file")
        else:
            self._send_text(404, "Challenge not found")

    # -- SSL health endpoint --

    def _serve_health(self):
        """Return JSON with certificate and upstream status."""
        cert_dir = _config.get("cert_dir", "")
        cert_info = _get_cert_info(cert_dir)
        upstream_host, upstream_port = self._parse_upstream()

        upstream_label = f"{upstream_host}:{upstream_port}"
        if upstream_port == 0:
            upstream_label += " (disabled)"

        reachable = _check_upstream_reachable(upstream_host, upstream_port)

        health = {
            "status": "ok",
            "domain": cert_info["domain"],
            "cert_expires": cert_info["cert_expires"],
            "days_remaining": cert_info["days_remaining"],
            "app_upstream": upstream_label,
            "app_reachable": reachable,
        }
        self._send_json(200, health)

    # -- Nonce endpoints --

    def _handle_nonce_get(self, nonce: str):
        """GET /_ssl/nonce/{nonce} -> 200 with raw nonce text if exists, 404 if not."""
        with _nonce_lock:
            if nonce in _nonces:
                self._send_text(200, nonce)
            else:
                self.send_error(404, "Nonce not found")

    def _handle_nonce_post(self, nonce: str):
        """POST /_ssl/nonce/{nonce} -> store nonce, return 201."""
        with _nonce_lock:
            _nonces[nonce] = time.time()
        self._send_json(201, {"nonce": nonce, "status": "stored"})

    def _handle_nonce_delete(self, nonce: str):
        """DELETE /_ssl/nonce/{nonce} -> remove nonce, return 200 or 404."""
        with _nonce_lock:
            if nonce in _nonces:
                del _nonces[nonce]
                self._send_json(200, {"nonce": nonce, "status": "deleted"})
            else:
                self._send_error_json(404, "Nonce not found")

    # -- Reverse proxy --

    def _proxy_request(self):
        """Forward request to upstream application."""
        upstream_host, upstream_port = self._parse_upstream()

        if upstream_port == 0:
            self._send_error_json(404, "No upstream configured")
            return

        # Read request body if present
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > MAX_PROXY_BODY:
            self._send_text(413, "Request body too large")
            return

        body = self.rfile.read(content_length) if content_length > 0 else None

        # Build forwarded headers
        forwarded_headers = {}
        for key, value in self.headers.items():
            # Skip hop-by-hop headers
            lower = key.lower()
            if lower in (
                "connection",
                "keep-alive",
                "transfer-encoding",
                "te",
                "trailer",
                "upgrade",
                "proxy-authorization",
                "proxy-authenticate",
            ):
                continue
            forwarded_headers[key] = value

        # Add/update forwarding headers
        client_ip = self.client_address[0]
        existing_xff = self.headers.get("X-Forwarded-For", "")
        if existing_xff:
            forwarded_headers["X-Forwarded-For"] = f"{existing_xff}, {client_ip}"
        else:
            forwarded_headers["X-Forwarded-For"] = client_ip

        forwarded_headers["X-Forwarded-Host"] = self.headers.get(
            "Host", f"localhost:{_config.get('port', 80)}"
        )
        forwarded_headers["X-Forwarded-Proto"] = "http"

        try:
            conn = http.client.HTTPConnection(
                upstream_host,
                upstream_port,
                timeout=READ_TIMEOUT,
            )
            conn.timeout = CONNECT_TIMEOUT
            conn.connect()
            # Reset timeout for reads after successful connect
            conn.sock.settimeout(READ_TIMEOUT)

            conn.request(
                self.command,
                self.path,
                body=body,
                headers=forwarded_headers,
            )
            resp = conn.getresponse()

            # Forward response
            self.send_response(resp.status)
            # Forward response headers (skip hop-by-hop)
            hop_by_hop = {
                "connection",
                "keep-alive",
                "transfer-encoding",
                "te",
                "trailer",
                "upgrade",
            }
            for key, value in resp.getheaders():
                if key.lower() not in hop_by_hop:
                    self.send_header(key, value)
            self.end_headers()

            # Stream response body
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                self.wfile.write(chunk)

            conn.close()

        except socket.timeout:
            self._send_error_json(504, "Gateway Timeout")
        except (ConnectionRefusedError, ConnectionResetError, OSError):
            self._send_error_json(502, "Bad Gateway")

    # -- Routing --

    def _route(self):
        """Route the request to the appropriate handler."""
        path = self.path

        # ACME challenge
        if path.startswith("/.well-known/acme-challenge/"):
            self._serve_acme_challenge()
            return

        # SSL health
        if path == "/_ssl/health":
            self._serve_health()
            return

        # Nonce endpoints
        if path.startswith("/_ssl/nonce/"):
            nonce = path[len("/_ssl/nonce/"):]
            # Strip query string
            if "?" in nonce:
                nonce = nonce.split("?", 1)[0]
            if not nonce:
                self._send_error_json(400, "Missing nonce")
                return
            if self.command == "GET":
                self._handle_nonce_get(nonce)
            elif self.command == "POST":
                self._handle_nonce_post(nonce)
            elif self.command == "DELETE":
                self._handle_nonce_delete(nonce)
            else:
                self._send_text(405, "Method Not Allowed")
            return

        # Everything else -> proxy
        self._proxy_request()

    def do_GET(self):
        self._route()

    def do_POST(self):
        self._route()

    def do_PUT(self):
        self._route()

    def do_DELETE(self):
        self._route()

    def do_PATCH(self):
        self._route()

    def do_HEAD(self):
        self._route()

    def do_OPTIONS(self):
        self._route()


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

class ThreadingHTTPServer(http.server.ThreadingHTTPServer):
    """ThreadingHTTPServer with SO_REUSEADDR."""

    allow_reuse_address = True
    daemon_threads = True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="ssl-manager HTTP reverse proxy"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("PROXY_PORT", "80")),
        help="Listen port (default: $PROXY_PORT or 80)",
    )
    parser.add_argument(
        "--webroot",
        type=str,
        default=os.environ.get("WEBROOT", "/var/www/acme-challenge"),
        help="ACME challenge webroot directory (default: $WEBROOT or /var/www/acme-challenge)",
    )
    parser.add_argument(
        "--upstream",
        type=str,
        default=os.environ.get(
            "UPSTREAM",
            f"127.0.0.1:{os.environ.get('APP_HTTP_PORT', '0')}",
        ),
        help="Upstream host:port (default: 127.0.0.1:$APP_HTTP_PORT or 127.0.0.1:0)",
    )
    parser.add_argument(
        "--cert-dir",
        type=str,
        default=os.environ.get("CERT_DIR", ""),
        help="Certificate directory (default: computed from $SSL_DOMAIN)",
    )
    return parser.parse_args()


def main():
    global _config

    args = parse_args()

    # Compute cert-dir from SSL_DOMAIN if not provided
    cert_dir = args.cert_dir
    if not cert_dir:
        ssl_domain = os.environ.get("SSL_DOMAIN", "")
        if ssl_domain:
            cert_dir = f"/etc/letsencrypt/live/{ssl_domain}"

    # Parse upstream port for validation
    upstream_parts = args.upstream.rsplit(":", 1)
    upstream_port = int(upstream_parts[1]) if len(upstream_parts) > 1 else 0

    # Reject circular proxy (APP_HTTP_PORT == listen port)
    if upstream_port == args.port:
        print(
            f"FATAL: upstream port {upstream_port} equals listen port "
            f"{args.port} -- this would create a circular proxy.",
            flush=True,
        )
        raise SystemExit(1)

    # Reject reserved ports
    if upstream_port in RESERVED_PORTS:
        print(
            f"FATAL: upstream port {upstream_port} is reserved and cannot be "
            f"used as APP_HTTP_PORT.",
            flush=True,
        )
        raise SystemExit(1)

    _config = {
        "port": args.port,
        "webroot": args.webroot,
        "upstream": args.upstream,
        "cert_dir": cert_dir,
    }

    print(
        f"ssl-http-proxy: listening on :{args.port}, "
        f"upstream={args.upstream}, "
        f"webroot={args.webroot}, "
        f"cert_dir={cert_dir or '(none)'}",
        flush=True,
    )

    server = ThreadingHTTPServer(("0.0.0.0", args.port), ProxyHandler)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
