#!/usr/bin/env python3
"""Test application for the PROXY protocol e2e: reports what it sees.

  :8080  HTTP   -> {"listener":"http","peer":..,"xff":..,"x_real_ip":..}
  :443   TLS    -> {"listener":"tls","peer":..}            (default shim mode)
  :8446  PROXY v2 (required) + TLS -> {"listener":"pp-tls","peer":..,"pp_src":..}
                                                          (shim upstream-proxy v2)
"""
import json
import os
import socket
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, "/usr/local/lib/ssl-manager")
try:
    import proxyproto as pp
except ImportError:  # old base image
    pp = None


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        body = json.dumps({
            "listener": "http",
            "peer": self.client_address[0],
            "xff": self.headers.get("X-Forwarded-For"),
            "x_real_ip": self.headers.get("X-Real-IP"),
        }).encode() + b"\n"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def tls_ctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.environ["SSL_CERT_FILE"], os.environ["SSL_KEY_FILE"])
    return ctx


def respond_tls(conn, payload):
    try:
        conn.settimeout(5)
        conn.recv(4096)
        body = json.dumps(payload).encode() + b"\n"
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n"
                     + f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def serve_tls(port, require_pp):
    ctx = tls_ctx()
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("0.0.0.0", port))
    ls.listen(64)
    while True:
        c, addr = ls.accept()
        threading.Thread(target=handle_tls, args=(ctx, c, addr, require_pp), daemon=True).start()


def handle_tls(ctx, c, addr, require_pp):
    pp_src = None
    try:
        c.settimeout(5)
        if require_pp:
            data = c.recv(2048, socket.MSG_PEEK)
            st, info = pp.classify(data)
            if st != pp.PROXY:
                c.close()
                return
            c.recv(info.header_len)
            pp_src = info.src_ip
        t = ctx.wrap_socket(c, server_side=True)
    except (OSError, ssl.SSLError):
        c.close()
        return
    respond_tls(t, {"listener": "pp-tls" if require_pp else "tls", "peer": addr[0], "pp_src": pp_src})


if __name__ == "__main__":
    threading.Thread(target=serve_tls, args=(443, False), daemon=True).start()
    if pp is not None:
        threading.Thread(target=serve_tls, args=(8446, True), daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()
