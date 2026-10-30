#!/usr/bin/env python3
"""
ssl-pp-proxy -- PROXY-protocol-aware TCP shim in front of an app's TLS port.

haproxy does TLS *passthrough* on :443, so the TLS terminator is the application
(nginx, node, Fulcrum, ...), which usually cannot read a PROXY header. With
PROXY v2 enabled, ssl-manager registers this shim's port as `https_proxy_port`:
haproxy connects here and prepends a PROXY v2 header; the shim

  * honours the header only if the TCP peer is trusted (default: the docker
    haproxy-net subnet), and CLOSES a connection from an untrusted peer that
    starts with a PROXY signature (spoofing attempt);
  * accepts connections WITHOUT a header too (header optional) -- so a haproxy
    that stops sending it (rollback) keeps working;
  * forwards the remaining byte stream unchanged (TLS stays end-to-end between
    client and app) to the upstream (default: this container's own non-loopback
    address on $SSL_HTTPS_PORT -- deliberately NOT 127.0.0.1, so app ACLs that
    trust loopback are not opened to the internet);
  * optionally re-emits the real client address to the app as a PROXY v1/v2
    header (--upstream-proxy v1|v2), for apps that can read it on a dedicated
    listener (e.g. nginx `listen 8446 ssl proxy_protocol;`).

The real client address is always available in the shim's own log when
SSL_PROXY_LOG_CONNECTIONS=true.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import socket
import sys

sys.path.insert(0, "/usr/local/lib/ssl-manager")
sys.path.insert(1, os.path.dirname(os.path.abspath(__file__)))
import proxyproto as pp  # noqa: E402

BUF = 65536


def log(msg: str) -> None:
    print(f"[ssl-pp-proxy] {msg}", flush=True)


def warn(msg: str) -> None:
    print(f"[ssl-pp-proxy] WARNING: {msg}", file=sys.stderr, flush=True)


def resolve_upstream(spec: str) -> tuple[str, int]:
    """'auto:<port>' -> (own non-loopback IP, port); 'host:port' otherwise."""
    host, _, port = spec.rpartition(":")
    if not host or not port.isdigit():
        raise ValueError(f"invalid upstream '{spec}' (want host:port or auto:port)")
    if host == "auto":
        ip = None
        try:
            ip = socket.gethostbyname(socket.gethostname())
        except OSError:
            ip = None
        if not ip or ip.startswith("127."):
            warn("could not find a non-loopback container address; falling back to 127.0.0.1 "
                 "(apps that trust loopback will see every client as local!)")
            ip = "127.0.0.1"
        host = ip
    return host, int(port)


class Shim:
    def __init__(self, args, policy: pp.TrustPolicy):
        self.args = args
        self.policy = policy
        self.upstream = resolve_upstream(args.upstream)
        self.sem = asyncio.Semaphore(args.max_connections)
        self.rl = pp.RateLimitedLog(warn, interval=1.0)
        self.active = 0

    async def _read_header(self, reader, peer_ip):
        """Return (info|None, leftover bytes) or raise ConnectionAbortedError to reject."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.args.header_timeout
        buf = b""
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                # Nothing (server-speaks-first protocol) or an incomplete prefix.
                if len(buf) >= pp.SIG_LEN:
                    raise ConnectionAbortedError("incomplete PROXY header (timeout)")
                return None, buf
            try:
                chunk = await asyncio.wait_for(reader.read(BUF), remaining)
            except asyncio.TimeoutError:
                continue
            if not chunk:
                raise ConnectionResetError("peer closed before sending data")
            buf += chunk
            if pp.starts_with_signature_prefix(buf) and len(buf) >= pp.SIG_LEN \
                    and not self.policy.is_trusted(peer_ip):
                raise ConnectionAbortedError(f"PROXY header from UNTRUSTED peer {peer_ip} rejected")
            state, val = pp.classify(buf, self.args.max_header)
            if state == pp.NOT_PROXY:
                return None, buf
            if state == pp.INVALID:
                raise ConnectionAbortedError(f"invalid PROXY header from {peer_ip}: {val}")
            if state == pp.PROXY:
                if not self.policy.is_trusted(peer_ip):  # signature split across reads
                    raise ConnectionAbortedError(f"PROXY header from UNTRUSTED peer {peer_ip} rejected")
                return val, buf[val.header_len:]
            # NEED_MORE: loop

    async def _pipe(self, reader, writer):
        try:
            while True:
                data = await reader.read(BUF)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except (ConnectionError, OSError, asyncio.CancelledError):
            pass
        finally:
            try:
                if writer.can_write_eof():
                    writer.write_eof()
            except (OSError, RuntimeError):
                pass

    async def handle(self, reader, writer):
        peer = writer.get_extra_info("peername") or ("?", 0)
        local = writer.get_extra_info("sockname") or ("0.0.0.0", 0)
        peer_ip = pp.normalize_ip(peer[0])
        if self.sem.locked():
            self.rl("full", f"max connections ({self.args.max_connections}) reached; rejecting {peer_ip}")
            writer.close()
            return
        async with self.sem:
            up_writer = None
            try:
                try:
                    info, leftover = await self._read_header(reader, peer_ip)
                except ConnectionAbortedError as e:
                    self.rl("reject", str(e))
                    return
                except ConnectionResetError:
                    return  # e.g. a plain TCP health probe

                if info is not None and info.src_ip:
                    client = (info.src_ip, info.src_port)
                    dst = (info.dst_ip, info.dst_port)
                    via = f"via {peer_ip} PROXYv2"
                else:
                    client = (peer_ip, peer[1])
                    dst = (pp.normalize_ip(local[0]), local[1])
                    via = "PROXYv2 LOCAL" if info is not None else "direct"

                try:
                    up_reader, up_writer = await asyncio.wait_for(
                        asyncio.open_connection(*self.upstream), self.args.connect_timeout)
                except (OSError, asyncio.TimeoutError) as e:
                    self.rl("upstream", f"upstream {self.upstream[0]}:{self.upstream[1]} unavailable: {e}")
                    return

                if self.args.log_connections and info is not None and info.command == "LOCAL":
                    pass  # health check: don't spam
                elif self.args.log_connections:
                    log(f"client {client[0]}:{client[1]} ({via}) -> {self.upstream[0]}:{self.upstream[1]}")

                if self.args.upstream_proxy != "none" and not (info is not None and info.command == "LOCAL"):
                    try:
                        if self.args.upstream_proxy == "v2":
                            hdr = pp.build_v2(client[0], client[1], dst[0], dst[1])
                        else:
                            hdr = pp.build_v1(client[0], client[1], dst[0], dst[1])
                    except ValueError:
                        hdr = pp.build_local_v2() if self.args.upstream_proxy == "v2" else b"PROXY UNKNOWN\r\n"
                    up_writer.write(hdr)
                elif self.args.upstream_proxy == "v2":
                    up_writer.write(pp.build_local_v2())
                elif self.args.upstream_proxy == "v1":
                    up_writer.write(b"PROXY UNKNOWN\r\n")
                if leftover:
                    up_writer.write(leftover)
                await up_writer.drain()

                self.active += 1
                try:
                    await asyncio.gather(self._pipe(reader, up_writer), self._pipe(up_reader, writer))
                finally:
                    self.active -= 1
            except (ConnectionError, OSError) as e:
                self.rl("conn", f"connection error from {peer_ip}: {e}")
            finally:
                for w in (writer, up_writer):
                    if w is not None:
                        try:
                            w.close()
                        except (OSError, RuntimeError):
                            pass


async def amain(args) -> None:
    policy = pp.policy_from_env()
    if args.trusted:
        policy = pp.TrustPolicy(spec=args.trusted, haproxy_host=os.environ.get("HAPROXY_HOST") or "haproxy")
    policy.refresh_now()
    shim = Shim(args, policy)
    server = await asyncio.start_server(shim.handle, host=args.bind, port=args.listen,
                                        reuse_address=True, backlog=512)
    log(f"listening on {args.bind}:{args.listen} -> {shim.upstream[0]}:{shim.upstream[1]} "
        f"(trusted PROXY sources: {policy.describe()}, upstream header: {args.upstream_proxy})")
    if args.pid_file:
        with open(args.pid_file, "w") as f:
            f.write(str(os.getpid()))
    async with server:
        await server.serve_forever()


def parse_args(argv=None):
    env = os.environ
    p = argparse.ArgumentParser(description="PROXY-protocol-aware TCP shim")
    p.add_argument("--listen", type=int, default=int(env.get("SSL_PROXY_HTTPS_PORT", "8445")))
    p.add_argument("--bind", default=env.get("SSL_PROXY_BIND", "0.0.0.0"))
    p.add_argument("--upstream", default=env.get("SSL_PROXY_HTTPS_UPSTREAM",
                                                  f"auto:{env.get('SSL_HTTPS_PORT', '443')}"))
    p.add_argument("--upstream-proxy", choices=["none", "v1", "v2"],
                   default=(env.get("SSL_PROXY_HTTPS_UPSTREAM_PROTOCOL", "none") or "none").lower())
    p.add_argument("--trusted", default=None, help="override SSL_PROXY_TRUSTED_CIDRS")
    p.add_argument("--header-timeout", type=float, default=float(env.get("SSL_PROXY_HEADER_TIMEOUT", "5")))
    p.add_argument("--connect-timeout", type=float, default=5.0)
    p.add_argument("--max-header", type=int, default=int(env.get("SSL_PROXY_MAX_HEADER", pp.DEFAULT_MAX_PAYLOAD)))
    p.add_argument("--max-connections", type=int, default=int(env.get("SSL_PROXY_MAX_CONNECTIONS", "4096")))
    p.add_argument("--log-connections", action="store_true",
                   default=(env.get("SSL_PROXY_LOG_CONNECTIONS", "false").lower() in ("1", "true", "yes")))
    p.add_argument("--pid-file", default="/tmp/.ssl-pp-proxy.pid")
    return p.parse_args(argv)


def main() -> None:
    args = parse_args()
    if args.listen == resolve_upstream(args.upstream)[1] and args.upstream.startswith(("auto:", "127.", "localhost")):
        print("FATAL: shim listen port equals upstream port (circular)", file=sys.stderr, flush=True)
        raise SystemExit(2)
    try:
        asyncio.run(amain(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
