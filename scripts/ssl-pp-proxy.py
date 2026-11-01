#!/usr/bin/env python3
"""
ssl-pp-proxy -- PROXY-protocol-aware TCP shim in front of an app's TLS port.

haproxy does TLS *passthrough* on :443, so the TLS terminator is the application
(nginx, node, Fulcrum, ...), which usually cannot read a PROXY header. With
PROXY v2 enabled, ssl-manager registers this shim's port as `https_proxy_port`:
haproxy connects here and prepends a PROXY v2 header; the shim

  * honours the header only if the TCP peer is trusted (default "haproxy": only
    the haproxy container's current address, see proxyproto.TrustPolicy). A
    well-formed header from an UNTRUSTED peer is stripped and IGNORED: the
    connection is treated as direct (the real TCP peer is the client, the
    claimed address is never adopted, logged as a client or forwarded). It is
    deliberately not closed: if haproxy's real source address is missing from
    the trusted set, closing would be a silent HTTPS outage that haproxy's TCP
    health check cannot see, whereas stripping has no security cost (the header
    bytes are never forwarded). Garbage after the signature is closed;
  * accepts connections WITHOUT a header too (header optional) -- so a haproxy
    that stops sending it (rollback) keeps working;
  * forwards the remaining byte stream unchanged (TLS stays end-to-end between
    client and app) to the upstream (default: this container's own non-loopback
    address on $SSL_HTTPS_PORT -- deliberately NOT 127.0.0.1, so app ACLs that
    trust loopback are not opened to the internet);
  * optionally re-emits the real client address to the app as a PROXY v1/v2
    header (--upstream-proxy v1|v2), for apps that can read it on a dedicated
    listener. That listener MUST be reachable only by the shim (bind it to
    127.0.0.1 and point --upstream at 127.0.0.1:<port>), otherwise any peer on
    the network can send it a forged header.

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


EXIT_CONFIG = 2  # ssl-pp-proxy-wrapper does not restart on 2; ssl-setup then registers "none"


def resolve_upstream(spec: str) -> tuple:
    """'auto:<port>' -> (own non-loopback IP, port); 'host:port' otherwise.
    Raises ValueError if 'auto' cannot find a non-loopback address: dialling
    127.0.0.1 instead would make every internet client look local to the app."""
    host, _, port = spec.rpartition(":")
    if not host or not port.isdigit():
        raise ValueError(f"invalid upstream '{spec}' (want host:port or auto:port)")
    if host == "auto":
        try:
            ip = socket.gethostbyname(socket.gethostname())
        except OSError:
            ip = None
        if not ip or ip.startswith("127."):
            raise ValueError("cannot determine this container's non-loopback address for "
                             "upstream 'auto' (refusing to fall back to 127.0.0.1)")
        host = ip
    return host, int(port)


class Shim:
    def __init__(self, args, policy: pp.TrustPolicy, upstream=None):
        self.args = args
        self.policy = policy
        self.upstream = upstream or resolve_upstream(args.upstream)
        self.sem = asyncio.Semaphore(args.max_connections)
        self.rl = pp.RateLimitedLog(warn, interval=1.0)
        self.rl_untrusted = pp.RateLimitedLog(warn, interval=60.0)
        self.active = 0
        self.untrusted_conns = {}  # peer ip -> open connections (untrusted peers only)

    async def _trusted(self, peer_ip) -> bool:
        # may hit DNS (re-resolution): keep it off the event loop
        return await asyncio.get_running_loop().run_in_executor(None, self.policy.is_trusted, peer_ip)

    async def _read_header(self, reader, peer_ip, trusted):
        """Return (info|None, leftover bytes) or raise ConnectionAbortedError to reject.
        A complete, well-formed header from an untrusted peer is consumed and
        dropped (info None, logged once a minute per peer): never adopted."""
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
            state, val = pp.classify(buf, self.args.max_header)
            if state == pp.NOT_PROXY:
                return None, buf
            if state == pp.INVALID:
                raise ConnectionAbortedError(f"invalid PROXY header from {peer_ip}: {val}")
            if state == pp.PROXY:
                if not trusted:
                    self.rl_untrusted(
                        f"untrusted:{peer_ip}",
                        f"PROXY header from untrusted peer {peer_ip} ignored; treating the "
                        f"connection as direct (if this peer is haproxy, fix SSL_PROXY_TRUSTED_CIDRS "
                        f"or SSL_PROXY_HAPROXY_ADDR)")
                    return None, buf[val.header_len:]
                return val, buf[val.header_len:]
            # NEED_MORE: loop

    async def _pump(self, reader, writer, st):
        try:
            while True:
                data = await reader.read(BUF)
                if not data:
                    break
                st["last"] = asyncio.get_running_loop().time()
                st["seen"] = True
                writer.write(data)
                await writer.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            try:
                if writer.can_write_eof():
                    writer.write_eof()
            except (OSError, RuntimeError):
                pass

    async def _relay(self, reader, writer, up_reader, up_writer, seen):
        """Pump both directions. Once either direction ends, the other gets
        half_close_grace seconds, then both sides are closed (a half-open
        connection must not hold a slot forever). Also closes after idle_timeout
        seconds without bytes in either direction (0 disables), and after
        header_timeout if no byte has flowed at all."""
        loop = asyncio.get_running_loop()
        st = {"last": loop.time(), "seen": seen}
        pending = {asyncio.ensure_future(self._pump(reader, up_writer, st)),
                   asyncio.ensure_future(self._pump(up_reader, writer, st))}
        eof_at = None
        try:
            while pending:
                now = loop.time()
                limits = []
                if eof_at is not None:
                    limits.append(eof_at + self.args.half_close_grace)
                limit = self.args.idle_timeout if st["seen"] else (
                    self.args.header_timeout if not self.args.idle_timeout
                    else min(self.args.idle_timeout, self.args.header_timeout))
                if limit:
                    limits.append(st["last"] + limit)
                timeout = max(0.0, min(limits) - now) if limits else None
                done, pending = await asyncio.wait(pending, timeout=timeout,
                                                   return_when=asyncio.FIRST_COMPLETED)
                now = loop.time()
                if done and eof_at is None:
                    eof_at = now
                if eof_at is not None and now - eof_at >= self.args.half_close_grace:
                    break
                if limit and now - st["last"] >= limit:
                    break
        finally:
            for t in pending:
                t.cancel()
            await asyncio.gather(*pending, return_exceptions=True)

    async def handle(self, reader, writer):
        peer = writer.get_extra_info("peername") or ("?", 0)
        local = writer.get_extra_info("sockname") or ("0.0.0.0", 0)
        peer_ip = pp.normalize_ip(peer[0])
        if self.sem.locked():
            self.rl("full", f"max connections ({self.args.max_connections}) reached; rejecting {peer_ip}")
            writer.close()
            return
        trusted = await self._trusted(peer_ip)
        counted = False
        if not trusted:
            # Only untrusted/direct peers are capped per IP: haproxy is the one
            # trusted peer and carries all traffic (bounded by the global limit).
            cap = self.args.max_conn_per_untrusted_peer
            if cap and self.untrusted_conns.get(peer_ip, 0) >= cap:
                self.rl(f"peercap:{peer_ip}", f"per-peer limit ({cap}) reached; rejecting {peer_ip}")
                writer.close()
                return
            self.untrusted_conns[peer_ip] = self.untrusted_conns.get(peer_ip, 0) + 1
            counted = True
        try:
            await self._serve(reader, writer, peer, local, peer_ip, trusted)
        finally:
            if counted:
                n = self.untrusted_conns.get(peer_ip, 0) - 1
                if n > 0:
                    self.untrusted_conns[peer_ip] = n
                else:
                    self.untrusted_conns.pop(peer_ip, None)

    async def _serve(self, reader, writer, peer, local, peer_ip, trusted):
        async with self.sem:
            up_writer = None
            try:
                try:
                    info, leftover = await self._read_header(reader, peer_ip, trusted)
                except ConnectionAbortedError as e:
                    self.rl(f"reject:{peer_ip}", str(e))
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
                    await self._relay(reader, writer, up_reader, up_writer, bool(leftover))
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


async def amain(args, upstream) -> None:
    policy = pp.policy_from_env()
    if args.trusted:
        policy = pp.TrustPolicy(spec=args.trusted, haproxy_host=os.environ.get("HAPROXY_HOST") or "haproxy")
    policy.refresh_now()
    shim = Shim(args, policy, upstream)
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
    p.add_argument("--header-timeout", type=float, default=float(env.get("SSL_PROXY_HEADER_TIMEOUT", "10")),
                   help="seconds to wait for a PROXY header / first byte (default 10)")
    p.add_argument("--idle-timeout", type=float, default=float(env.get("SSL_PP_IDLE_TIMEOUT", "600")),
                   help="close after this many seconds without bytes either way; 0 disables")
    p.add_argument("--half-close-grace", type=float, default=float(env.get("SSL_PP_HALF_CLOSE_GRACE", "5")),
                   help="seconds the other direction may linger once one side hit EOF")
    p.add_argument("--max-conn-per-untrusted-peer", type=int,
                   default=int(env.get("SSL_PP_MAX_CONN_PER_UNTRUSTED_PEER", "64")),
                   help="concurrent connections per NON-trusted peer IP; 0 disables")
    p.add_argument("--connect-timeout", type=float, default=5.0)
    p.add_argument("--max-header", type=int, default=int(env.get("SSL_PROXY_MAX_HEADER", pp.DEFAULT_MAX_PAYLOAD)))
    p.add_argument("--max-connections", type=int, default=int(env.get("SSL_PROXY_MAX_CONNECTIONS", "4096")))
    p.add_argument("--log-connections", action="store_true",
                   default=(env.get("SSL_PROXY_LOG_CONNECTIONS", "false").lower() in ("1", "true", "yes")))
    p.add_argument("--pid-file", default="/tmp/.ssl-pp-proxy.pid")
    return p.parse_args(argv)


def main() -> None:
    args = parse_args()
    try:
        upstream = resolve_upstream(args.upstream)
    except ValueError as e:
        print(f"[ssl-pp-proxy] FATAL: {e}", file=sys.stderr, flush=True)
        raise SystemExit(EXIT_CONFIG)
    if args.listen == upstream[1] and args.upstream.startswith(("auto:", "127.", "localhost")):
        print("[ssl-pp-proxy] FATAL: shim listen port equals upstream port (circular)", file=sys.stderr, flush=True)
        raise SystemExit(EXIT_CONFIG)
    try:
        asyncio.run(amain(args, upstream))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
