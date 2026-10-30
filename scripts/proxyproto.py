"""
proxyproto -- PROXY protocol v2 parsing, building and source-trust policy.

Shared by ssl-http-proxy (:80) and ssl-pp-proxy (the PROXY-aware TLS/TCP shim).
Installed in the image as /usr/local/lib/ssl-manager/proxyproto.py.

Rules this module implements (see haproxy repo docs/PROXY-PROTOCOL-V2-DESIGN.md):

* The header is OPTIONAL. A connection that does not start with the 12-byte v2
  signature is passed through untouched (direct container-to-container calls,
  local health checks, a haproxy that does not send the header yet / any more).
* A header is honoured ONLY when the TCP peer is trusted (TrustPolicy). A peer
  that is not trusted and starts with the signature is a spoofing attempt: the
  caller must close the connection (never strip-and-continue, never pass the
  bytes on to the application).
* Only v2 is accepted. v1 ("PROXY TCP4 ...") is not parsed: haproxy is
  configured with send-proxy-v2 and accepting both widens the attack surface.
* The header is bounded: payload length beyond max_payload is rejected.

Spec: https://www.haproxy.org/download/3.2/doc/proxy-protocol.txt
"""

from __future__ import annotations

import ipaddress
import os
import socket
import struct
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"
SIG_LEN = len(SIGNATURE)  # 12
FIXED_LEN = 16  # signature + ver/cmd + fam/proto + len
DEFAULT_MAX_PAYLOAD = 1024  # addresses (<=216) + generous TLV budget

CMD_LOCAL = 0x0
CMD_PROXY = 0x1

# Classification results
NEED_MORE = "need_more"
NOT_PROXY = "not_proxy"
PROXY = "proxy"
INVALID = "invalid"


@dataclass(frozen=True)
class ProxyInfo:
    """A parsed v2 header. src_ip is None for LOCAL / UNSPEC / AF_UNIX headers
    (health checks): the caller then uses the real TCP peer address."""

    command: str  # "PROXY" or "LOCAL"
    src_ip: Optional[str]
    src_port: Optional[int]
    dst_ip: Optional[str]
    dst_port: Optional[int]
    header_len: int


def normalize_ip(ip: str) -> str:
    """Canonical text form: strip IPv6 zone ids and unwrap IPv4-mapped IPv6."""
    if ip is None:
        return ip
    ip = ip.split("%", 1)[0]
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return str(addr.ipv4_mapped)
    return str(addr)


def starts_with_signature_prefix(buf: bytes) -> bool:
    """True when buf is (a prefix of) the signature or starts with it."""
    n = min(len(buf), SIG_LEN)
    return n > 0 and buf[:n] == SIGNATURE[:n]


def classify(buf: bytes, max_payload: int = DEFAULT_MAX_PAYLOAD):
    """Classify the first bytes of a connection.

    Returns (NOT_PROXY, None), (NEED_MORE, None), (INVALID, reason) or
    (PROXY, ProxyInfo).
    """
    if not buf:
        return NEED_MORE, None
    if not starts_with_signature_prefix(buf):
        return NOT_PROXY, None
    if len(buf) < FIXED_LEN:
        return NEED_MORE, None

    ver_cmd = buf[12]
    version, command = ver_cmd >> 4, ver_cmd & 0x0F
    if version != 2:
        return INVALID, f"unsupported PROXY version {version}"
    if command not in (CMD_LOCAL, CMD_PROXY):
        return INVALID, f"unsupported PROXY command {command}"

    fam_proto = buf[13]
    (length,) = struct.unpack("!H", buf[14:16])
    if length > max_payload:
        return INVALID, f"PROXY header payload {length} exceeds limit {max_payload}"
    total = FIXED_LEN + length
    if len(buf) < total:
        return NEED_MORE, None

    payload = buf[FIXED_LEN:total]
    family = fam_proto >> 4

    if command == CMD_LOCAL:
        return PROXY, ProxyInfo("LOCAL", None, None, None, None, total)

    if family == 0x1:  # AF_INET
        if length < 12:
            return INVALID, "truncated IPv4 address block"
        src = socket.inet_ntop(socket.AF_INET, payload[0:4])
        dst = socket.inet_ntop(socket.AF_INET, payload[4:8])
        sport, dport = struct.unpack("!HH", payload[8:12])
        return PROXY, ProxyInfo("PROXY", src, sport, dst, dport, total)
    if family == 0x2:  # AF_INET6
        if length < 36:
            return INVALID, "truncated IPv6 address block"
        src = socket.inet_ntop(socket.AF_INET6, payload[0:16])
        dst = socket.inet_ntop(socket.AF_INET6, payload[16:32])
        sport, dport = struct.unpack("!HH", payload[32:36])
        return PROXY, ProxyInfo("PROXY", normalize_ip(src), sport, normalize_ip(dst), dport, total)
    # AF_UNSPEC / AF_UNIX: no usable address -> behave like LOCAL
    return PROXY, ProxyInfo("PROXY", None, None, None, None, total)


def build_v2(src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> bytes:
    """Build a PROXY v2 header (TCP over IPv4/IPv6). Mixed families are encoded
    as IPv6 (IPv4-mapped), as the spec requires one family per header."""
    s, d = ipaddress.ip_address(src_ip), ipaddress.ip_address(dst_ip)
    if s.version == 4 and d.version == 4:
        payload = s.packed + d.packed + struct.pack("!HH", src_port, dst_port)
        fam = 0x11
    else:
        s6 = s if s.version == 6 else ipaddress.IPv6Address("::ffff:" + str(s))
        d6 = d if d.version == 6 else ipaddress.IPv6Address("::ffff:" + str(d))
        payload = s6.packed + d6.packed + struct.pack("!HH", src_port, dst_port)
        fam = 0x21
    return SIGNATURE + bytes([0x21, fam]) + struct.pack("!H", len(payload)) + payload


def build_local_v2() -> bytes:
    return SIGNATURE + bytes([0x20, 0x00]) + struct.pack("!H", 0)


def build_v1(src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> bytes:
    s, d = ipaddress.ip_address(src_ip), ipaddress.ip_address(dst_ip)
    if s.version == 4 and d.version == 4:
        proto = "TCP4"
        src, dst = str(s), str(d)
    else:
        proto = "TCP6"
        src = str(s) if s.version == 6 else "::ffff:" + str(s)
        dst = str(d) if d.version == 6 else "::ffff:" + str(d)
    return f"PROXY {proto} {src} {dst} {src_port} {dst_port}\r\n".encode("ascii")


# ---------------------------------------------------------------------------
# Trust policy
# ---------------------------------------------------------------------------

def _resolve_all(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, OSError):
        return []
    out = []
    for info in infos:
        ip = normalize_ip(info[4][0])
        if ip not in out:
            out.append(ip)
    return out


def _connected_ipv4_routes(route_file: str = "/proc/net/route"):
    """Directly connected (gateway 0.0.0.0) IPv4 routes as ip_network objects."""
    nets = []
    try:
        with open(route_file) as f:
            next(f, None)
            for line in f:
                cols = line.split()
                if len(cols) < 8:
                    continue
                dest, gw, mask = cols[1], cols[2], cols[7]
                if int(gw, 16) != 0 or int(mask, 16) == 0:
                    continue
                d = socket.inet_ntoa(struct.pack("<I", int(dest, 16)))
                m = socket.inet_ntoa(struct.pack("<I", int(mask, 16)))
                try:
                    nets.append(ipaddress.ip_network(f"{d}/{m}", strict=False))
                except ValueError:
                    continue
    except OSError:
        pass
    return nets


def _connected_ipv6_routes(route_file: str = "/proc/net/ipv6_route"):
    nets = []
    try:
        with open(route_file) as f:
            for line in f:
                cols = line.split()
                if len(cols) < 10:
                    continue
                dest, plen, nexthop = cols[0], int(cols[1], 16), cols[4]
                if plen == 0 or int(nexthop, 16) != 0:
                    continue
                addr = ipaddress.IPv6Address(int(dest, 16))
                if addr.is_link_local or addr.is_multicast or addr.is_loopback:
                    continue
                nets.append(ipaddress.ip_network(f"{addr}/{plen}", strict=False))
    except (OSError, ValueError):
        pass
    return nets


class TrustPolicy:
    """Which TCP peers may supply a PROXY header.

    spec is a comma/space separated list of:
      <CIDR> or <IP>  static entries (IPv4 or IPv6)
      auto            the directly-connected subnet(s) through which the haproxy
                      host is reached (i.e. the docker haproxy-net subnet). This is
                      the DEFAULT.
      haproxy         only the haproxy host's current IP address(es) (strictest;
                      re-resolved, so a restarted haproxy with a new IP is followed)
      none            trust nobody (every header is rejected)
    Dynamic entries are re-resolved every `refresh` seconds and, rate-limited, on a
    miss -- so a haproxy that started after us, or restarted with a new IP, is
    picked up without restarting the proxy.
    """

    def __init__(
        self,
        spec: str = "auto",
        haproxy_host: str = "haproxy",
        refresh: float = 60.0,
        miss_refresh: float = 5.0,
        resolver: Callable[[str], list[str]] = _resolve_all,
        v4_routes: Callable[[], list] = _connected_ipv4_routes,
        v6_routes: Callable[[], list] = _connected_ipv6_routes,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.haproxy_host = haproxy_host or "haproxy"
        self.refresh = refresh
        self.miss_refresh = miss_refresh
        self._resolver = resolver
        self._v4_routes = v4_routes
        self._v6_routes = v6_routes
        self._clock = clock
        self._lock = threading.Lock()
        self.static: list = []
        self.use_auto = False
        self.use_haproxy = False
        tokens = [t for t in (spec or "auto").replace(",", " ").split() if t]
        if not tokens:
            tokens = ["auto"]
        for tok in tokens:
            low = tok.lower()
            if low == "auto":
                self.use_auto = True
            elif low == "haproxy":
                self.use_haproxy = True
            elif low == "none":
                continue
            else:
                # raises ValueError on garbage: a typo must not silently trust nobody/everyone
                if "/" in tok:
                    net = ipaddress.ip_network(tok, strict=False)
                else:
                    net = ipaddress.ip_network(normalize_ip(tok))
                if net.prefixlen == 0:
                    raise ValueError(f"refusing to trust the whole address space: {tok}")
                self.static.append(net)
        self._dynamic: list = []
        self._last_refresh = None
        self._last_miss_refresh = None

    @property
    def is_dynamic(self) -> bool:
        return self.use_auto or self.use_haproxy

    def _compute_dynamic(self) -> list:
        nets = []
        ips = self._resolver(self.haproxy_host)
        for ip in ips:
            addr = ipaddress.ip_address(ip)
            if self.use_haproxy:
                nets.append(ipaddress.ip_network(f"{addr}/{addr.max_prefixlen}"))
            if self.use_auto:
                routes = self._v4_routes() if addr.version == 4 else self._v6_routes()
                matches = [n for n in routes if addr in n]
                if matches:
                    nets.append(max(matches, key=lambda n: n.prefixlen))
                else:
                    # haproxy reachable only via a gateway: trust just its address
                    nets.append(ipaddress.ip_network(f"{addr}/{addr.max_prefixlen}"))
        out = []
        for n in nets:
            if n not in out:
                out.append(n)
        return out

    def refresh_now(self) -> None:
        if not self.is_dynamic:
            return
        nets = self._compute_dynamic()
        with self._lock:
            if nets or self._last_refresh is None:
                self._dynamic = nets
            self._last_refresh = self._clock()

    def _maybe_refresh(self) -> None:
        if not self.is_dynamic:
            return
        now = self._clock()
        if self._last_refresh is None or now - self._last_refresh >= self.refresh:
            self.refresh_now()

    def _match(self, addr) -> bool:
        with self._lock:
            nets = list(self.static) + list(self._dynamic)
        return any(addr.version == n.version and addr in n for n in nets)

    def is_trusted(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(normalize_ip(ip))
        except (ValueError, TypeError):
            return False
        self._maybe_refresh()
        if self._match(addr):
            return True
        if self.is_dynamic:
            now = self._clock()
            if self._last_miss_refresh is None or now - self._last_miss_refresh >= self.miss_refresh:
                self._last_miss_refresh = now
                self.refresh_now()
                return self._match(addr)
        return False

    def describe(self) -> str:
        with self._lock:
            nets = [str(n) for n in self.static] + [str(n) for n in self._dynamic]
        parts = []
        if self.use_auto:
            parts.append(f"auto(via {self.haproxy_host})")
        if self.use_haproxy:
            parts.append(f"haproxy({self.haproxy_host})")
        return ",".join(parts + nets) or "none"


def policy_from_env(env=os.environ) -> TrustPolicy:
    return TrustPolicy(
        spec=env.get("SSL_PROXY_TRUSTED_CIDRS", "haproxy"),
        haproxy_host=env.get("HAPROXY_HOST") or "haproxy",
    )


def pp_enabled_from_env(env=os.environ) -> bool:
    v = (env.get("SSL_PROXY_PROTOCOL", "v2") or "v2").strip().lower()
    return v not in ("off", "none", "false", "0", "no", "disabled")


class RateLimitedLog:
    """At most one line per `interval` seconds per key; counts what it drops."""

    def __init__(self, emit: Callable[[str], None], interval: float = 1.0, clock=time.monotonic):
        self.emit = emit
        self.interval = interval
        self.clock = clock
        self._lock = threading.Lock()
        self._last: dict = {}
        self._dropped: dict = {}

    def __call__(self, key: str, msg: str) -> None:
        now = self.clock()
        with self._lock:
            last = self._last.get(key)
            if last is not None and now - last < self.interval:
                self._dropped[key] = self._dropped.get(key, 0) + 1
                return
            dropped = self._dropped.pop(key, 0)
            self._last[key] = now
        if dropped:
            msg = f"{msg} (+{dropped} similar suppressed)"
        self.emit(msg)

