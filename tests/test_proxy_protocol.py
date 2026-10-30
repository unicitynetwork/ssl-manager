"""Unit + loopback tests for PROXY protocol v2 support.

Run:  python3 -m unittest discover -s tests -v      (from the repo root)

Covers scripts/proxyproto.py, scripts/ssl-pp-proxy.py (TLS/TCP shim) and the
PROXY handling in scripts/ssl-http-proxy.py. Everything runs on 127.0.0.1;
"untrusted" is simulated by trusting a different address.
"""

import asyncio
import http.server
import importlib.machinery
import importlib.util
import ipaddress
import json
import os
import socket
import sys
import threading
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(ROOT, "scripts")
sys.path.insert(0, SCRIPTS)

import proxyproto as pp  # noqa: E402


def load_script(name, filename):
    loader = importlib.machinery.SourceFileLoader(name, os.path.join(SCRIPTS, filename))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def recv_all(sock, timeout=5):
    sock.settimeout(timeout)
    out = b""
    while True:
        try:
            d = sock.recv(65536)
        except socket.timeout:
            break
        if not d:
            break
        out += d
    return out


# ---------------------------------------------------------------------------
# proxyproto
# ---------------------------------------------------------------------------

class TestParse(unittest.TestCase):
    def test_roundtrip_v4(self):
        h = pp.build_v2("203.0.113.7", 40000, "172.20.0.5", 443)
        st, info = pp.classify(h + b"\x16\x03\x01rest")
        self.assertEqual(st, pp.PROXY)
        self.assertEqual((info.src_ip, info.src_port, info.dst_ip, info.dst_port),
                         ("203.0.113.7", 40000, "172.20.0.5", 443))
        self.assertEqual(info.header_len, 28)

    def test_roundtrip_v6_and_mapped(self):
        h = pp.build_v2("2001:db8::1", 1, "2001:db8::2", 2)
        st, info = pp.classify(h)
        self.assertEqual((st, info.src_ip), (pp.PROXY, "2001:db8::1"))
        self.assertEqual(info.header_len, 16 + 36)
        # IPv4-mapped source comes back as plain IPv4
        h = pp.build_v2("::ffff:198.51.100.9", 5, "2001:db8::2", 6)
        st, info = pp.classify(h)
        self.assertEqual(info.src_ip, "198.51.100.9")

    def test_local_command(self):
        st, info = pp.classify(pp.build_local_v2())
        self.assertEqual((st, info.command, info.src_ip), (pp.PROXY, "LOCAL", None))

    def test_not_proxy(self):
        for data in (b"GET / HTTP/1.1\r\n", b"\x16\x03\x01\x02\x00", b"PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n"):
            self.assertEqual(pp.classify(data)[0], pp.NOT_PROXY, data)

    def test_need_more_prefix(self):
        h = pp.build_v2("1.2.3.4", 1, "5.6.7.8", 2)
        for n in (1, 5, 12, 15, 20, 27):
            self.assertEqual(pp.classify(h[:n])[0], pp.NEED_MORE, n)

    def test_invalid(self):
        h = bytearray(pp.build_v2("1.2.3.4", 1, "5.6.7.8", 2))
        bad_ver = bytes(h[:12]) + b"\x11" + bytes(h[13:])
        self.assertEqual(pp.classify(bad_ver)[0], pp.INVALID)
        bad_cmd = bytes(h[:12]) + b"\x2f" + bytes(h[13:])
        self.assertEqual(pp.classify(bad_cmd)[0], pp.INVALID)
        huge = pp.SIGNATURE + b"\x21\x11" + (60000).to_bytes(2, "big")
        st, reason = pp.classify(huge, max_payload=1024)
        self.assertEqual(st, pp.INVALID)
        self.assertIn("exceeds", reason)
        short_v4 = pp.SIGNATURE + b"\x21\x11" + (4).to_bytes(2, "big") + b"\x01\x02\x03\x04"
        self.assertEqual(pp.classify(short_v4)[0], pp.INVALID)

    def test_tlvs_are_skipped(self):
        h = pp.build_v2("1.2.3.4", 1, "5.6.7.8", 2)
        tlv = b"\x04\x00\x03abc"  # PP2_TYPE_NOOP
        length = int.from_bytes(h[14:16], "big") + len(tlv)
        h2 = h[:14] + length.to_bytes(2, "big") + h[16:] + tlv
        st, info = pp.classify(h2 + b"DATA")
        self.assertEqual((st, info.src_ip, info.header_len), (pp.PROXY, "1.2.3.4", len(h2)))

    def test_v1_builder(self):
        self.assertEqual(pp.build_v1("1.2.3.4", 1, "5.6.7.8", 2), b"PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n")
        self.assertTrue(pp.build_v1("2001:db8::1", 1, "5.6.7.8", 2).startswith(b"PROXY TCP6 2001:db8::1 ::ffff:5.6.7.8"))


class TestTrust(unittest.TestCase):
    def test_static(self):
        t = pp.TrustPolicy("172.20.0.0/16, 10.1.2.3, 2001:db8::/32", resolver=lambda h: [])
        self.assertTrue(t.is_trusted("172.20.5.6"))
        self.assertTrue(t.is_trusted("::ffff:172.20.5.6"))
        self.assertTrue(t.is_trusted("10.1.2.3"))
        self.assertFalse(t.is_trusted("10.1.2.4"))
        self.assertTrue(t.is_trusted("2001:db8::99"))
        self.assertFalse(t.is_trusted("8.8.8.8"))
        self.assertFalse(t.is_trusted("garbage"))

    def test_refuses_everything_and_typos(self):
        with self.assertRaises(ValueError):
            pp.TrustPolicy("0.0.0.0/0")
        with self.assertRaises(ValueError):
            pp.TrustPolicy("172.20.0.0/33")
        with self.assertRaises(ValueError):
            pp.TrustPolicy("haproxy-net")
        t = pp.TrustPolicy("none", resolver=lambda h: ["172.20.0.9"])
        self.assertFalse(t.is_trusted("172.20.0.9"))

    def test_auto_uses_connected_subnet_of_haproxy(self):
        routes = [ipaddress.ip_network("172.20.0.0/16"), ipaddress.ip_network("172.30.0.0/24")]
        t = pp.TrustPolicy("auto", resolver=lambda h: ["172.20.0.9"], v4_routes=lambda: routes)
        self.assertTrue(t.is_trusted("172.20.200.1"))
        self.assertFalse(t.is_trusted("172.30.0.5"))  # app network is NOT trusted
        self.assertIn("172.20.0.0/16", t.describe())

    def test_auto_falls_back_to_host_when_routed(self):
        t = pp.TrustPolicy("auto", resolver=lambda h: ["10.0.0.9"], v4_routes=lambda: [])
        self.assertTrue(t.is_trusted("10.0.0.9"))
        self.assertFalse(t.is_trusted("10.0.0.10"))

    def test_haproxy_strict_follows_ip_change(self):
        now = [0.0]
        ips = [["172.20.0.9"]]
        t = pp.TrustPolicy("haproxy", resolver=lambda h: ips[0], clock=lambda: now[0], miss_refresh=5)
        self.assertTrue(t.is_trusted("172.20.0.9"))
        self.assertFalse(t.is_trusted("172.20.0.10"))
        ips[0] = ["172.20.0.10"]  # haproxy restarted with a new IP
        now[0] += 1
        self.assertFalse(t.is_trusted("172.20.0.10"))  # miss-refresh is rate limited
        now[0] += 5
        self.assertTrue(t.is_trusted("172.20.0.10"))  # picked up without a restart
        self.assertFalse(t.is_trusted("172.20.0.9"))

    def test_late_haproxy(self):
        now = [0.0]
        ips = [[]]  # haproxy not resolvable yet at startup
        t = pp.TrustPolicy("auto", resolver=lambda h: ips[0], clock=lambda: now[0],
                           v4_routes=lambda: [ipaddress.ip_network("172.20.0.0/16")])
        t.refresh_now()
        self.assertFalse(t.is_trusted("172.20.0.9"))
        ips[0] = ["172.20.0.9"]
        now[0] += 6
        self.assertTrue(t.is_trusted("172.20.0.9"))

    def test_resolution_blip_keeps_last_good(self):
        now = [0.0]
        ips = [["172.20.0.9"]]
        t = pp.TrustPolicy("haproxy", resolver=lambda h: ips[0], clock=lambda: now[0], refresh=10)
        self.assertTrue(t.is_trusted("172.20.0.9"))
        ips[0] = []  # DNS hiccup
        now[0] += 11
        self.assertTrue(t.is_trusted("172.20.0.9"))

    def test_env(self):
        self.assertTrue(pp.pp_enabled_from_env({}))
        self.assertTrue(pp.pp_enabled_from_env({"SSL_PROXY_PROTOCOL": "v2"}))
        for v in ("off", "none", "false", "0", "OFF"):
            self.assertFalse(pp.pp_enabled_from_env({"SSL_PROXY_PROTOCOL": v}))


# ---------------------------------------------------------------------------
# ssl-pp-proxy (TCP shim) over loopback
# ---------------------------------------------------------------------------

class UpstreamRecorder:
    """TCP server that records the first bytes of each connection and echoes."""

    def __init__(self):
        self.port = free_port()
        self.received = []
        self.peers = []
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", self.port))
        self.sock.listen(16)
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            try:
                c, addr = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(c, addr), daemon=True).start()

    def _serve(self, c, addr):
        self.peers.append(addr)
        c.settimeout(2)
        data = b""
        try:
            while not data.endswith(b"\n"):
                d = c.recv(4096)
                if not d:
                    break
                data += d
        except socket.timeout:
            pass
        self.received.append(data)
        try:
            c.sendall(b"ECHO:" + data)
            c.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        c.close()

    def close(self):
        self.sock.close()


class ShimHarness:
    def __init__(self, trusted, upstream_port, upstream_proxy="none", header_timeout=1.0):
        self.shim_mod = load_script("ssl_pp_proxy", "ssl-pp-proxy.py")
        self.port = free_port()
        args = self.shim_mod.parse_args([
            "--listen", str(self.port), "--bind", "127.0.0.1",
            "--upstream", f"127.0.0.1:{upstream_port}", "--upstream-proxy", upstream_proxy,
            "--trusted", trusted, "--header-timeout", str(header_timeout), "--pid-file", os.devnull,
        ])
        self.loop = asyncio.new_event_loop()
        self.ready = threading.Event()
        self.thread = threading.Thread(target=self._run, args=(args,), daemon=True)
        self.thread.start()
        if not self.ready.wait(5):
            raise RuntimeError("shim did not start")

    def _run(self, args):
        asyncio.set_event_loop(self.loop)
        policy = self.shim_mod.pp.TrustPolicy(spec=args.trusted, resolver=lambda h: [])
        shim = self.shim_mod.Shim(args, policy)

        async def start():
            self.server = await asyncio.start_server(shim.handle, "127.0.0.1", args.listen)
            self.ready.set()
        self.loop.run_until_complete(start())
        self.loop.run_forever()

    def close(self):
        self.loop.call_soon_threadsafe(self.server.close)
        self.loop.call_soon_threadsafe(self.loop.stop)

    def talk(self, payload):
        s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        s.sendall(payload)
        out = recv_all(s, timeout=3)
        s.close()
        return out


class TestShim(unittest.TestCase):
    def setUp(self):
        self.up = UpstreamRecorder()

    def tearDown(self):
        self.up.close()
        if hasattr(self, "shim"):
            self.shim.close()

    def test_trusted_header_is_stripped(self):
        self.shim = ShimHarness("127.0.0.1", self.up.port)
        out = self.shim.talk(pp.build_v2("203.0.113.7", 4444, "172.20.0.5", 443) + b"hello\n")
        self.assertEqual(out, b"ECHO:hello\n")
        self.assertEqual(self.up.received[-1], b"hello\n")

    def test_no_header_passes_through(self):
        self.shim = ShimHarness("127.0.0.1", self.up.port)
        self.assertEqual(self.shim.talk(b"\x16\x03\x01plain\n"), b"ECHO:\x16\x03\x01plain\n")

    def test_untrusted_header_is_rejected(self):
        self.shim = ShimHarness("10.9.9.9", self.up.port)  # loopback is NOT trusted
        out = self.shim.talk(pp.build_v2("6.6.6.6", 1, "7.7.7.7", 2) + b"evil\n")
        self.assertEqual(out, b"")
        time.sleep(0.2)
        self.assertEqual(self.up.received, [], "forged header must never reach the app")

    def test_untrusted_without_header_still_served(self):
        self.shim = ShimHarness("10.9.9.9", self.up.port)
        self.assertEqual(self.shim.talk(b"direct\n"), b"ECHO:direct\n")

    def test_oversized_header_rejected(self):
        self.shim = ShimHarness("127.0.0.1", self.up.port)
        out = self.shim.talk(pp.SIGNATURE + b"\x21\x11" + (5000).to_bytes(2, "big") + b"x" * 100)
        self.assertEqual(out, b"")

    def test_split_header_across_segments(self):
        self.shim = ShimHarness("127.0.0.1", self.up.port)
        h = pp.build_v2("203.0.113.7", 4444, "172.20.0.5", 443)
        s = socket.create_connection(("127.0.0.1", self.shim.port), timeout=5)
        for b in (h[:5], h[5:14], h[14:]):
            s.sendall(b)
            time.sleep(0.05)
        s.sendall(b"split\n")
        self.assertEqual(recv_all(s), b"ECHO:split\n")
        s.close()

    def test_upstream_v2_reemits_client(self):
        self.shim = ShimHarness("127.0.0.1", self.up.port, upstream_proxy="v2")
        self.shim.talk(pp.build_v2("203.0.113.7", 4444, "172.20.0.5", 443) + b"x\n")
        st, info = pp.classify(self.up.received[-1])
        self.assertEqual((st, info.src_ip, info.src_port), (pp.PROXY, "203.0.113.7", 4444))
        self.assertEqual(self.up.received[-1][info.header_len:], b"x\n")

    def test_upstream_v1(self):
        self.shim = ShimHarness("127.0.0.1", self.up.port, upstream_proxy="v1")
        self.shim.talk(pp.build_v2("203.0.113.7", 4444, "172.20.0.5", 443) + b"x\n")
        self.assertTrue(self.up.received[-1].startswith(b"PROXY TCP4 203.0.113.7 172.20.0.5 4444 443\r\n"))

    def test_health_check_local_and_connect_only(self):
        self.shim = ShimHarness("127.0.0.1", self.up.port)
        # haproxy check-send-proxy: header then close
        self.assertEqual(self.shim.talk(pp.build_local_v2()), b"ECHO:")
        # bare TCP connect/close
        s = socket.create_connection(("127.0.0.1", self.shim.port))
        s.close()
        # shim still alive
        self.assertEqual(self.shim.talk(b"ok\n"), b"ECHO:ok\n")


# ---------------------------------------------------------------------------
# ssl-http-proxy over loopback
# ---------------------------------------------------------------------------

class HeaderEchoApp(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        # first occurrence wins, like a real app's headers.get()
        body = json.dumps({k.lower(): self.headers.get(k) for k in self.headers.keys()}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class TestHttpProxy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app_port = free_port()
        cls.app = http.server.ThreadingHTTPServer(("127.0.0.1", cls.app_port), HeaderEchoApp)
        threading.Thread(target=cls.app.serve_forever, daemon=True).start()
        cls.mod = load_script("ssl_http_proxy", "ssl-http-proxy.py")
        cls.mod.PP_HEADER_TIMEOUT = 1.0
        cls.mod._config = {"port": 0, "webroot": "/nonexistent", "upstream": f"127.0.0.1:{cls.app_port}",
                           "cert_dir": ""}
        cls.port = free_port()
        cls.srv = cls.mod.ThreadingHTTPServer(("127.0.0.1", cls.port), cls.mod.ProxyHandler)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.app.shutdown()

    def set_policy(self, enabled, trusted="127.0.0.1"):
        self.mod._pp_enabled = enabled
        self.mod._pp_policy = self.mod.pp.TrustPolicy(trusted, resolver=lambda h: [])

    def request(self, prefix=b"", extra_headers=""):
        s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        s.sendall(prefix + f"GET /x HTTP/1.1\r\nHost: t.example\r\n{extra_headers}Connection: close\r\n\r\n".encode())
        raw = recv_all(s)
        s.close()
        return raw

    def body(self, raw):
        head, _, body = raw.partition(b"\r\n\r\n")
        self.assertTrue(head.startswith(b"HTTP/1.0 200") or head.startswith(b"HTTP/1.1 200"), raw[:200])
        return json.loads(body)

    def test_trusted_header_overwrites_xff(self):
        self.set_policy(True)
        hdr = pp.build_v2("203.0.113.7", 5555, "172.20.0.5", 80)
        h = self.body(self.request(hdr, "X-Forwarded-For: 6.6.6.6\r\nX-Real-IP: 6.6.6.6\r\n"))
        self.assertEqual(h["x-forwarded-for"], "203.0.113.7")
        self.assertEqual(h["x-real-ip"], "203.0.113.7")

    def test_no_header_legacy_append(self):
        self.set_policy(True)
        h = self.body(self.request(b"", "X-Forwarded-For: 6.6.6.6\r\nX-Real-IP: 6.6.6.6\r\n"))
        self.assertEqual(h["x-forwarded-for"], "6.6.6.6, 127.0.0.1")
        self.assertEqual(h["x-real-ip"], "127.0.0.1")

    def test_lowercase_client_headers_cannot_shadow(self):
        # haproxy forwards header names lower-cased; ours must still be the only one
        self.set_policy(True)
        raw = self.request(b"", "x-forwarded-for: 6.6.6.6\r\nx-real-ip: 6.6.6.6\r\nx-forwarded-proto: https\r\n")
        h = self.body(raw)
        self.assertEqual(h["x-forwarded-for"], "6.6.6.6, 127.0.0.1")
        self.assertEqual(h["x-real-ip"], "127.0.0.1")
        self.assertEqual(h["x-forwarded-proto"], "http")
        hdr = pp.build_v2("203.0.113.7", 5555, "172.20.0.5", 80)
        h = self.body(self.request(hdr, "x-forwarded-for: 6.6.6.6\r\n"))
        self.assertEqual(h["x-forwarded-for"], "203.0.113.7")

    def test_untrusted_header_rejected(self):
        self.set_policy(True, trusted="10.9.9.9")
        raw = self.request(pp.build_v2("6.6.6.6", 1, "7.7.7.7", 80))
        self.assertEqual(raw, b"")

    def test_local_header_uses_peer(self):
        self.set_policy(True)
        h = self.body(self.request(pp.build_local_v2()))
        self.assertEqual(h["x-forwarded-for"], "127.0.0.1")

    def test_disabled_does_not_parse(self):
        # PROXY off: the header is NOT interpreted (a stray one just breaks that request)
        self.set_policy(False)
        raw = self.request(pp.build_v2("203.0.113.7", 5555, "172.20.0.5", 80))
        self.assertNotIn(b"203.0.113.7", raw)
        h = self.body(self.request())
        self.assertEqual(h["x-forwarded-for"], "127.0.0.1")

    def test_health_probe_connect_only(self):
        self.set_policy(True)
        s = socket.create_connection(("127.0.0.1", self.port))
        s.close()
        s = socket.create_connection(("127.0.0.1", self.port))
        s.sendall(pp.build_local_v2())
        s.close()
        self.assertEqual(self.body(self.request())["x-real-ip"], "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
