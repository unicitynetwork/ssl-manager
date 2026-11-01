"""Robustness tests: untrusted PROXY header is stripped (not closed), slot/leak
handling in the TLS shim, idle/header timeouts, per-peer cap, registration fallback.

Run:  python3 -m unittest discover -s tests
"""

import asyncio
import os
import socket
import subprocess
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_proxy_protocol import (  # noqa: E402
    SCRIPTS, UpstreamRecorder, free_port, load_script, pp, recv_all,
)


class Upstream:
    """Upstream that records bytes, never replies unless asked, and can close on demand."""

    def __init__(self, close_after_first_byte=False):
        self.port = free_port()
        self.received = []
        self.peers = []
        self.close_after_first_byte = close_after_first_byte
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", self.port))
        self.sock.listen(64)
        self.conns = []
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            try:
                c, addr = self.sock.accept()
            except OSError:
                return
            self.conns.append(c)
            self.peers.append(addr)
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()

    def _serve(self, c):
        try:
            d = c.recv(4096)
            self.received.append(d)
            if self.close_after_first_byte:
                c.close()
                return
            while c.recv(4096):
                pass
            c.close()
        except OSError:
            pass

    def close(self):
        self.sock.close()
        for c in self.conns:
            try:
                c.close()
            except OSError:
                pass


class Harness:
    def __init__(self, trusted, upstream_port, **opts):
        self.mod = load_script("ssl_pp_proxy_rb", "ssl-pp-proxy.py")
        self.port = free_port()
        argv = ["--listen", str(self.port), "--bind", "127.0.0.1",
                "--upstream", f"127.0.0.1:{upstream_port}", "--trusted", trusted,
                "--pid-file", os.devnull]
        for k, v in opts.items():
            argv += ["--" + k.replace("_", "-"), str(v)]
        args = self.mod.parse_args(argv)
        self.loop = asyncio.new_event_loop()
        self.ready = threading.Event()
        threading.Thread(target=self._run, args=(args,), daemon=True).start()
        if not self.ready.wait(5):
            raise RuntimeError("shim did not start")

    def _run(self, args):
        asyncio.set_event_loop(self.loop)
        policy = self.mod.pp.TrustPolicy(spec=args.trusted, resolver=lambda h: [])
        self.shim = self.mod.Shim(args, policy)

        async def start():
            self.server = await asyncio.start_server(self.shim.handle, "127.0.0.1", args.listen)
            self.ready.set()
        self.loop.run_until_complete(start())
        self.loop.run_forever()

    def close(self):
        async def shutdown():
            self.server.close()
            tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            asyncio.get_running_loop().stop()
        asyncio.run_coroutine_threadsafe(shutdown(), self.loop)

    def connect(self):
        return socket.create_connection(("127.0.0.1", self.port), timeout=5)


def closed_within(sock, seconds):
    """True if the peer closes (EOF/RST) within `seconds` without us sending."""
    sock.settimeout(seconds)
    t0 = time.monotonic()
    try:
        while True:
            d = sock.recv(4096)
            if not d:
                return True
    except socket.timeout:
        return False
    except OSError:
        return True
    finally:
        sock.settimeout(5)
        _ = t0


class TestUntrustedHeader(unittest.TestCase):
    def setUp(self):
        self.up = UpstreamRecorder()

    def tearDown(self):
        self.up.close()
        self.h.close()

    def test_untrusted_header_not_closed_and_peer_is_real(self):
        self.h = Harness("10.9.9.9", self.up.port, upstream_proxy="v2")
        out = self.h.connect()
        out.sendall(pp.build_v2("6.6.6.6", 1, "7.7.7.7", 2) + b"hi\n")
        data = recv_all(out)
        self.assertTrue(data.endswith(b"hi\n"), data)
        self.assertNotIn(b"6.6.6.6", data)
        got = self.up.received[-1]
        st, info = pp.classify(got)  # re-emitted header must carry the REAL peer
        self.assertEqual((st, info.src_ip), (pp.PROXY, "127.0.0.1"))
        self.assertNotIn(b"6.6.6.6", got)
        self.assertEqual(got[info.header_len:], b"hi\n")

    def test_untrusted_no_header_forwarding_none(self):
        self.h = Harness("10.9.9.9", self.up.port)
        s = self.h.connect()
        s.sendall(pp.build_v2("6.6.6.6", 1, "7.7.7.7", 2) + b"hi\n")
        recv_all(s)
        self.assertEqual(self.up.received, [b"hi\n"])

    def test_trusted_header_still_adopted(self):
        self.h = Harness("127.0.0.1", self.up.port, upstream_proxy="v2")
        s = self.h.connect()
        s.sendall(pp.build_v2("203.0.113.7", 4444, "172.20.0.5", 443) + b"hi\n")
        recv_all(s)
        st, info = pp.classify(self.up.received[-1])
        self.assertEqual(info.src_ip, "203.0.113.7")

    def test_untrusted_garbage_after_signature_closed(self):
        self.h = Harness("10.9.9.9", self.up.port)
        s = self.h.connect()
        s.sendall(pp.SIGNATURE + b"\x99\x11\x00\x0c" + b"x" * 20)  # version 9: invalid
        self.assertTrue(closed_within(s, 2))
        time.sleep(0.2)
        self.assertEqual(self.up.received, [])

    def test_untrusted_oversized_length_closed(self):
        self.h = Harness("10.9.9.9", self.up.port)
        s = self.h.connect()
        s.sendall(pp.SIGNATURE + b"\x21\x11" + (60000).to_bytes(2, "big") + b"x" * 10)
        self.assertTrue(closed_within(s, 2))

    def test_untrusted_header_log_rate_limited(self):
        self.h = Harness("10.9.9.9", self.up.port)
        lines = []
        self.h.shim.rl_untrusted.emit = lines.append
        for _ in range(3):
            s = self.h.connect()
            s.sendall(pp.build_v2("6.6.6.6", 1, "7.7.7.7", 2) + b"a\n")
            recv_all(s)
        self.assertEqual(len(lines), 1)
        self.assertIn("127.0.0.1", lines[0])
        self.assertNotIn("6.6.6.6", lines[0])


class TestLeaksAndTimeouts(unittest.TestCase):
    def tearDown(self):
        self.up.close()
        self.h.close()

    def test_upstream_close_releases_slot_after_grace(self):
        self.up = Upstream(close_after_first_byte=True)
        self.h = Harness("127.0.0.1", self.up.port, max_connections=2, half_close_grace=0.3,
                         idle_timeout=0, header_timeout=2)
        held = []
        for _ in range(2):
            s = self.h.connect()
            s.sendall(b"x")
            held.append(s)  # client stays open, upstream is gone
        time.sleep(0.15)
        # both slots busy within grace: third is turned away
        s3 = self.h.connect()
        self.assertTrue(closed_within(s3, 1.0))
        # the client stays open (never sends EOF); after the grace the shim must
        # fully close both sides and give the slots back
        deadline = time.monotonic() + 3
        while self.h.shim.sem._value != 2 and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertEqual(self.h.shim.sem._value, 2, "slots released after grace")
        # a full close (not just the half-close FIN) resets further client writes
        def reset_seen(sock):
            try:
                for _ in range(20):
                    sock.sendall(b"z")
                    time.sleep(0.05)
            except OSError:
                return True
            return False
        for s in held:
            self.assertTrue(reset_seen(s), "client side must be fully closed after grace")
        s4 = self.h.connect()
        s4.sendall(b"y")
        self.assertTrue(closed_within(s4, 2.0))  # served (then closed by upstream), not rejected
        self.assertEqual(len(self.up.received), 3)

    def test_idle_timeout_closes_established(self):
        self.up = Upstream()
        self.h = Harness("127.0.0.1", self.up.port, idle_timeout=0.5, half_close_grace=5, header_timeout=2)
        s = self.h.connect()
        s.sendall(b"hello")
        time.sleep(0.2)
        self.assertEqual(self.up.received, [b"hello"])
        t0 = time.monotonic()
        self.assertTrue(closed_within(s, 3.0))
        self.assertLess(time.monotonic() - t0, 2.5)
        time.sleep(0.1)
        self.assertEqual(self.h.shim.sem._value, self.h.shim.args.max_connections)

    def test_idle_timeout_reset_by_traffic(self):
        self.up = Upstream()
        self.h = Harness("127.0.0.1", self.up.port, idle_timeout=0.6, header_timeout=2)
        s = self.h.connect()
        for _ in range(4):
            s.sendall(b"k")
            time.sleep(0.3)
        s.settimeout(0.05)
        try:
            self.assertNotEqual(s.recv(1), b"")  # would be EOF if closed
        except socket.timeout:
            pass

    def test_header_timeout_closes_silent_and_partial(self):
        self.up = Upstream()
        self.h = Harness("127.0.0.1", self.up.port, header_timeout=0.4, idle_timeout=600)
        silent = self.h.connect()
        partial = self.h.connect()
        partial.sendall(pp.SIGNATURE + b"\x21")  # >= signature, header incomplete
        t0 = time.monotonic()
        self.assertTrue(closed_within(partial, 2.0))
        self.assertTrue(closed_within(silent, 3.0))
        self.assertLess(time.monotonic() - t0, 3.0)
        time.sleep(0.1)
        self.assertEqual(self.h.shim.sem._value, self.h.shim.args.max_connections)

    def test_untrusted_per_peer_cap_trusted_unlimited(self):
        self.up = Upstream()
        # untrusted (loopback not trusted): cap 3
        self.h = Harness("10.9.9.9", self.up.port, max_conn_per_untrusted_peer=3, idle_timeout=0,
                         header_timeout=5)
        conns = [self.h.connect() for _ in range(3)]
        for c in conns:
            c.sendall(b"x")
        time.sleep(0.2)
        extra = self.h.connect()
        self.assertTrue(closed_within(extra, 1.0), "4th connection from an untrusted peer refused")
        conns[0].close()
        time.sleep(0.3)
        self.assertEqual(self.h.shim.untrusted_conns.get("127.0.0.1"), 2)
        again = self.h.connect()
        again.sendall(b"x")
        time.sleep(0.2)
        self.assertEqual(len(self.up.received), 4)
        for c in conns[1:] + [again]:
            c.close()
        time.sleep(0.3)
        self.assertEqual(self.h.shim.untrusted_conns, {}, "counter released on every path")

    def test_trusted_peer_not_limited_by_peer_cap(self):
        self.up = Upstream()
        self.h = Harness("127.0.0.1", self.up.port, max_conn_per_untrusted_peer=2, idle_timeout=0,
                         header_timeout=5)
        conns = [self.h.connect() for _ in range(6)]
        for c in conns:
            c.sendall(b"x")
        time.sleep(0.3)
        self.assertEqual(len(self.up.received), 6)
        self.assertEqual(self.h.shim.untrusted_conns, {})


class TestRegistrationFallback(unittest.TestCase):
    SETUP = os.path.join(SCRIPTS, "ssl-setup.sh")

    def _run_selftest_fn(self, cmd):
        """Run the real pp_trust_selftest() from ssl-setup.sh with a stubbed command and
        report the PP_REG_MODE the shim-ready branch would pick."""
        src = open(self.SETUP).read()
        start = src.index("pp_trust_selftest() {")
        end = src.index("\n}\n", start) + 3
        fn = src[start:end]
        script = (fn + 'PP_REG_MODE=v2; HTTPS_PROXY_PORT_REG=8445\n'
                  'if ! pp_trust_selftest; then PP_REG_MODE=none; HTTPS_PROXY_PORT_REG=null; fi\n'
                  'echo "$PP_REG_MODE $HTTPS_PROXY_PORT_REG"\n')
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                           env=dict(os.environ, SSL_PP_SELFTEST_CMD=cmd))
        return r.stdout.strip().splitlines()[-1]

    def test_setup_wires_selftest_before_state_file(self):
        src = open(self.SETUP).read()
        i_call = src.index("if ! pp_trust_selftest; then")
        i_none = src.index('PP_REG_MODE="none"', i_call)
        i_state = src.index("write_pp_state   # after")
        self.assertLess(i_call, i_none)
        self.assertLess(i_none, i_state)

    def test_selftest_failure_registers_none(self):
        self.assertEqual(self._run_selftest_fn("false"), "none null")

    def test_selftest_success_keeps_v2(self):
        self.assertEqual(self._run_selftest_fn("true"), "v2 8445")

    def test_trust_selftest_unit(self):
        env = {"HAPROXY_HOST": "haproxy"}
        ok, _ = pp.trust_selftest(env, resolver=lambda h: ["10.0.0.2"])
        self.assertTrue(ok)
        ok, why = pp.trust_selftest(env, resolver=lambda h: [])
        self.assertFalse(ok, why)
        ok, why = pp.trust_selftest(env, resolver=lambda h: ["10.0.0.2", "10.1.0.2"])
        self.assertFalse(ok, why)  # ambiguous, nothing pinned
        ok, _ = pp.trust_selftest(dict(env, SSL_PROXY_HAPROXY_ADDR="10.0.0.0/8"),
                                  resolver=lambda h: ["10.0.0.2", "10.1.0.2"])
        self.assertTrue(ok)
        ok, why = pp.trust_selftest(dict(env, SSL_PROXY_TRUSTED_CIDRS="none"),
                                    resolver=lambda h: ["10.0.0.2"])
        self.assertFalse(ok, why)  # haproxy not in the trusted set


class TestHttpProxyBounds(unittest.TestCase):
    def test_idle_timeout_and_peer_cap_attributes(self):
        mod = load_script("ssl_http_proxy_rb", "ssl-http-proxy.py")
        self.assertEqual(mod.ProxyHandler.timeout, 60.0)
        self.assertEqual(mod.MAX_CONN_PER_UNTRUSTED_PEER, 64)


if __name__ == "__main__":
    unittest.main()
