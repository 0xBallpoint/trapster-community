import asyncio
import unittest

from trapster.logger import JsonLogger
from trapster.modules.http import HttpHoneypot, TrustedProxyMiddleware

from .base import BaseServerTest


def scope_for(peer, headers=None, scope_type="http"):
    return {
        "type": scope_type,
        "client": peer,
        "headers": [[k.lower().encode("latin1"), v.encode("latin1")]
                     for k, v in (headers or {}).items()],
    }


class TrustedProxyMiddlewareTests(unittest.TestCase):
    def resolve(self, proxies, peer, headers=None):
        middleware = TrustedProxyMiddleware(app=None, trusted_proxies=proxies)
        scope = scope_for(peer, headers)
        middleware._resolve(scope)
        return scope["client"][0]

    def resolve_raw(self, proxies, peer, headers):
        middleware = TrustedProxyMiddleware(app=None, trusted_proxies=proxies)
        scope = {"type": "http", "client": peer,
                 "headers": [[k, v] for k, v in headers]}
        middleware._resolve(scope)
        return scope["client"]

    def test_no_config_keeps_peer(self):
        self.assertEqual(
            self.resolve([], ("192.0.2.99", 1000), {"X-Forwarded-For": "1.2.3.4"}),
            "192.0.2.99")

    def test_trusted_peer_uses_xff(self):
        self.assertEqual(
            self.resolve(["127.0.0.1"], ("127.0.0.1", 1000),
                         {"X-Forwarded-For": "203.0.113.7"}),
            "203.0.113.7")

    def test_cidr_network_matches(self):
        self.assertEqual(
            self.resolve(["10.0.0.0/8"], ("10.1.2.3", 1000),
                         {"X-Forwarded-For": "203.0.113.7"}),
            "203.0.113.7")

    def test_single_ip_matches_own_network(self):
        self.assertEqual(
            self.resolve(["127.0.0.1/32"], ("127.0.0.1", 1000),
                         {"X-Forwarded-For": "203.0.113.7"}),
            "203.0.113.7")

    def test_untrusted_peer_headers_ignored(self):
        self.assertEqual(
            self.resolve(["127.0.0.1"], ("198.51.100.9", 1000),
                         {"X-Forwarded-For": "203.0.113.7"}),
            "198.51.100.9")

    def test_untrusted_peer_x_real_ip_ignored(self):
        self.assertEqual(
            self.resolve(["10.0.0.0/8"], ("198.51.100.9", 1000),
                         {"X-Real-IP": "203.0.113.7"}),
            "198.51.100.9")

    def test_chain_rightmost_untrusted_wins(self):
        self.assertEqual(
            self.resolve(["10.0.0.0/8"], ("10.1.2.3", 1000),
                         {"X-Forwarded-For": "203.0.113.7, 10.9.9.9"}),
            "203.0.113.7")

    def test_chain_all_trusted_keeps_peer(self):
        self.assertEqual(
            self.resolve(["10.0.0.0/8"], ("10.1.2.3", 1000),
                         {"X-Forwarded-For": "10.9.9.9"}),
            "10.1.2.3")

    def test_x_real_ip_fallback(self):
        self.assertEqual(
            self.resolve(["127.0.0.1"], ("127.0.0.1", 1000),
                         {"X-Real-IP": "203.0.113.7"}),
            "203.0.113.7")
    def test_x_real_ip_ignored_when_xff_present(self):
        self.assertEqual(
            self.resolve(["10.0.0.0/8"], ("10.1.2.3", 1000),
                         {"X-Forwarded-For": "garbage",
                          "X-Real-IP": "203.0.113.7"}),
            "10.1.2.3")

    def test_x_real_ip_ignored_when_chain_all_trusted(self):
        self.assertEqual(
            self.resolve(["10.0.0.0/8"], ("10.1.2.3", 1000),
                         {"X-Forwarded-For": "10.9.9.9",
                          "X-Real-IP": "203.0.113.7"}),
            "10.1.2.3")

    def test_garbage_xff_falls_back_to_peer(self):
        self.assertEqual(
            self.resolve(["10.0.0.0/8"], ("10.1.2.3", 1000),
                         {"X-Forwarded-For": "garbage"}),
            "10.1.2.3")

    def test_empty_chain_entry_ends_walk(self):
        self.assertEqual(
            self.resolve(["10.0.0.0/8"], ("10.1.2.3", 1000),
                         {"X-Forwarded-For": "203.0.113.7,,10.9.9.9"}),
            "10.1.2.3")

    def test_ipv4_mapped_peer(self):
        self.assertEqual(
            self.resolve(["10.0.0.0/8"], ("::ffff:10.1.2.3", 1000),
                         {"X-Forwarded-For": "203.0.113.7"}),
            "203.0.113.7")

    def test_ipv6_network(self):
        self.assertEqual(
            self.resolve(["fd00::/8"], ("fd00::1", 1000),
                         {"X-Forwarded-For": "203.0.113.7"}),
            "203.0.113.7")

    def test_invalid_entry_ignored(self):
        self.assertEqual(
            self.resolve(["nonsense"], ("10.1.2.3", 1000),
                         {"X-Forwarded-For": "203.0.113.7"}),
            "10.1.2.3")

    def test_multiple_xff_headers_joined_in_order(self):
        self.assertEqual(
            self.resolve_raw(["10.0.0.0/8"], ("10.1.2.3", 1000),
                             [(b"x-forwarded-for", b"1.1.1.1"),
                              (b"x-forwarded-for", b"2.2.2.2")])[0],
            "2.2.2.2")

    def test_multiple_x_real_ip_ignored(self):
        self.assertEqual(
            self.resolve_raw(["10.0.0.0/8"], ("10.1.2.3", 1000),
                             [(b"x-real-ip", b"203.0.113.7"),
                              (b"x-real-ip", b"198.51.100.9")])[0],
            "10.1.2.3")

    def test_zero_network_warns(self):
        with self.assertLogs(level="WARNING"):
            middleware = TrustedProxyMiddleware(app=None,
                                                trusted_proxies=["0.0.0.0/0"])
        self.assertEqual(len(middleware.networks), 1)

    def test_bracketed_v6_resolved(self):
        self.assertEqual(
            self.resolve(["127.0.0.1"], ("127.0.0.1", 1000),
                         {"X-Forwarded-For": "[2001:db8::1]"}),
            "2001:db8::1")

    def test_bracketed_v6_with_port_resolved(self):
        self.assertEqual(
            self.resolve(["127.0.0.1"], ("127.0.0.1", 1000),
                         {"X-Forwarded-For": "[2001:db8::1]:443"}),
            "2001:db8::1")

    def test_unterminated_bracket_ends_walk(self):
        self.assertEqual(
            self.resolve(["10.0.0.0/8"], ("10.1.2.3", 1000),
                         {"X-Forwarded-For": "[2001:db8::1"}),
            "10.1.2.3")

    def test_long_chain_window_capped(self):
        chain = "203.0.113.7," + ",".join(["127.0.0.1"] * 40)
        self.assertEqual(
            self.resolve(["127.0.0.0/8", "10.0.0.0/8"], ("10.1.2.3", 1000),
                         {"X-Forwarded-For": chain}),
            "10.1.2.3")

    def test_chain_within_window_resolved(self):
        chain = "203.0.113.7," + ",".join(["127.0.0.1"] * 31)
        self.assertEqual(
            self.resolve(["127.0.0.1"], ("127.0.0.1", 1000),
                         {"X-Forwarded-For": chain}),
            "203.0.113.7")

    def test_port_preserved(self):
        middleware = TrustedProxyMiddleware(app=None,
                                            trusted_proxies=["127.0.0.1"])
        scope = scope_for(("127.0.0.1", 4321),
                          {"X-Forwarded-For": "203.0.113.7"})
        middleware._resolve(scope)
        self.assertEqual(scope["client"], ("203.0.113.7", 4321))

    def test_call_rewrites_http_scope_only(self):
        seen = []

        async def app(scope, receive, send):
            seen.append(scope["client"])

        middleware = TrustedProxyMiddleware(app=app,
                                            trusted_proxies=["127.0.0.1"])
        http_scope = scope_for(("127.0.0.1", 1000),
                               {"X-Forwarded-For": "203.0.113.7"})
        asyncio.run(middleware(http_scope, None, None))
        ws_scope = scope_for(("127.0.0.1", 1000),
                             {"X-Forwarded-For": "203.0.113.7"},
                             scope_type="websocket")
        asyncio.run(middleware(ws_scope, None, None))
        self.assertEqual(seen, [("203.0.113.7", 1000), ("127.0.0.1", 1000)])

    def test_trusted_proxies_as_string(self):
        self.assertEqual(
            self.resolve("10.0.0.0/8", ("10.1.2.3", 1000),
                         {"X-Forwarded-For": "203.0.113.7"}),
            "203.0.113.7")

    def test_host_bits_entry_warns(self):
        with self.assertLogs(level="WARNING"):
            middleware = TrustedProxyMiddleware(
                app=None, trusted_proxies=["10.0.0.1/8"])
        self.assertEqual(str(middleware.networks[0]), "10.0.0.0/8")

    def test_mapped_network_warns(self):
        with self.assertLogs(level="WARNING"):
            middleware = TrustedProxyMiddleware(
                app=None, trusted_proxies=["::ffff:127.0.0.1/128"])
        self.assertEqual(len(middleware.networks), 1)


class CaptureLogger(JsonLogger):
    def __init__(self, node_id):
        super().__init__(node_id)
        self.events = []

    def log(self, logtype, transport, data='', extra={}):
        event = self.parse_log(logtype, transport, data, extra)
        if event:
            self.events.append(event)
        return event


class ReverseProxy:
    """Minimal nginx-style hop: appends the client address to
    X-Forwarded-For and replaces X-Real-IP (proxy_set_header
    X-Real-IP $remote_addr, X-Forwarded-For $proxy_add_x_forwarded_for),
    forwarding from its own address."""

    def __init__(self, listen_addr, target_addr):
        self.listen_addr = listen_addr
        self.target_addr = target_addr
        self.server = None

    async def start(self):
        self.server = await asyncio.start_server(
            self._handle, self.listen_addr[0], self.listen_addr[1])

    async def stop(self):
        self.server.close()
        await self.server.wait_closed()

    async def _pump(self, src, dst):
        try:
            while True:
                data = await src.read(4096)
                if not data:
                    break
                dst.write(data)
                await dst.drain()
        finally:
            dst.close()

    async def _handle(self, reader, writer):
        client_ip = writer.get_extra_info("peername")[0]
        up_reader, up_writer = await asyncio.open_connection(
            self.target_addr[0], self.target_addr[1],
            local_addr=(self.listen_addr[0], 0))
        head = await reader.readuntil(b"\r\n\r\n")
        request_line, *header_lines = head.decode("latin1").split("\r\n")[:-2]
        xff = ""
        out = [request_line]
        for line in header_lines:
            name, _, value = line.partition(":")
            key = name.strip().lower()
            if key == "x-forwarded-for":
                xff = value.strip()
            elif key == "x-real-ip":
                continue
            else:
                out.append(line)
        chain = xff + ", " + client_ip if xff else client_ip
        out.append("X-Forwarded-For: " + chain)
        out.append("X-Real-IP: " + client_ip)
        up_writer.write(("\r\n".join(out) + "\r\n\r\n").encode("latin1"))
        await up_writer.drain()
        await asyncio.gather(self._pump(reader, up_writer),
                             self._pump(up_reader, writer))


class HttpProxyPathTests(unittest.IsolatedAsyncioTestCase):
    async def logged_src_ip(self, client_headers):
        logger = CaptureLogger("trapster-test")
        config = {"port": 8893, "basic_auth": True,
                  "username": "u", "password": "p", "skin": "demo_api",
                  "trusted_proxies": ["127.0.0.2"]}
        server = BaseServerTest(HttpHoneypot, config, logger)
        await server.start_server()
        proxy = ReverseProxy(("127.0.0.2", 8894), ("127.0.0.1", 8893))
        await proxy.start()
        try:
            reader, writer = await asyncio.open_connection("127.0.0.2", 8894)
            lines = ["GET / HTTP/1.1", "Host: test"] + client_headers \
                + ["Connection: close", ""]
            writer.write(("\r\n".join(lines) + "\r\n").encode("latin1"))
            await writer.drain()
            while await reader.read(4096):
                pass
            writer.close()
        finally:
            await proxy.stop()
            await server.stop_server()
        queries = [e for e in logger.events if e["logtype"] == "http.query"]
        return queries[-1]["src_ip"]

    async def test_client_ip_logged_behind_proxy(self):
        self.assertEqual(await self.logged_src_ip([]), "127.0.0.1")

    async def test_spoofed_xff_dropped_behind_proxy(self):
        self.assertEqual(
            await self.logged_src_ip(["X-Forwarded-For: 203.0.113.7"]),
            "127.0.0.1")

    async def test_garbage_xff_and_spoofed_real_ip_dropped(self):
        self.assertEqual(
            await self.logged_src_ip(
                ["X-Forwarded-For: garbage", "X-Real-IP: 203.0.113.7"]),
            "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
