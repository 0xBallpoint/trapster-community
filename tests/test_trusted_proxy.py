import asyncio
import unittest

from trapster.modules.http import HttpHoneypot, TrustedProxyMiddleware

from .helpers import HoneypotTestCase, RecordingLogger, free_port


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
        """With no trusted proxy configured, forwarding headers are ignored."""
        self.assertEqual(
            self.resolve([], ("192.0.2.99", 1000), {"X-Forwarded-For": "1.2.3.4"}),
            "192.0.2.99")

    def test_trusted_peer_uses_xff(self):
        """A request from a trusted proxy is logged with the client IP from X-Forwarded-For."""
        self.assertEqual(
            self.resolve(["127.0.0.1"], ("127.0.0.1", 1000),
                         {"X-Forwarded-For": "203.0.113.7"}),
            "203.0.113.7")

    def test_cidr_network_matches(self):
        """Trusted proxies can be given as a network."""
        self.assertEqual(
            self.resolve(["10.0.0.0/8"], ("10.1.2.3", 1000),
                         {"X-Forwarded-For": "203.0.113.7"}),
            "203.0.113.7")

    def test_single_ip_matches_own_network(self):
        """A single IP written as a /32 network is trusted."""
        self.assertEqual(
            self.resolve(["127.0.0.1/32"], ("127.0.0.1", 1000),
                         {"X-Forwarded-For": "203.0.113.7"}),
            "203.0.113.7")

    def test_untrusted_peer_headers_ignored(self):
        """X-Forwarded-For from an untrusted peer is ignored, so attackers cannot fake their IP."""
        self.assertEqual(
            self.resolve(["127.0.0.1"], ("198.51.100.9", 1000),
                         {"X-Forwarded-For": "203.0.113.7"}),
            "198.51.100.9")

    def test_untrusted_peer_x_real_ip_ignored(self):
        """X-Real-IP from an untrusted peer is ignored as well."""
        self.assertEqual(
            self.resolve(["10.0.0.0/8"], ("198.51.100.9", 1000),
                         {"X-Real-IP": "203.0.113.7"}),
            "198.51.100.9")

    def test_chain_rightmost_untrusted_wins(self):
        """In a proxy chain, the client is the rightmost address that is not a trusted proxy."""
        self.assertEqual(
            self.resolve(["10.0.0.0/8"], ("10.1.2.3", 1000),
                         {"X-Forwarded-For": "203.0.113.7, 10.9.9.9"}),
            "203.0.113.7")

    def test_chain_all_trusted_keeps_peer(self):
        """If every address in the chain is a trusted proxy, the peer address is kept."""
        self.assertEqual(
            self.resolve(["10.0.0.0/8"], ("10.1.2.3", 1000),
                         {"X-Forwarded-For": "10.9.9.9"}),
            "10.1.2.3")

    def test_x_real_ip_fallback(self):
        """Without X-Forwarded-For, X-Real-IP from a trusted proxy is used."""
        self.assertEqual(
            self.resolve(["127.0.0.1"], ("127.0.0.1", 1000),
                         {"X-Real-IP": "203.0.113.7"}),
            "203.0.113.7")
    def test_x_real_ip_ignored_when_xff_present(self):
        """X-Real-IP is not used when X-Forwarded-For is present, even if it is invalid."""
        self.assertEqual(
            self.resolve(["10.0.0.0/8"], ("10.1.2.3", 1000),
                         {"X-Forwarded-For": "garbage",
                          "X-Real-IP": "203.0.113.7"}),
            "10.1.2.3")

    def test_x_real_ip_ignored_when_chain_all_trusted(self):
        """X-Real-IP is not used when the X-Forwarded-For chain only holds trusted proxies."""
        self.assertEqual(
            self.resolve(["10.0.0.0/8"], ("10.1.2.3", 1000),
                         {"X-Forwarded-For": "10.9.9.9",
                          "X-Real-IP": "203.0.113.7"}),
            "10.1.2.3")

    def test_garbage_xff_falls_back_to_peer(self):
        """An X-Forwarded-For that is not an IP address is ignored."""
        self.assertEqual(
            self.resolve(["10.0.0.0/8"], ("10.1.2.3", 1000),
                         {"X-Forwarded-For": "garbage"}),
            "10.1.2.3")

    def test_empty_chain_entry_ends_walk(self):
        """An empty entry in the chain stops the walk instead of skipping to an earlier address."""
        self.assertEqual(
            self.resolve(["10.0.0.0/8"], ("10.1.2.3", 1000),
                         {"X-Forwarded-For": "203.0.113.7,,10.9.9.9"}),
            "10.1.2.3")

    def test_ipv4_mapped_peer(self):
        """A peer seen as an IPv4-mapped IPv6 address still matches an IPv4 trusted network."""
        self.assertEqual(
            self.resolve(["10.0.0.0/8"], ("::ffff:10.1.2.3", 1000),
                         {"X-Forwarded-For": "203.0.113.7"}),
            "203.0.113.7")

    def test_ipv6_network(self):
        """Trusted proxies can be IPv6 networks."""
        self.assertEqual(
            self.resolve(["fd00::/8"], ("fd00::1", 1000),
                         {"X-Forwarded-For": "203.0.113.7"}),
            "203.0.113.7")

    def test_invalid_entry_ignored(self):
        """An invalid trusted_proxies entry is ignored instead of trusting anything."""
        self.assertEqual(
            self.resolve(["nonsense"], ("10.1.2.3", 1000),
                         {"X-Forwarded-For": "203.0.113.7"}),
            "10.1.2.3")

    def test_multiple_xff_headers_joined_in_order(self):
        """Several X-Forwarded-For headers are read as one chain, in order."""
        self.assertEqual(
            self.resolve_raw(["10.0.0.0/8"], ("10.1.2.3", 1000),
                             [(b"x-forwarded-for", b"1.1.1.1"),
                              (b"x-forwarded-for", b"2.2.2.2")])[0],
            "2.2.2.2")

    def test_multiple_x_real_ip_ignored(self):
        """Several X-Real-IP headers are ambiguous, so none is used."""
        self.assertEqual(
            self.resolve_raw(["10.0.0.0/8"], ("10.1.2.3", 1000),
                             [(b"x-real-ip", b"203.0.113.7"),
                              (b"x-real-ip", b"198.51.100.9")])[0],
            "10.1.2.3")

    def test_zero_network_warns(self):
        """Trusting 0.0.0.0/0 (every address) logs a warning."""
        with self.assertLogs(level="WARNING"):
            middleware = TrustedProxyMiddleware(app=None,
                                                trusted_proxies=["0.0.0.0/0"])
        self.assertEqual(len(middleware.networks), 1)

    def test_port_preserved(self):
        """Rewriting the client IP keeps the original source port."""
        middleware = TrustedProxyMiddleware(app=None,
                                            trusted_proxies=["127.0.0.1"])
        scope = scope_for(("127.0.0.1", 4321),
                          {"X-Forwarded-For": "203.0.113.7"})
        middleware._resolve(scope)
        self.assertEqual(scope["client"], ("203.0.113.7", 4321))

    def test_call_rewrites_http_scope_only(self):
        """Only HTTP requests get the client IP rewritten, not websocket connections."""
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
        """trusted_proxies also accepts a single string instead of a list."""
        self.assertEqual(
            self.resolve("10.0.0.0/8", ("10.1.2.3", 1000),
                         {"X-Forwarded-For": "203.0.113.7"}),
            "203.0.113.7")

    def test_host_bits_entry_warns(self):
        """A network written with host bits set is normalised, with a warning."""
        with self.assertLogs(level="WARNING"):
            middleware = TrustedProxyMiddleware(
                app=None, trusted_proxies=["10.0.0.1/8"])
        self.assertEqual(str(middleware.networks[0]), "10.0.0.0/8")


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


class HttpProxyPathTests(HoneypotTestCase):
    async def logged_src_ip(self, client_headers):
        logger = RecordingLogger()
        config = {"basic_auth": True,
                  "username": "u", "password": "p", "skin": "demo_api",
                  "trusted_proxies": ["127.0.0.2"]}
        _, port = await self.start_honeypot(HttpHoneypot, config, logger)
        proxy_port = free_port()
        proxy = ReverseProxy(("127.0.0.2", proxy_port), ("127.0.0.1", port))
        await proxy.start()
        try:
            reader, writer = await asyncio.open_connection("127.0.0.2", proxy_port)
            lines = ["GET / HTTP/1.1", "Host: test"] + client_headers \
                + ["Connection: close", ""]
            writer.write(("\r\n".join(lines) + "\r\n").encode("latin1"))
            await writer.drain()
            while await reader.read(4096):
                pass
            writer.close()
        finally:
            await proxy.stop()
        queries = [e for e in logger.events if e["logtype"] == "http.query"]
        return queries[-1]["src_ip"]

    async def test_client_ip_logged_behind_proxy(self):
        """Behind a real reverse proxy, the event has the client's IP, not the proxy's."""
        self.assertEqual(await self.logged_src_ip([]), "127.0.0.1")

    async def test_spoofed_xff_dropped_behind_proxy(self):
        """A forged X-Forwarded-For sent through the proxy does not replace the real client IP."""
        self.assertEqual(
            await self.logged_src_ip(["X-Forwarded-For: 203.0.113.7"]),
            "127.0.0.1")

    async def test_garbage_xff_and_spoofed_real_ip_dropped(self):
        """Invalid and forged forwarding headers sent through the proxy are both ignored."""
        self.assertEqual(
            await self.logged_src_ip(
                ["X-Forwarded-For: garbage", "X-Real-IP: 203.0.113.7"]),
            "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
