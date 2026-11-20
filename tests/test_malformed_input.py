"""Malformed input on every TCP module.

Scanners and exploits send garbage, cut packets short and hang up mid-way.
None of that may take a service down or escape as an unhandled exception.
"""

import asyncio
import json
import random
import socket
from pathlib import Path

from trapster.modules import (
    DnsHoneypot,
    FtpHoneypot,
    HttpHoneypot,
    HttpsHoneypot,
    LdapHoneypot,
    LdapsHoneypot,
    MssqlHoneypot,
    MysqlHoneypot,
    PostgresHoneypot,
    RdpHoneypot,
    RsyncHoneypot,
    SshHoneypot,
    TelnetHoneypot,
    VncHoneypot,
)

from .helpers import HOST, HoneypotTestCase, RecordingLogger, exchange

SHIPPED_CONFIG = json.loads(
    (Path(__file__).parent.parent / "trapster" / "data" / "trapster.conf").read_text())

TCP_MODULES = {
    "ftp": FtpHoneypot,
    "http": HttpHoneypot,
    "https": HttpsHoneypot,
    "ssh": SshHoneypot,
    "telnet": TelnetHoneypot,
    "vnc": VncHoneypot,
    "mysql": MysqlHoneypot,
    "mssql": MssqlHoneypot,
    "postgres": PostgresHoneypot,
    "ldap": LdapHoneypot,
    "ldaps": LdapsHoneypot,
    "rdp": RdpHoneypot,
    "rsync": RsyncHoneypot,
}

TLS_MODULES = {"https", "ldaps", "rdp"}

_random = random.Random(1337)  # same bytes on every run

PAYLOADS = {
    "random bytes": _random.randbytes(512),
    "single NUL": b"\x00",
    "truncated TLS ClientHello": b"\x16\x03\x01\x02\x00\x01",
    "truncated TPKT": b"\x03\x00\x00",
    "BER with a 4 GiB length": b"\x30\x84\xff\xff\xff\xff\x02\x01",
    "postgres SSLRequest": b"\x00\x00\x00\x08\x04\xd2\x16\x2f",
    "length field larger than packet": b"\xff\xff\xff\x7f" + b"A" * 16,
    "70 KB line": b"A" * 70_000 + b"\r\n",
    "1 MiB random": _random.randbytes(1 << 20),
    "invalid UTF-8 line": b"USER \xff\xfe\xfd\r\n",
}


def service_config(name):
    """The module's entry from the shipped trapster.conf, with the global keys
    TrapsterManager merges in."""
    global_vars = {k: SHIPPED_CONFIG[k] for k in ("hostname", "domain", "trusted_proxies")}
    return {**global_vars, **SHIPPED_CONFIG["services"][name][0]}


class MalformedInputTests(HoneypotTestCase):
    async def test_every_tcp_module_survives_malformed_input(self):
        """Garbage, truncated and oversized input never crashes a module or stops its server."""
        for name, honeypot_class in TCP_MODULES.items():
            with self.subTest(module=name):
                self.loop_errors.clear()
                config = service_config(name)
                if name in TLS_MODULES:
                    config.update(self.tls_paths(name))
                honeypot, port = await self.start_honeypot(
                    honeypot_class, config, RecordingLogger())

                # All payloads at once, plus clients that hang up right away.
                await asyncio.gather(
                    *(exchange(port, payload, read_timeout=0.3) for payload in PAYLOADS.values()),
                    *(exchange(port, close_right_away=True) for _ in range(5)),
                )

                # Still serving: the server task is alive and a new client connects.
                self.assertFalse(honeypot.task.done(), f"{name} server task stopped")
                await exchange(port, read_timeout=0.3)
                self.assertNoLoopErrors()

    async def test_dns_drops_short_and_truncated_udp_packets(self):
        """Truncated DNS packets are dropped without an error and without an event."""
        logger = RecordingLogger()
        honeypot, port = await self.start_honeypot(
            DnsHoneypot, service_config("dns"), logger, udp=True)
        query = bytes.fromhex("123401000001000000000000") + b"\x03www\x00\x00\x01\x00\x01"
        packets = [b"", b"\x00", query[:11], query[:15], query[:-2]]
        # A plain socket: asyncio's sendto() silently skips empty datagrams.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            for packet in packets:
                sock.sendto(packet, (HOST, port))
        await asyncio.sleep(0.3)

        self.assertFalse(honeypot.task.done())
        self.assertEqual(logger.events, [])
        self.assertNoLoopErrors()
