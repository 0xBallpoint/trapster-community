"""MySQL login handling with raw handshake packets."""

import asyncio
import struct

from trapster.modules.mysql import MysqlHoneypot

from .helpers import HoneypotTestCase, RecordingLogger, exchange

CLIENT_PROTOCOL_41 = 0x00000200


def login_packet(username=b"root", password=b"\x01\x02\x03"):
    """HandshakeResponse41: capabilities, max packet size, charset, 23 filler
    bytes, then username, password and auth plugin."""
    payload = (struct.pack("<I", CLIENT_PROTOCOL_41) + struct.pack("<I", 1 << 24)
               + b"\x21" + b"\x00" * 23
               + username + b"\x00" + bytes([len(password)]) + password
               + b"mysql_native_password\x00")
    return struct.pack("<I", len(payload))[:3] + b"\x01" + payload


class MysqlLoginTests(HoneypotTestCase):
    async def start(self):
        self.logger = RecordingLogger()
        _, port = await self.start_honeypot(MysqlHoneypot, {}, self.logger)
        return port

    async def test_login_is_refused_and_logged(self):
        """A client login is refused like a real MySQL server and its credentials are logged."""
        port = await self.start()

        reply = await exchange(port, login_packet())
        await asyncio.sleep(0.1)

        self.assertIn(b"\xff\x15\x04#28000Access denied for user 'root'", reply)
        self.assertEqual(logger_types := self.logger.logtypes(),
                         ["mysql.connection", "mysql.data", "mysql.login"], logger_types)
        extra = self.logger.events[-1]["extra"]
        self.assertEqual((extra["username"], extra["password"]), ("root", "010203"))
        self.assertNoLoopErrors()

    async def test_malformed_login_gets_bad_handshake_and_no_login_event(self):
        """A broken login packet gets MySQL's Bad handshake error instead of crashing the handler."""
        port = await self.start()
        packets = [
            login_packet()[:40],                                   # cut inside the username
            login_packet(username=b"root")[:0x24 + 5],             # NUL is the last byte
            struct.pack("<I", CLIENT_PROTOCOL_41) * 4,             # no username at all
        ]
        for packet in packets:
            with self.subTest(packet=packet):
                self.logger.events.clear()
                reply = await exchange(port, packet)
                await asyncio.sleep(0.1)
                self.assertIn(b"\xff\x13\x04#08S01Bad handshake", reply)
                self.assertEqual(self.logger.logtypes(), ["mysql.connection", "mysql.data"])
        self.assertNoLoopErrors()
