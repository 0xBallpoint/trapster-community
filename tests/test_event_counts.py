"""Each action creates the right number of events.

The events are what the console shows and what alerts are built on: one
attacker action must give one alert, not zero and not five.
"""

import asyncio
import base64
import ftplib
import ssl
import struct
from collections import Counter

import asyncssh
from scapy.asn1.asn1 import ASN1_OID
from scapy.layers.snmp import SNMP, SNMPget, SNMPvarbind

from trapster.modules import (
    DnsHoneypot,
    FtpHoneypot,
    HttpHoneypot,
    LdapHoneypot,
    LdapsHoneypot,
    MssqlHoneypot,
    MysqlHoneypot,
    PostgresHoneypot,
    RsyncHoneypot,
    SnmpHoneypot,
    SshHoneypot,
    TelnetHoneypot,
    VncHoneypot,
)

from .helpers import HOST, HoneypotTestCase, RecordingLogger, converse, exchange, raw_http
from .test_ftp import ftp_login
from .test_malformed_input import TCP_MODULES, service_config
from .test_mysql import login_packet

DNS_QUERY = bytes.fromhex("123401000001000000000000") + b"\x03www\x07example\x03com\x00\x00\x01\x00\x01"
SNMP_GET = bytes(SNMP(community="public", PDU=SNMPget(
    varbindlist=[SNMPvarbind(oid=ASN1_OID("1.3.6.1.2.1.1.1.0"))])))


def counts(logger):
    """Events per kind: {'connection': 1, 'data': 2, 'login': 1}."""
    return Counter(logtype.rsplit(".", 1)[1] for logtype in logger.logtypes())


def logins(logger):
    return [event["extra"] for event in logger.events if event["logtype"].endswith(".login")]


def ber(tag, value):
    """BER TLV, short-form length only (enough for test messages)."""
    return bytes([tag, len(value)]) + value


def ldap_simple_bind(dn, password):
    bind = ber(0x60, ber(0x02, b"\x03") + ber(0x04, dn) + ber(0x80, password))
    return ber(0x30, ber(0x02, b"\x01") + bind)


def mssql_login7(username, password):
    """TDS LOGIN7 with only the username and password set. The password is
    obfuscated like a real client does it: swap nibbles, then XOR 0xA5."""
    user = username.encode("utf-16-le")
    secret = bytes((((b << 4) & 0xF0) | (b >> 4)) ^ 0xA5 for b in password.encode("utf-16-le"))
    body = bytearray(94)
    struct.pack_into("<HHHH", body, 40, 94, len(username), 94 + len(user), len(password))
    body += user + secret
    struct.pack_into("<I", body, 0, len(body))
    return struct.pack(">BBHHBB", 0x10, 0x01, 8 + len(body), 0, 1, 0) + body


def postgres_login(username, password):
    params = b"user\x00" + username + b"\x00database\x00postgres\x00\x00"
    startup = struct.pack("!I", 196608) + params
    password_message = password + b"\x00"
    return [
        b"\x00\x00\x00\x08\x04\xd2\x16\x2f",  # SSLRequest, refused with 'N'
        struct.pack("!I", len(startup) + 4) + startup,
        b"p" + struct.pack("!I", len(password_message) + 4) + password_message,
    ]


def basic_auth(username, password):
    return "Authorization: Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()


async def send_udp(port, *packets):
    transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
        asyncio.DatagramProtocol, remote_addr=(HOST, port))
    try:
        for packet in packets:
            transport.sendto(packet)
        await asyncio.sleep(0.3)
    finally:
        transport.close()


class ThreePasswords(asyncssh.SSHClient):
    """Tries three passwords on one connection, like a brute-force tool."""

    def __init__(self):
        self.passwords = iter(["first", "second", "third"])

    def password_auth_requested(self):
        return next(self.passwords, None)


def ftp_three_logins(port):
    with ftplib.FTP() as ftp:
        ftp.connect(HOST, port, timeout=5)
        for password in ("first", "second", "third"):
            try:
                ftp.login("root", password)
            except ftplib.error_perm:
                pass


class ConnectionEventTests(HoneypotTestCase):
    async def test_bare_connect_gives_one_connection_event(self):
        """A port scan (connect, send nothing, close) gives exactly one connection event per module."""
        for name, honeypot_class in TCP_MODULES.items():
            if name in ("http", "https", "ldaps"):
                continue  # one event per request / per TLS session, see below
            with self.subTest(module=name):
                logger = RecordingLogger()
                _, port = await self.start_honeypot(honeypot_class, service_config(name), logger)

                await exchange(port, close_right_away=True)
                await asyncio.sleep(0.2)

                self.assertEqual(logger.logtypes(), [f"{name}.connection"])
        self.assertNoLoopErrors()

    async def test_ldaps_logs_the_connection_once_tls_is_up(self):
        """LDAPS logs its connection under its own name, ldaps, once the TLS handshake is done."""
        logger = RecordingLogger()
        _, port = await self.start_honeypot(
            LdapsHoneypot,
            {**service_config("ldaps"), **self.tls_paths("ldaps")}, logger)
        client_tls = ssl.create_default_context()
        client_tls.check_hostname = False
        client_tls.verify_mode = ssl.CERT_NONE

        _, writer = await asyncio.open_connection(HOST, port, ssl=client_tls)
        writer.close()
        await asyncio.sleep(0.2)

        self.assertEqual(logger.logtypes(), ["ldaps.connection"])

    async def test_http_bare_connect_gives_no_event(self):
        """HTTP logs requests, not connections: a connect without a request gives no event."""
        logger = RecordingLogger()
        _, port = await self.start_honeypot(HttpHoneypot, service_config("http"), logger)

        await exchange(port, close_right_away=True)
        await asyncio.sleep(0.2)

        self.assertEqual(logger.events, [])


class LoginEventTests(HoneypotTestCase):
    """One failed login on the modules not covered by test_ftp, test_ssh and test_mysql."""

    async def assertOneLogin(self, honeypot_class, config, payloads, expected_login,
                             greeting_timeout=None, extra_counts=None):
        logger = RecordingLogger()
        _, port = await self.start_honeypot(honeypot_class, config, logger)

        await converse(port, payloads, greeting_timeout=greeting_timeout)
        await asyncio.sleep(0.2)

        found = counts(logger)
        self.assertEqual((found["connection"], found["login"]), (1, 1), logger.logtypes())
        for kind, expected in (extra_counts or {}).items():
            self.assertEqual(found[kind], expected, logger.logtypes())
        login = logins(logger)[0]
        self.assertEqual({key: login[key] for key in expected_login}, expected_login)
        self.assertNoLoopErrors()

    async def test_telnet_typed_one_key_at_a_time(self):
        """A terminal in character mode sends each key separately; the credentials are rebuilt."""
        keys = [bytes([key]) for key in b"admin"] + [b"\r\n"] + \
               [bytes([key]) for key in b"cisco"] + [b"\r\n"]
        await self.assertOneLogin(TelnetHoneypot, service_config("telnet"), keys,
                                  {"username": "admin", "password": "cisco"})

    async def test_telnet_typed_one_line_at_a_time(self):
        """Bots and line-mode clients send a whole line per packet; the credentials are kept."""
        await self.assertOneLogin(TelnetHoneypot, service_config("telnet"),
                                  [b"admin\r\n", b"cisco\r\n"],
                                  {"username": "admin", "password": "cisco"})

    async def test_telnet_line_endings(self):
        """Every common line ending, in one packet or split over two, gives the same credentials."""
        cases = {
            "whole login in one packet": [b"admin\r\ncisco\r\n"],
            "CR NUL endings": [b"admin\r\x00", b"cisco\r\x00"],
            "CR and LF in separate packets": [b"admin", b"\r", b"\n", b"cisco", b"\r", b"\n"],
            "bare LF": [b"admin\n", b"cisco\n"],
        }
        for case, payloads in cases.items():
            with self.subTest(case):
                await self.assertOneLogin(TelnetHoneypot, service_config("telnet"), payloads,
                                          {"username": "admin", "password": "cisco"})

    async def test_telnet_password_only_prompt(self):
        """Profiles that only ask for a password log that password with an empty username."""
        await self.assertOneLogin(TelnetHoneypot, {"version": "HP JetDirect printer telnetd"}, [b"hunter2\r\n"],
                                  {"username": "", "password": "hunter2"})

    async def test_postgres(self):
        """A cleartext password login gives one connection and one login event."""
        await self.assertOneLogin(PostgresHoneypot, service_config("postgres"),
                                  postgres_login(b"postgres", b"hunter2"),
                                  {"username": "postgres", "password": "hunter2"})

    async def test_vnc(self):
        """A VNC authentication gives one login event with the client's challenge response."""
        version = b"RFB 003.008\n"
        await self.assertOneLogin(VncHoneypot, service_config("vnc"),
                                  [version, b"\x02", b"\xaa" * 16],
                                  {"response": "aa" * 8})

    async def test_mssql(self):
        """A LOGIN7 packet gives one login event with the decoded username and password."""
        await self.assertOneLogin(MssqlHoneypot, service_config("mssql"),
                                  [mssql_login7("sa", "hunter2")],
                                  {"username": "sa", "password": "hunter2"})

    async def test_ldap_simple_bind(self):
        """An LDAP simple bind gives one login event with the bind DN and password."""
        await self.assertOneLogin(LdapHoneypot, service_config("ldap"),
                                  [ldap_simple_bind(b"cn=admin,dc=corp", b"hunter2")],
                                  {"username": "cn=admin,dc=corp", "password": "hunter2"})

    async def test_rsync_module_then_login(self):
        """Asking for a module is a query event and the authentication line a login event."""
        await self.assertOneLogin(RsyncHoneypot, service_config("rsync"),
                                  [b"@RSYNCD: 31.0\n", b"Backup\n", b"root 0123abcd\n"],
                                  {"username": "root", "password": "0123abcd"},
                                  greeting_timeout=1.0, extra_counts={"query": 1})


class RepeatedLoginTests(HoneypotTestCase):
    async def test_ssh_three_passwords_on_one_connection(self):
        """Brute-force tools try several passwords per connection: each attempt is one login event."""
        logger = RecordingLogger()
        _, port = await self.start_honeypot(SshHoneypot, {}, logger)

        with self.assertRaises(asyncssh.PermissionDenied):
            await asyncssh.connect(HOST, port, username="root", known_hosts=None,
                                   preferred_auth="password", client_factory=ThreePasswords)
        await asyncio.sleep(0.1)

        self.assertEqual(logger.logtypes(), ["ssh.connection"] + ["ssh.login"] * 3)
        self.assertEqual([login["password"] for login in logins(logger)],
                         ["first", "second", "third"])
        self.assertNoLoopErrors()

    async def test_ftp_three_logins_on_one_connection(self):
        """Each USER/PASS attempt on one FTP connection is its own login event."""
        logger = RecordingLogger()
        _, port = await self.start_honeypot(FtpHoneypot, service_config("ftp"), logger)

        await asyncio.to_thread(ftp_three_logins, port)
        await asyncio.sleep(0.1)

        found = counts(logger)
        self.assertEqual((found["connection"], found["login"]), (1, 3), logger.logtypes())
        self.assertEqual([login["password"] for login in logins(logger)],
                         ["first", "second", "third"])
        self.assertNoLoopErrors()


    async def test_telnet_hangs_up_after_one_failed_login(self):
        """Telnet closes the connection after one failed login, without prompting again."""
        logger = RecordingLogger()
        _, port = await self.start_honeypot(TelnetHoneypot, service_config("telnet"), logger)

        replies = await converse(port, [b"admin\r\n", b"first\r\n", b"admin\r\n", b"second\r\n"])
        await asyncio.sleep(0.1)

        self.assertEqual(logger.logtypes(), ["telnet.connection", "telnet.login"])
        self.assertEqual(logins(logger)[0]["password"], "first")
        # The failure message, then the connection is closed: no second prompt.
        self.assertEqual(replies[2], b"\r\n% Login invalid\r\n\r\n")
        self.assertEqual(b"".join(replies[3:]), b"")
        self.assertNoLoopErrors()

    async def test_telnet_logs_only_the_first_login_of_a_packet(self):
        """Logins sent after the first one in the same packet are not processed: the connection is closed."""
        logger = RecordingLogger()
        _, port = await self.start_honeypot(TelnetHoneypot, service_config("telnet"), logger)

        await converse(port, [b"a\r\n1\r\nb\r\n2\r\n"])
        await asyncio.sleep(0.1)

        self.assertEqual([(login["username"], login["password"]) for login in logins(logger)],
                         [("a", "1")])
        self.assertNoLoopErrors()


class HttpEventTests(HoneypotTestCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.logger = RecordingLogger()
        _, self.port = await self.start_honeypot(HttpHoneypot, service_config("http"), self.logger)

    async def request(self, *args, **kwargs):
        self.logger.events.clear()
        await raw_http(self.port, *args, **kwargs)
        await asyncio.sleep(0.1)
        self.assertEqual(len(self.logger.events), 1, self.logger.logtypes())
        return self.logger.events[0]

    async def test_plain_request_is_one_query_event(self):
        """A plain GET is a single query event, with no credentials."""
        event = await self.request("GET / HTTP/1.1")

        self.assertEqual(event["logtype"], "http.query")
        self.assertNotIn("username", event["extra"])

    async def test_basic_auth_is_one_login_event_with_the_credentials(self):
        """Basic auth credentials are decoded into the request's single login event."""
        event = await self.request("GET / HTTP/1.1", headers=[basic_auth("admin", "hunter2")])

        self.assertEqual(event["logtype"], "http.login")
        self.assertEqual((event["extra"]["username"], event["extra"]["password"]),
                         ("admin", "hunter2"))

    async def test_form_post_is_one_login_event_with_the_credentials(self):
        """Login form fields are extracted into the request's single login event, raw body included."""
        body = b"username=admin&password=hunter2"
        event = await self.request(
            "POST /api/v1/login HTTP/1.1",
            headers=["Content-Type: application/x-www-form-urlencoded"], body=body)

        self.assertEqual(event["logtype"], "http.login")
        self.assertEqual((event["extra"]["username"], event["extra"]["password"]),
                         ("admin", "hunter2"))
        self.assertEqual(bytes.fromhex(event["data"]), body)


class UdpEventTests(HoneypotTestCase):
    async def test_dns_query_is_one_event(self):
        """One DNS query gives one query event with the decoded domain name."""
        logger = RecordingLogger()
        _, port = await self.start_honeypot(DnsHoneypot, service_config("dns"), logger, udp=True)

        await send_udp(port, DNS_QUERY)

        self.assertEqual(logger.logtypes(), ["dns.query"])
        question = logger.events[0]["extra"]["query"]["questions"][0]
        self.assertEqual(question["domain_name"], ["www", "example", "com"])
        self.assertNoLoopErrors()

    async def test_snmp_get_is_one_event(self):
        """One SNMP GET gives one query event with the community string and OID."""
        logger = RecordingLogger()
        _, port = await self.start_honeypot(SnmpHoneypot, service_config("snmp"), logger, udp=True)

        await send_udp(port, SNMP_GET)

        self.assertEqual(logger.logtypes(), ["snmp.query"])
        extra = logger.events[0]["extra"]
        self.assertEqual((extra["community"], extra["varbind"]), ("public", "1.3.6.1.2.1.1.1.0"))
        self.assertNoLoopErrors()


class WhitelistTests(HoneypotTestCase):
    async def test_whitelisted_ip_creates_no_event(self):
        """Traffic from a whitelisted IP is never logged, whichever way the module reads the source."""
        # One logger for every module: each code path builds the source
        # address differently (transport, HTTP scope, UDP datagram).
        logger = RecordingLogger(whitelist_ips=[HOST])
        _, ftp_port = await self.start_honeypot(FtpHoneypot, service_config("ftp"), logger)
        _, mysql_port = await self.start_honeypot(MysqlHoneypot, {}, logger)
        _, http_port = await self.start_honeypot(HttpHoneypot, service_config("http"), logger)
        _, dns_port = await self.start_honeypot(DnsHoneypot, service_config("dns"), logger, udp=True)
        _, snmp_port = await self.start_honeypot(SnmpHoneypot, service_config("snmp"), logger, udp=True)

        await asyncio.to_thread(ftp_login, ftp_port, "root", "toor")
        await exchange(mysql_port, login_packet())
        await raw_http(http_port, "GET / HTTP/1.1", headers=[basic_auth("admin", "hunter2")])
        await send_udp(dns_port, DNS_QUERY)
        await send_udp(snmp_port, SNMP_GET)

        self.assertEqual(logger.events, [])
        self.assertNoLoopErrors()


class ConcurrencyTests(HoneypotTestCase):
    async def test_twenty_mysql_clients_at_once(self):
        """Concurrent clients do not mix up their events: each login is tied to its own connection."""
        logger = RecordingLogger()
        _, port = await self.start_honeypot(MysqlHoneypot, {}, logger)
        usernames = [f"user{i}" for i in range(20)]

        await asyncio.gather(*(exchange(port, login_packet(username=name.encode()))
                               for name in usernames))
        await asyncio.sleep(0.2)

        self.assertEqual(counts(logger), {"connection": 20, "data": 20, "login": 20})
        self.assertEqual(sorted(login["username"] for login in logins(logger)), sorted(usernames))
        # Every login is tied to its own connection.
        connection_ports = {e["src_port"] for e in logger.events if e["logtype"] == "mysql.connection"}
        login_ports = {e["src_port"] for e in logger.events if e["logtype"] == "mysql.login"}
        self.assertEqual(len(connection_ports), 20)
        self.assertEqual(login_ports, connection_ports)
        self.assertNoLoopErrors()

    async def test_twenty_http_clients_at_once(self):
        """Concurrent HTTP requests give exactly one event each."""
        logger = RecordingLogger()
        _, port = await self.start_honeypot(HttpHoneypot, service_config("http"), logger)

        await asyncio.gather(*(raw_http(port, f"GET /?client={i} HTTP/1.1") for i in range(20)))
        await asyncio.sleep(0.2)

        self.assertEqual(logger.logtypes(), ["http.query"] * 20)
        self.assertEqual(sorted(e["extra"]["target"] for e in logger.events),
                         sorted(f"/?client={i}" for i in range(20)))
