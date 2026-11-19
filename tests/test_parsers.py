"""Parsers of attacker-supplied bytes.

Each parser gets every truncation of a valid message, random bit flips of it,
and random bytes. It must answer within a time limit and only fail the way its
caller expects (the caller's except clause is the contract).
"""

import random
import struct
import threading
import unittest

from pyasn1.codec.ber import encoder

from trapster.libs import dns, ldapasn1, ntlm
from trapster.modules.ldap import LdapProtocol
from trapster.modules.rdp import RdpProtocol

from .helpers import RecordingLogger

TIME_LIMIT = 2  # seconds, per input


def mutations(valid, seed):
    """Every truncation, 200 single-byte corruptions, and 200 random inputs."""
    rng = random.Random(seed)
    yield from (valid[:n] for n in range(len(valid)))
    for _ in range(200):
        data = bytearray(valid)
        data[rng.randrange(len(data))] = rng.randrange(256)
        yield bytes(data)
    for _ in range(200):
        yield rng.randbytes(rng.randrange(0, 128))


def call_with_time_limit(test, function, data):
    """Run function(data) in a thread; fail the test if it hangs. Returns
    (result, exception)."""
    outcome = {}

    def target():
        try:
            outcome["result"] = function(data)
        except BaseException as exc:
            outcome["exception"] = exc

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    thread.join(TIME_LIMIT)
    if thread.is_alive():
        test.fail(f"{function.__qualname__} still running after {TIME_LIMIT}s on {data!r}")
    return outcome.get("result"), outcome.get("exception")


def dns_query(name="www.corp.local"):
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return struct.pack("!6H", 0x1234, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!2H", 1, 1)


def ntlm_type3(username="alice", domain="CORP"):
    user, dom = username.encode("utf-16-le"), domain.encode("utf-16-le")
    nt_response = bytes(range(48))
    header = 72
    nt_off, dom_off = header, header + len(nt_response)
    user_off = dom_off + len(dom)
    return (b"NTLMSSP\x00" + struct.pack("<I", 3)
            + struct.pack("<HHI", 0, 0, header)                         # LM response
            + struct.pack("<HHI", len(nt_response), len(nt_response), nt_off)
            + struct.pack("<HHI", len(dom), len(dom), dom_off)
            + struct.pack("<HHI", len(user), len(user), user_off)
            + struct.pack("<HHI", 0, 0, header)                         # workstation
            + struct.pack("<HHI", 0, 0, header)                         # session key
            + struct.pack("<I", 0x01)                                   # flags: unicode
            + b"\x00" * 8                                               # version
            + nt_response + dom + user)


def ldap_simple_bind(name="cn=admin,dc=corp,dc=local", password="secret"):
    message = ldapasn1.LDAPMessage()
    message["messageID"] = 1
    bind = message["protocolOp"].getComponentByName("bindRequest")
    bind["version"] = 3
    bind["name"] = name
    bind["authentication"]["simple"] = password
    return encoder.encode(message)


class FakeTransport:
    def __init__(self):
        self.written = []

    def get_extra_info(self, name, default=None):
        return {"sockname": ("127.0.0.1", 389), "peername": ("127.0.0.2", 50000)}.get(name, default)

    def write(self, data):
        self.written.append(data)

    def close(self):
        pass


class ParserTests(unittest.TestCase):
    def test_dns_decoder_only_raises_what_the_udp_handler_catches(self):
        """Mutated DNS packets only raise the errors the DNS module expects, so none escapes."""
        self.assertEqual(dns.decode_dns_message(dns_query())["questions"][0]["domain_name"],
                         ["www", "corp", "local"])
        # DnsUdpProtocol.datagram_received catches (ValueError, IndexError).
        for data in mutations(dns_query(), seed=1):
            _, exc = call_with_time_limit(self, dns.decode_dns_message, data)
            if exc is not None and not isinstance(exc, (ValueError, IndexError)):
                self.fail(f"{type(exc).__name__}: {exc} on {data!r}")

    def test_dns_compression_pointer_loop_terminates(self):
        """A DNS name that points to itself is rejected instead of looping forever."""
        looping = struct.pack("!6H", 1, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c" + struct.pack("!2H", 1, 1)
        _, exc = call_with_time_limit(self, dns.decode_dns_message, looping)
        self.assertIsInstance(exc, ValueError)

    def test_ntlm_helpers_never_raise(self):
        """The NTLM helpers return a value or None on any input, never an exception."""
        self.assertEqual(ntlm.parse_ntlm_type3(ntlm_type3()), ("alice", "CORP"))
        for data in mutations(ntlm_type3(), seed=2):
            for function in (ntlm.parse_ntlm_type3, ntlm.extract_ntlm):
                result, exc = call_with_time_limit(self, function, data)
                self.assertIsNone(exc, f"{function.__name__} raised {exc!r} on {data!r}")
            username, domain = ntlm.parse_ntlm_type3(data)
            self.assertIsInstance(username, str)
            self.assertIsInstance(domain, str)

    def test_rdp_ntlm_parser_returns_none_or_credentials(self):
        """The RDP NTLM parser returns credentials or None on any input."""
        protocol = RdpProtocol(config={})
        self.assertEqual(protocol._parse_ntlm_type3(ntlm_type3())["username"], "alice")
        for data in mutations(ntlm_type3(), seed=3):
            result, exc = call_with_time_limit(self, protocol._parse_ntlm_type3, data)
            self.assertIsNone(exc, f"raised {exc!r} on {data!r}")
            self.assertTrue(result is None or isinstance(result, dict))

    def test_ldap_handler_returns_on_any_input(self):
        """data_received loops while bytes remain: a parse that consumes
        nothing would spin forever."""
        def feed(data):
            protocol = LdapProtocol(config={})
            protocol.logger = RecordingLogger()
            protocol.connection_made(FakeTransport())
            protocol.data_received(data)

        _, exc = call_with_time_limit(self, feed, ldap_simple_bind())
        self.assertIsNone(exc)
        for data in mutations(ldap_simple_bind(), seed=4):
            _, exc = call_with_time_limit(self, feed, data)
            self.assertIsNone(exc, f"raised {exc!r} on {data!r}")
