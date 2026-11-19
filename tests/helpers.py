"""Shared test helpers.

Honeypots run for real on 127.0.0.1, on a free port, and log through a
RecordingLogger: a real BaseLogger that keeps every event, so the event
format and count are checked instead of being hidden behind a MagicMock.
"""

import asyncio
import socket
import ssl
import tempfile
import unittest
from pathlib import Path

from trapster.logger.base import BaseLogger

HOST = "127.0.0.1"


class RecordingLogger(BaseLogger):
    """Keeps every event parse_log() produces, after the whitelist check."""

    def __init__(self, node_id="trapster-test", whitelist_ips=()):
        super().__init__(node_id)
        self.whitelist_ips = list(whitelist_ips)
        self.events = []

    def log(self, logtype, transport, data='', extra=None):
        if extra is None:
            extra = {}
        event = self.parse_log(logtype, transport, data, extra)
        if event:
            self.events.append(event)
        return event

    def logtypes(self):
        return [event["logtype"] for event in self.events]


def free_port(kind=socket.SOCK_STREAM):
    """A port nothing listens on right now. Fixed ports clash in CI."""
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind((HOST, 0))
        return sock.getsockname()[1]


class HoneypotTestCase(unittest.IsolatedAsyncioTestCase):
    """Starts honeypots for one test and stops them afterwards.

    Exceptions that escape a protocol callback do not reach the test: asyncio
    hands them to the loop's exception handler and closes the connection. They
    are collected in self.loop_errors so a test can assert there were none.
    """

    async def asyncSetUp(self):
        self.loop_errors = []
        asyncio.get_running_loop().set_exception_handler(
            lambda loop, context: self.loop_errors.append(context))
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))

    def tls_paths(self, name):
        """key/certificate config values pointing at a per-test directory, so
        generated certificates never land in the repository."""
        return {"key": str(self.tmp / name / "key.pem"),
                "certificate": str(self.tmp / name / "certificate.pem")}

    async def start_honeypot(self, honeypot_class, config, logger, udp=False, prepare=None):
        """Start honeypot_class on a free port; returns (honeypot, port).
        prepare(honeypot), if given, runs before the server starts."""
        port = free_port(socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
        honeypot = honeypot_class({**config, "port": port}, logger, bindaddr=HOST)
        if prepare:
            prepare(honeypot)
        await honeypot.start()
        self.addAsyncCleanup(honeypot.stop)
        if udp:
            # A UDP port cannot be probed without sending a datagram (which
            # would be logged): give the server task time to bind it.
            await asyncio.sleep(0.1)
        else:
            await wait_until_listening(port)
            # The readiness probe is itself a connection: drop its events.
            await asyncio.sleep(0.1)
            logger.events.clear()
        return honeypot, port

    def assertNoLoopErrors(self):
        # A client hanging up during the TLS or SSH handshake is reported by
        # asyncio itself, not by trapster code: TrapsterManager drops the
        # ssl.SSLError ones, the resets are the client's doing.
        errors = [c for c in self.loop_errors
                  if not isinstance(c.get("exception"), (ssl.SSLError, ConnectionError))]
        messages = [f"{c.get('message')}: {c.get('exception')!r}" for c in errors]
        self.assertEqual(messages, [], "exception escaped a protocol callback")


async def wait_until_listening(port, max_wait=10):
    loop = asyncio.get_running_loop()
    deadline = loop.time() + max_wait
    while True:
        try:
            _, writer = await asyncio.open_connection(HOST, port)
        except OSError:
            if loop.time() > deadline:
                raise TimeoutError(f"nothing listening on {HOST}:{port}") from None
            await asyncio.sleep(0.05)
            continue
        writer.close()
        await writer.wait_closed()
        return


async def exchange(port, payload=b"", read_timeout=0.5, close_right_away=False):
    """Connect, read the greeting, send payload, read the reply, close.
    Returns everything the server sent."""
    reader, writer = await asyncio.open_connection(HOST, port)
    received = b""
    try:
        if close_right_away:
            return received
        received += await read_for(reader, read_timeout)
        if payload:
            writer.write(payload)
            await writer.drain()
            received += await read_for(reader, read_timeout)
    except (ConnectionError, OSError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass
    return received


async def converse(port, payloads, read_timeout=0.3, greeting_timeout=None):
    """Connect, read the greeting, then send each payload in turn and read the
    reply, like a client typing one line at a time. Returns the replies, the
    greeting first."""
    reader, writer = await asyncio.open_connection(HOST, port)
    replies = []
    try:
        replies.append(await read_for(reader, greeting_timeout or read_timeout))
        for payload in payloads:
            writer.write(payload)
            await writer.drain()
            replies.append(await read_for(reader, read_timeout))
    except (ConnectionError, OSError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass
    return replies


async def read_for(reader, seconds):
    """Read whatever arrives within `seconds` (servers that wait for more
    input never close the connection themselves)."""
    data = b""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + seconds
    while (remaining := deadline - loop.time()) > 0:
        try:
            chunk = await asyncio.wait_for(reader.read(65536), remaining)
        except TimeoutError:
            break
        if not chunk:
            break
        data += chunk
    return data


async def raw_http(port, request_line, headers=(), body=b"", host="test"):
    """Send an HTTP/1.1 request byte for byte (httpx would normalize the
    path). Returns (status, headers, body)."""
    lines = [request_line, f"Host: {host}"] + list(headers)
    if body:
        lines.append(f"Content-Length: {len(body)}")
    lines += ["Connection: close", "", ""]
    reader, writer = await asyncio.open_connection(HOST, port)
    writer.write("\r\n".join(lines).encode("latin1") + body)
    await writer.drain()
    response = await reader.read()
    writer.close()
    head, _, content = response.partition(b"\r\n\r\n")
    status_line, *header_lines = head.decode("latin1").split("\r\n")
    response_headers = {}
    for line in header_lines:
        name, _, value = line.partition(":")
        response_headers[name.strip().lower()] = value.strip()
    if response_headers.get("transfer-encoding") == "chunked":
        content = dechunk(content)
    return int(status_line.split()[1]), response_headers, content


def dechunk(data):
    body = b""
    while data:
        size_line, _, data = data.partition(b"\r\n")
        size = int(size_line.split(b";")[0], 16)
        if size == 0:
            break
        body, data = body + data[:size], data[size + 2:]
    return body
