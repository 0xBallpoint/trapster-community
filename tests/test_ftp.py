"""FTP honeypot driven by the standard library client."""

import asyncio
import ftplib

from trapster.modules.ftp import FtpHoneypot

from .helpers import HOST, HoneypotTestCase, RecordingLogger


def ftp_login(port, username, password):
    """Log in with ftplib; returns the server's refusal."""
    with ftplib.FTP() as ftp:
        ftp.connect(HOST, port, timeout=5)
        try:
            ftp.login(username, password)
        except ftplib.error_perm as refusal:
            return str(refusal)
    return None


class FtpLoginTests(HoneypotTestCase):
    async def test_failed_login_logs_one_event_per_step(self):
        """A real FTP client's failed login logs each command, then one login event with the credentials."""
        logger = RecordingLogger()
        _, port = await self.start_honeypot(
            FtpHoneypot, {"banner": "Microsoft FTP Service"}, logger)

        refusal = await asyncio.to_thread(ftp_login, port, "username", "randompass")
        await asyncio.sleep(0.1)

        self.assertEqual(refusal, "530 User cannot log in.")
        # One data event per command (USER, PASS, then QUIT sent by ftplib on
        # close), and the login event right after PASS.
        self.assertEqual(logger.logtypes(),
                         ["ftp.connection", "ftp.data", "ftp.data", "ftp.login", "ftp.data"])
        commands = [bytes.fromhex(e["data"]) for e in logger.events if e["logtype"] == "ftp.data"]
        self.assertEqual(commands, [b"USER username\r\n", b"PASS randompass\r\n", b"QUIT\r\n"])
        login = logger.events[3]
        self.assertEqual(login["extra"], {"username": "username", "password": "randompass"})
        self.assertEqual((login["dst_ip"], login["dst_port"]), (HOST, port))
        self.assertEqual(login["src_ip"], HOST)
        self.assertNoLoopErrors()

    async def test_unix_banner_gives_the_unix_refusal(self):
        """A Unix FTP banner answers a failed login with the Unix server's message, not the Windows one."""
        _, port = await self.start_honeypot(
            FtpHoneypot, {"banner": "vsFTPd 3.0.3"}, RecordingLogger())

        refusal = await asyncio.to_thread(ftp_login, port, "root", "toor")

        self.assertEqual(refusal, "530 Login incorrect.")
