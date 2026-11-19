"""SSH honeypot driven by a real asyncssh client."""

import asyncio

import asyncssh

from trapster.modules.ssh import SshHoneypot

from .helpers import HOST, HoneypotTestCase, RecordingLogger


class SshLoginTests(HoneypotTestCase):
    async def test_failed_password_login_is_refused_and_logged(self):
        """A real SSH client's password login is refused and its credentials are logged."""
        logger = RecordingLogger()
        _, port = await self.start_honeypot(SshHoneypot, {}, logger)

        with self.assertRaises(asyncssh.PermissionDenied):
            await asyncssh.connect(HOST, port, username="invalid_user",
                                   password="invalid_pass", known_hosts=None,
                                   preferred_auth="password")
        await asyncio.sleep(0.1)

        self.assertEqual(logger.logtypes(), ["ssh.connection", "ssh.login"])
        self.assertEqual(logger.events[-1]["extra"],
                         {"username": "invalid_user", "password": "invalid_pass"})
        self.assertNoLoopErrors()
