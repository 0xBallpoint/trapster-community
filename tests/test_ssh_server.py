import pytest
import asyncio
import asyncssh
from trapster.modules.ssh import SshHoneypot
from trapster.logger import JsonLogger

from .base import BaseServerTest


class SSHTest(BaseServerTest):
    async def connect_and_login(self, port, username="invalid_user", password="invalid_pass"):
        try:
            async with asyncssh.connect(self.bindaddr, port, username=username, password=password, known_hosts=None) as conn:
                # If login succeeds, it's a failure in the test
                pytest.fail("Expected authentication to fail, but it succeeded")
        except asyncssh.PermissionDenied:
            print("Authentication failed as expected")
            # Authentication failed as expected; this is the desired outcome
            return True
        except Exception as e:
            pytest.fail(f"Unexpected error occurred: {e}")
            return False

    async def run_test(self):
        await self.connect_and_login(self.service_config['port'])


@pytest.mark.asyncio
async def test_ssh_authentication_failed():
    service_config = {
        'port': 2222,
    }
    logger = JsonLogger('trapster-1')

    # Initialize the SSH-specific test
    ssh_test = SSHTest(SshHoneypot, service_config, logger)

    # Start the server
    await ssh_test.start_server()

    try:
        # Run the SSH-specific test logic
        await ssh_test.run_test()
    finally:
        # Stop the server
        await ssh_test.stop_server()