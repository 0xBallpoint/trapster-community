import pytest
import asyncio
import socket
from unittest.mock import MagicMock

from trapster.modules.ftp import FtpHoneypot
from trapster.logger import JsonLogger

from .base import BaseServerTest

class FTPTest(BaseServerTest):
    def connect_and_login(self, port, username="username", password="randompass"):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            # Connect to the FTP server
            sock.connect((self.bindaddr, port))  

            # Read initial response
            response = sock.recv(1024).decode('utf-8')
            self.assert_response(response, 220, f"{self.service_config['banner']}\r\n")

            # Send USER command
            sock.sendall(f'USER {username}\r\n'.encode())
            response = sock.recv(1024).decode('utf-8')
            self.assert_response(response, 331, f"User {username} OK. Password required\r\n")

            # Send PASS command
            sock.sendall(f'PASS {password}\r\n'.encode())
            response = sock.recv(1024).decode('utf-8')
            self.assert_response(response, 530, "Authentication Failed\r\n")

    def assert_response(self, response, expected_code, expected_message):
        assert response.startswith(f'{expected_code}'), f"Expected {expected_code} response, got {response[:3]}"
        assert expected_message in response, f"Expected message '{expected_message}', got '{response.strip()}'"

    def validate_logger_output(self):
        """
        Validates the logger output by checking the arguments passed to the mocked log method.
        """
        # Mock the return values of the log method
        mock_return_value = {"type": "mocked_event", "extra": {}}
        self.logger.log.return_value = mock_return_value

        # After running the test, check that log was called the expected number of times
        assert self.logger.log.call_count == 4, "Expected four log entries"

        # check that extra contains the username/password
        connection_args = self.logger.log.call_args_list[3]          
        assert connection_args[1] == {'extra': {'password': 'randompass', 'username': 'username'}}, "Expected extra data with username/password"

    async def run_test(self):
        await asyncio.to_thread(self.connect_and_login, self.service_config['port'])
        self.validate_logger_output()

@pytest.mark.asyncio
async def test_ftp_authentication_failed():
    service_config = {
        'port': 2121,
        'banner': "Microsoft FTP Service"
    }

     # Mock the logger
    mock_logger = MagicMock(JsonLogger('trapster-1'))

    # Initialize the FTP-specific test
    ftp_test = FTPTest(FtpHoneypot, service_config, mock_logger)

    # Start the server
    await ftp_test.start_server()

    try:
        # Run the FTP-specific test logic
        await ftp_test.run_test()
    finally:
        # Stop the server
        await ftp_test.stop_server()

