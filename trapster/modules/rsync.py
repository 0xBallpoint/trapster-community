from .base import BaseProtocol, BaseHoneypot
import asyncio
import os, base64, random


class RsyncProtocol(BaseProtocol):

    def __init__(self, config=None):
        self.config = config or {
            'version': "31.0",
        }
        self.protocol_name = "rsync"
        self.user = ""
        self.password = ""
        self.state = "greeting" # can be greeting or startup
        self.expected_auth = False
        self.modules = self.config.get('modules', ['Backup', 'Users'])

    def connection_made(self, transport) -> None:
        self.transport = transport
        self.logger.log(self.protocol_name + "." + self.logger.CONNECTION, self.transport)
        
        # Set a timer to send greeting, based on ampirical data
        self.greeting_timer = asyncio.get_event_loop().call_later(
            random.uniform(0.4, 0.7), 
            self._send_server_greeting
        )

    def _send_server_greeting(self):
        """Send greeting"""
        greeting = f"@RSYNCD: {self.config.get('version', '31.0')}"
        self.transport.write(greeting.encode() + b"\n")

    def data_received(self, data):
        self.logger.log(self.protocol_name + "." + self.logger.DATA, self.transport, data=data)

        if self.state == "greeting":
            if data.startswith(b"@RSYNCD: "):
                ## Client sent version string (proper rsync client)
                self.state = "startup"
            else:
                # Invalid data - close connection
                self.transport.write(b"@ERROR: protocol startup error\n")
                self.transport.close()
                return

        elif self.state == "startup":
            if data == b"\n":
                self.logger.log(self.protocol_name + "." + self.logger.QUERY, self.transport, extra={"module": ""})
                for module in self.modules:
                    self.transport.write(f"{module}    	{module}\n".encode())
                self.transport.write(b"@RSYNCD: EXIT\n")
                return

            module = data.decode('utf-8', errors='replace').strip()
            if module in self.modules:
                self.logger.log(self.protocol_name + "." + self.logger.QUERY, self.transport, extra={"module": module})
                self.requested_module = module
                self.auth_challenge = self.generate_challenge()
                self.transport.write(f"@RSYNCD: AUTHREQD {self.auth_challenge}\n".encode())
                self.expected_auth = True
                return

            # Handle authentication response
            elif self.expected_auth:
                auth_data = data.decode().strip().split(" ", 1)
                if len(auth_data) != 2:
                    self.logger.log(self.protocol_name + "." + self.logger.LOGIN, self.transport, extra={"username": auth_data})
                    self.transport.write(f"@ERROR: auth failed on module {self.requested_module}\n".encode())
                    return

                username, hashed_response = auth_data
                self.logger.log(self.protocol_name + "." + self.logger.LOGIN, self.transport, extra={"username": str(username), "password": str(hashed_response)})

                # Always deny authentication (honeypot behavior)
                self.transport.write(f"@ERROR: auth failed on module {self.requested_module}\n".encode())
                self.expected_auth = False  # Reset authentication state
                return

            else:
                self.logger.log(self.protocol_name + "." + self.logger.QUERY, self.transport, extra={"module": module})
                self.transport.write(f"@ERROR: unknown module '{module}'\n".encode())

    def generate_challenge(self):
        """Generate a base64 random challenge string (16 bytes)."""
        return base64.b64encode(os.urandom(16)).decode()
    

class RsyncHoneypot(BaseHoneypot):
    """common class to all trapster instance"""
    service_name = "rsync"

    def __init__(self, config, logger, bindaddr="0.0.0.0"):
        super().__init__(config, logger, bindaddr)
        self.handler = lambda: RsyncProtocol(config=config)
        self.handler.logger = logger
        self.handler.config = config
