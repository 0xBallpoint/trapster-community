from .base import BaseProtocol, BaseHoneypot
import os, base64

class RsyncProtocol(BaseProtocol):

    config = {
        'version': "31.0",
    }

    def __init__(self, config=None):
        if config:
            self.config = config
        self.protocol_name = "rsync"
        self.user = ""
        self.password = ""
        self.expected_auth = False
        self.modules = ["Backup", "Users"]

    def connection_made(self, transport) -> None:
        self.transport = transport
        self.logger.log(self.protocol_name + "." + self.logger.CONNECTION, self.transport)

    def data_received(self, data):
        self.logger.log(self.protocol_name + "." + self.logger.DATA, self.transport, data=data)

        if data.startswith(b"@RSYNCD:"):
            greeting = f"@RSYNCD: {self.config['version']}"
            self.transport.write(greeting.encode() + b"\n")
            return

        elif data == b"\n":
            for module in self.modules:
                self.transport.write(f"{module}    	{module}\n".encode())
            self.transport.write(b"@RSYNCD: EXIT\n")
            return
        
        module = data.decode().strip()
        if module in self.modules:
            self.requested_module = module
            self.auth_challenge = self.generate_challenge()
            self.transport.write(f"@RSYNCD: AUTHREQD {self.auth_challenge}\n".encode())
            self.expected_auth = True
            return

        # Step 4: Handle authentication response
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
            self.logger.log(self.protocol_name + "." + self.logger.QUERY, self.transport, extra={"module": data.decode('utf-8', errors='replace')})
            self.transport.write(f"@ERROR: unknown module '{module}'\n".encode())
            return

    def generate_challenge(self):
        """Generate a base64 random challenge string (16 bytes)."""
        return base64.b64encode(os.urandom(16)).decode()
    

class RsyncHoneypot(BaseHoneypot):
    """common class to all trapster instance"""

    def __init__(self, config, logger, bindaddr="0.0.0.0"):
        super().__init__(config, logger, bindaddr)
        self.handler = lambda: RsyncProtocol(config=config)
        self.handler.logger = logger
        self.handler.config = config
