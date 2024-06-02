from .base import BaseProtocol, BaseHoneypot

import re

class RdpProtocol(BaseProtocol):

    def __init__(self, config=None):
        if config:
            self.config = config
        self.protocol_name = "rdp"
        self.initial_connection = True

    def connection_made(self, transport) -> None:
        self.transport = transport
        self.logger.log(self.protocol_name + "." + self.logger.CONNECTION, self.transport)
       

    def data_received(self, data):
      
        self.logger.log(self.protocol_name + "." + self.logger.DATA, self.transport, data=data)

        decoded_data = data.decode(encoding="utf-8", errors="ignore")
        # Use regex to extract the username.
        match = re.search(r"mstshash=(?P<username>[a-zA-Z0-9-_@]*)", decoded_data)
        username = match and match.groupdict().get("username")

        if self.initial_connection:
            self.logger.log(self.protocol_name + "." + self.logger.LOGIN, self.transport, extra={"username": username, "password": ''})

            # Respond as an NLA-enabled RDP server
            self.transport.write(
                b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x124\x00\x02\x1f\x08\x00\x08\x00\x00\x00"
            )
            self.initial_connection = False
        else:
            # Always respond with a negotiation failure, details from
            # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/96327ab4-d43f-4803-9aff-392ce1fc2073
            self.transport.write(bytes.fromhex("0001000400010000052e"))
            self.connection_lost('')

class RdpHoneypot(BaseHoneypot):
    """common class to all trapster instance"""

    def __init__(self, config, logger, bindaddr="0.0.0.0"):
        super().__init__(config, logger, bindaddr)
        self.handler = lambda: RdpProtocol(config=config)
        self.handler.logger = logger
        self.handler.config = config
