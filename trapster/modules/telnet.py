from .base import BaseProtocol, BaseHoneypot

# Telnet command definitions
IAC  = b'\xff'  # Interpret as Command
WILL = b'\xfb'
WONT = b'\xfc'
DO   = b'\xfd'
DONT = b'\xfe'
SE   = b'\xf0'  # End of subnegotiation parameters
NOP  = b'\xf1'  # No operation
DM   = b'\xf2'  # Data mark
BRK  = b'\xf3'  # Break
IP   = b'\xf4'  # Interrupt process
AO   = b'\xf5'  # Abort output
AYT  = b'\xf6'  # Are you there
EC   = b'\xf7'  # Erase character
EL   = b'\xf8'  # Erase line
GA   = b'\xf9'  # Go ahead
SB   = b'\xfa'  # Subnegotiation of the indicated option follows

class TelnetProtocol(BaseProtocol):
    """
    Telnet Honeypot server based on https://www.rfc-editor.org/rfc/rfc854
    """
    
    versions = {
        "D-Link DSL router": b"\xff\xfd\x01\xff\xfd!\xff\xfb\x01\xff\xfb\x03\r\nlogin: ",
    }

    def __init__(self, config=None):
        if config:
            self.config = config
        self.protocol_name = "telnet"
        self.username = b''
        self.password = b''
        self.state = 'USERNAME'

    def connection_made(self, transport):
        self.transport = transport
        self.logger.log(self.protocol_name + "." + self.logger.CONNECTION, self.transport)

        self.transport.write(self.versions[self.config['version']])

    def data_received(self, data):

        if IAC in data:
            self.logger.log(self.protocol_name + "." + self.logger.DATA, self.transport, data=data)
            self.handle_telnet_command(data)
        else:
            self.handle_user_input(data)

    def handle_telnet_command(self, data):
        # Handle incoming Telnet commands here
        i = 0
        while i < len(data):
            if data[i] == IAC[0]:
                i += 1
                if i < len(data) and data[i] in [WILL[0], WONT[0], DO[0], DONT[0]]:
                    option = data[i]
                    i += 1
                    if i < len(data):
                        option_code = data[i]
                        # For simplicity, we'll just respond with DONT for DO and WONT for WILL
                        if option == DO[0]:
                            self.transport.write(IAC + DONT + bytes([option_code]))
                        elif option == WILL[0]:
                            self.transport.write(IAC + WONT + bytes([option_code]))
                        i += 1
                else:
                    # Handle other Telnet commands like SE, NOP, etc.
                    i += 1
            else:
                i += 1

    def handle_user_input(self, data):
        if data == b"\x7f":  # DEL character
            self.erase_character()
        
        if self.state == 'USERNAME':
            if b'\n' in data or b'\r' in data:
                self.transport.write(b"\r\nPassword: ")
                self.state = 'PASSWORD'
            else:
                self.username += data
                self.transport.write(data)
        elif self.state == 'PASSWORD':
            if b'\n' in data or b'\r' in data:
                self.authenticate()
            else:
                self.password += data

    def erase_character(self):
        # Intentionally not removing data from self.username or self.password, to keep informations
        # Send backspace to client
        self.transport.write(b'\b \b')

    def authenticate(self):
        username = self.username.decode('utf-8', errors='replace')
        password = self.password.decode('utf-8', errors='replace')
        self.logger.log(self.protocol_name + "." + self.logger.LOGIN, self.transport, extra={"username": username, "password": password})
        self.transport.write(b"\r\nLogin incorrect.\r\n")
        self.transport.close()

class TelnetHoneypot(BaseHoneypot):

    def __init__(self, config, logger, bindaddr="0.0.0.0"):
        super().__init__(config, logger, bindaddr)
        self.handler = lambda: TelnetProtocol(config=config)
        self.handler.logger = logger
        self.handler.config = config
