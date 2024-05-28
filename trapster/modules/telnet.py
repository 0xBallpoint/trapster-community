from .base import BaseProtocol, BaseHoneypot
import asyncio
import binascii
import time


class TelnetProtocol(BaseProtocol):

    def __init__(self, config=None):
        if config:
            self.config = config
        self.protocol_name = "telnet"
        self.username = ''
        self.password = ''
        self.buffer = ''  # Buffer to accumulate data
        self.state = 0

    def connection_made(self, transport):
        '''self.transport = transport
        connection_data = {
            "transport": str(self.transport),
            "peername": self.transport.get_extra_info('peername')
        }'''
        self.transport = transport

        self.logger.log(self.protocol_name + "." + self.logger.CONNECTION, self.transport)
        self.transport.write(b"\xff\xfb\x01\xff\xfb\x03\xff\xfb\x00\xff\xfd\x00\xff\xfd\x1f\r\n")
        self.transport.write(self.config.get('banner').encode('utf-8') + b"\r\n")
        self.transport.write(b"User Access Verification\r\n\r\nUsername: ")
        self.state = 1

    def data_received(self, data):
        # Ignore telnet negotiation sequences
        if data.startswith(b'\xff'):
            return

        if data == b'\x03':  # CTRL-C
            print('Closing!!')
            self.transport.close()
            return

        for char in data:
            if char == ord(b'\r') or char == ord(b'\n'):  # Check for Enter key
                line = self.buffer.strip()
                self.buffer = ''

                if self.state == 1:
                    self.username = line
                    self.state = 2
                    self.transport.write(b"\r\nPassword: ")
                elif self.state == 2:
                    self.password = line
                    self.transport.write(b"\r\n")  # Move to a new line after password entry
                    username = self.username.strip()
                    password = self.password.strip()
                    self.logger.log(self.protocol_name + "." + self.logger.CONNECTION, self.transport)
                    self.logger.log(self.protocol_name + "." + self.logger.DATA, self.transport, data=data)
                    self.logger.log(self.protocol_name + "." + self.logger.LOGIN, self.transport,
                                    extra={"username": str(self.username), "password": str(self.password)})

                    self.state = 3
                    if self.check_credentials(username, password):
                        self.transport.write(b"===============================================================================\r\n\r\n")
                        self.transport.write(b"Microsoft  Telnet Server\r\n\r\n")
                        self.transport.write(b"===============================================================================\r\n\r\n")

                        self.transport.write(b"root@OGM:~$  ")
                        print(data)
                    else:
                        self.transport.write(b"\r\n% Login invalid\r\n\r\n")
                        self.transport.write(b"Username: ")
                        self.username = ''
                        self.password = ''
                        self.state = 1
            else:
                # Echo the character back to the client for username
                if self.state == 1:
                    self.transport.write(bytes([char]))
                # Replace the character with '*' for password
                elif self.state == 2:
                    self.transport.write(b'')
                # Add the character to the buffer
                self.buffer += chr(char)

    def check_credentials(self, username, password):
        return username == self.config.get('username') and password == self.config.get('password')

    '''def connection_lost(self, exc):
        self.logger.log(self.protocol_name + ".CONNECTION_LOST", self.transport)    '''

    def unrecognized_data(self, data):
        self.logger.log('unrecognized_data', self.transport.get_extra_info('peername')[0],
                        binascii.hexlify(data).decode())
        self.transport.close()


class TelnetHoneypot(BaseHoneypot):

    def __init__(self, config, logger, bindaddr="0.0.0.0"):
        super().__init__(config, logger, bindaddr)
        self.handler = lambda: TelnetProtocol(config=config)
        self.handler.logger = logger
        self.handler.config = config
