from .base import BaseProtocol, BaseHoneypot

import asyncio
import binascii
import time
import sys

class TelnetProtocol(BaseProtocol):

    def __init__(self, config=None):
        if config:
            self.config = config
        self.protocol_name = "telnet"
        self.username = b''
        self.password = b''
        self.state = 0

    def connection_made(self, transport):
        self.transport = transport
        self.log_data("connection_made", self.transport.get_extra_info('peername'), time.time())

        self.transport.write(b"\xff\xfb\x01\xff\xfb\x03\xff\xfb\0\xff\xfd\0\xff\xfd\x1f\r\n")
        self.transport.write(b"\nUser Access Verification\r\n\r\n")
        self.transport.write(b"Username: ")
        self.state = 1
        
    def data_received(self, data):
        print(data)
        if data == b'\xff\xfd\x01\xff\xfd\x03\xff\xfd\x00\xff\xfb\x00\xff\xfb\x1f\xff\xfa\x1f\x00e\x00\x1b\xff\xf0':
            self.state = 1
            return

        if data == b'\x03': #CTRL-C
            print('Closing!!')
            self.connection_lost(None)
        else:
            if self.state == 1:
                if data == b'\x0D' or data == b'\r' or data[-1] == 0: #ENTER
                    self.state = 2
                    self.transport.write(b"\r\nPassword: ")
                else:
                    self.transport.write(data)
                    self.username += data 

            elif self.state == 2:
                if data == b'\x0D' or data[-1] == 0: #ENTER
                    self.state = 1
                    self.transport.write(b"\r\n% Login invalid\r\n\r\n")
                    self.transport.write(b"Username: ")
                    print(self.username + b' / ' + self.password)
                    self.username = b''
                else:
                    self.password += data 
                
    def unrecognized_data(self, data):
        self.log_data('unrecognized_data', self.transport.get_extra_info('peername')[0], time.time(), {"data":data})
        self.transport.close()


class TelnetHoneypot(BaseHoneypot):

    def __init__(self, config, logger, bindaddr="0.0.0.0"):
        super().__init__(config, logger, bindaddr)
        self.handler = lambda: TelnetProtocol(config=config)
        self.handler.logger = logger
        self.handler.config = config
