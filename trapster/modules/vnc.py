from .base import BaseProtocol, BaseHoneypot

import binascii
from typing import Optional

#TODO add SSL support

class VncProtocol(BaseProtocol):
    
    # All possible version:
    versions = {
        "RFB_33" : b'RFB 003.003\n',
        "RFB_37" : b'RFB 003.007\n',
        "RFB_38" : b'RFB 003.008\n',
    }
    
    config = {
        "version": "RFB_38"
    }

    def __init__(self, config=None):
        if config:
            self.config = config
        self.protocol_name = "vnc"
        self.challenge = None

    def connection_made(self, transport):
        self.transport = transport
        
        self.logger.log(self.protocol_name + "." + self.logger.CONNECTION, self.transport)
        
        self.transport.write(self.versions[self.config['version']])
        self.state = 'wait_pversion'
        
    def data_received(self, data):
        self.logger.log(self.protocol_name + "." + self.logger.DATA, self.transport, data=data)

        if self.state == 'wait_pversion':
            if data == self.versions[self.config['version']]:
                # sending security types
                self.transport.write(binascii.unhexlify('020217'))
                self.state = 2
            else:
                self.unrecognized_data(data)
        elif self.state == 2:
            if data == binascii.unhexlify('02'):
                self.accept_vnc_authentication()
            else:
                self.unrecognized_data(data)
        elif self.state == 3:
            self.authentication(data)

    def make_challenge(self):
        from os import urandom
        self.challenge = binascii.hexlify(urandom(16))        
        return binascii.unhexlify(self.challenge)

    def accept_vnc_authentication(self):
        self.transport.write(self.make_challenge())
        self.state = 3

    def authentication(self, data):
        # needs to be truncated to 8bytes length (max password length)
        response = binascii.hexlify(data)[:16]
        challenge = self.challenge[:16]


        # https://hashcat.net/forum/thread-8833-post-46908.html
        # Clear password can be retrieved using hashcat (very long)
        # print("./hashcat.bin -m 14000 -a 3  -1 resources/VNC_ascii.hcchr --hex-charset {}:{} '?1?1?1?1?1?1?1?1'".format(
        #    response.decode(),
        #    challenge.decode()
        #    ))
        # 
        # VNC_ascii.hcchr (all 95 ascii characters transfomed for VNC) with 00:
        # 8646c626a666e6169656d636b676f60e8e4ece2eae6eee1e9e5e8242c222a262e2129252d232b272f20a8a4aca2aaa6aea1a9a5a0c8c4ccc2cac6cec1c9c840224a4547ab4d4fabc7edabadebe5cdc3c7c3474fcf43a449414e46406043e00

        self.transport.write(binascii.unhexlify('00000001')) #response code
        self.transport.write(binascii.unhexlify('00000016')) #message length
        self.transport.write(b'Authentication failure') #message
        self.transport.close()
        
        self.logger.log(self.protocol_name + "." + self.logger.LOGIN, self.transport, extra={'response': response.decode(), 'challenge': challenge.decode()})

    def unrecognized_data(self, data):
        self.transport.close()

    def connection_lost(self, exc: Optional[Exception]) -> None:
        self.state = 0
        self.transport.close()

class VncHoneypot(BaseHoneypot):
    def __init__(self, config, logger, bindaddr="0.0.0.0"):
        super().__init__(config, logger, bindaddr)
        self.handler = lambda: VncProtocol(config=config)
        self.handler.logger = logger
        self.handler.config = config