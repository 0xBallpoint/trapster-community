from .base import BaseProtocol, BaseHoneypot

from struct import unpack

class PostgresProtocol(BaseProtocol):
    '''based on https://github.com/qeeqbox/honeypots/blob/main/honeypots/postgres_server.py'''
    
    config = {
    }

    def __init__(self, config=None):
        if config:
            self.config = config
        self.protocol_name = "postgres"

    def connection_made(self, transport):
        self.transport = transport
        self._state = 1
        self._variables = {}
        self.logger.log(self.protocol_name + "." + self.logger.CONNECTION, self.transport)
        
    def data_received(self, data):    
        
        self.logger.log(self.protocol_name + "." + self.logger.DATA, self.transport, data=data)

        if self._state == 1:
            if data == b'\x00\x00\x00\x08\x04\xd2\x16/': # SSLRequest
                self._state = 2
                self.transport.write(b'N')
            else:
                # error code for nmap scan
                self.transport.write(b"E\x00\x00\x00\x8b\x53\x46\x41\x54\x41\x4c\x00\x56\x46\x41\x54\x41\x4c\x00\x43\x30\x41\x30\x30\x30\x00\x4d\x75\x6e\x73\x75\x70\x70\x6f\x72\x74\x65\x64\x20\x66\x72\x6f\x6e\x74\x65\x6e\x64\x20\x70\x72\x6f\x74\x6f\x63\x6f\x6c\x20\x36\x35\x33\x36\x33\x2e\x31\x39\x37\x37\x38\x3a\x20\x73\x65\x72\x76\x65\x72\x20\x73\x75\x70\x70\x6f\x72\x74\x73\x20\x33\x2e\x30\x20\x74\x6f\x20\x33\x2e\x30\x00\x46\x70\x6f\x73\x74\x6d\x61\x73\x74\x65\x72\x2e\x63\x00\x4c\x32\x31\x39\x35\x00\x52\x50\x72\x6f\x63\x65\x73\x73\x53\x74\x61\x72\x74\x75\x70\x50\x61\x63\x6b\x65\x74\x00\x00")
                self.transport.close()

        elif self._state == 2:
            self.read_data_custom(data)        
            self._state = 3
            # from https://www.postgresql.org/docs/current/protocol-message-formats.html
            self.transport.write(b'R\x00\x00\x00\x08\x00\x00\x00\x03') #AuthenticationCleartextPassword
            
        elif self._state == 3:
            if data[0] == 112 and 'user' in self._variables:
                self.read_password_custom(data)
                username = self.check_bytes(self._variables['user'])
                password = self.check_bytes(self._variables['password'])
                
                self.logger.log(self.protocol_name + "." + self.logger.LOGIN, self.transport, extra={"username": username, "password": password})

                # based on https://www.postgresql.org/docs/current/protocol-message-formats.html
                # ErrorResponse
                message = b'Mpassword authentication failed for user "' + username.encode() + b'"\x00'
                length = ( 4 + 21 + len(message) + 27 ).to_bytes(4, byteorder='big')
                self.transport.write(b'E' + length + b'SFATAL\x00' + b'VFATAL\x00' +b'C28P01\x00' + message + b'\x46\x61\x75\x74\x68\x2e\x63\x00\x4c\x33\x32\x36\x00\x52\x61\x75\x74\x68\x5f\x66\x61\x69\x6c\x65\x64\x00\x00')
                self.transport.close()
            else:
                self.transport.close()

    def check_bytes(self, string):
        if isinstance(string, bytes):
            return string.decode()
        else:
            return str(string)

    def read_data_custom(self, data):
        _data = data.decode('utf-8')
        length = unpack('!I', data[0:4])
        encoded_list = (_data[8:-1].split('\x00'))
        self._variables = dict(zip(*([iter(encoded_list)] * 2)))

    def read_password_custom(self, data):
        data = data.decode('utf-8')
        self._variables['password'] = data[5:].split('\x00')[0]


class PostgresHoneypot(BaseHoneypot):

    def __init__(self, config, logger, bindaddr='0.0.0.0'):
        super().__init__(config, logger, bindaddr)
        self.handler = lambda: PostgresProtocol(config=config)
        self.handler.logger = logger
        self.handler.config = config
