from .base import BaseProtocol, BaseHoneypot

class Socks5Protocol(BaseProtocol):
    '''based on RFC 1928 (https://datatracker.ietf.org/doc/html/rfc1928) '''

    SOCKS_VERSION = b'\x05'
    METHOD = b'\x02' # USERNAME/PASSWORD
       
    def __init__(self, config=None):
        if config:
            self.config = config
        self.protocol_name = "socks5"

#    def connection_made(self, transport):
#        self.transport = transport
#        self.log_data("connection_made", self.transport.get_extra_info('peername'), time.time())
#        
#    def data_received(self, data):    
#        self.log_data("data_received", self.transport.get_extra_info('peername'), time.time(), {'data':data})
#
#        if data[:1] == b'\x05':
#            self.initial_handshake(data)
#        elif data[:1] == b'\x01':
#            self.authenticate(data)
#        else:
#            self.socks_failed()
#
#    def initial_handshake(self, payload):
#        try:
#            #+----+----------+----------+
#            #|VER | NMETHODS | METHODS  |
#            #+----+----------+----------+
#            #| 1  |    1     | 1 to 255 |
#            #+----+----------+----------+
#            ver, nmethods, methods  = struct.unpack("!BB%ds" % (len(payload)-2), payload)
#        except struct.error:
#            # not a socks handshake packet
#            self.socks_failed()
#
#        if ver != 0x05:
#            # version not correct
#            self.socks_failed()
#
#        if self.METHOD not in methods:
#            # client doesn't support password
#            self.socks_failed()
#
#        self.transport.write(self.SOCKS_VERSION + self.METHOD)
#
#    def authenticate(self, payload):
#        username_length = payload[1]
#        username = payload[2:2 + username_length]
#        password_length = int.from_bytes( payload[2 + username_length:2 + username_length + 1], "little")
#        
#        if password_length != 0:
#            password = payload[-password_length:]
#        else:
#            password = b""
#        
#        self.log_data("authenticate", self.transport.get_extra_info('peername'), time.time(), {'username': username,'password':password})
#        self.socks_failed()
#        return username, password
#
#    def socks_failed(self):
#        self.transport.write(self.SOCKS_VERSION + b'\xFF') # NO ACCEPTABLE METHODS
#        self.connection_lost(None)

class Socks5Honeypot(BaseHoneypot):

   def __init__(self, config, logger, bindaddr="0.0.0.0"):
        super().__init__(config, logger, bindaddr)
        self.handler = lambda: Socks5Protocol(config=config)
        self.handler.logger = logger
        self.handler.config = config