from .base import BaseProtocol, BaseHoneypot

class FtpProtocol(BaseProtocol):

    config = {
        'banner': "Microsoft FTP Service"
       # 'passwords' : 
       #     {'root': 'vpRcL9QNUFj093yMp',
       #     'user': 'GzUODJoYqwg5jjhXG',
       # },
    }

    def __init__(self, config=None):
        if config:
            self.config = config
        self.protocol_name = "ftp"
        self.user = ""
        self.password = ""
        self.authenticated = False

    def connection_made(self, transport) -> None:
        self.transport = transport

        self.logger.log(self.protocol_name + "." + self.logger.CONNECTION, self.transport)
       
        self.transport.write(b'220 ' + bytes(self.config['banner'], "utf-8") + b'\r\n')

    def data_received(self, data):
        # log all data received : print(binascii.hexlify(data))
      
        self.logger.log(self.protocol_name + "." + self.logger.DATA, self.transport, data=data)
        try:
            cmd = data[:4].decode()
            client_input = data[5:].decode().strip('\r\n')
        except UnicodeDecodeError:
            return
    
        if cmd == 'USER':
            self.user = client_input
            self.transport.write("331 User {} OK. Password required\r\n".format(client_input).encode())
        elif cmd == 'PASS':
            self.handle_password(client_input)
        elif cmd == 'SYST':
            if "microsoft" in self.config['banner'].lower():
                self.transport.write(b"215 Windows_NT\r\n")
            else:
                self.transport.write(b"215 UNIX Type: L8\r\n")
        elif cmd == 'QUIT':
            self.transport.write(b"221 Logout\r\n")
            self.connection_lost(None)
        else:
            self.transport.write(b"500 Unknown Command\r\n")

    def handle_password(self, data):
        self.password = data
        
        if not self.user:
            self.transport.write(b"503 Login with USER first.\r\n")
        elif self.user:
            self.logger.log(self.protocol_name + "." + self.logger.LOGIN, self.transport, extra={"username": str(self.user), "password": str(self.password)})

            self.transport.write(b"530 Authentication Failed\r\n")

            #try:
            #    true_password = self.config.get('passwords').get(self.user)
            #    if true_password == self.password:
            #        self.transport.write(b"230 OK. Current restricted directory is /\r\n")
            #        self.authenticated = True    
            #except KeyError:
            #    self.transport.write(b"530 Authentication Failed\r\n")

class FtpHoneypot(BaseHoneypot):
    """common class to all trapster instance"""

    def __init__(self, config, logger, bindaddr="0.0.0.0"):
        super().__init__(config, logger, bindaddr)
        self.handler = lambda: FtpProtocol(config=config)
        self.handler.logger = logger
        self.handler.config = config
