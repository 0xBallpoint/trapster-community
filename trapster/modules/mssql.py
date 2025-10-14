from trapster.modules.base import BaseProtocol, BaseHoneypot

class MssqlProtocol(BaseProtocol):

    def __init__(self, config=None):
        self.protocol_name = "mssql"
        self.config = config or {
            "version": "2012",
            "hostname": "SQL01",
        }
        
        self.versions = {
            "2008": "0A000000",  # SQL Server 2008
            "2012": "0B000000",  # SQL Server 2012
            "2014": "0C000000",  # SQL Server 2014
            "2016": "0D000000",  # SQL Server 2016
            "2017": "0E000000",  # SQL Server 2017
            "2019": "0F000000",  # SQL Server 2019
            "2022": "10000000",  # SQL Server 2022
        }
        self.version = self.versions.get(self.config.get("version", "2012"), "0B000000")
        self.hostname = self.config.get("hostname", "SQL01")

    def connection_made(self, transport):
        self.transport = transport
        self.logger.log(self.protocol_name + "." + self.logger.CONNECTION, self.transport)

    def data_received(self, data):
        self.logger.log(self.protocol_name + "." + self.logger.DATA, self.transport, data=data)
        
        if len(data) < 1:
            self.transport.close()
            return
        
        packet_type = data[0]
        
        if packet_type == 0x12:  # PRELOGIN
            self.pre_login(data)
        elif packet_type == 0x10:  # LOGIN7
            self.login(data)
        elif packet_type == 0x16:  # TLS/SSL handshake - we don't support encryption
            # Close immediately - we already indicated ENCRYPT_NOT_SUP
            self.transport.close()
        elif packet_type == 0x80:  # SQL Browser packet
            # Close - not SQL Browser service
            self.transport.close()
        else:
            # Unknown packet type
            self.transport.close()

    def pre_login(self, data):
        # PRELOGIN response
        self.transport.write(
            bytes.fromhex(
                "0401002500000100000015000601001b000102"
                f"001c000103001d0000ff{self.version}00000200"
            )
        )

    def login(self, data):
        try:
            credentials = self.extract_credentials(data)
            self.logger.log(self.protocol_name + "." + self.logger.LOGIN, self.transport, extra=credentials)
            
            auth_response = self.generate_login_error("Login failed for user '" + credentials['username'] + "'.", 18456)
            self.transport.write(auth_response)
        except Exception as e:
            # If extraction fails, just log the raw data
            self.logger.log(self.protocol_name + "." + self.logger.DATA, self.transport, data=data)
        finally:
            # Always close connection after login attempt
            self.transport.close()

    def decrypt_mssql_password(self, encrypted):
        # The decryption is done with a simple XOR and nibble swap
        # https://nvd.nist.gov/vuln/detail/CVE-2002-1872
            
        def decrypt_byte(b):
            # XOR byte with A5
            decrypted_byte = b ^ 0xA5
            # Swap nibbles
            return ((decrypted_byte & 0x0F) << 4) | ((decrypted_byte & 0xF0) >> 4)
        
        decrypted_bytes = bytearray(decrypt_byte(b) for b in encrypted)
        return decrypted_bytes.decode('utf-16-le')

    def extract_credentials(self, data):
        username_start = int.from_bytes(data[48:50], byteorder='little')
        username_length = int.from_bytes(data[50:52], byteorder='little')
        username = data[8 + username_start : 8 + username_start + (username_length * 2)].decode('utf-16-le').strip('\x00')

        password_start = int.from_bytes(data[52:54], byteorder='little')
        password_length = int.from_bytes(data[54:56], byteorder='little')
        password_encoded = data[8 + password_start : 8 + password_start + (password_length * 2)]
        password = self.decrypt_mssql_password(password_encoded)

        return {"username": username, "password": password}

    def generate_login_error(self, error_msg="", error_code=18456):
        if not error_msg:
            error_msg = "Login failed due to invalid credentials."
        
        hostname_len = len(self.hostname).to_bytes(1, 'little')
        error_msg_len = len(error_msg).to_bytes(2, 'little')
        error_code_bytes = error_code.to_bytes(4, 'little')
        
        error_token = (
            error_code_bytes
            + b'\x01\x0e'
            + error_msg_len
            + error_msg.encode('utf-16-le')
            + hostname_len
            + self.hostname.encode('utf-16-le')
            + b'\x00\x01\x00\x00\x00'
        )
        
        done_token = b'\xfd\x02' + b'\x00' * 10
        
        error_token_len = len(error_token).to_bytes(2, 'little')
        packet_data = b'\xaa' + error_token_len + error_token + done_token
        
        total_length = (len(packet_data) + 8).to_bytes(2, 'big')
        header = b'\x04\x01' + total_length + b'\x00\x35\x01\x00'
        
        return header + packet_data

class MssqlHoneypot(BaseHoneypot):
    def __init__(self, config, logger, bindaddr='0.0.0.0'):
        super().__init__(config, logger, bindaddr)
        
        def protocol_factory():
            protocol = MssqlProtocol(config=config)
            protocol.logger = logger
            protocol.config = config
            protocol.config['host'] = bindaddr
            return protocol
        
        self.handler = protocol_factory
        self.handler.logger = logger
        self.handler.config = config
