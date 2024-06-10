from .base import BaseProtocol, BaseHoneypot

import struct
import os

#TODO Switch paquet for clear text password  def auth_switch_request(self, seq_no):

class MysqlProtocol(BaseProtocol):
    '''based on https://dev.mysql.com/doc/internals/en/mysql-packet.html'''

    # auth_plugin can be: 
    # "mysql_native_password" : SHA-1 of password
    # "mysql_clear_password" : clear password
    

    config = {
        "version": "5.6.4-m7-log",
        "auth_plugin": "mysql_native_password",
    }

    def __init__(self, config=None):
        if config:
            self.config = config
        self.protocol_name = "mysql"
        self.protocol_version = b'\x0a'

    def connection_made(self, transport):
        self.transport = transport

        self.logger.log(self.protocol_name + "." + self.logger.CONNECTION, self.transport)

        # send initial handshake
        self.transport.write(self.build_packet(self.initial_handshake(), 0))
        
    def data_received(self, data):    
        self.logger.log(self.protocol_name + "." + self.logger.DATA, self.transport, data=data)

        capability_flag = int.from_bytes(data[0x04:0x08], 'little')

        #CLIENT_PROTOCOL_41
        if not capability_flag & 0x00000200:
            # If client version is less than 4.1
            self.transport.write(b"Client does not support authentication protocol requested by server; consider upgrading MySQL client")
            self.connection_lost(None)
            return

        # ClIENT_SSL
        if capability_flag & 0x00000800:
            # client ask for SSL
            self.connection_lost(None)
            return
     
        max_size = int.from_bytes(data[0x08:0x0C], byteorder='little')
        username_end = data.index(b'\x00', 0x24, max_size - 0x24)
        username = str(data[0x24:username_end], 'utf-8')

        password_len = data[username_end + 1]
        using_password = "YES" if password_len > 0 else "NO"

        password_end = username_end + 2 + password_len
        password = None
        if password_len > 0:
            # converted to printable hex for loggin
            password = data[username_end + 2:password_end].hex()
        
        extra_details = data[password_end:]

        self.logger.log(self.protocol_name + "." + self.logger.LOGIN, self.transport, extra={'username':username, 'password':password, 'details':extra_details})

        local_ip, local_port = self.transport.get_extra_info('sockname')

        self.transport.write(
            self.build_packet(
                self.auth_failed("Access denied for user '{}'@'{}' (using password: {})".format(username, local_ip , using_password)),
                2
            )
        )

    def initial_handshake(self):
        # https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_v10.html
        
        protocol_version = self.protocol_version
        server_version = (self.config['version'] + '\x00').encode()
        connection_id = os.urandom(4) # b'\x56\x0a\x00\x00'
        auth_plugin_data_part_1 = os.urandom(8)
        filler_1 = b'\x00'
        capability_flag_1 = b'\xFF\xF7'
        character_set = b'\x21' #utf8_general_ci
        status_flags = b'\x02\x00'
        capability_flag_2 = b'\xFF\x81'
        auth_plugin_data_len = bytes([21]) # 20 bytes random data + \x00 for mysql_native_password
        zeros = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        auth_plugin_data_part_2 = os.urandom(12) + b'\x00'
        auth_plugin = (self.config['auth_plugin'] + '\x00').encode()

        packet = protocol_version + server_version + connection_id  + auth_plugin_data_part_1 + filler_1 + \
            capability_flag_1 + character_set + status_flags + capability_flag_2 + \
            auth_plugin_data_len + zeros + auth_plugin_data_part_2 + auth_plugin

        return packet

    def auth_failed(self, message:str):
        '''
        int<1>  header  [ff] header of the ERR packet
        int<2>  error_code  error-code
        if capabilities & CLIENT_PROTOCOL_41 {
          string[1]     sql_state_marker    # marker of the SQL State
          string[5]     sql_state   SQL State
        }
        string<EOF>     error_message   human readable error message
        '''

        error_packet = b'\xFF'  # Error Packet ID
        error_code = b'\x15\x04'  # Error code 1045 (0x0415)
        sql_state = bytes("#28000", 'utf-8')
        message = message.encode()

        packet = error_packet + error_code + sql_state + message
        
        return packet


    def build_packet(self, payload, id):
        '''
        int<3>  payload_length  Length of the payload. The number of bytes in the packet beyond the initial 4 bytes that make up the packet header.
        int<1>  sequence_id     Sequence ID
        string<var>     payload     [len=payload_length] payload of the packet
        '''
        payload_length = struct.pack("<I", len(payload) )[:3]
        sequence_id = struct.pack("<B", id)
        packet = payload_length + sequence_id + payload

        return packet


class MysqlHoneypot(BaseHoneypot):

    def __init__(self, config, logger, bindaddr='0.0.0.0'):
        super().__init__(config, logger, bindaddr)
        self.handler = lambda: MysqlProtocol(config=config)
        self.handler.logger = logger
        self.handler.config = config
        self.handler.config['host'] = bindaddr
