from trapster.modules.base import BaseHoneypot, BaseProtocol

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
    Banners sourced from nmap service fingerprint database (nmap-service-probes).
    Entries marked [nmap] use exact byte sequences from the database.
    Entries marked [approx] use realistic approximations for services not in the database.
    """

    # greeting: bytes sent on connect ({hostname} is substituted at connection time)
    # failure:  response after wrong credentials (login/password modes only)
    # mode:     "login"    - collect username then password
    #           "password" - collect password only (no username prompt)
    #           "menu"     - display banner and close (no credential capture)
    versions = {

        # [nmap] Backwards compatibility key — D-Link DSL router telnetd
        "D-Link DSL router": {
            "greeting": b"\xff\xfd\x01\xff\xfd\x21\xff\xfb\x01\xff\xfb\x03\r\nlogin: ",
            "failure":  b"\r\nLogin incorrect.\r\n",
            "mode":     "login",
        },
        "D-Link DSL router telnetd": {
            "greeting": b"\xff\xfd\x01\xff\xfd\x21\xff\xfb\x01\xff\xfb\x03\r\nlogin: ",
            "failure":  b"\r\nLogin incorrect.\r\n",
            "mode":     "login",
        },
        "Cisco router telnetd / IOS": {
            "greeting": (
                b"\xff\xfb\x01\xff\xfb\x03\xff\xfd\x18\xff\xfd\x1f"
                b"\r\n\r\nUser Access Verification\r\n\r\nUsername: "
            ),
            "failure":  b"\r\n% Login invalid\r\n\r\n",
            "mode":     "login",
        },
        "HP JetDirect printer telnetd": {
            "greeting": b"\xff\xfc\x01\r\nHP JetDirect\r\n\r\nPassword:",
            "failure":  b"\r\nAccess denied.\r\n",
            "mode":     "password",
        },
        "IBM switch telnetd": {
            "greeting": (
                b"\x1b[1;1H\x1b[2J\x1b[8;38H\x1b[1;1H"
                b"\x1b[2;1H(C) Copyright IBM Corp. 1999\x1b[3;1HAll Rights Reserved.\r\n\r\nLogin: "
            ),
            "failure":  b"\r\nLogin incorrect.\r\n",
            "mode":     "login",
        },
        "Netgear FSM router/switch telnetd": {
            "greeting": b"\xff\xfb\x01\xff\xfb\x03\r\n(FSM7328S) \r\nUser:",
            "failure":  b"\r\nLogin incorrect.\r\n",
            "mode":     "login",
        },
        "Netgear broadband router telnetd": {
            "greeting": b"\xff\xfb\x03\xff\xfb\x01\r\nPassword: ",
            "failure":  b"\r\nLogin failed.\r\n",
            "mode":     "password",
        },
        "Siemens router telnetd": {
            "greeting": b"\r\nSiemens 3640 T1E1 [COMBO] Router (RS-130) v5.2.0 Ready\r\n\xff\xfb\x01\xff\xfb\x03\xff\xfd\x01\xff\xfe\x01Username: ",
            "failure":  b"\r\nAccess denied.\r\n",
            "mode":     "login",
        },
        "Hikvision DVR": {
            "greeting": (
                b"\r\n******************************************************************************\r\n"
                b"* Copyright (c) 2023 Hikvision Digital Technology Co., Ltd.                  *\r\n"
                b"* Without the owner's prior written consent,                                 *\r\n"
                b"* no decompiling or reverse-engineering shall be allowed.                    *\r\n"
                b"******************************************************************************\r\n"
                b"\r\nLogin: "
            ),
            "failure":  b"\r\nLogin failed.\r\n",
            "mode":     "login",
        }
    }

    def __init__(self, config=None):
        self.config = config or {}
        self.config.setdefault('version', 'Cisco router telnetd / IOS')
        self.config.setdefault('hostname', 'router')
        self.protocol_name = "telnet"
        self.username = b''
        self.password = b''
        self.state = 'USERNAME'
        self.after_cr = False

    def connection_made(self, transport):
        self.transport = transport
        self.logger.log(self.protocol_name + "." + self.logger.CONNECTION, self.transport)

        version_key = self.config.get('version', 'Cisco router telnetd / IOS')
        self._version = self.versions.get(version_key, self.versions['Cisco router telnetd / IOS'])

        hostname = self.config.get('hostname', 'router').encode()
        greeting = self._version["greeting"].replace(b"{hostname}", hostname)
        self.transport.write(greeting)

        mode = self._version.get("mode", "login")
        if mode == "password":
            self.state = 'PASSWORD'
        elif mode == "menu":
            self.state = 'MENU'

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
        if self.state == 'MENU':
            self.transport.close()
            return

        if data == b"\x7f":  # DEL character
            self.erase_character()

        # The "\n" or "\0" closing a "\r" sent in an earlier packet
        if self.after_cr and data[:1] in (b'\n', b'\x00'):
            data = data[1:]
        self.after_cr = False

        # Clients send one key at a time (character mode) or a whole line at
        # once (line mode, bots): keep the text before each line ending.
        while data:
            ends = [i for i in (data.find(b'\r'), data.find(b'\n')) if i != -1]
            end = min(ends) if ends else len(data)
            text, data = data[:end], data[end:]

            if self.state == 'USERNAME':
                self.username += text
                self.transport.write(text)
            elif self.state == 'PASSWORD':
                self.password += text

            if not ends:
                return
            # "\r\n" and "\r\0" are one line ending
            self.after_cr = data == b'\r'
            data = data[2:] if data[:2] in (b'\r\n', b'\r\x00') else data[1:]

            if self.state == 'USERNAME':
                self.transport.write(b"\r\nPassword: ")
                self.state = 'PASSWORD'
            elif self.state == 'PASSWORD':
                self.authenticate()
                return

    def erase_character(self):
        # Intentionally not removing data from self.username or self.password, to keep informations
        # Send backspace to client
        self.transport.write(b'\b \b')

    def authenticate(self):
        username = self.username.decode('utf-8', errors='replace')
        password = self.password.decode('utf-8', errors='replace')
        self.logger.log(self.protocol_name + "." + self.logger.LOGIN, self.transport, extra={"username": username, "password": password})
        self.transport.write(self._version["failure"])
        self.transport.close()

class TelnetHoneypot(BaseHoneypot):
    service_name = "telnet"

    def __init__(self, config, logger, bindaddr="0.0.0.0"):
        super().__init__(config, logger, bindaddr)
        self.handler = lambda: TelnetProtocol(config=config)
        self.handler.logger = logger
        self.handler.config = config
