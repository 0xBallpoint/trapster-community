from .base import BaseProtocol, BaseHoneypot

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

import asyncio, asyncssh, os, datetime

async def handle_client(process: asyncssh.SSHServerProcess) -> None:
    """
    Not used, but can be used if we want to allow SSH connection with a very simple simulated prompt
    """
    
    welcome_message = '''Welcome to Ubuntu 20.10 (GNU/Linux 5.8.0-63-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of {time}

  System load:  1.11              Processes:             132
  Usage of /:   50.7% of 1.79TB   Users logged in:       1
  Memory usage: 10%               IPv4 address for eno0: 151.80.38.22
  Swap usage:   6%                IPv6 address for eno0: 2001:41d0:e:b16::1

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

0 updates can be installed immediately.
0 of these updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release. Check your Internet connection or proxy settings


Last login: Wed Jun  8 22:06:15 2022 from 188.64.246.56
'''
    now = datetime.datetime.now(datetime.UTC)
    process.stdout.write(welcome_message.format(time=now.strftime('%a %b  %d %H:%M:%S UTC %Y')))

    while not process.stdin.at_eof():
        try:
            process.stdout.write('root@computer:~# ')
            await process.stdin.readline()
        except asyncssh.misc.BreakReceived:
            process.stdout.write('\n')
            process.stdin.feed_eof()
            process.close()
        except asyncssh.misc.TerminalSizeChanged:
            pass

class SshProtocol(asyncssh.SSHServer, BaseProtocol):

    def __init__(self):
        self.protocol_name = "ssh"
        self.passwords = {'root': '123456',
             'guest': 'password'
            }

    def connection_made(self, transport: asyncssh.SSHServerConnection) -> None:
        self.transport = transport
        self.logger.log(self.protocol_name + "." + self.logger.CONNECTION, self.transport)

    def begin_auth(self, username: str) -> bool:
        # If the user's password is the empty string, no auth is required
        # return passwords.get(username) != ''
        return True

    def password_auth_supported(self) -> bool:
        return True

    async def validate_password(self, username: str, password: str) -> bool:
        self.logger.log(self.protocol_name + "." + self.logger.LOGIN, self.transport, extra={"username":username, "password":password})
        return False
        #return self.passwords.get(username) == password

    def public_key_auth_supported(self) -> bool:
        return True
    
    async def validate_public_key(self, username, key):
        key_type = key.get_algorithm()
        key_data = key.export_public_key().decode()
        fingerprint = key.get_fingerprint()
        
        self.logger.log(self.protocol_name + "." + self.logger.LOGIN, self.transport, extra={
            "username":username, 
            "key_type":key_type, 
            "key_data":key_data,
            "fingerprint": fingerprint
        })
        return False

    def kbdint_auth_supported(self) -> bool:
        return False

    # from https://asyncssh.readthedocs.io/en/latest/_modules/asyncssh/connection.html
    def _send_version(self) -> None:
        """Start the SSH handshake"""
        version = b'SSH-2.0-' + b"OpenSSH_8.3p1 Ubuntu 1ubuntu0.1"

        if self.is_client():
            self._client_version = version
            self.set_extra_info(client_version=version.decode('ascii'))
        else:
            self._server_version = version
            self.set_extra_info(server_version=version.decode('ascii'))

        self._send(version + b'\r\n')


    asyncssh.connection.SSHConnection._send_version = _send_version

class SshHoneypot(BaseHoneypot):
    """common class to all trapster instance"""

    def __init__(self, config, logger, bindaddr="0.0.0.0"):
        super().__init__(config, logger, bindaddr)
        self.handler = SshProtocol
        self.handler.logger = logger
        self.handler.config = config

        self.generate_keys()

    async def _start_server(self):
        try:
            self.server = await asyncssh.create_server(SshProtocol, self.bindaddr, self.port,
                                 server_host_keys=[os.path.dirname(__file__)+"/../data/ssh/ssh_host_key"],
                                 process_factory=handle_client
                                 )
            await self.server.serve_forever()
        except OSError as e:
            if e.errno == 98:
                print("port ssh already in use")
                print(e)
        except asyncio.CancelledError:
            raise

    def generate_keys(self):
        # Generate an RSA private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Serialize the private key in OpenSSH format
        private_key_openssh = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Serialize the public key in OpenSSH format
        public_key_openssh = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        )

        if not os.path.exists(os.path.dirname(__file__)+"/../data/ssh"):
            os.makedirs(os.path.dirname(__file__)+"/../data/ssh")

        # Save the private and public keys in OpenSSH format
        with open(os.path.dirname(__file__)+"/../data/ssh/ssh_host_key", 'w+') as private:
            private.write(private_key_openssh.decode('utf-8'))

        with open(os.path.dirname(__file__)+"/../data/ssh/ssh_host_key.pub", 'w+') as public:
            public.write(public_key_openssh.decode('utf-8'))
    
