from trapster.modules.base import BaseProtocol, BaseHoneypot

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

import asyncio, asyncssh, os, datetime, logging, random

# Optional AI import - gracefully handle when AI dependencies aren't installed
try:
    from trapster.ai import SSHAgent
    AI_AVAILABLE = True
except ImportError:
    SSHAgent = None
    AI_AVAILABLE = False

logging.getLogger('asyncssh').setLevel(logging.WARNING)

async def handle_client(process: asyncssh.SSHServerProcess) -> None:    
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

    # some variables
    username = process.get_extra_info('username')
    peer_addr = process.get_extra_info('peername')[0]
    session_id = "ssh:" + peer_addr + ":" + username
    current_directory = "~"
    server_name = "ns" + str(random.randint(100000, 999999))


    # Initialize AI agent if available
    ai_agent = SSHAgent(username=username) if AI_AVAILABLE else None

    while True:
        try:
            process.stdout.write(f'{username}@{server_name}:{current_directory}$ ')
            command = await process.stdin.readline()

            # Handle EOF (CTRL+D) or empty input
            if process.stdin.at_eof() or not command:
                process.stdout.write('logout\n')
                process.stdout.write('\n')
                process.close()
                return
                
            command = command.strip()
            if command == "":
                continue
            
            # exit command
            if command in ['exit', 'logout']:
                process.stdout.write('logout\n')
                process.close()
                return
            
            # make query to AI agent
            result = await ai_agent.make_query(session_id, command)

            # handle result
            result['directory'] = result['directory'] or "/home/guest/"
            result['command_result'] = result['command_result'] or ""

            if result['directory'] == f"/home/{username}/":
                current_directory = "~"
            else:
                current_directory = result['directory'].replace(f"/home/{username}", "~")

            if result['command_result'] == "":
                continue

            process.stdout.write(result['command_result'] + '\n')

        except asyncssh.misc.BreakReceived:
            process.stdout.write('\n')
            process.stdin.feed_eof()
            process.close()
            return
        except KeyboardInterrupt:
            process.stdout.write('^C\n')
            process.stdin.feed_eof() 
            process.close()
            return
        except asyncssh.misc.TerminalSizeChanged:
            process.stdout.write(f'\r')
            continue

        except Exception as e:
            process.stdout.write(f'Error: {e}\n')
            process.close()
            return

class SshProtocol(asyncssh.SSHServer, BaseProtocol):
    def __init__(self, config=None):
        self.protocol_name = "ssh"
        self.config = config or {
            'version': 'SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u7',
            'banner': '',
            'users': {
            }
        }

    def connection_made(self, transport: asyncssh.SSHServerConnection) -> None:
        self.transport = transport
        self.transport._send_version = self.send_version
        self.logger.log(self.protocol_name + "." + self.logger.CONNECTION, self.transport)

    def begin_auth(self, username: str) -> bool:
        # If the user's password is the empty string, no auth is required
        # return self.config.get('users').get(username) != ''
        auth_banner = self.config.get('banner', None)
        if auth_banner:
            self.transport.send_auth_banner(auth_banner.encode() + '\r\n')
    
        return True

    def password_auth_supported(self) -> bool:
        return True

    async def validate_password(self, username: str, password: str) -> bool:
        self.logger.log(self.protocol_name + "." + self.logger.LOGIN, self.transport, extra={"username":username, "password":password})
        # Get the expected password for the username from the users dict
        expected_password = self.config.get('users', {}).get(username)
        # Compare the provided password with the expected password
        return password == expected_password

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
    def send_version(self) -> None:
        """Start the SSH handshake"""
        version = self.config.get('version', 'SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u7').encode()
    
        if self.transport.is_client():
            self.transport._client_version = version
            self.transport.set_extra_info(client_version=version.decode('ascii'))
        else:
            self.transport._server_version = version
            self.transport.set_extra_info(server_version=version.decode('ascii'))

        self.transport._send(version + b'\r\n')

class SshHoneypot(BaseHoneypot):
    """common class to all trapster instance"""

    def __init__(self, config, logger, bindaddr="0.0.0.0"):
        super().__init__(config, logger, bindaddr)
        self.handler = lambda: SshProtocol(config=config)
        self.handler.logger = logger
        self.handler.config = config

        self.generate_keys()

    async def _start_server(self):
        try:
            # Get all available host keys
            host_keys = self.get_host_keys()
            
            if not host_keys:
                logging.error("No SSH host keys found")
                return False
            
            self.server = await asyncssh.create_server(self.handler, self.bindaddr, self.port,
                                 server_host_keys=host_keys,
                                 process_factory=handle_client
                                 )
            await self.server.serve_forever()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logging.error(e)
            return False

    def generate_keys(self):
        """Generate multiple host key types: RSA, ECDSA, and ED25519"""
        ssh_dir = os.path.dirname(__file__) + "/../data/ssh"
        
        if not os.path.exists(ssh_dir):
            os.makedirs(ssh_dir)

        # Define key configurations
        key_configs = [
            {
                'type': 'rsa',
                'filename': 'ssh_host_rsa_key',
                'generator': lambda: rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=3072,
                    backend=default_backend()
                )
            },
            {
                'type': 'ecdsa',
                'filename': 'ssh_host_ecdsa_key',
                'generator': lambda: ec.generate_private_key(
                    curve=ec.SECP256R1(),
                    backend=default_backend()
                )
            },
            {
                'type': 'ed25519',
                'filename': 'ssh_host_ed25519_key',
                'generator': lambda: ed25519.Ed25519PrivateKey.generate()
            }
        ]

        for config in key_configs:
            private_key_path = os.path.join(ssh_dir, config['filename'])
            public_key_path = os.path.join(ssh_dir, config['filename'] + '.pub')
            
            # Skip if keys already exist
            if os.path.exists(private_key_path) and os.path.exists(public_key_path):
                continue
                
            try:
                # Generate the private key
                private_key = config['generator']()
                
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

                # Save the private and public keys
                with open(private_key_path, 'w') as private_file:
                    private_file.write(private_key_openssh.decode('utf-8'))

                with open(public_key_path, 'w') as public_file:
                    public_file.write(public_key_openssh.decode('utf-8'))
                    
            except Exception as e:
                logging.warning(f"Failed to generate {config['type']} key: {e}")
                continue

    def get_host_keys(self):
        """Get all available host key files"""
        ssh_dir = os.path.dirname(__file__) + "/../data/ssh"
        host_keys = []
        
        # List of key types to look for
        key_types = ['rsa', 'ecdsa', 'ed25519']
        
        for key_type in key_types:
            key_path = os.path.join(ssh_dir, f'ssh_host_{key_type}_key')
            if os.path.exists(key_path):
                host_keys.append(key_path)
        
        # Fallback to legacy key if no new keys exist
        legacy_key_path = os.path.join(ssh_dir, 'ssh_host_key')
        if not host_keys and os.path.exists(legacy_key_path):
            host_keys.append(legacy_key_path)
            
        return host_keys
    
