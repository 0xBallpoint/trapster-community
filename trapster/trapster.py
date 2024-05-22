import asyncio, json
import netifaces, os

from trapster.modules import *
from trapster.logger import *

class TrapsterManager:
    def __init__(self, config):
        self.logger = None
        self.config = config

    def get_ip(self, config_interface):
        for interface in netifaces.interfaces():
            if interface == config_interface:
                return netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
        
        print(f"Interface {config_interface} does not exist")
        return

    async def start(self):
        ip = self.get_ip(self.config['interface'])

        for service_type in self.config['services']:
            for service_config in self.config['services'][service_type]:

                if service_type == 'ftp':
                    server = FtpHoneypot(service_config, self.logger, bindaddr=ip)
                elif service_type == 'http':
                    server = HttpHoneypot(service_config, self.logger, bindaddr=ip)
                elif service_type == 'ssh':
                    server = SshHoneypot(service_config, self.logger, bindaddr=ip)
                elif service_type == 'dns':            
                    server = DnsHoneypot(service_config, self.logger, bindaddr=ip, proxy_dns_ip="127.0.0.1")
                elif service_type == 'vnc':
                    server = VncHoneypot(service_config, self.logger, bindaddr=ip)
                elif service_type == 'mysql':
                    server = MysqlHoneypot(service_config, self.logger, bindaddr=ip)
                elif service_type == 'postgres':
                    server = PostgresHoneypot(service_config, self.logger, bindaddr=ip)
                elif service_type == 'ldap':
                    server = LdapHoneypot(service_config, self.logger, bindaddr=ip)
                elif service_type == 'rdp':
                    server = RdpHoneypot(service_config, self.logger, bindaddr=ip)
                else:
                    print(f"[-] Unreconized service {service_type}")
                    break
                                        
                try:
                    print(f"[+] Starting service {service_type} on port {service_config['port']}")
                    await server.start()
                except Exception as e:
                    print(e)
        
        while True:
            await asyncio.sleep(10)

def main():
    print('[+] Starting trapster')

    if os.path.exists('data/trapster.conf'):
        print('[+] using config file at : data/trapster.conf')
        with open('data/trapster.conf', 'r') as f:
            config = json.load(f)
    else:
        print('[-] config file not found (data/trapster.conf)')
        return

    manager = TrapsterManager(config)

    logger = JsonLogger(config['id'])
    logger.whitelist_ips = []

    manager.logger = logger

    try:
        asyncio.run(manager.start())
    except KeyboardInterrupt:
        print('Finishing')
