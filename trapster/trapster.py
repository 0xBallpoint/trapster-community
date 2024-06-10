import asyncio
import psutil
import argparse, json, socket, os

from . import __version__
from .modules import *
from .logger import *

class TrapsterManager:
    def __init__(self, config):
        self.logger = None
        self.config = config

    def get_ip(self, config_interface):
        for interface, addrs in psutil.net_if_addrs().items():
            if interface == config_interface:
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        return addr.address
        
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
                elif service_type == 'telnet':
                    server = TelnetHoneypot(service_config, self.logger, bindaddr=ip)
                elif service_type == 'snmp':
                    server = SnmpHoneypot(service_config, self.logger, bindaddr=ip)
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

def list_interfaces():
    interfaces = psutil.net_if_addrs()
    for interface, addrs in interfaces.items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                print(f"{addr.address}\t({interface})")

def main():
    parser = argparse.ArgumentParser(description="Trapster Community honeypot.")
    
    parser.add_argument('-i', '--interfaces', action='store_true', help='Show list of interfaces and their corresponding IPs.')
    parser.add_argument('-c', '--config', type=str, help='Specify the config file to use.')
    parser.add_argument('-s', '--show-config', action='store_true', help='Show the config file currently in use.')
    parser.add_argument('-v', '--version', action='store_true', help='Print version')
    args = parser.parse_args()
    
    if args.version:
        print(__version__)
        return

    if args.interfaces:
        list_interfaces()
        return
    
    if args.config:
        config_file = args.config
        print(f"[+] using config file at : {config_file}")
    else:
        config_file = os.path.dirname(__file__)+"/data/trapster.conf"
        print(f"[+] using default config file")
    
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            config = json.load(f)
    else:
        print(f'[-] config file {config_file} not found')
        return

    if args.show_config:
        print(config)
        return

    print('[+] Starting Trapster Community')
    manager = TrapsterManager(config)

    logger = JsonLogger(config['id'])
    logger.whitelist_ips = []

    manager.logger = logger

    try:
        asyncio.run(manager.start())
    except KeyboardInterrupt:
        print('Finishing')
