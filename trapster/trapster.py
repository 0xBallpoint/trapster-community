import asyncio
import psutil
import argparse, json, socket, os
import logging

from . import __version__
from .modules import *
from .logger import set_logger

class TrapsterManager:
    def __init__(self, config):
        self.logger = None
        self.config = config

    def get_ip(self, config_interface):
        for interface, addrs in psutil.net_if_addrs().items():
            if interface == config_interface:
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        logging.info(f"Using IP: {addr.address} ({config_interface})")
                        return addr.address
        
        logging.warning(f"Interface {config_interface} does not exist, using 0.0.0.0")
        return

    async def start(self):
        ip = self.get_ip(self.config.get('interface', None))
        
        for service_type in self.config['services']:
            for service_config in self.config['services'][service_type]:
                if service_type == 'ftp':
                    server = FtpHoneypot(service_config, self.logger, bindaddr=ip)
                elif service_type == 'http':
                    server = HttpHoneypot(service_config, self.logger, bindaddr=ip)
                elif service_type == 'https':
                    server = HttpsHoneypot(service_config, self.logger, bindaddr=ip)
                elif service_type == 'ssh':
                    server = SshHoneypot(service_config, self.logger, bindaddr=ip)
                elif service_type == 'dns':            
                    server = DnsHoneypot(service_config, self.logger, bindaddr=ip, proxy_dns_ip="127.0.0.1")
                elif service_type == 'vnc':
                    server = VncHoneypot(service_config, self.logger, bindaddr=ip)
                elif service_type == 'mysql':
                    server = MysqlHoneypot(service_config, self.logger, bindaddr=ip)
                elif service_type == 'mssql':
                    server = MssqlHoneypot(service_config, self.logger, bindaddr=ip)
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
                    logging.error(f"Unrecognized service {service_type}")
                    break
                                        
                try:
                    logging.info(f"Starting service {service_type} on port {service_config['port']}")
                    await server.start()
                except Exception as e:
                    logging.error(f"Error starting {service_type}: {e}")
        
        while True:
            await asyncio.sleep(10)

def list_interfaces():
    interfaces = psutil.net_if_addrs()
    for interface, addrs in interfaces.items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                logging.info(f"{addr.address}\t({interface})")

def load_config(config_path):
    if config_path:
        logging.info(f"Using config file at: {config_path}")
    else:
        config_path = os.path.join(os.path.dirname(__file__), "data", "trapster.conf")
        logging.info(f"Using default config file at: {config_path}")
    
    if not os.path.exists(config_path):
        logging.error(f'Config file {config_path} not found')
        return None
    
    with open(config_path, 'r') as f:
        return json.load(f)
    
def main():
    # set logging level to INFO
    logging.basicConfig(level=logging.INFO)
    
    parser = argparse.ArgumentParser(description="Trapster Community honeypot.")
    parser.add_argument('-i', '--interfaces', action='store_true', help='Show list of interfaces and their corresponding IPs.')
    parser.add_argument('-c', '--config', type=str, help='Specify the config file to use.')
    parser.add_argument('-s', '--show-config', action='store_true', help='Show the config file currently in use.')
    parser.add_argument('-v', '--version', action='store_true', help='Print version')
    args = parser.parse_args()
    
    if args.version:
        logging.info(__version__)
        return

    if args.interfaces:
        list_interfaces()
        return

    logging.info('=== Starting Trapster Community ===')
    config = load_config(args.config)
    if not config:
        return

    if args.show_config:
        logging.info(config)
        return

    logger = set_logger(config)
    if logger == None:
        return
      
    manager = TrapsterManager(config)
    logger.whitelist_ips = []
    manager.logger = logger

    try:
        asyncio.run(manager.start())
    except KeyboardInterrupt:
        logging.info('Finishing')
