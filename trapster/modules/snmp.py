from .base import BaseProtocol, BaseHoneypot, UdpTransporter

import asyncio
from scapy.all import SNMP
from scapy.error import Scapy_Exception

class SnmpUdpProtocol(BaseProtocol):
    '''
    SNMP log only server
    TODO: could be improve to respond to messages with custom data
    '''
    def __init__(self, config=None):
        if config:
            self.config = config
        self.protocol_name = "snmp"
    
    def connection_made(self, transport) -> None:
        self.transport = transport
        
    async def GetRequest():
        return
    async def GetResponse():
        return
    async def SetRequest():
        return

    def datagram_received(self, data, addr):
        version, community, oids = self.parse_snmp(data)
        if version or community or oids:
            src_ip, src_port = addr
            dst_ip, dst_port = self.transport.get_extra_info('sockname')
            transport_udp = UdpTransporter(dst_ip, dst_port, src_ip, src_port)
            self.logger.log(self.protocol_name + "." + self.logger.QUERY, transport_udp, extra={"community":community, "version":version, "varbind":oids})

    def parse_snmp(self, data):
        try:
            snmp_data = SNMP(data)
            community = snmp_data.community.val.decode()
            oids = " ".join([item.oid.val for item in snmp_data.PDU.varbindlist])
            version = snmp_data.version.val

        except Scapy_Exception:
            #TODO: Scapy does not support SNMPv3 by default, but a new class can be created to support it, like in PySNMP
            version = "Unknown"
            community = "Unknown"
            oids = "Unknown"
            
        return version, community, oids

class SnmpHoneypot(BaseHoneypot):
    """common class to all trapster instance"""

    def __init__(self, config, logger, bindaddr="0.0.0.0"):
        super().__init__(config, logger, bindaddr)
        self.handler = lambda: SnmpUdpProtocol(config=config)
        self.handler.logger = logger
        self.handler.config = config

        self.handler_udp = SnmpUdpProtocol

    async def _start_server(self):
        loop = asyncio.get_running_loop()

        # Create UDP server
        transport, protocol = await loop.create_datagram_endpoint(lambda: self.handler_udp(), 
                                    local_addr=(self.bindaddr, self.port))