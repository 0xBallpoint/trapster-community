#port 161/162
#udp 

from .base import BaseProtocol, BaseHoneypot
from .libs import dns

import asyncio
from scapy.all import SNMP

class UdpTransporter():
    def __init__(self, dst_ip = "0.0.0.0", dst_port=1, src_ip="0.0.0.0", src_port=1):
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.src_ip = src_ip
        self.src_port = src_port
    def get_extra_info(self, name, default=None):
        #https://docs.python.org/3/library/asyncio-protocol.html
        if name == 'sockname':
            return self.dst_ip, self.dst_port
        elif name == 'peername':
            return self.src_ip, self.src_port
        else:
            return None

class SnmpUdpProtocol(BaseProtocol):

    def __init__(self, config=None):
        if config:
            self.config = config
        self.protocol_name = "snmp"
    
    def connection_made(self, transport) -> None:
        self.transport = transport
        #print("snmp connection made")
        #self.logger.log(self.protocol_name + "." + self.logger.CONNECTION, self.transport)
    async def GetRequest():
        return
    async def GetResponse():
        return
    async def SetRequest():
        return

    def datagram_received(self, data, addr):
        snmp_data = SNMP(data)
        snmp_data.show()
        community = snmp_data.community.val
        oids = " ".join([item.oid.val for item in snmp_data.PDU.varbindlist])
        version = snmp_data.version.val

        src_ip, src_port = addr
        dst_ip, dst_port = self.transport.get_extra_info('sockname')
        udp_log = UdpTransporter(dst_ip, dst_port, src_ip, src_port)
        self.logger.log(self.protocol_name + "." + self.logger.DATA, udp_log, extra={"community":community, "version":version, "varbind":oids})


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

        transport, protocol = await loop.create_datagram_endpoint(lambda: self.handler_udp(), 
                                    local_addr=(self.bindaddr, self.port))
        
        self.server = await loop.create_server(self.handler, host=self.bindaddr, port=self.port)
        
        try:
            await self.server.serve_forever()
        except asyncio.CancelledError:
            raise