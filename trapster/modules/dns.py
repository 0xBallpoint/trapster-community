from .base import BaseProtocol, BaseHoneypot, UdpTransporter
from .libs import dns

import asyncio
        
class EchoClientProtocol(asyncio.DatagramProtocol):
    def __init__(self, message, on_con_lost):
        self.message = message
        self.on_con_lost = on_con_lost
        self.transport = None
        self.return_data = b''

    def connection_made(self, transport):
        self.transport = transport
        self.transport.sendto(self.message)

    def datagram_received(self, data, addr):        
        self.return_data = data
        self.transport.close()

    def connection_lost(self, exc):
        try:
            self.on_con_lost.set_result(True)
        except asyncio.exceptions.InvalidStateError:
            pass


class DnsUdpProtocol(BaseProtocol):

    config = {
        'dns1': "127.0.0.1"
    }

    def __init__(self, config=None):
        self.protocol_name = "dns"

        if config:
            self.config = config

    def connection_made(self, transport) -> None:
        self.transport = transport
        
    def datagram_received(self, data, addr):
        # decode dns packet to json
        decoded_packet = dns.decode_dns_message(data)    

        # proxy packet to legit dns server
        self.loop = asyncio.get_running_loop()
        self.loop.create_task(self.proxy_packet(data, addr, decoded_packet))

    async def proxy_packet(self, data, addr, decoded_packet):
        on_con_lost = self.loop.create_future()

        # need to specify src_ip and src_port because self.transport endpoint is not connected
        src_ip, src_port = addr
        dst_ip, dst_port = self.transport.get_extra_info('sockname')
        transport_udp = UdpTransporter(dst_ip, dst_port, src_ip, src_port)
        self.logger.log(self.protocol_name + "." + self.logger.QUERY, transport_udp, extra={"query": decoded_packet})


        transport, protocol = await self.loop.create_datagram_endpoint(
            lambda: EchoClientProtocol(data, on_con_lost),
            remote_addr=(self.config['dns1'], 53))

        try:
            # send back data from the legit dns server
            await on_con_lost
            self.transport.sendto(protocol.return_data, addr)
        finally:
            transport.close()        


class DnsTcpProtocol(BaseProtocol):
    """
    For now it indicates that DNS is enable to attackers scanning only TCP
    """
    #TODO

    def __init__(self):
        self.protocol_name = "dns"  

class DnsHoneypot(BaseHoneypot):

    def __init__(self, config, logger, bindaddr, proxy_dns_ip):
        super().__init__(config, logger, bindaddr)
        # binaddr 0.0.0.0 is not accepted because real dns server is running on 127.0.0.1
        # so it mused be set in the conf file
        self.handler = lambda: DnsTcpProtocol(config=config)
        self.handler.logger = logger
        self.handler.config = config

        self.handler_udp = DnsUdpProtocol
        self.handler_udp.config['dns1'] = proxy_dns_ip

    async def _start_server(self):
        loop = asyncio.get_running_loop()

        # Create UDP server
        transport, protocol = await loop.create_datagram_endpoint(lambda: self.handler_udp(), 
                                    local_addr=(self.bindaddr, self.port))
        
        # Create TCP server
        self.server = await loop.create_server(self.handler, host=self.bindaddr, port=self.port)
        try:
            await self.server.serve_forever()
        except asyncio.CancelledError:
            raise
