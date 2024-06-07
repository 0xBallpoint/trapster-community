from datetime import datetime, timezone
import asyncio, httpx, redis, json, binascii

class BaseLogger(object):
    CONNECTION  = "connection"
    DATA        = "data"
    LOGIN       = "login"
    QUERY       = "query"
    
    def __init__(self, node_id):
        self.node_id = node_id
        self.whitelist_ips = []

    def parse_log(self, logtype, transport, data='', extra={}):
        try:
            dst_ip, dst_port = transport.get_extra_info('sockname')
        except:
            dst_ip = extra.pop("dst_ip", "")
            dst_port = extra.pop("dst_port", 1)
            
        try:
            src_ip, src_port = transport.get_extra_info('peername')
        except:
            # except for the modules : samba, dns, kerberos
            # src_ip is in extra because there is no transport
            src_ip = extra.pop("src_ip", "0.0.0.0")
            src_port = extra.pop("src_port", 1)

        if src_ip in self.whitelist_ips or dst_ip == "255.255.255.255":
            # ignore because IP in whitelist
            return
        else:
            if data:
                # Convert data in Hex format
                data = binascii.hexlify(data).decode()

            event = {
                "device": self.node_id,
                "logtype": logtype,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "src_ip": src_ip,
                "src_port": src_port,
                "timestamp": datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f'),
                "data": data,
                "extra": extra
            }

            return event
        
    def log(self, logtype, transport, data='', extra={}):
        event = self.parse_log(logtype, transport, data, extra)
        return event

class JsonLogger(BaseLogger):
    def log(self, logtype, transport, data='', extra={}):
        event = self.parse_log(logtype, transport, data, extra)
            
        if event:
            print(event)

class RedisLogger(BaseLogger):
    def __init__(self, node_id, host="localhost", port=6379):
        self.node_id = node_id
        self.whitelist_ips = []
        self.r = redis.Redis(host=host, port=port)

    def log(self, logtype, transport, data='', extra={}):
        event = self.parse_log(logtype, transport, data, extra)
        
        if event:
            # Add the event to the sorted set using its timestamp as the primary score
            score = datetime.fromisoformat(event['timestamp']).timestamp()
            self.r.zadd('events', {json.dumps(event): score })

class ApiLogger(BaseLogger):

    def __init__(self, node_id, api_key):
        self.node_id = node_id
        self.headers = {'Authorization': f'token {api_key}'}
        self.whitelist_ips = []

    def log(self, logtype, transport, data='', extra={}):
        event = self.parse_log(logtype, transport, data, extra)
            
        if event:
            loop = asyncio.get_event_loop()            
            loop.create_task(self.post_request(event))

    async def post_request(self, event):
        print(event)
        print('')
        response = await asyncio.to_thread(self._post_request_threaded, event)
        return response

    def _post_request_threaded(self, event):
        with httpx.Client(headers=self.headers) as client:
            response = client.post('http://127.0.0.1:8000/api/v1/event/', json=event, timeout=10)
        return response
