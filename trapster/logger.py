from datetime import datetime, timezone
import asyncio, httpx, redis, json, binascii, logging

def set_logger(config):
    node_id = config.get('id')
    try:
        config.get('logger')
        logger_name = config.get('logger').get('name')

        if logger_name is not None: #Set logger type
            Logger_class = globals().get(logger_name, None)
            kwargs = config.get('logger').get("kwargs", None)

            try:
                logger = Logger_class(node_id, **kwargs)
            except Exception as e:
                logging.error(f'[-] Invalid logger: {e}')
                return
            
        else:
            raise TypeError
        
        logging.info(f"[+] using logger type: {logger_name} ")
        
    except: #Default to JsonLogger
        logging.info(f"[+] defaulting to logger type: JsonLogger")
        return JsonLogger(node_id)
    
    return logger

class BaseLogger(object):
    CONNECTION  = "connection"
    DATA        = "data"
    LOGIN       = "login"
    QUERY       = "query"
    
    def __init__(self, node_id):
        self.node_id = node_id
        self.whitelist_ips = []
        self.type = "Base"

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
    def __init__(self, node_id):
        self.node_id = node_id
        self.whitelist_ips = []

    def log(self, logtype, transport, data='', extra={}):
        event = self.parse_log(logtype, transport, data, extra)
            
        if event:
            logging.info(event)

class FileLogger(BaseLogger):
    def __init__(self, node_id, logfile = "/var/log/trapster-community.log", mode = "w+"):
        self.node_id = node_id
        self.logfile = logfile
        self.mode = mode
        self.file = open(self.logfile, self.mode)

    def log(self, logtype, transport, data='', extra={}):
        event = self.parse_log(logtype, transport, data, extra)
            
        try:
            json.dump(event, self.file)
            self.file.write("\n")
            self.file.flush()
        except IOError as e:
            logging.error(f"An error occurred while writing to the log file: {e}")
        
    def __del__(self):
        if self.file:
            self.file.close()

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

    def __init__(self, node_id, url, headers={}):
        self.node_id = node_id
        self.url = url
        self.headers = headers
        self.whitelist_ips = []
        
    def log(self, logtype, transport, data='', extra={}):
        event = self.parse_log(logtype, transport, data, extra)
            
        if event:
            loop = asyncio.get_event_loop()            
            loop.create_task(self.post_request(event))

    async def post_request(self, event):
        response = await asyncio.to_thread(self._post_request_threaded, event)
        return response

    def _post_request_threaded(self, event):
        with httpx.Client(headers=self.headers) as client:
            response = client.post(self.url, json=event, timeout=10)
        return response
