from datetime import datetime
import asyncio, httpx, base64, redis, time, json

class BaseLogger(object):

    LOG_DEVICE_BOOT                             = "trapster.device.boot"
    LOG_DEVICE_MSG                              = "trapster.device.message"
    LOG_DEVICE_DEBUG                            = "trapster.device.debug"
    LOG_DEVICE_ERROR                            = "trapster.device.error"
    LOG_DEVICE_PING                             = "trapster.device.ping"
    LOG_DEVICE_CONFIG_SAVE                      = "trapster.device.config"

    LOG_BASE_CONNECTION_MADE                    = "trapster.base.connection"
    LOG_BASE_DATA_RECEIVED                      = "trapster.base.data"

    LOG_FTP_CONNECTION_MADE                     = "trapster.ftp.connection"
    LOG_FTP_DATA_RECEIVED                       = "trapster.ftp.data"
    LOG_FTP_LOGIN                               = "trapster.ftp.login"

    LOG_SSH_CONNECTION_MADE                     = "trapster.ssh.connection"
    LOG_SSH_LOGIN                               = "trapster.ssh.login"

    LOG_DNS_QUERY                               = "trapster.dns.query"

    LOG_HTTP_GET                                = "trapster.http.get"
    LOG_HTTP_POST                               = "trapster.http.post"
    LOG_HTTP_BASIC                              = "trapster.http.basic"
    
    LOG_LDAP_CONNECTION_MADE                    = "trapster.ldap.connection"
    LOG_LDAP_DATA_RECEIVED                      = "trapster.ldap.data"
    LOG_LDAP_LOGIN                              = "trapster.ldap.login"
    LOG_LDAP_SEARCH                             = "trapster.ldap.search"

    LOG_VNC_CONNECTION_MADE                     = "trapster.vnc.connection"
    LOG_VNC_DATA_RECEIVED                       = "trapster.vnc.data"
    LOG_VNC_AUTH                                = "trapster.vnc.auth"

    LOG_MYSQL_CONNECTION_MADE                   = "trapster.mysql.connection"
    LOG_MYSQL_DATA_RECEIVED                     = "trapster.mysql.data"
    LOG_MYSQL_LOGIN                             = "trapster.mysql.login"
    LOG_MYSQL_UNRECOGNIZED                      = "trapster.mysql.unrecognized"

    LOG_POSTGRES_CONNECTION_MADE                = "trapster.postgres.connection"
    LOG_POSTGRES_DATA_RECEIVED                  = "trapster.postgres.data"
    LOG_POSTGRES_LOGIN                          = "trapster.postgres.login"

    LOG_RDP_CONNECTION_MADE                     = "trapster.rdp.connection"
    LOG_RDP_DATA_RECEIVED                       = "trapster.rdp.data"
    LOG_RDP_LOGIN                               = "trapster.rdp.login"
    
    def __init__(self, node_id):
        self.node_id = node_id
        self.whitelist_ips = []

    def parse_log(self, logtype, transport, extra={}):
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
            return
        else:
            # data are always byte encoded, so we need to use base64
            if extra.get('data', False):
                extra['data'] = base64.b16encode(extra['data']).decode()

            event = {
                "device": self.node_id,
                "logtype": logtype,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "src_ip": src_ip,
                "src_port": src_port,
                "timestamp": str(datetime.utcnow()),
                "extra": extra,
            }

            return event
        
    def log(self, logtype, transport, extra={}):
        event = self.parse_log(logtype, transport, extra)
        return event

class JsonLogger(BaseLogger):
    def log(self, logtype, transport, extra={}):
        event = self.parse_log(logtype, transport, extra)
            
        if event:
            print(event)

class RedisLogger(BaseLogger):
    def __init__(self, node_id, host="localhost", port=6379):
        self.node_id = node_id
        self.whitelist_ips = []
        self.r = redis.Redis(host=host, port=port)

    def log(self, logtype, transport, extra={}):
        event = self.parse_log(logtype, transport, extra)
        
        if event:
            # Add the event to the sorted set using its timestamp as the primary score
            score = datetime.fromisoformat(event['timestamp']).timestamp()
            self.r.zadd('events', {json.dumps(event): score })

class ApiLogger(BaseLogger):

    def __init__(self, node_id, api_key):
        self.node_id = node_id
        self.headers = {'Authorization': f'token {api_key}'}
        self.whitelist_ips = []

    def log(self, logtype, transport, extra={}):
        event = self.parse_log(logtype, transport, extra)
            
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
