from datetime import datetime, timezone
import binascii


class BaseLogger(object):
    CONNECTION = "connection"
    DATA = "data"
    LOGIN = "login"
    QUERY = "query"

    def __init__(self, node_id):
        self.node_id = node_id
        self.whitelist_ips = []
        self.type = "Base"

    def parse_log(self, logtype, transport, data='', extra={}):
        try:
            dst_ip, dst_port = transport.get_extra_info('sockname')
        except Exception:
            dst_ip = extra.pop("dst_ip", "")
            dst_port = extra.pop("dst_port", 1)

        try:
            src_ip, src_port = transport.get_extra_info('peername')
        except Exception:
            # except for modules where no transport object exists.
            src_ip = extra.pop("src_ip", "0.0.0.0")
            src_port = extra.pop("src_port", 1)

        if src_ip in self.whitelist_ips or dst_ip == "255.255.255.255":
            return

        if data:
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
            "extra": extra,
        }
        return event

    def log(self, logtype, transport, data='', extra={}):
        return self.parse_log(logtype, transport, data, extra)
