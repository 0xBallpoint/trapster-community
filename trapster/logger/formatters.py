from datetime import datetime, timezone
import ipaddress


class DefaultFormatter:
    def format(self, event):
        return event


class EcsFormatter:
    DATABASE_PROTOCOLS = {"mysql", "postgres", "mssql"}
    PROTOCOL_TRANSPORT_MAP = {
        "http": "tcp",
        "https": "tcp",
        "ftp": "tcp",
        "ssh": "tcp",
        "telnet": "tcp",
        "ldap": "tcp",
        "ldaps": "tcp",
        "mysql": "tcp",
        "mssql": "tcp",
        "postgres": "tcp",
        "rdp": "tcp",
        "vnc": "tcp",
        "rsync": "tcp",
        "dns": "udp",
        "snmp": "udp",
    }

    def __init__(
        self,
        node_id,
        service_version=None,
        environment=None,
        host_name=None,
        observer_name="Trapster",
        ecs_version="8.11.0",
    ):
        self.node_id = node_id
        self.service_version = service_version
        self.environment = environment
        self.host_name = host_name or node_id
        self.observer_name = observer_name
        self.ecs_version = ecs_version

    @staticmethod
    def _compact(value):
        if isinstance(value, dict):
            compacted = {}
            for key, nested_value in value.items():
                cleaned = EcsFormatter._compact(nested_value)
                if cleaned is not None:
                    compacted[key] = cleaned
            return compacted if compacted else None

        if isinstance(value, list):
            compacted = [EcsFormatter._compact(item) for item in value]
            compacted = [item for item in compacted if item is not None]
            return compacted if compacted else None

        return value

    @staticmethod
    def _to_utc_iso(timestamp):
        if not timestamp:
            return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        if isinstance(timestamp, datetime):
            dt = timestamp
        else:
            dt = None
            for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
                try:
                    dt = datetime.strptime(timestamp, fmt)
                    break
                except Exception:
                    continue

            if dt is None:
                return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        try:
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        except Exception:
            return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    @staticmethod
    def _infer_network_type(*ips):
        for ip in ips:
            if not ip:
                continue
            try:
                ip_obj = ipaddress.ip_address(ip)
                return "ipv6" if ip_obj.version == 6 else "ipv4"
            except ValueError:
                continue
        return "ipv4"

    def format(self, event):
        logtype = event.get("logtype", "")
        protocol, _, action = logtype.partition(".")
        protocol = protocol.lower() if isinstance(protocol, str) else protocol
        protocol_key = protocol or "unknown"
        transport = self.PROTOCOL_TRANSPORT_MAP.get(protocol, None)
        extra = event.get("extra", {})
        username = extra.get("username")
        password = extra.get("password")
        protocol_extra = {
            key: value for key, value in extra.items() if key not in {"username", "password"}
        }

        event_type = ["info"]
        event_category = ["network"]
        event_outcome = "unknown"
        if action in {"login"}:
            event_type = ["start", "info"]
            event_category = ["authentication", "network"]
            event_outcome = "failure"
        elif action in {"connection"}:
            event_type = ["connection", "start"]
            event_outcome = "success"
        elif action in {"query"}:
            event_type = ["access", "info"]
            if protocol in self.DATABASE_PROTOCOLS:
                event_category = ["network", "database"]
            event_outcome = "unknown"
        elif action in {"data"}:
            event_outcome = "unknown"

        trapster_payload = {
            "raw": event.get("data"),
            "login": {
                "username": username,
                "password": password,
            },
            protocol_key: protocol_extra,
        }

        ecs_event = {
            "@timestamp": self._to_utc_iso(event.get("timestamp")),
            "ecs": {"version": self.ecs_version},
            "event": {
                "kind": "event",
                "category": event_category,
                "type": event_type,
                "action": action or None,
                "outcome": event_outcome,
                "dataset": f"trapster.{protocol}" if protocol else "trapster.unknown",
            },
            "observer": {
                "name": self.observer_name,
                "id": self.node_id,
                "type": "honeypot",
                "vendor": "Ballpoint",
                "product": "Trapster",
            },
            "service": {
                "version": self.service_version,
                "environment": self.environment,
            },
            "host": {"name": self.host_name},
            "network": {
                "transport": transport,
                "protocol": protocol or None,
                "application": protocol or None,
                "type": self._infer_network_type(event.get("src_ip"), event.get("dst_ip")),
            },
            "source": {
                "ip": event.get("src_ip"),
                "port": event.get("src_port"),
                "user": {"name": username},
            },
            "destination": {
                "ip": event.get("dst_ip"),
                "port": event.get("dst_port"),
            },
            "related": {
                "ip": list(
                    dict.fromkeys(
                        ip for ip in [event.get("src_ip"), event.get("dst_ip")] if ip is not None
                    )
                ),
                "user": list(dict.fromkeys(user for user in [username] if user is not None)),
            },
            "user": {"name": username},
            "trapster": trapster_payload,
        }

        if protocol in {"http", "https"}:
            ecs_event["http"] = {
                "request": {
                    "method": extra.get("method"),
                    "headers": extra.get("headers"),
                },
                "response": {"status_code": extra.get("status_code")},
            }
            ecs_event["url"] = {"path": extra.get("target")}

        return self._compact(ecs_event)
