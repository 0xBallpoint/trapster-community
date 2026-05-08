from .output import OutputLogger


class RedisLogger(OutputLogger):
    def __init__(self, node_id, host="localhost", port=6379, event_format="default", format_kwargs=None):
        super().__init__(
            node_id=node_id,
            output="redis",
            event_format=event_format,
            output_kwargs={"host": host, "port": port},
            format_kwargs=format_kwargs or {},
        )
