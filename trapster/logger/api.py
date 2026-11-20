from .output import OutputLogger


class ApiLogger(OutputLogger):
    def __init__(self, node_id, url, headers=None, event_format="default", format_kwargs=None):
        if headers is None:
            headers = {}
        super().__init__(
            node_id=node_id,
            output="api",
            event_format=event_format,
            output_kwargs={"url": url, "headers": headers},
            format_kwargs=format_kwargs or {},
        )
