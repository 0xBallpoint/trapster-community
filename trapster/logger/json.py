from .output import OutputLogger


class JsonLogger(OutputLogger):
    def __init__(self, node_id, event_format="default", format_kwargs=None):
        super().__init__(
            node_id=node_id,
            output="terminal",
            event_format=event_format,
            output_kwargs={},
            format_kwargs=format_kwargs or {},
        )
